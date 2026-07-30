package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	rdebug "runtime/debug" // aliased: the package name collides with the -debug flag
	"strings"
)

// maxIMAPResponseBytes bounds how much of an untagged IMAP response is buffered
// while waiting for the tagged line that ends it. Without a limit a hostile (or
// merely broken) server can grow the buffer until the proxy runs out of memory.
const maxIMAPResponseBytes = 1 << 20

// MailProxy handles IMAP and SMTP proxy connections
type MailProxy struct {
	// Protocol type (IMAP or SMTP)
	Protocol string

	// Listen port
	Port int

	// Default remote port if not specified
	DefaultRemotePort int

	// TLS config for upstream connections
	TLSConfig *tls.Config

	// Enable debug logging
	Debug bool
}

// MailConnection represents a single mail proxy connection
type MailConnection struct {
	id            string
	clientConn    net.Conn
	serverConn    net.Conn
	protocol      string
	targetServer  string
	realUsername  string
	authenticated bool
	tlsEnabled    bool
	reader        *bufio.Reader
	writer        *bufio.Writer
	serverReader  *bufio.Reader
	serverWriter  *bufio.Writer
	debug         bool
}

func IMAPMain() {
	// Create TLS config for upstream connections
	systemRoots, err := loadSystemCertPool()
	if err != nil {
		log.Println("Warning: Could not load system certificate pool:", err)
		systemRoots = x509.NewCertPool()
	} else {
		if *debug {
			log.Printf("Loaded system certificate pool with %d certificates", len(systemRoots.Subjects()))
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS10,
		RootCAs:    systemRoots,
	}

	// Start IMAP proxy
	if !*disableIMAP {
		imapProxy := &MailProxy{
			Protocol:          "IMAP",
			Port:              *imapPort,
			DefaultRemotePort: 993,
			TLSConfig:         tlsConfig,
			Debug:             *debug,
		}
		if err := imapProxy.Start(); err != nil {
			log.Fatal("Failed to start IMAP proxy:", err)
		}
	}

	// Start SMTP proxy
	if !*disableSMTP {
		smtpProxy := &MailProxy{
			Protocol:          "SMTP",
			Port:              *smtpPort,
			DefaultRemotePort: 587,
			TLSConfig:         tlsConfig,
			Debug:             *debug,
		}
		if err := smtpProxy.Start(); err != nil {
			log.Fatal("Failed to start SMTP proxy:", err)
		}
	}

	// Print single startup message
	if !*disableIMAP && !*disableSMTP {
		log.Printf("Aqua Mail Proxy started (IMAP:%d, SMTP:%d)", *imapPort, *smtpPort)
	} else if !*disableIMAP {
		log.Printf("Aqua Mail Proxy started (IMAP:%d)", *imapPort)
	} else if !*disableSMTP {
		log.Printf("Aqua Mail Proxy started (SMTP:%d)", *smtpPort)
	}
	if *allowRemoteConnections {
		log.Println("Remote connections are ALLOWED")
	}
}

// Start starts the mail proxy listener
func (mp *MailProxy) Start() error {
	listeners, err := proxyListeners(mp.Port)
	if err != nil {
		return fmt.Errorf("failed to start %s proxy on port %d: %w", mp.Protocol, mp.Port, err)
	}

	for _, listener := range listeners {
		listener := listener
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					if mp.Debug {
						log.Printf("%s proxy accept error: %v", mp.Protocol, err)
					}
					continue
				}

				go mp.handleConnection(conn)
			}
		}()
	}

	return nil
}

// handleConnection handles a single client connection
func (mp *MailProxy) handleConnection(clientConn net.Conn) {
	// A panic while handling one connection must not take down the process, which
	// also serves the HTTP proxy and every other mail session.
	defer recoverConn(fmt.Sprintf("%s-%p", mp.Protocol, clientConn))

	// Check if connection is from localhost unless allow-remote-connections is set
	if !*allowRemoteConnections {
		host, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			if mp.Debug {
				log.Printf("Error parsing remote address: %v", err)
			}
			clientConn.Close()
			return
		}

		// Check if the connection is from localhost
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			if mp.Debug {
				log.Printf("Rejected non-localhost connection from %s", host)
			}
			clientConn.Close()
			return
		}
	}

	connID := fmt.Sprintf("%s-%p", mp.Protocol, clientConn)
	mc := &MailConnection{
		id:         connID,
		clientConn: clientConn,
		protocol:   mp.Protocol,
		reader:     bufio.NewReader(clientConn),
		writer:     bufio.NewWriter(clientConn),
		debug:      mp.Debug,
	}

	defer mc.Close()

	if mc.debug {
		log.Printf("[%s] New %s connection from %s", connID, mp.Protocol, clientConn.RemoteAddr())
	}

	// Handle based on protocol
	if mp.Protocol == "IMAP" {
		mp.handleIMAP(mc)
	} else if mp.Protocol == "SMTP" {
		mp.handleSMTP(mc)
	}
}

// handleIMAP handles IMAP protocol specifics
func (mp *MailProxy) handleIMAP(mc *MailConnection) {
	// Send initial IMAP greeting
	greeting := "* OK AquaProxy IMAP server ready\r\n"
	mc.writer.WriteString(greeting)
	mc.writer.Flush()

	// Process commands until we get authentication
	for {
		line, err := mc.reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading from client: %v", mc.id, err)
			}
			return
		}

		if mc.debug {
			log.Printf("[%s] Client: %s", mc.id, strings.TrimSpace(line))
		}

		// Parse IMAP command. parseIMAPArgs honours quoting, so an argument that
		// contains a space — a password, most often — survives intact instead of
		// being split into fragments.
		parts := parseIMAPArgs(line)
		if len(parts) < 2 {
			mc.writer.WriteString("* BAD Invalid command\r\n")
			mc.writer.Flush()
			continue
		}

		tag := parts[0]
		command := strings.ToUpper(parts[1])

		// The tag is echoed verbatim into the commands sent upstream, so it must be
		// a plain IMAP atom and nothing that could end the line early.
		if !validIMAPTag(tag) {
			mc.writer.WriteString("* BAD Invalid tag\r\n")
			mc.writer.Flush()
			return
		}

		// Check for authentication commands
		if command == "LOGIN" && len(parts) >= 4 {
			// Extract username and password
			username := parts[2]
			password := parts[3]

			// Parse username for server info
			if err := mc.parseUsername(username); err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO %v\r\n", tag, err))
				mc.writer.Flush()
				return
			}

			// Connect to real server
			if err := mc.connectToServer(mp.TLSConfig, mp.DefaultRemotePort); err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO Failed to connect to server: %v\r\n", tag, err))
				mc.writer.Flush()
				return
			}

			// Read server greeting
			serverGreeting, err := mc.serverReader.ReadString('\n')
			if err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO Failed to read server greeting\r\n", tag))
				mc.writer.Flush()
				return
			}

			if mc.debug {
				log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(serverGreeting))
			}

			// Send real login command. Both arguments are quoted and escaped: they
			// are client-supplied, and interpolating them raw would let a quote or
			// CRLF inject additional commands into the upstream session.
			if strings.ContainsAny(password, "\r\n\x00") {
				mc.writer.WriteString(fmt.Sprintf("%s NO Invalid password\r\n", tag))
				mc.writer.Flush()
				return
			}
			realLogin := fmt.Sprintf("%s LOGIN %s %s\r\n", tag, imapQuote(mc.realUsername), imapQuote(password))
			mc.serverWriter.WriteString(realLogin)
			mc.serverWriter.Flush()

			// Read response
			response, ok, err := mc.readIMAPResponse(tag)
			if err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
				mc.writer.Flush()
				return
			}

			// Forward response to client
			mc.writer.WriteString(response)
			mc.writer.Flush()

			// Check if authentication succeeded
			if ok {
				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				mc.transparentProxy()
				return
			}

			// Authentication failed
			return

		} else if command == "AUTHENTICATE" && len(parts) >= 3 {
			authType := strings.ToUpper(parts[2])
			if authType == "PLAIN" {
				// Send continuation response
				mc.writer.WriteString("+ \r\n")
				mc.writer.Flush()

				// Read base64 encoded credentials
				credLine, err := mc.reader.ReadString('\n')
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
					mc.writer.Flush()
					return
				}

				// Decode credentials
				decoded, err := decodeBase64(strings.TrimSpace(credLine))
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Invalid credentials encoding\r\n", tag))
					mc.writer.Flush()
					return
				}

				// AUTH PLAIN format: \0username\0password
				parts := strings.Split(decoded, "\x00")
				if len(parts) != 3 {
					mc.writer.WriteString(fmt.Sprintf("%s NO Invalid AUTH PLAIN format\r\n", tag))
					mc.writer.Flush()
					return
				}

				username := parts[1]
				password := parts[2]

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO %v\r\n", tag, err))
					mc.writer.Flush()
					return
				}

				// Connect to real server
				if err := mc.connectToServer(mp.TLSConfig, mp.DefaultRemotePort); err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Failed to connect to server: %v\r\n", tag, err))
					mc.writer.Flush()
					return
				}

				// Read server greeting
				serverGreeting, err := mc.serverReader.ReadString('\n')
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Failed to read server greeting\r\n", tag))
					mc.writer.Flush()
					return
				}

				if mc.debug {
					log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(serverGreeting))
				}

				// Send AUTHENTICATE PLAIN to server
				mc.serverWriter.WriteString(fmt.Sprintf("%s AUTHENTICATE PLAIN\r\n", tag))
				mc.serverWriter.Flush()

				// Read continuation response
				contResp, err := mc.serverReader.ReadString('\n')
				if err != nil || !strings.HasPrefix(contResp, "+") {
					mc.writer.WriteString(fmt.Sprintf("%s NO Server rejected authentication\r\n", tag))
					mc.writer.Flush()
					return
				}

				// Send real credentials
				realCreds := encodeBase64(fmt.Sprintf("\x00%s\x00%s", mc.realUsername, password))
				mc.serverWriter.WriteString(realCreds + "\r\n")
				mc.serverWriter.Flush()

				// Read response
				response, ok, err := mc.readIMAPResponse(tag)
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
					mc.writer.Flush()
					return
				}

				// Forward response to client
				mc.writer.WriteString(response)
				mc.writer.Flush()

				// Check if authentication succeeded
				if ok {
					mc.authenticated = true
					if mp.Debug {
						log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
					}

					// Switch to transparent proxy mode
					mc.transparentProxy()
					return
				}

				// Authentication failed
				return
			} else {
				mc.writer.WriteString(fmt.Sprintf("%s NO Unsupported authentication mechanism\r\n", tag))
				mc.writer.Flush()
			}

		} else if command == "CAPABILITY" {
			// Respond with basic capabilities
			mc.writer.WriteString("* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n")
			mc.writer.WriteString(fmt.Sprintf("%s OK CAPABILITY completed\r\n", tag))
			mc.writer.Flush()

		} else if command == "NOOP" {
			mc.writer.WriteString(fmt.Sprintf("%s OK NOOP completed\r\n", tag))
			mc.writer.Flush()

		} else if command == "LOGOUT" {
			mc.writer.WriteString("* BYE AquaProxy logging out\r\n")
			mc.writer.WriteString(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag))
			mc.writer.Flush()
			return

		} else {
			// Before authentication, reject other commands
			mc.writer.WriteString(fmt.Sprintf("%s NO Please authenticate first\r\n", tag))
			mc.writer.Flush()
		}
	}
}

// handleSMTP handles SMTP protocol specifics
func (mp *MailProxy) handleSMTP(mc *MailConnection) {
	// Send initial SMTP greeting
	greeting := "220 localhost AquaProxy SMTP server ready\r\n"
	mc.writer.WriteString(greeting)
	mc.writer.Flush()

	// Process commands until we get authentication
	for {
		line, err := mc.reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading from client: %v", mc.id, err)
			}
			return
		}

		if mc.debug {
			log.Printf("[%s] Client: %s", mc.id, strings.TrimSpace(line))
		}

		// Parse SMTP command. A line with no fields at all — the blank line that
		// ends the headers of any HTTP request, which is all it takes for a web
		// page to reach this port — must not index past the end of the slice.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			mc.writer.WriteString("500 Syntax error, command unrecognized\r\n")
			mc.writer.Flush()
			continue
		}
		command := strings.ToUpper(fields[0])

		switch command {
		case "EHLO", "HELO":
			// Respond with capabilities
			domain := "localhost"
			if len(fields) > 1 {
				domain = fields[1]
			}

			if command == "EHLO" {
				mc.writer.WriteString(fmt.Sprintf("250-localhost Hello %s\r\n", domain))
				mc.writer.WriteString("250-AUTH PLAIN LOGIN\r\n")
				mc.writer.WriteString("250-8BITMIME\r\n")
				mc.writer.WriteString("250 OK\r\n")
			} else {
				mc.writer.WriteString(fmt.Sprintf("250 localhost Hello %s\r\n", domain))
			}
			mc.writer.Flush()

		case "AUTH":
			// Parse AUTH command
			authParts := fields
			if len(authParts) < 2 {
				mc.writer.WriteString("501 Syntax error\r\n")
				mc.writer.Flush()
				continue
			}

			authType := strings.ToUpper(authParts[1])

			if authType == "LOGIN" {
				// Handle AUTH LOGIN
				mc.writer.WriteString("334 VXNlcm5hbWU6\r\n") // Base64 for "Username:"
				mc.writer.Flush()

				// Read username
				userLine, err := mc.reader.ReadString('\n')
				if err != nil {
					return
				}

				username, err := decodeBase64(strings.TrimSpace(userLine))
				if err != nil {
					mc.writer.WriteString("501 Invalid username encoding\r\n")
					mc.writer.Flush()
					return
				}

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					mc.writer.WriteString(fmt.Sprintf("535 %v\r\n", err))
					mc.writer.Flush()
					return
				}

				mc.writer.WriteString("334 UGFzc3dvcmQ6\r\n") // Base64 for "Password:"
				mc.writer.Flush()

				// Read password
				passLine, err := mc.reader.ReadString('\n')
				if err != nil {
					return
				}

				password, err := decodeBase64(strings.TrimSpace(passLine))
				if err != nil {
					mc.writer.WriteString("501 Invalid password encoding\r\n")
					mc.writer.Flush()
					return
				}

				// Connect and authenticate
				if mc.debug {
					log.Printf("[%s] Attempting to connect to server on port 587", mc.id)
				}
				if err := mc.connectToServer(mp.TLSConfig, 587); err != nil {
					if mc.debug {
						log.Printf("[%s] Failed to connect on port 587: %v, trying port 465", mc.id, err)
					}
					// Try port 465 if 587 fails
					if err := mc.connectToServer(mp.TLSConfig, 465); err != nil {
						if mc.debug {
							log.Printf("[%s] Failed to connect on port 465: %v", mc.id, err)
						}
						mc.writer.WriteString("535 Failed to connect to server\r\n")
						mc.writer.Flush()
						return
					}
				}

				// Perform SMTP authentication with real server
				if mc.debug {
					log.Printf("[%s] Starting SMTP authentication with %s", mc.id, mc.targetServer)
				}
				if err := mc.authenticateSMTP(authType, mc.realUsername, password, mp.TLSConfig); err != nil {
					if mc.debug {
						log.Printf("[%s] SMTP authentication failed: %v", mc.id, err)
					}
					mc.writer.WriteString("535 Authentication failed\r\n")
					mc.writer.Flush()
					return
				}

				if mc.debug {
					log.Printf("[%s] SMTP authentication succeeded, sending 235 to client", mc.id)
				}
				mc.writer.WriteString("235 Authentication successful\r\n")
				if err := mc.writer.Flush(); err != nil {
					if mc.debug {
						log.Printf("[%s] Error flushing 235 response: %v", mc.id, err)
					}
					return
				}
				if mc.debug {
					log.Printf("[%s] Successfully sent 235 response to client", mc.id)
				}

				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				if mc.debug {
					log.Printf("[%s] About to switch to transparent proxy mode", mc.id)
				}
				mc.transparentProxy()
				if mc.debug {
					log.Printf("[%s] Returned from transparentProxy()", mc.id)
				}
				return

			} else if authType == "PLAIN" {
				// Handle AUTH PLAIN
				var credentials string
				if len(authParts) > 2 {
					// Credentials provided inline
					credentials = authParts[2]
				} else {
					// Request credentials
					mc.writer.WriteString("334 \r\n")
					mc.writer.Flush()

					credLine, err := mc.reader.ReadString('\n')
					if err != nil {
						return
					}
					credentials = strings.TrimSpace(credLine)
				}

				// Decode and parse credentials
				decoded, err := decodeBase64(credentials)
				if err != nil {
					mc.writer.WriteString("501 Invalid credentials encoding\r\n")
					mc.writer.Flush()
					return
				}

				// AUTH PLAIN format: \0username\0password
				parts := strings.Split(decoded, "\x00")
				if len(parts) != 3 {
					mc.writer.WriteString("501 Invalid AUTH PLAIN format\r\n")
					mc.writer.Flush()
					return
				}

				username := parts[1]
				password := parts[2]

				// Parse username for server info
				if err := mc.parseUsername(username); err != nil {
					mc.writer.WriteString(fmt.Sprintf("535 %v\r\n", err))
					mc.writer.Flush()
					return
				}

				// Connect and authenticate
				if mc.debug {
					log.Printf("[%s] Attempting to connect to server on port 587", mc.id)
				}
				if err := mc.connectToServer(mp.TLSConfig, 587); err != nil {
					if mc.debug {
						log.Printf("[%s] Failed to connect on port 587: %v, trying port 465", mc.id, err)
					}
					// Try port 465 if 587 fails
					if err := mc.connectToServer(mp.TLSConfig, 465); err != nil {
						if mc.debug {
							log.Printf("[%s] Failed to connect on port 465: %v", mc.id, err)
						}
						mc.writer.WriteString("535 Failed to connect to server\r\n")
						mc.writer.Flush()
						return
					}
				}

				// Perform SMTP authentication with real server
				if mc.debug {
					log.Printf("[%s] Starting SMTP authentication with %s", mc.id, mc.targetServer)
				}
				if err := mc.authenticateSMTP(authType, mc.realUsername, password, mp.TLSConfig); err != nil {
					if mc.debug {
						log.Printf("[%s] SMTP authentication failed: %v", mc.id, err)
					}
					mc.writer.WriteString("535 Authentication failed\r\n")
					mc.writer.Flush()
					return
				}

				if mc.debug {
					log.Printf("[%s] SMTP authentication succeeded, sending 235 to client", mc.id)
				}
				mc.writer.WriteString("235 Authentication successful\r\n")
				if err := mc.writer.Flush(); err != nil {
					if mc.debug {
						log.Printf("[%s] Error flushing 235 response: %v", mc.id, err)
					}
					return
				}
				if mc.debug {
					log.Printf("[%s] Successfully sent 235 response to client", mc.id)
				}

				mc.authenticated = true
				if mp.Debug {
					log.Printf("[%s] Successfully authenticated to %s", mc.id, mc.targetServer)
				}

				// Switch to transparent proxy mode
				if mc.debug {
					log.Printf("[%s] About to switch to transparent proxy mode", mc.id)
				}
				mc.transparentProxy()
				if mc.debug {
					log.Printf("[%s] Returned from transparentProxy()", mc.id)
				}
				return

			} else {
				mc.writer.WriteString("504 Unrecognized authentication type\r\n")
				mc.writer.Flush()
			}

		case "QUIT":
			mc.writer.WriteString("221 Bye\r\n")
			mc.writer.Flush()
			return

		case "NOOP":
			mc.writer.WriteString("250 OK\r\n")
			mc.writer.Flush()

		case "RSET":
			mc.writer.WriteString("250 OK\r\n")
			mc.writer.Flush()

		default:
			// Before authentication, reject other commands
			mc.writer.WriteString("530 Please authenticate first\r\n")
			mc.writer.Flush()
		}
	}
}

// parseUsername extracts the real username and target server from the proxy username
func (mc *MailConnection) parseUsername(username string) error {
	// The username arrives either straight off the wire or base64-decoded from an
	// AUTH exchange, so it can carry anything at all. Both halves end up inside
	// commands sent upstream; a control character there would let the client
	// append commands of its own, and the server half additionally decides where
	// the proxy connects.
	if strings.ContainsAny(username, "\r\n\x00 \t") {
		return fmt.Errorf("invalid characters in username")
	}

	// Username format: realuser@domain@server
	lastAt := strings.LastIndex(username, "@")
	if lastAt == -1 || lastAt == 0 || lastAt == len(username)-1 {
		return fmt.Errorf("invalid username format, use: user@domain@server")
	}

	mc.realUsername = username[:lastAt]
	mc.targetServer = username[lastAt+1:]

	// Validate server name
	if mc.targetServer == "" || strings.EqualFold(mc.serverName(), "localhost") {
		return fmt.Errorf("invalid target server")
	}
	if strings.ContainsAny(mc.targetServer, "/\\@") {
		return fmt.Errorf("invalid target server")
	}

	if mc.debug {
		log.Printf("[%s] Parsed username: %s -> server: %s", mc.id, mc.realUsername, mc.targetServer)
	}
	return nil
}

// serverName returns the target server's hostname without any port. Certificate
// verification matches against this, so the port must be stripped — a
// ServerName of "mail.example.com:993" matches no certificate at all.
func (mc *MailConnection) serverName() string {
	if h, _, err := net.SplitHostPort(mc.targetServer); err == nil {
		return h
	}
	return mc.targetServer
}

// connectToServer establishes connection to the real mail server
func (mc *MailConnection) connectToServer(tlsConfig *tls.Config, port int) error {
	// Add port if not specified
	server := mc.targetServer
	if !strings.Contains(server, ":") {
		server = fmt.Sprintf("%s:%d", server, port)
	}

	if mc.debug {
		log.Printf("[%s] Connecting to %s", mc.id, server)
	}

	// For SMTP on port 465, use direct TLS
	if mc.protocol == "SMTP" && port == 465 {
		tlsConf := &tls.Config{
			ServerName: mc.serverName(),
		}
		if tlsConfig != nil {
			*tlsConf = *tlsConfig
			tlsConf.ServerName = mc.serverName()
		}

		conn, err := tls.Dial("tcp", server, tlsConf)
		if err != nil {
			return err
		}

		mc.serverConn = conn
		mc.tlsEnabled = true
	} else {
		// For IMAP and SMTP on 587, start with plain connection
		conn, err := net.Dial("tcp", server)
		if err != nil {
			return err
		}

		mc.serverConn = conn

		// For IMAP, always upgrade to TLS immediately
		if mc.protocol == "IMAP" {
			tlsConf := &tls.Config{
				ServerName: mc.serverName(),
			}
			if tlsConfig != nil {
				*tlsConf = *tlsConfig
				tlsConf.ServerName = mc.serverName()
			}

			tlsConn := tls.Client(conn, tlsConf)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return fmt.Errorf("TLS handshake failed: %w", err)
			}

			mc.serverConn = tlsConn
			mc.tlsEnabled = true
		}
	}

	mc.serverReader = bufio.NewReader(mc.serverConn)
	mc.serverWriter = bufio.NewWriter(mc.serverConn)

	return nil
}

// authenticateSMTP performs SMTP authentication with the real server
func (mc *MailConnection) authenticateSMTP(authType, username, password string, tlsConfig *tls.Config) error {
	// Read server greeting
	greeting, err := mc.serverReader.ReadString('\n')
	if err != nil {
		return err
	}

	if mc.debug {
		log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(greeting))
	}

	// Send EHLO
	mc.serverWriter.WriteString("EHLO localhost\r\n")
	mc.serverWriter.Flush()

	// Read EHLO response and check for STARTTLS
	hasSTARTTLS := false
	for {
		line, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return err
		}

		if mc.debug {
			log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
		}

		// Check for STARTTLS support. Match the capability itself rather than the
		// line, so a greeting or hostname that happens to contain the word does
		// not count as an offer.
		if !mc.tlsEnabled && isSMTPCapability(line, "STARTTLS") {
			hasSTARTTLS = true
		}

		// Check if this is the last line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// If STARTTLS is supported and we're not already using TLS, upgrade the connection
	if hasSTARTTLS && !mc.tlsEnabled {
		// Send STARTTLS command
		mc.serverWriter.WriteString("STARTTLS\r\n")
		mc.serverWriter.Flush()

		response, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return err
		}

		if mc.debug {
			log.Printf("[%s] STARTTLS response: %s", mc.id, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(response, "220") {
			return fmt.Errorf("STARTTLS failed: %s", response)
		}

		// Upgrade connection
		tlsConf := &tls.Config{
			ServerName: mc.targetServer,
		}
		// CRITICAL: Copy the TLS config to get RootCAs for Snow Leopard
		if tlsConfig != nil {
			*tlsConf = *tlsConfig
			tlsConf.ServerName = mc.targetServer
		} else {
			if mc.debug {
				log.Printf("[%s] WARNING: No TLS config provided for STARTTLS!", mc.id)
			}
		}

		if mc.debug {
			log.Printf("[%s] Starting TLS handshake with %s", mc.id, mc.targetServer)
		}

		// Anything already buffered was sent before the handshake began, so it is
		// unauthenticated data the server could not have known we would accept —
		// the classic STARTTLS command-injection trick. Discarding it silently
		// would hide the attack; refuse the connection instead.
		if n := mc.serverReader.Buffered(); n > 0 {
			return fmt.Errorf("server sent %d bytes before the TLS handshake (STARTTLS command injection?)", n)
		}

		tlsConn := tls.Client(mc.serverConn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			if mc.debug {
				log.Printf("[%s] TLS handshake failed: %v", mc.id, err)
			}
			return fmt.Errorf("TLS handshake failed: %w", err)
		}

		mc.serverConn = tlsConn
		mc.serverReader = bufio.NewReader(mc.serverConn)
		mc.serverWriter = bufio.NewWriter(mc.serverConn)
		mc.tlsEnabled = true

		if mc.debug {
			log.Printf("[%s] TLS connection established successfully", mc.id)
		}

		// Send EHLO again after STARTTLS
		if mc.debug {
			log.Printf("[%s] Sending EHLO after STARTTLS", mc.id)
		}
		mc.serverWriter.WriteString("EHLO localhost\r\n")
		if err := mc.serverWriter.Flush(); err != nil {
			if mc.debug {
				log.Printf("[%s] Error flushing EHLO after STARTTLS: %v", mc.id, err)
			}
			return fmt.Errorf("failed to send EHLO after STARTTLS: %w", err)
		}

		// Read EHLO response again
		if mc.debug {
			log.Printf("[%s] Reading EHLO response after STARTTLS", mc.id)
		}
		for {
			line, err := mc.serverReader.ReadString('\n')
			if err != nil {
				if mc.debug {
					log.Printf("[%s] Error reading EHLO response after STARTTLS: %v", mc.id, err)
				}
				return err
			}

			if mc.debug {
				log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
			}

			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
	}

	// Reaching here without TLS means the EHLO response advertised no STARTTLS, so
	// unencrypted AUTH is the only form this server accepts. Deliberately send it
	// anyway: a provider that never gained STARTTLS is exactly the kind this proxy
	// exists to keep reachable, and refusing would only mean the account cannot be
	// used at all. Note it in the log, since anyone on the path can read what
	// follows — including an attacker who stripped the capability to cause this.
	if !mc.tlsEnabled {
		log.Printf("[%s] WARNING: %s offered no STARTTLS; sending credentials unencrypted", mc.id, mc.serverName())
	}

	// Perform authentication
	if authType == "LOGIN" {
		if mc.debug {
			log.Printf("[%s] Sending AUTH LOGIN", mc.id)
		}
		mc.serverWriter.WriteString("AUTH LOGIN\r\n")
		mc.serverWriter.Flush()

		// Read username prompt
		response, err := mc.serverReader.ReadString('\n')
		if err != nil {
			if mc.debug {
				log.Printf("[%s] Error reading AUTH LOGIN response: %v", mc.id, err)
			}
			return err
		}

		if mc.debug {
			log.Printf("[%s] AUTH LOGIN response: %s", mc.id, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(response, "334") {
			return fmt.Errorf("AUTH LOGIN failed: %s", response)
		}

		// Send username
		if mc.debug {
			log.Printf("[%s] Sending username", mc.id)
		}
		mc.serverWriter.WriteString(encodeBase64(username) + "\r\n")
		mc.serverWriter.Flush()

		// Read password prompt
		response, err = mc.serverReader.ReadString('\n')
		if err != nil {
			if mc.debug {
				log.Printf("[%s] Error reading password prompt: %v", mc.id, err)
			}
			return err
		}

		if mc.debug {
			log.Printf("[%s] Password prompt response: %s", mc.id, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(response, "334") {
			return fmt.Errorf("AUTH LOGIN failed: %s", response)
		}

		// Send password
		if mc.debug {
			log.Printf("[%s] Sending password", mc.id)
		}
		mc.serverWriter.WriteString(encodeBase64(password) + "\r\n")
		mc.serverWriter.Flush()

	} else if authType == "PLAIN" {
		// Encode credentials
		credentials := encodeBase64(fmt.Sprintf("\x00%s\x00%s", username, password))
		if mc.debug {
			log.Printf("[%s] Sending AUTH PLAIN", mc.id)
		}
		mc.serverWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", credentials))
		mc.serverWriter.Flush()
	}

	// Read authentication response
	response, err := mc.serverReader.ReadString('\n')
	if err != nil {
		if mc.debug {
			log.Printf("[%s] Error reading authentication response: %v", mc.id, err)
		}
		return err
	}

	if mc.debug {
		log.Printf("[%s] Authentication response: %s", mc.id, strings.TrimSpace(response))
	}

	if !strings.HasPrefix(response, "235") {
		return fmt.Errorf("authentication failed: %s", response)
	}

	return nil
}

// readIMAPResponse reads a complete IMAP response for a given tag. ok reports
// whether the command succeeded, and is decided by the tagged line alone — the
// only line that carries the result. Searching the whole response for
// "<tag> OK" would let a server report failure in the tagged line while smuggling
// the same text through an untagged data line, and be believed.
func (mc *MailConnection) readIMAPResponse(tag string) (response string, ok bool, err error) {
	var b strings.Builder

	for {
		line, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return "", false, err
		}

		if mc.debug {
			log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
		}

		if b.Len()+len(line) > maxIMAPResponseBytes {
			return "", false, fmt.Errorf("response exceeded %d bytes with no tagged line", maxIMAPResponseBytes)
		}
		b.WriteString(line)

		// Check if this is the tagged response
		if strings.HasPrefix(line, tag+" ") {
			status := strings.ToUpper(strings.TrimSpace(line[len(tag)+1:]))
			return b.String(), status == "OK" || strings.HasPrefix(status, "OK "), nil
		}
	}
}

// parseIMAPArgs splits an IMAP command line into its arguments, honouring
// double-quoted strings and backslash escapes within them. Splitting on
// whitespace alone corrupts any argument containing a space.
func parseIMAPArgs(line string) []string {
	var (
		args    []string
		cur     strings.Builder
		inQuote bool
		escaped bool
		quoted  bool
	)
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case inQuote && r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
			quoted = true
		case !inQuote && (r == ' ' || r == '\t' || r == '\r' || r == '\n'):
			if quoted || cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
				quoted = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quoted || cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// imapQuote renders s as an IMAP quoted string. Backslashes and quotes are
// escaped so a crafted value cannot close the string and start a new command.
func imapQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// validIMAPTag reports whether tag is a plain IMAP atom, safe to echo into a
// command line sent upstream.
func validIMAPTag(tag string) bool {
	if tag == "" || len(tag) > 32 {
		return false
	}
	for _, r := range tag {
		if r <= ' ' || r > '~' {
			return false
		}
		if strings.ContainsRune(`"\(){%*]`, r) {
			return false
		}
	}
	return true
}

// isSMTPCapability reports whether an EHLO response line advertises the named
// capability. Response lines look like "250-STARTTLS" or "250 STARTTLS".
func isSMTPCapability(line, capability string) bool {
	line = strings.TrimSpace(line)
	if len(line) < 4 {
		return false
	}
	fields := strings.Fields(line[4:])
	return len(fields) > 0 && strings.EqualFold(fields[0], capability)
}

// recoverConn turns a panic while serving one connection into a logged error.
// Every connection runs on its own goroutine, where an unrecovered panic would
// otherwise terminate the whole process — including the HTTP proxy and every
// other session in flight. Use it as `defer recoverConn(id)`: recover() only
// takes effect when the function calling it is the one that was deferred.
func recoverConn(id string) {
	logPanic(id, recover())
}

// logPanic reports a recovered panic value. It is separate from recoverConn so
// that deferred closures which need to do more than recover — signal a channel,
// close a connection — can call recover() themselves and hand the value here.
func logPanic(id string, r interface{}) {
	if r != nil {
		log.Printf("[%s] recovered from panic: %v\n%s", id, r, rdebug.Stack())
	}
}

// transparentProxy switches to transparent proxy mode after authentication
func (mc *MailConnection) transparentProxy() {
	if mc.debug {
		log.Printf("[%s] Switching to transparent proxy mode", mc.id)
	}

	// Verify connections are established
	if mc.clientConn == nil {
		if mc.debug {
			log.Printf("[%s] ERROR: clientConn is nil in transparentProxy", mc.id)
		}
		return
	}
	if mc.serverConn == nil {
		if mc.debug {
			log.Printf("[%s] ERROR: serverConn is nil in transparentProxy", mc.id)
		}
		return
	}

	// For SMTP, we need to rewrite MAIL FROM commands
	if mc.protocol == "SMTP" {
		mc.transparentSMTPProxy()
		return
	}

	// For IMAP, use simple transparent proxy
	done := make(chan bool, 2)

	// Client to server. The done signal is sent from a defer so a panic cannot
	// leave the waiter below blocked forever.
	go func() {
		defer func() {
			logPanic(mc.id, recover())
			done <- true
		}()
		io.Copy(mc.serverConn, mc.clientConn)
	}()

	// Server to client
	go func() {
		defer func() {
			logPanic(mc.id, recover())
			done <- true
		}()
		io.Copy(mc.clientConn, mc.serverConn)
	}()

	// Wait for either direction to complete
	<-done

	// Close connections
	mc.Close()
}

// transparentSMTPProxy handles SMTP-specific transparent proxying with MAIL FROM rewriting
func (mc *MailConnection) transparentSMTPProxy() {
	if mc.debug {
		log.Printf("[%s] Entered transparentSMTPProxy", mc.id)
	}

	// Server to client - log responses if debug enabled
	go func() {
		// Close from a defer too, so a panic still tears the session down rather
		// than stranding the client half.
		defer func() {
			logPanic(mc.id, recover())
			mc.Close()
		}()
		if mc.debug {
			log.Printf("[%s] Starting server-to-client relay goroutine", mc.id)
		}
		scanner := bufio.NewScanner(mc.serverConn)
		for scanner.Scan() {
			line := scanner.Text()
			if mc.debug {
				log.Printf("[%s] Server response: %s", mc.id, line)
			}
			mc.writer.WriteString(line + "\r\n")
			if err := mc.writer.Flush(); err != nil {
				if mc.debug {
					log.Printf("[%s] Error flushing server response to client: %v", mc.id, err)
				}
				break
			}
		}
		if err := scanner.Err(); err != nil && mc.debug {
			log.Printf("[%s] Server scanner error: %v", mc.id, err)
		}
		if mc.debug {
			log.Printf("[%s] Server-to-client relay goroutine exiting", mc.id)
		}
		mc.Close()
	}()

	// Client to server - rewrite MAIL FROM commands
	if mc.debug {
		log.Printf("[%s] Starting client-to-server relay loop", mc.id)
		log.Printf("[%s] clientConn type: %T", mc.id, mc.clientConn)
		log.Printf("[%s] serverConn type: %T", mc.id, mc.serverConn)
	}

	scanner := bufio.NewScanner(mc.clientConn)
	for scanner.Scan() {
		line := scanner.Text()

		if mc.debug {
			log.Printf("[%s] Client command: %s", mc.id, line)
		}

		// Check if this is a MAIL FROM command
		upperLine := strings.ToUpper(line)
		if strings.HasPrefix(upperLine, "MAIL FROM:") {
			// Extract the email address
			fromMatch := regexp.MustCompile(`<([^>]+)>`).FindStringSubmatch(line)
			if len(fromMatch) > 1 {
				email := fromMatch[1]
				// Check if it contains our proxy suffix
				if strings.Contains(email, "@imap.mail.me.com") || strings.Contains(email, "@smtp.mail.me.com") {
					// Extract the real email (everything before the last @)
					lastAt := strings.LastIndex(email, "@")
					if lastAt > 0 {
						realEmail := email[:lastAt]
						// Rewrite the command
						line = strings.Replace(line, email, realEmail, 1)
						if mc.debug {
							log.Printf("[%s] Rewritten MAIL FROM: %s", mc.id, line)
						}
					}
				}
			}
		}

		// Also check for From: header in email data
		if strings.HasPrefix(line, "From:") {
			// Look for email addresses with our proxy suffix
			fromMatch := regexp.MustCompile(`<([^>]+@(?:imap|smtp)\.mail\.[^>]+)>`).FindAllStringSubmatch(line, -1)
			for _, match := range fromMatch {
				if len(match) > 1 {
					email := match[1]
					// Extract the real email (everything before the last @)
					lastAt := strings.LastIndex(email, "@")
					if lastAt > 0 {
						realEmail := email[:lastAt]
						// Rewrite the From header
						line = strings.Replace(line, email, realEmail, 1)
						if mc.debug {
							log.Printf("[%s] Rewritten From header: %s", mc.id, line)
						}
					}
				}
			}
		}

		// Send the (possibly rewritten) command to server
		mc.serverWriter.WriteString(line + "\r\n")
		if err := mc.serverWriter.Flush(); err != nil {
			if mc.debug {
				log.Printf("[%s] Error flushing client command to server: %v", mc.id, err)
			}
			break
		}

		// Check for QUIT command
		if strings.ToUpper(strings.TrimSpace(line)) == "QUIT" {
			if mc.debug {
				log.Printf("[%s] Received QUIT command, exiting relay loop", mc.id)
			}
			// Read final response and close
			mc.serverReader.ReadString('\n')
			break
		}
	}

	if err := scanner.Err(); err != nil && mc.debug {
		log.Printf("[%s] Client scanner error: %v", mc.id, err)
	}
	if mc.debug {
		log.Printf("[%s] Client-to-server relay loop exited", mc.id)
	}

	mc.Close()
}

// Close closes all connections
func (mc *MailConnection) Close() {
	if mc.clientConn != nil {
		mc.clientConn.Close()
	}
	if mc.serverConn != nil {
		mc.serverConn.Close()
	}
}

// Helper functions for base64 encoding/decoding
func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func decodeBase64(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
