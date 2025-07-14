package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var (
	// Command line flags
	imapPort  = flag.Int("imap-port", 6532, "IMAP proxy port")
	smtpPort  = flag.Int("smtp-port", 6533, "SMTP proxy port")
	debug     = flag.Bool("debug", false, "Enable debug logging")
	disableIMAP = flag.Bool("no-imap", false, "Disable IMAP proxy")
	disableSMTP = flag.Bool("no-smtp", false, "Disable SMTP proxy")
	allowRemoteConnections = flag.Bool("allow-remote-connections", false, "Allow connections from non-localhost addresses")
)

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
	id           string
	clientConn   net.Conn
	serverConn   net.Conn
	protocol     string
	targetServer string
	realUsername string
	authenticated bool
	tlsEnabled    bool
	reader       *bufio.Reader
	writer       *bufio.Writer
	serverReader *bufio.Reader
	serverWriter *bufio.Writer
	debug        bool
}

func loadSystemCertPool() (*x509.CertPool, error) {
	// Try the standard method first
	systemRoots, err := x509.SystemCertPool()
	if err == nil && systemRoots != nil && len(systemRoots.Subjects()) > 0 {
		return systemRoots, nil
	}
	
	// Fallback: Use security command to export certificates. Needed on Snow Leopard.
	log.Println("Using security to load system certificates.")
	
	pool := x509.NewCertPool()
	keychains := []string{
		"", // empty string for default keychain search list
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
	
	// Load from all keychains
	for _, keychain := range keychains {
		args := []string{"find-certificate", "-a", "-p"}
		if keychain != "" {
			args = append(args, keychain)
		}
		
		cmd := exec.Command("security", args...)
		output, err := cmd.Output()
		if err != nil {
			if keychain != "" {
				log.Printf("Warning: Failed to load certificates from %s: %v", keychain, err)
			}
			continue
		}
		
		// Parse the PEM output
		for len(output) > 0 {
			block, rest := pem.Decode(output)
			if block == nil {
				break
			}
			output = rest
			
			if block.Type != "CERTIFICATE" {
				continue
			}
			
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			
			pool.AddCert(cert)
		}
	}
	
	if len(pool.Subjects()) == 0 {
		log.Fatal("Failed to load any certificates from system keychains")
	}

	return pool, nil
}

func main() {
	// Read flags from flags.txt if it exists
	if data, err := ioutil.ReadFile("flags.txt"); err == nil {
		flags := strings.Fields(string(data))
		os.Args = append([]string{os.Args[0]}, append(flags, os.Args[1:]...)...)
	}
	
	flag.CommandLine.SetOutput(io.Discard)
	flag.Parse()
	flag.CommandLine.SetOutput(os.Stderr)
	
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
	
	if *disableIMAP && *disableSMTP {
		log.Fatal("Both IMAP and SMTP are disabled, nothing to do")
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
	// Keep the main thread running
	select {}
}

// Start starts the mail proxy listener
func (mp *MailProxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", mp.Port))
	if err != nil {
		return fmt.Errorf("failed to start %s proxy on port %d: %w", mp.Protocol, mp.Port, err)
	}
	
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
	
	return nil
}

// handleConnection handles a single client connection
func (mp *MailProxy) handleConnection(clientConn net.Conn) {
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
		
		// Parse IMAP command
		parts := strings.Fields(line)
		if len(parts) < 2 {
			mc.writer.WriteString("* BAD Invalid command\r\n")
			mc.writer.Flush()
			continue
		}
		
		tag := parts[0]
		command := strings.ToUpper(parts[1])
		
		// Check for authentication commands
		if command == "LOGIN" && len(parts) >= 4 {
			// Extract username and password
			username := strings.Trim(parts[2], "\"")
			password := strings.Trim(parts[3], "\"")
			
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
			
			// Send real login command
			realLogin := fmt.Sprintf("%s LOGIN \"%s\" \"%s\"\r\n", tag, mc.realUsername, password)
			mc.serverWriter.WriteString(realLogin)
			mc.serverWriter.Flush()
			
			// Read response
			response, err := mc.readIMAPResponse(tag)
			if err != nil {
				mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
				mc.writer.Flush()
				return
			}
			
			// Forward response to client
			mc.writer.WriteString(response)
			mc.writer.Flush()
			
			// Check if authentication succeeded
			if strings.Contains(response, tag+" OK") {
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
				response, err := mc.readIMAPResponse(tag)
				if err != nil {
					mc.writer.WriteString(fmt.Sprintf("%s NO Authentication failed\r\n", tag))
					mc.writer.Flush()
					return
				}
				
				// Forward response to client
				mc.writer.WriteString(response)
				mc.writer.Flush()
				
				// Check if authentication succeeded
				if strings.Contains(response, tag+" OK") {
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
		
		// Parse SMTP command
		command := strings.ToUpper(strings.Fields(line)[0])
		
		switch command {
		case "EHLO", "HELO":
			// Respond with capabilities
			domain := "localhost"
			if len(strings.Fields(line)) > 1 {
				domain = strings.Fields(line)[1]
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
			authParts := strings.Fields(line)
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
	// Username format: realuser@domain@server
	lastAt := strings.LastIndex(username, "@")
	if lastAt == -1 || lastAt == 0 || lastAt == len(username)-1 {
		return fmt.Errorf("invalid username format, use: user@domain@server")
	}
	
	mc.realUsername = username[:lastAt]
	mc.targetServer = username[lastAt+1:]
	
	// Validate server name
	if mc.targetServer == "" || mc.targetServer == "localhost" {
		return fmt.Errorf("invalid target server")
	}
	
	if mc.debug {
		log.Printf("[%s] Parsed username: %s -> server: %s", mc.id, mc.realUsername, mc.targetServer)
	}
	return nil
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
			ServerName: mc.targetServer,
		}
		if tlsConfig != nil {
			*tlsConf = *tlsConfig
			tlsConf.ServerName = mc.targetServer
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
				ServerName: mc.targetServer,
			}
			if tlsConfig != nil {
				*tlsConf = *tlsConfig
				tlsConf.ServerName = mc.targetServer
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
		
		// Check for STARTTLS support
		if !mc.tlsEnabled && strings.Contains(line, "STARTTLS") {
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
			if mc.debug {
				log.Printf("[%s] Copying TLS config for STARTTLS", mc.id)
				log.Printf("[%s] Original TLS config has RootCAs: %v", mc.id, tlsConfig.RootCAs != nil)
				if tlsConfig.RootCAs != nil {
					log.Printf("[%s] RootCAs pool has %d subjects", mc.id, len(tlsConfig.RootCAs.Subjects()))
				}
			}
			*tlsConf = *tlsConfig
			tlsConf.ServerName = mc.targetServer
		} else {
			if mc.debug {
				log.Printf("[%s] WARNING: No TLS config provided for STARTTLS!", mc.id)
			}
		}
		
		if mc.debug {
			log.Printf("[%s] Starting TLS handshake with %s", mc.id, mc.targetServer)
			log.Printf("[%s] TLS config ServerName: %s", mc.id, tlsConf.ServerName)
			log.Printf("[%s] TLS config has RootCAs: %v", mc.id, tlsConf.RootCAs != nil)
			log.Printf("[%s] TLS config MinVersion: %x", mc.id, tlsConf.MinVersion)
		}
		
		tlsConn := tls.Client(mc.serverConn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			if mc.debug {
				log.Printf("[%s] TLS handshake failed: %v", mc.id, err)
				log.Printf("[%s] Error type: %T", mc.id, err)
				// Try to get more details about certificate errors
				if certErr, ok := err.(x509.CertificateInvalidError); ok {
					log.Printf("[%s] Certificate error reason: %v", mc.id, certErr.Reason)
				}
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

// readIMAPResponse reads a complete IMAP response for a given tag
func (mc *MailConnection) readIMAPResponse(tag string) (string, error) {
	var response strings.Builder
	
	for {
		line, err := mc.serverReader.ReadString('\n')
		if err != nil {
			return "", err
		}
		
		if mc.debug {
			log.Printf("[%s] Server: %s", mc.id, strings.TrimSpace(line))
		}
		
		response.WriteString(line)
		
		// Check if this is the tagged response
		if strings.HasPrefix(line, tag+" ") {
			break
		}
	}
	
	return response.String(), nil
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
	
	// Client to server
	go func() {
		io.Copy(mc.serverConn, mc.clientConn)
		done <- true
	}()
	
	// Server to client  
	go func() {
		io.Copy(mc.clientConn, mc.serverConn)
		done <- true
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