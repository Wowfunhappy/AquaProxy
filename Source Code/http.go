package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ClientHello detection structures
type clientHelloInfo struct {
	raw            []byte
	tlsVersion     uint16
	alpnProtocols  []string
	supportsTLS13  bool
	supportsHTTP2  bool
	isModernClient bool
}

// redirectRule represents a URL redirect rule
type redirectRule struct {
	fromURL *url.URL
	toURL   *url.URL
}

// headerRule represents a custom header rule for a URL prefix or domain.
// If urlPrefix is nil, the rule matches all requests for the domain.
type headerRule struct {
	domain    string
	urlPrefix *url.URL // nil for domain-only rules
	headers   http.Header
}

// TLS constants for parsing
const (
	tlsHandshakeTypeClientHello   = 0x01
	tlsExtensionALPN              = 0x0010
	tlsExtensionSupportedVersions = 0x002b

	// TLS versions
	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)

// parseClientHello parses a TLS ClientHello message to detect modern TLS features
func parseClientHello(data []byte) (*clientHelloInfo, error) {
	info := &clientHelloInfo{
		raw: data,
	}

	// Minimum size check: 5 bytes for TLS record header + 4 bytes for handshake header
	if len(data) < 9 {
		return nil, fmt.Errorf("data too short to be ClientHello")
	}

	// Check TLS record header
	if data[0] != 0x16 { // Handshake record type
		return nil, fmt.Errorf("not a TLS handshake record")
	}

	// Skip TLS version from record header (backwards compatibility version)
	_ = uint16(data[1])<<8 | uint16(data[2])

	// Get record length
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return nil, fmt.Errorf("incomplete TLS record")
	}

	// Parse handshake message
	pos := 5
	if data[pos] != tlsHandshakeTypeClientHello {
		return nil, fmt.Errorf("not a ClientHello message")
	}

	// Skip handshake length (3 bytes)
	pos += 4

	// Get client version (2 bytes)
	if len(data) < pos+2 {
		return nil, fmt.Errorf("truncated ClientHello")
	}
	info.tlsVersion = uint16(data[pos])<<8 | uint16(data[pos+1])
	pos += 2

	// Skip client random (32 bytes)
	pos += 32

	// Skip session ID
	if len(data) < pos+1 {
		return nil, fmt.Errorf("truncated ClientHello at session ID")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if len(data) < pos+2 {
		return nil, fmt.Errorf("truncated ClientHello at cipher suites")
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if len(data) < pos+1 {
		return nil, fmt.Errorf("truncated ClientHello at compression")
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Parse extensions if present
	if len(data) >= pos+2 {
		extensionsLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if len(data) >= pos+extensionsLen {
			if err := parseExtensions(data[pos:pos+extensionsLen], info); err != nil {
				log.Printf("Error parsing extensions: %v", err)
			}
		}
	}

	// Determine if this is a modern client
	info.isModernClient = info.supportsTLS13 || info.supportsHTTP2

	return info, nil
}

// parseExtensions parses TLS extensions looking for ALPN and supported versions
func parseExtensions(data []byte, info *clientHelloInfo) error {
	pos := 0

	for pos+4 <= len(data) {
		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > len(data) {
			return fmt.Errorf("truncated extension")
		}

		extData := data[pos : pos+extLen]

		switch extType {
		case tlsExtensionALPN:
			parseALPN(extData, info)
		case tlsExtensionSupportedVersions:
			parseSupportedVersions(extData, info)
		}

		pos += extLen
	}

	return nil
}

// parseALPN parses the ALPN extension to detect HTTP/2 support
func parseALPN(data []byte, info *clientHelloInfo) {
	if len(data) < 2 {
		return
	}

	protocolListLen := int(data[0])<<8 | int(data[1])
	pos := 2

	for pos < 2+protocolListLen && pos < len(data) {
		protoLen := int(data[pos])
		pos++

		if pos+protoLen <= len(data) {
			proto := string(data[pos : pos+protoLen])
			info.alpnProtocols = append(info.alpnProtocols, proto)

			if proto == "h2" {
				info.supportsHTTP2 = true
			}
		}

		pos += protoLen
	}
}

// parseSupportedVersions parses the supported_versions extension to detect TLS 1.3
func parseSupportedVersions(data []byte, info *clientHelloInfo) {
	if len(data) < 1 {
		return
	}

	// For ClientHello, this is a list
	listLen := int(data[0])
	pos := 1

	for i := 0; i < listLen/2 && pos+2 <= len(data); i++ {
		version := uint16(data[pos])<<8 | uint16(data[pos+1])
		if version == tlsVersion13 {
			info.supportsTLS13 = true
		}
		pos += 2
	}
}

// peekClientHello peeks at the beginning of a connection to read the ClientHello
func peekClientHello(conn net.Conn) (*clientHelloInfo, error) {
	// We need to peek at enough data to parse the ClientHello
	// Maximum size is 16KB for the TLS record
	buf := make([]byte, 16384)

	// Set a short read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClientHello: %w", err)
	}

	// Parse the ClientHello
	info, err := parseClientHello(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ClientHello: %w", err)
	}

	// Store the exact bytes we read
	info.raw = buf[:n]

	return info, nil
}

// startKeyPool starts background generation of RSA keys
func startKeyPool() {
	// Start key generation in background
	go func() {

		// Set lower CPU priority for this goroutine
		syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)

		for {
			// First check if the pool needs more keys
			if len(keyPool) >= cap(keyPool) {
				// Pool is full, wait before checking again
				time.Sleep(1 * time.Second)
				continue
			}

			// Generate a new RSA key only when needed
			key, err := rsa.GenerateKey(rand.Reader, RSAKeyLength)
			if err != nil {
				log.Printf("Error pre-generating RSA key: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Add the key to the pool
			keyPool <- key
		}
	}()
}

// getKey gets an RSA key from the pool or generates one if needed
func getKey() (*rsa.PrivateKey, error) {
	// Try to get a key from the pool with a short timeout
	select {
	case key := <-keyPool:
		return key, nil
	default:
		// Immediately generate a key if none available
		return rsa.GenerateKey(rand.Reader, RSAKeyLength)
	}
}

// checkRedirect checks if the request URL matches any redirect rules and returns the target URL
func checkRedirect(reqURL *url.URL) (*url.URL, bool) {
	redirectMutex.RLock()
	defer redirectMutex.RUnlock()

	// Check if domain has any redirect rules
	rules, exists := redirectRules[reqURL.Host]
	if !exists {
		return nil, false
	}

	// Build the full URL string for comparison
	fullURL := reqURL.String()

	// Check each rule for the domain
	for _, rule := range rules {
		fromPrefix := rule.fromURL.String()
		if strings.HasPrefix(fullURL, fromPrefix) {
			// Apply the redirect, preserving the path suffix
			suffix := strings.TrimPrefix(fullURL, fromPrefix)

			// Parse the target URL and append the suffix properly
			targetURL, _ := url.Parse(rule.toURL.String())
			if targetURL != nil {
				// If suffix contains a query string, handle it properly
				if idx := strings.Index(suffix, "?"); idx >= 0 {
					targetURL.Path = targetURL.Path + suffix[:idx]
					targetURL.RawQuery = suffix[idx+1:]
				} else {
					targetURL.Path = targetURL.Path + suffix
				}
			}
			return targetURL, true
		}
	}

	return nil, false
}

// checkHeaders checks if the request URL matches any custom header rules and returns headers to apply
func checkHeaders(reqURL *url.URL) (http.Header, bool) {
	headerMutex.RLock()
	defer headerMutex.RUnlock()

	return matchHeaderRules(reqURL)
}

// hasHeaderRules checks if a domain has header rules, including wildcard matches
func hasHeaderRules(domain string) bool {
	headerMutex.RLock()
	defer headerMutex.RUnlock()

	if headerDomains[domain] {
		return true
	}
	if idx := strings.Index(domain, "."); idx >= 0 {
		if headerDomains["*"+domain[idx:]] {
			return true
		}
	}
	return false
}

// matchHeaderRules checks exact domain then wildcard. Must be called with headerMutex held.
func matchHeaderRules(reqURL *url.URL) (http.Header, bool) {
	fullURL := reqURL.String()

	// Check exact domain first
	if rules, exists := headerRules[reqURL.Host]; exists {
		for _, rule := range rules {
			if rule.urlPrefix == nil {
				return rule.headers, true
			}
			if strings.HasPrefix(fullURL, rule.urlPrefix.String()) {
				return rule.headers, true
			}
		}
	}

	// Check wildcard domain (e.g. *.wikipedia.org matches en.wikipedia.org)
	if idx := strings.Index(reqURL.Host, "."); idx >= 0 {
		wildcard := "*" + reqURL.Host[idx:]
		if rules, exists := headerRules[wildcard]; exists {
			for _, rule := range rules {
				if rule.urlPrefix == nil {
					return rule.headers, true
				}
				// Substitute wildcard host with actual host in the prefix
				prefix := strings.Replace(rule.urlPrefix.String(), wildcard, reqURL.Host, 1)
				if strings.HasPrefix(fullURL, prefix) {
					return rule.headers, true
				}
			}
		}
	}

	return nil, false
}

// applyHeaders sets or removes custom headers on a request and logs each change.
// An empty value means the header should be removed.
func applyHeaders(req *http.Request, headers http.Header) {
	for key, values := range headers {
		if len(values) == 1 && values[0] == "" {
			log.Printf("Removing header %s on %s", key, req.URL.String())
			req.Header.Del(key)
		} else {
			for _, value := range values {
				log.Printf("Setting header %s: %s on %s", key, value, req.URL.String())
				req.Header.Set(key, value)
			}
		}
	}
}

// loadRedirectRules loads URL redirect rules from redirects.txt
func loadRedirectRules() error {
	redirectFile := "redirects.txt"

	// Check if file exists
	if _, err := os.Stat(redirectFile); os.IsNotExist(err) {
		log.Println("Warning: no redirects.txt file found")
		return nil
	}

	file, err := os.Open(redirectFile)
	if err != nil {
		return fmt.Errorf("failed to open redirects file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var fromURL *url.URL

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse URL
		u, err := url.Parse(line)
		if err != nil {
			log.Printf("Warning: Invalid URL on line %d: %s", lineNum, line)
			continue
		}

		// Ensure URL has a scheme
		if u.Scheme == "" {
			log.Printf("Warning: URL missing scheme on line %d: %s", lineNum, line)
			continue
		}

		if fromURL == nil {
			// This is a "from" URL
			fromURL = u
		} else {
			// This is a "to" URL, create the redirect rule
			rule := redirectRule{
				fromURL: fromURL,
				toURL:   u,
			}

			// Extract domain from fromURL
			domain := fromURL.Host

			redirectMutex.Lock()
			redirectRules[domain] = append(redirectRules[domain], rule)
			redirectDomains[domain] = true
			redirectMutex.Unlock()

			// Reset for next pair
			fromURL = nil
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading redirects file: %w", err)
	}

	if fromURL != nil {
		log.Printf("Warning: Incomplete redirect rule (missing target URL) for: %s", fromURL.String())
	}

	return nil
}

// loadHeaderRules loads custom header rules from headers.txt
func loadHeaderRules() error {
	headerFile := "headers.txt"

	// Check if file exists
	if _, err := os.Stat(headerFile); os.IsNotExist(err) {
		log.Println("Warning: no headers.txt file found")
		return nil
	}

	file, err := os.Open(headerFile)
	if err != nil {
		return fmt.Errorf("failed to open headers file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var currentURL *url.URL
	var currentDomain string
	var currentHeaders http.Header

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Blank line ends the current group
		if line == "" {
			if currentDomain != "" && len(currentHeaders) > 0 {
				rule := headerRule{
					domain:    currentDomain,
					urlPrefix: currentURL,
					headers:   currentHeaders,
				}
				headerMutex.Lock()
				headerRules[currentDomain] = append(headerRules[currentDomain], rule)
				headerDomains[currentDomain] = true
				headerMutex.Unlock()
			}
			currentURL = nil
			currentDomain = ""
			currentHeaders = nil
			continue
		}

		if currentURL == nil && currentDomain == "" {
			// First non-blank line in a group is the URL prefix or bare domain
			if strings.Contains(line, "://") {
				u, err := url.Parse(line)
				if err != nil {
					log.Printf("Warning: Invalid URL on line %d of headers.txt: %s", lineNum, line)
					continue
				}
				currentURL = u
				currentDomain = u.Host
			} else {
				// Bare domain
				currentDomain = line
				if h, _, err := net.SplitHostPort(line); err == nil {
					currentDomain = h
				}
			}
			currentHeaders = make(http.Header)
		} else {
			// Subsequent lines are headers in "Key: Value" format
			colonIdx := strings.Index(line, ":")
			if colonIdx < 1 {
				log.Printf("Warning: Invalid header on line %d of headers.txt: %s", lineNum, line)
				continue
			}
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			currentHeaders.Set(key, value)
		}
	}

	// Handle last group if file doesn't end with a blank line
	if currentDomain != "" && len(currentHeaders) > 0 {
		rule := headerRule{
			domain:    currentDomain,
			urlPrefix: currentURL,
			headers:   currentHeaders,
		}
		headerMutex.Lock()
		headerRules[currentDomain] = append(headerRules[currentDomain], rule)
		headerDomains[currentDomain] = true
		headerMutex.Unlock()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading headers file: %w", err)
	}

	return nil
}

// loadExclusionRules loads URLs to never MITM from no-mitm.txt
func loadExclusionRules() error {
	exclusionFile := "no-mitm.txt"

	// Check if file exists
	if _, err := os.Stat(exclusionFile); os.IsNotExist(err) {
		log.Println("Warning: no no-mitm.txt file found")
		return nil
	}

	file, err := os.Open(exclusionFile)
	if err != nil {
		return fmt.Errorf("failed to open exclusion file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse URL or domain
		if strings.Contains(line, "://") {
			// It's a full URL, extract the domain
			u, err := url.Parse(line)
			if err != nil {
				log.Printf("Warning: Invalid URL on line %d: %s", lineNum, line)
				continue
			}

			if u.Host != "" {
				excludedMutex.Lock()
				excludedDomains[u.Host] = true
				excludedMutex.Unlock()
				log.Printf("Excluding domain from MITM: %s", u.Host)
			}
		} else {
			// It's just a domain
			domain := line
			// Remove port if present
			if h, _, err := net.SplitHostPort(domain); err == nil {
				domain = h
			}

			excludedMutex.Lock()
			excludedDomains[domain] = true
			excludedMutex.Unlock()
			log.Printf("Excluding domain from MITM: %s", domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading exclusion file: %w", err)
	}

	return nil
}

func HTTPMain() {
	// Read flags from flags.txt if it exists
	if data, err := ioutil.ReadFile("flags.txt"); err == nil {
		flags := strings.Fields(string(data))
		os.Args = append([]string{os.Args[0]}, append(flags, os.Args[1:]...)...)
	}

	// Parse command line flags
	flag.Parse()

	// Setup CPU profiling if requested
	if *cpuProfile {
		f, err := os.Create("legacy_proxy_cpu.prof")
		if err != nil {
			log.Fatal("Could not create CPU profile: ", err)
		}

		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			log.Fatal("Could not start CPU profile: ", err)
		}

		// Ensure profile is written on exit
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			pprof.StopCPUProfile()
			f.Close()
			os.Exit(0)
		}()

		log.Println("CPU profiling enabled to legacy_proxy_cpu.prof")
	}

	// Load redirect rules
	if err := loadRedirectRules(); err != nil {
		log.Printf("Error loading redirect rules: %v", err)
	}

	// Load custom header rules
	if err := loadHeaderRules(); err != nil {
		log.Printf("Error loading header rules: %v", err)
	}

	// Load MITM exclusion rules
	if err := loadExclusionRules(); err != nil {
		log.Printf("Error loading exclusion rules: %v", err)
	}

	// Start background key generation
	startKeyPool()

	ca, err := loadCA()
	if err != nil {
		log.Fatal("Error loading certificate:", err)
	}

	// Configure server side with relaxed security for old OS X clients
	tlsServerConfig := &tls.Config{
		MinVersion: tls.VersionSSL30,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// Create a cert pool with system roots and our CA
	systemRoots, err := loadSystemCertPool()
	if err != nil {
		log.Fatal("Warning: Could not load system certificate pool:", err)
		systemRoots = x509.NewCertPool()
	}

	// Add our CA to the system roots
	systemRoots.AddCert(ca.Leaf)

	// Configure client side with secure connections but enable AIA chasing
	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS10, // Maintain decent security for outbound
		RootCAs:    systemRoots,
		// Let Go use default secure cipher suites for outbound connections
		VerifyPeerCertificate: createCertVerifier(systemRoots),
		// Enable session tickets for upstream connections
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}

	p := &Proxy{
		CA:              &ca,
		TLSServerConfig: tlsServerConfig,
		TLSClientConfig: tlsClientConfig,
		FlushInterval:   100 * time.Millisecond,
		Wrap:            transparentProxy,
	}
	// Set after p exists; the transport's TLS dialer is a method on p.
	p.upstreamTransport = p.newUpstreamTransport()

	log.Printf("Aqua HTTP Proxy started on port %d", *httpPort)
	if *logURLs {
		log.Println("URL logging is ENABLED")
	}
	if *forceMITM {
		log.Println("Force MITM mode is ENABLED")
	}
	if *allowRemoteConnections {
		log.Println("Remote connections are ALLOWED")
	}
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *httpPort), p))
}

// getIntermediateCerts retrieves cached certificates for the provided pool
func getIntermediateCerts(pool *x509.CertPool) {
	aiaCacheMutex.RLock()
	defer aiaCacheMutex.RUnlock()

	for _, cert := range aiaCertCache {
		pool.AddCert(cert)
	}
}

// createCertVerifier returns a function that verifies certificates and performs AIA chasing
// rootCAs should include both system roots and our generated CA certificate
func createCertVerifier(rootCAs *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Convert raw certificates
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return err
			}
			certs[i] = cert
		}

		// Try standard verification first
		intermediatePool := x509.NewCertPool()

		// Add any certificates we've previously fetched via AIA
		getIntermediateCerts(intermediatePool)

		// Add all but the first cert as intermediates
		for _, cert := range certs[1:] {
			intermediatePool.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediatePool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		_, err := certs[0].Verify(opts)
		if err == nil {
			return nil
		}

		// If verification failed, try AIA chasing
		// AIA certificates are already cached in the chaseAIA function
		_, chainErr := chaseAIA(certs, rootCAs)
		if chainErr == nil {
			return nil
		}

		// If still failing, log the missing root cert info
		var unknownAuthorityErr x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthorityErr) {
			certInfo := extractCertificateChainInfo(err, certs)
			if certInfo != "" {
				log.Printf("Certificate verification failed: %v%s", err, certInfo)
			}
		}

		return err
	}
}

// chaseAIA follows AIA URLs to download missing certificates
// rootCAs contains both system roots from macOS Keychain and our custom CA
func chaseAIA(certs []*x509.Certificate, rootCAs *x509.CertPool) ([]*x509.Certificate, error) {
	var downloadedCerts []*x509.Certificate
	intermediates := x509.NewCertPool()

	// Add all but the first cert as intermediates
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Check if we need to chase AIAs
	leaf := certs[0]
	for _, url := range leaf.IssuingCertificateURL {
		// Check if we've already fetched this certificate by url
		cacheKey := url

		aiaCacheMutex.RLock()
		cachedCert, found := aiaCertCache[cacheKey]
		aiaCacheMutex.RUnlock()

		if found {
			intermediates.AddCert(cachedCert)
			downloadedCerts = append(downloadedCerts, cachedCert)
			continue
		}

		resp, err := http.Get(url)
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Println("Failed to fetch AIA certificate:", err)
			continue
		}

		certData, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Println("Failed to read AIA certificate:", err)
			continue
		}

		aiaCert, err := x509.ParseCertificate(certData)
		if err != nil {
			// Try parsing as PEM
			block, _ := pem.Decode(certData)
			if block == nil {
				log.Println("Failed to parse AIA certificate:", err)
				continue
			}

			aiaCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Println("Failed to parse AIA certificate from PEM:", err)
				continue
			}
		}

		// Cache the certificate by URL
		aiaCacheMutex.Lock()
		aiaCertCache[cacheKey] = aiaCert
		aiaCacheMutex.Unlock()

		intermediates.AddCert(aiaCert)
		downloadedCerts = append(downloadedCerts, aiaCert)

		// Recursively check if this cert has AIAs too
		if len(aiaCert.IssuingCertificateURL) > 0 {
			moreCerts, _ := chaseAIA([]*x509.Certificate{aiaCert}, rootCAs)
			downloadedCerts = append(downloadedCerts, moreCerts...)
			for _, c := range moreCerts {
				intermediates.AddCert(c)
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(opts)
	return downloadedCerts, err
}

func loadCA() (cert tls.Certificate, err error) {
	// Only load existing certificates
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return cert, fmt.Errorf("could not load certificate files (%s, %s): %w", certFile, keyFile, err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, fmt.Errorf("could not parse certificate: %w", err)
	}

	return
}

func transparentProxy(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := fmt.Sprintf("%p", r)

		if *logURLs {
			log.Printf("[%s] HTTP URL: %s %s", reqID, r.Method, r.URL.String())
		}

		rw := &responseTracker{
			ResponseWriter: w,
			reqID:          reqID,
			url:            r.URL.String(),
		}

		upstream.ServeHTTP(rw, r)
	})
}

// responseTracker tracks response status and completion
type responseTracker struct {
	http.ResponseWriter
	reqID       string
	url         string
	status      int
	wroteHeader bool
}

func (rw *responseTracker) WriteHeader(statusCode int) {
	rw.wroteHeader = true
	rw.status = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseTracker) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	Wrap func(upstream http.Handler) http.Handler

	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CA *tls.Certificate

	// TLSServerConfig specifies the tls.Config to use when generating leaf
	// cert using CA.
	TLSServerConfig *tls.Config

	// TLSClientConfig specifies the tls.Config to use when establishing
	// an upstream connection for proxying.
	TLSClientConfig *tls.Config

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// upstreamTransport is the single shared transport used to dial upstreams for
	// both the plain-HTTP and MITM paths. One pooled transport — the way a
	// browser keeps a single connection pool — reuses and bounds upstream
	// connections, rather than opening (and leaking) one per request or per
	// client connection.
	upstreamTransport *http.Transport
}

// newUpstreamTransport builds the shared upstream transport. Plain (http)
// targets use the transport's default dialer. TLS (https) targets are dialed
// through dialUpstream so the modern-TLS bridge and certificate-chain
// diagnostics are preserved; setting DialTLS also keeps upstream connections on
// HTTP/1.1 and means the transport's own TLSClientConfig is never consulted, so
// it is deliberately omitted (dialUpstream applies p.TLSClientConfig itself).
// Redirect resolution lives entirely in the directors, which rewrite the request
// URL before it reaches the dialer; the dialer just dials what it is told, so a
// dead origin on a non-redirected path surfaces as a 502 rather than being
// silently sent to a guessed redirect target. Idle connections are pooled and
// expire (a hand-built Transport otherwise keeps them forever, since
// IdleConnTimeout defaults to 0).
func (p *Proxy) newUpstreamTransport() *http.Transport {
	return &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			host := addr
			if h, _, err := net.SplitHostPort(addr); err == nil {
				host = h
			}
			return p.dialUpstream(addr, true, host, "upstream")
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
}

// roundTripper returns the RoundTripper both proxy paths hand to
// httputil.ReverseProxy: the shared upstream pool wrapped to drop the
// X-Forwarded-For header ReverseProxy adds, so the proxy stays transparent on
// the plain-HTTP and MITM paths alike.
func (p *Proxy) roundTripper() http.RoundTripper {
	return transparentTransport{base: p.upstreamTransport}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if !*allowRemoteConnections {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid remote address", http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "Remote connections not allowed", http.StatusForbidden)
			return
		}
	}

	if r.Method == "CONNECT" {
		p.serveConnect(w, r)
		return
	}

	// Create a custom director that handles redirects and custom headers transparently
	director := func(req *http.Request) {
		httpDirector(req)

		// Check for redirects and modify the request to go to the redirect target
		if targetURL, shouldRedirect := checkRedirect(req.URL); shouldRedirect {
			log.Printf("Redirecting %s → %s", req.URL.String(), targetURL.String())
			req.URL = targetURL
			req.Host = targetURL.Host
		}

		// Apply custom headers if any match
		if headers, ok := checkHeaders(req.URL); ok {
			applyHeaders(req, headers)
		}
	}

	rp := &httputil.ReverseProxy{
		Director:      director,
		Transport:     p.roundTripper(),
		FlushInterval: p.FlushInterval,
	}
	p.Wrap(rp).ServeHTTP(w, r)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		name = dnsName(r.Host)
		host = r.Host
	)

	// Generate a unique ID for this connection
	connID := fmt.Sprintf("conn-%p", r)

	if name == "" {
		log.Printf("[%s] Cannot determine cert name for %s", connID, host)
		http.Error(w, "no upstream", 503)
		return
	}

	// Hijack the connection early
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[%s] ResponseWriter does not support hijacking", connID)
		http.Error(w, "internal server error", 500)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[%s] Failed to hijack connection: %v", connID, err)
		http.Error(w, "internal server error", 500)
		return
	}

	// Send 200 OK response
	if _, err = clientConn.Write(okHeader); err != nil {
		log.Printf("[%s] Failed to send 200 OK: %v", connID, err)
		clientConn.Close()
		return
	}

	// Peek at the ClientHello to determine routing
	clientHello, err := peekClientHello(clientConn)
	if err != nil {
		// Fall back to MITM mode if we can't parse the ClientHello
		p.serveMITM(clientConn, host, name, nil, connID)
		return
	}

	// Check if domain has redirect/header rules or is excluded from MITM
	// Extract domain without port
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	redirectMutex.RLock()
	hasRedirects := redirectDomains[domain]
	redirectMutex.RUnlock()

	hasHeaders := hasHeaderRules(domain)

	excludedMutex.RLock()
	isExcluded := excludedDomains[domain]
	excludedMutex.RUnlock()

	needsMITM := hasRedirects || hasHeaders

	// Route based on client capabilities, redirect/header rules, and exclusion rules
	if isExcluded {
		// Domain is explicitly excluded from MITM - always use passthrough
		log.Printf("[%s] Domain %s is excluded from MITM, using passthrough", connID, domain)
		p.passthroughConnection(clientConn, host, clientHello, connID)
	} else if clientHello.isModernClient && !needsMITM && !*forceMITM {
		// Modern client detected, no redirects/headers, and force MITM not enabled - use passthrough mode
		p.passthroughConnection(clientConn, host, clientHello, connID)
	} else {
		// Legacy client OR domain has redirects/headers OR force MITM enabled - use MITM mode
		p.serveMITM(clientConn, host, name, clientHello, connID)
	}
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	// Create a cache key from the domain names
	cacheKey := names[0]

	// Check if we have a cached certificate for this domain
	leafCertMutex.RLock()
	cachedCert, found := leafCertCache[cacheKey]
	leafCertMutex.RUnlock()

	if found {
		// Check if the certificate is still valid (has not expired)
		if time.Now().Before(cachedCert.Leaf.NotAfter) {
			// Create a defensive copy of the certificate to prevent shared state issues
			certCopy := new(tls.Certificate)
			*certCopy = *cachedCert
			return certCopy, nil
		}
		// Certificate expired, remove from cache
		leafCertMutex.Lock()
		delete(leafCertCache, cacheKey)
		leafCertMutex.Unlock()
	}

	// Generate a new certificate
	cert, err := genCert(p.CA, names)
	if err != nil {
		log.Printf("Error generating certificate for %s: %v", cacheKey, err)
		return nil, err
	}

	// Cache the new certificate
	leafCertMutex.Lock()
	leafCertCache[cacheKey] = cert
	leafCertMutex.Unlock()

	// Return a copy to prevent shared state issues
	certCopy := new(tls.Certificate)
	*certCopy = *cert
	return certCopy, nil
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// copyData copies data between connections without closing them
func copyData(dst, src net.Conn, connID, direction string) {
	io.Copy(dst, src)
}

// passthroughConnection handles a connection in passthrough mode without TLS interception
func (p *Proxy) passthroughConnection(clientConn net.Conn, host string, clientHello *clientHelloInfo, connID string) {
	// Connect to the real server
	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("[%s] Failed to connect to upstream host %s: %v", connID, host, err)
		clientConn.Close()
		return
	}

	// Send the ClientHello we already read to the server
	_, err = serverConn.Write(clientHello.raw)
	if err != nil {
		log.Printf("[%s] Failed to send ClientHello to server: %v", connID, err)
		serverConn.Close()
		clientConn.Close()
		return
	}

	// Set up bidirectional copying
	done := make(chan bool, 2)

	// Client to server
	go func() {
		copyData(serverConn, clientConn, connID, "Client→Server")
		// Half-close: signal EOF to server but keep reading
		if tcpConn, ok := serverConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- true
	}()

	// Server to client
	go func() {
		copyData(clientConn, serverConn, connID, "Server→Client")
		// Half-close: signal EOF to client but keep reading
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- true
	}()

	// Wait for both directions to complete
	<-done
	<-done

	// Now close both connections fully
	clientConn.Close()
	serverConn.Close()
}

// dialUpstream opens a connection to addr. When isTLS is set it performs a TLS
// handshake using serverName; on a certificate-authority failure it retries
// once with verification disabled, solely to log the offending chain.
func (p *Proxy) dialUpstream(addr string, isTLS bool, serverName, connID string) (net.Conn, error) {
	if !isTLS {
		return net.Dial("tcp", addr)
	}

	cConfig := new(tls.Config)
	if p.TLSClientConfig != nil {
		*cConfig = *p.TLSClientConfig
	}
	cConfig.ServerName = serverName

	conn, err := tls.Dial("tcp", addr, cConfig)
	if err == nil {
		return conn, nil
	}

	// Only if there's a certificate error, retry to capture the chain for logging
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		retryConfig := new(tls.Config)
		*retryConfig = *cConfig
		retryConfig.InsecureSkipVerify = true
		if retryConn, retryErr := tls.Dial("tcp", addr, retryConfig); retryErr == nil {
			capturedChain := retryConn.ConnectionState().PeerCertificates
			retryConn.Close()
			log.Printf("[%s] Failed to connect to upstream %s: %v%s", connID, addr, err, extractCertificateChainInfo(err, capturedChain))
			return nil, err
		}
	}
	log.Printf("[%s] Failed to connect to upstream %s: %v", connID, addr, err)
	return nil, err
}

// serverErrorLog silences the internal error logging of the per-connection
// http.Server and ReverseProxy; meaningful upstream-dial failures are already
// reported by dialUpstream.
var serverErrorLog = log.New(ioutil.Discard, "", 0)

// mitmIdleTimeout bounds how long an intercepted keep-alive connection may sit
// idle between requests before the proxy closes it.
var mitmIdleTimeout = 60 * time.Second

// tlsHandshakeTimeout bounds the client-facing TLS handshake so connections that
// open but never finish handshaking (e.g. speculative pre-connects) can't pile up
const tlsHandshakeTimeout = 30 * time.Second

// transparentTransport strips the X-Forwarded-For header that ReverseProxy adds
// before each request is sent upstream, to avoid revealing the request came through
// a proxy. In theory, servers shouldn't care if a proxy is in use, but they may, and
// it's really none of their business.
type transparentTransport struct{ base http.RoundTripper }

func (t transparentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Del("X-Forwarded-For")
	return t.base.RoundTrip(req)
}

// handleMITMWithProxy serves an intercepted, TLS-terminated connection through
// Go's HTTP engine. An httputil.ReverseProxy handles the decrypted requests and
// re-originates each one to the real server over a modern TLS connection.
func (p *Proxy) handleMITMWithProxy(tlsConn net.Conn, defaultHost, connID string, checkRedirects bool) {
	director := func(req *http.Request) {
		// The intercepted request carries only an origin-form target, so rebuild
		// the absolute HTTPS URL it was really for.
		req.URL.Scheme = "https"
		if req.Host == "" {
			req.Host = defaultHost
		}
		req.URL.Host = req.Host

		if *logURLs {
			log.Printf("[%s] MITM URL: %s https://%s%s", connID, req.Method, req.Host, req.URL.RequestURI())
		}

		// Apply header rules matching the original URL, then any redirect, then
		// header rules matching the redirect target.
		if headers, ok := checkHeaders(req.URL); ok {
			applyHeaders(req, headers)
		}
		if checkRedirects {
			if targetURL, shouldRedirect := checkRedirect(req.URL); shouldRedirect {
				log.Printf("[%s] Redirecting %s → %s", connID, req.URL.String(), targetURL.String())
				req.URL = targetURL
				req.Host = targetURL.Host
				if headers, ok := checkHeaders(req.URL); ok {
					applyHeaders(req, headers)
				}
			}
		}
	}

	rp := &httputil.ReverseProxy{
		Director: director,
		// The shared upstream pool reuses connections across client connections
		// and expires idle ones, so there is nothing to clean up per connection.
		Transport:     p.roundTripper(),
		FlushInterval: p.FlushInterval,
		ErrorLog:      serverErrorLog,
	}

	// Serve the single connection. http.Server drives request parsing, keep-alive,
	// and upgrade hijacking; Serve returns once the connection is closed. The
	// timeouts ensure idle or half-open connections are reclaimed instead of being
	// held open forever (which would leak file descriptors).
	server := &http.Server{
		Handler:           rp,
		ErrorLog:          serverErrorLog,
		IdleTimeout:       mitmIdleTimeout,
		ReadHeaderTimeout: 30 * time.Second,
	}
	server.Serve(newSingleUseListener(tlsConn))
}

// singleUseListener adapts a single, already-accepted connection to the
// net.Listener interface so an http.Server can serve it. Accept yields the
// connection once; subsequent calls block until the connection is closed, so
// http.Server.Serve returns only after the connection is finished.
type singleUseListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleUseListener(conn net.Conn) *singleUseListener {
	l := &singleUseListener{done: make(chan struct{})}
	// Wrap the connection so that when the server closes it, Accept unblocks and
	// Serve unwinds.
	l.conn = &closeNotifyConn{Conn: conn, notify: l.shutdown}
	return l
}

func (l *singleUseListener) shutdown() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}

func (l *singleUseListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, io.EOF
}

func (l *singleUseListener) Close() error {
	l.shutdown()
	return nil
}

func (l *singleUseListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// closeNotifyConn invokes notify the first time the connection is closed, which
// lets the owning singleUseListener release http.Server.Serve.
type closeNotifyConn struct {
	net.Conn
	once   sync.Once
	notify func()
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(c.notify)
	return c.Conn.Close()
}

// serveMITM handles a connection in MITM mode with TLS interception
func (p *Proxy) serveMITM(clientConn net.Conn, host, name string, clientHello *clientHelloInfo, connID string) {
	orighost := host
	// Get certificate from cache or generate new one
	cert, err := p.cert(name)
	if err != nil {
		log.Printf("[%s] Certificate error for %s: %v", connID, name, err)
		clientConn.Close()
		return
	}

	// Create TLS server config
	sConfig := new(tls.Config)
	if p.TLSServerConfig != nil {
		*sConfig = *p.TLSServerConfig
	}
	sConfig.Certificates = []tls.Certificate{*cert}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Only request a new cert if the ServerName differs from our initial one
		if hello.ServerName == name {
			return cert, nil
		}

		return p.cert(hello.ServerName)
	}

	// Create a connection that can replay the ClientHello
	var tlsConn *tls.Conn
	if clientHello != nil {
		// We have already read the ClientHello, so we need to create a special connection
		// that will replay it when the TLS handshake starts
		replayConn := &replayConn{
			Conn:   clientConn,
			buffer: bytes.NewBuffer(clientHello.raw),
		}
		tlsConn = tls.Server(replayConn, sConfig)
	} else {
		// No ClientHello was peeked, proceed normally
		tlsConn = tls.Server(clientConn, sConfig)
	}

	// Perform TLS handshake
	tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	err = tlsConn.Handshake()
	if err != nil {
		//log.Printf("[%s] TLS handshake error: %v", connID, err)
		tlsConn.Close()
		return
	}
	// Clear the handshake deadline; http.Server applies its own idle/read timeouts.
	tlsConn.SetDeadline(time.Time{})

	// Determine whether this connection needs HTTP-level handling (URL logging,
	// header rewriting, or redirects). Rule lookups use the original host.
	domain := orighost
	if h, _, err := net.SplitHostPort(orighost); err == nil {
		domain = h
	}

	redirectMutex.RLock()
	hasRedirects := redirectDomains[domain]
	redirectMutex.RUnlock()

	hasHeaders := hasHeaderRules(domain)

	// If URL logging is enabled OR the domain has redirect/header rules, hand the
	// decrypted connection to Go's HTTP engine, which resolves the real target
	// per request (so a redirect to a live host still works when the original
	// host is down) and handles the full range of HTTP behavior.
	if *logURLs || hasRedirects || hasHeaders {
		p.handleMITMWithProxy(tlsConn, orighost, connID, hasRedirects)
		return
	}

	// Otherwise no per-request inspection is needed: dial the upstream once and
	// splice raw TLS bytes in both directions.
	serverConn, err := p.dialUpstream(host, true, name, connID)
	if err != nil {
		tlsConn.Close()
		return
	}

	done := make(chan bool, 2)

	// Client to server
	go func() {
		copyData(serverConn, tlsConn, connID, "Client→Server")
		done <- true
	}()

	// Server to client
	go func() {
		copyData(tlsConn, serverConn, connID, "Server→Client")
		done <- true
	}()

	// Wait for both directions to complete
	<-done
	<-done

	// Now close both connections
	tlsConn.Close()
	serverConn.Close()
}

// extractCertificateChainInfo analyzes the certificate chain to identify the missing root
func extractCertificateChainInfo(err error, chain []*x509.Certificate) string {
	if err == nil || len(chain) == 0 {
		return ""
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		// Find the topmost certificate in the chain
		topCert := chain[len(chain)-1]

		// Check if it's self-signed (a root cert)
		if topCert.Subject.String() == topCert.Issuer.String() {
			// The root is in the chain but not trusted
			return fmt.Sprintf(" (untrusted root CA: %s)", topCert.Subject.CommonName)
		} else {
			// The chain is incomplete - missing the root
			return fmt.Sprintf(" (missing root CA: %s)", topCert.Issuer.CommonName)
		}
	}

	return ""
}

// replayConn is a net.Conn wrapper that replays buffered data before reading from the underlying connection
type replayConn struct {
	net.Conn
	buffer *bytes.Buffer
}

func (c *replayConn) Read(b []byte) (int, error) {
	// First, read from the buffer if there's data
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}
	// Then read from the underlying connection
	return c.Conn.Read(b)
}

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

func genCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	key, err := getKey()
	if err != nil {
		return nil, err
	}

	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		// If certificate generation fails, log detailed error message
		log.Printf("Certificate generation error: %v", err)
		log.Printf("Attempted to sign with CA subject: %s", ca.Leaf.Subject)
		return nil, err
	}

	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}
