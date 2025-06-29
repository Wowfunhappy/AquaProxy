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

var (
	hostname, _ = os.Hostname()

	// Use certificates in current directory
	
	keyFile  = "AquaProxy-key.pem"
	certFile = "AquaProxy-cert.pem"
	
	// Generated certs are only used between the OS and the proxy, so prioritize speed.
	RSAKeyLength = 1024
	
	// In-memory cache for certificates fetched via AIA
	aiaCertCache = make(map[string]*x509.Certificate)
	aiaCacheMutex sync.RWMutex
	
	// In-memory cache for generated leaf certificates
	leafCertCache = make(map[string]*tls.Certificate)
	leafCertMutex sync.RWMutex
	
	// Pre-generated RSA keys for fast certificate generation
	// This eliminates the expensive RSA key generation step
	keyPool = make(chan *rsa.PrivateKey, 20)
	
	// Command line flags
	logURLs = flag.Bool("log-urls", false, "Print URLs being accessed in MITM mode")
	forceMITM = flag.Bool("force-mitm", false, "Force MITM mode for all connections")
	
	// URL redirect configuration
	redirectRules = make(map[string][]redirectRule)
	redirectDomains = make(map[string]bool)
	redirectMutex sync.RWMutex
	
	// Custom header configuration
	headerRules = make(map[string]headerRule)
	headerMutex sync.RWMutex
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
	fromURL    *url.URL
	toURL      *url.URL
	isPrefix   bool // true if the fromURL ends with / and should match prefixes
}

// headerRule represents custom headers for a domain
type headerRule struct {
	domain  string
	headers map[string]string // header name -> value
}

// TLS constants for parsing
const (
	tlsHandshakeTypeClientHello = 0x01
	tlsExtensionALPN           = 0x0010
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
		log.Println("Starting background key generation")
		
		// Set lower CPU priority for this goroutine
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19); err != nil {
			log.Printf("Warning: could not set lower CPU priority: %v", err)
		}
		
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
		if rule.isPrefix {
			// This is a prefix match (fromURL ended with /)
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
		} else {
			// This is an exact match
			if fullURL == rule.fromURL.String() {
				return rule.toURL, true
			}
		}
	}
	
	return nil, false
}

// loadRedirectRules loads URL redirect rules from redirects.txt
func loadRedirectRules() error {
	redirectFile := "redirects.txt"
	
	// Check if file exists
	if _, err := os.Stat(redirectFile); os.IsNotExist(err) {
		log.Println("No redirects.txt file found, URL redirects disabled")
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
				fromURL:  fromURL,
				toURL:    u,
				isPrefix: strings.HasSuffix(fromURL.Path, "/"),
			}
			
			// Extract domain from fromURL
			domain := fromURL.Host
			
			redirectMutex.Lock()
			redirectRules[domain] = append(redirectRules[domain], rule)
			redirectDomains[domain] = true
			redirectMutex.Unlock()
			
			log.Printf("Loaded redirect: %s -> %s (prefix=%v)", fromURL.String(), u.String(), rule.isPrefix)
			
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
	
	redirectMutex.RLock()
	domainCount := len(redirectDomains)
	redirectMutex.RUnlock()
	
	log.Printf("Loaded %d domains with redirect rules", domainCount)
	return nil
}

// loadHeaderRules loads custom header rules from headers.txt
func loadHeaderRules() error {
	headerFile := "headers.txt"
	
	// Check if file exists
	if _, err := os.Stat(headerFile); os.IsNotExist(err) {
		log.Println("No headers.txt file found, custom headers disabled")
		return nil
	}
	
	file, err := os.Open(headerFile)
	if err != nil {
		return fmt.Errorf("failed to open headers file: %w", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	var currentDomain string
	var currentHeaders map[string]string
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Empty line indicates end of current domain block
		if line == "" {
			if currentDomain != "" && len(currentHeaders) > 0 {
				// Save the current domain's headers
				headerMutex.Lock()
				headerRules[currentDomain] = headerRule{
					domain:  currentDomain,
					headers: currentHeaders,
				}
				headerMutex.Unlock()
				
				log.Printf("Loaded %d headers for domain: %s", len(currentHeaders), currentDomain)
				
				// Reset for next domain
				currentDomain = ""
				currentHeaders = nil
			}
			continue
		}
		
		// Check if this line contains a colon (header format)
		if strings.Contains(line, ":") {
			if currentDomain == "" {
				log.Printf("Warning: Header without domain on line %d: %s", lineNum, line)
				continue
			}
			
			// Parse header
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				headerValue := strings.TrimSpace(parts[1])
				
				if currentHeaders == nil {
					currentHeaders = make(map[string]string)
				}
				currentHeaders[headerName] = headerValue
			}
		} else {
			// This line is a domain
			if currentDomain != "" && len(currentHeaders) > 0 {
				// Save previous domain's headers before starting new one
				headerMutex.Lock()
				headerRules[currentDomain] = headerRule{
					domain:  currentDomain,
					headers: currentHeaders,
				}
				headerMutex.Unlock()
				
				log.Printf("Loaded %d headers for domain: %s", len(currentHeaders), currentDomain)
			}
			
			currentDomain = line
			currentHeaders = nil
		}
	}
	
	// Handle last domain if file doesn't end with empty line
	if currentDomain != "" && len(currentHeaders) > 0 {
		headerMutex.Lock()
		headerRules[currentDomain] = headerRule{
			domain:  currentDomain,
			headers: currentHeaders,
		}
		headerMutex.Unlock()
		
		log.Printf("Loaded %d headers for domain: %s", len(currentHeaders), currentDomain)
	}
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading headers file: %w", err)
	}
	
	headerMutex.RLock()
	domainCount := len(headerRules)
	headerMutex.RUnlock()
	
	log.Printf("Loaded custom headers for %d domains", domainCount)
	return nil
}

// applyCustomHeaders applies custom headers for a domain to the request
func applyCustomHeaders(req *http.Request, domain string) {
	headerMutex.RLock()
	rule, exists := headerRules[domain]
	headerMutex.RUnlock()
	
	if exists {
		for name, value := range rule.headers {
			req.Header.Set(name, value)
		}
	}
}

func main() {
	// Parse command line flags
	flag.Parse()
	
	// Setup CPU profiling if requested
	if flag.NArg() > 0 && flag.Arg(0) == "cpu-profile" {
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
		
		log.Println("CPU profiling enabled - press Ctrl+C to stop and save profile")
	}
	
	// Load redirect rules
	if err := loadRedirectRules(); err != nil {
		log.Printf("Error loading redirect rules: %v", err)
		// Continue running without redirects
	}
	
	// Load custom header rules
	if err := loadHeaderRules(); err != nil {
		log.Printf("Error loading header rules: %v", err)
		// Continue running without custom headers
	}
	
	// Start background key generation
	startKeyPool()

	ca, err := loadCA()
	if err != nil {
		log.Fatal("Error loading certificate:", err)
	}
	
	// Configure server side with relaxed security for older OS X clients
	tlsServerConfig := &tls.Config{
		MinVersion: tls.VersionSSL30, // Support very old protocols
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
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		log.Println("Warning: Could not load system certificate pool:", err)
		systemRoots = x509.NewCertPool()
	}
	
	// Add our CA to the system roots
	systemRoots.AddCert(ca.Leaf)

	// Configure client side with secure connections but enable AIA chasing
	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS10,      // Maintain decent security for outbound
		RootCAs:    systemRoots,
		// Let Go use default secure cipher suites for outbound connections
		VerifyPeerCertificate: createCertVerifier(systemRoots),
	}

	p := &Proxy{
		CA:               &ca,
		TLSServerConfig:  tlsServerConfig,
		TLSClientConfig:  tlsClientConfig,
		FlushInterval:    100 * time.Millisecond,
		Wrap:             transparentProxy,
	}

	log.Println("Starting proxy on port 6531")
	log.Println("Using certificate from:", certFile)
	if *logURLs {
		log.Println("URL logging is ENABLED")
	}
	if *forceMITM {
		log.Println("Force MITM mode is ENABLED - all connections will be intercepted")
	}
	log.Fatal(http.ListenAndServe(":6531", p))
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
	
	// Try verification with the enhanced intermediate pool
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

// transparentProxy passes the request through without modifying content
func transparentProxy(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := fmt.Sprintf("%p", r) // Create a unique ID for this request
		
		// Build full URL for redirect checking
		fullURL := r.URL
		if fullURL.Scheme == "" {
			fullURL.Scheme = "http"
		}
		if fullURL.Host == "" {
			fullURL.Host = r.Host
		}
		
		// Check for redirects
		if targetURL, shouldRedirect := checkRedirect(fullURL); shouldRedirect {
			log.Printf("[%s] HTTP Redirecting %s -> %s", reqID, fullURL.String(), targetURL.String())
			http.Redirect(w, r, targetURL.String(), http.StatusFound)
			return
		}
		
		// Log URL if flag is enabled (for plain HTTP requests)
		if *logURLs {
			log.Printf("[%s] HTTP URL: %s %s", reqID, r.Method, r.URL.String())
		}
		
		// Capture response
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
	reqID    string
	url      string
	status   int
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
	n, err := rw.ResponseWriter.Write(b)
	if err != nil {
		log.Printf("[%s] Error writing response: %v", rw.reqID, err)
	}
	return n, err
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
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		p.serveConnect(w, r)
		return
	}
	rp := &httputil.ReverseProxy{
		Director:      httpDirector,
		FlushInterval: p.FlushInterval,
	}
	p.Wrap(rp).ServeHTTP(w, r)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	var (
		name  = dnsName(r.Host)
		host  = r.Host
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
		log.Printf("[%s] Failed to peek ClientHello: %v - falling back to MITM mode", connID, err)
		// Fall back to MITM mode if we can't parse the ClientHello
		p.serveMITM(clientConn, host, name, nil, connID)
		return
	}
	
	// Check if domain has redirect rules
	// Extract domain without port
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}
	
	redirectMutex.RLock()
	hasRedirects := redirectDomains[domain]
	redirectMutex.RUnlock()
	
	// Check if domain has custom headers
	headerMutex.RLock()
	_, hasHeaders := headerRules[domain]
	headerMutex.RUnlock()
	
	// Route based on client capabilities, redirect rules, and header rules
	if clientHello.isModernClient && !hasRedirects && !hasHeaders && !*forceMITM {
		// Modern client detected, no redirects, and force MITM not enabled - use passthrough mode
		log.Printf("[%s] PASSTHROUGH: %s", connID, host)
		p.passthroughConnection(clientConn, host, clientHello, connID)
	} else {
		// Legacy client OR domain has redirects OR custom headers OR force MITM enabled - use MITM mode
		if *forceMITM {
			log.Printf("[%s] MITM (forced): %s", connID, host)
		} else if hasHeaders {
			log.Printf("[%s] MITM (headers): %s", connID, host)
		} else if hasRedirects {
			log.Printf("[%s] MITM (redirects): %s", connID, host)
		} else {
			log.Printf("[%s] MITM (legacy): %s", connID, host)
		}
		p.serveMITM(clientConn, host, name, clientHello, connID)
	}
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	// Create a cache key from the domain names
	cacheKey := names[0]
	log.Printf("Certificate requested for: %s", cacheKey)
	
	// Check if we have a cached certificate for this domain
	leafCertMutex.RLock()
	cachedCert, found := leafCertCache[cacheKey]
	leafCertMutex.RUnlock()
	
	if found {
		// Check if the certificate is still valid (has not expired)
		if time.Now().Before(cachedCert.Leaf.NotAfter) {
			log.Printf("Using cached certificate for: %s (expires: %s)", cacheKey, cachedCert.Leaf.NotAfter)
			// Create a defensive copy of the certificate to prevent shared state issues
			certCopy := new(tls.Certificate)
			*certCopy = *cachedCert
			return certCopy, nil
		}
		log.Printf("Cached certificate for %s has expired, regenerating", cacheKey)
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
	
	log.Printf("Successfully generated new certificate for: %s (expires: %s)", cacheKey, cert.Leaf.NotAfter)
	
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
	_, err := io.Copy(dst, src)
	
	if err != nil && err != io.EOF {
		log.Printf("[%s] %s copy error: %v", connID, direction, err)
	}
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

// handleMITMWithLogging handles MITM connections with HTTP parsing and URL logging/redirects
func (p *Proxy) handleMITMWithLogging(tlsConn *tls.Conn, serverConn *tls.Conn, host, connID string, checkRedirects bool) {
	// Read HTTP requests from client and forward to server
	reader := bufio.NewReader(tlsConn)
	serverReader := bufio.NewReader(serverConn)
	
	for {
		// Read the request
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading request: %v", connID, err)
			}
			break
		}
		
		// Set up the request URL
		req.URL.Scheme = "https"
		if req.Host == "" {
			req.Host = host
		}
		req.URL.Host = req.Host
		
		// Log the URL if enabled
		if *logURLs {
			fullURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
			if req.URL.RawQuery != "" {
				fullURL += "?" + req.URL.RawQuery
			}
			log.Printf("[%s] MITM URL: %s %s", connID, req.Method, fullURL)
		}
		
		// Check for redirects if enabled for this domain
		if checkRedirects {
			if targetURL, shouldRedirect := checkRedirect(req.URL); shouldRedirect {
				log.Printf("[%s] Redirecting %s -> %s", connID, req.URL.String(), targetURL.String())
				
				// Update request to point to new URL
				req.URL = targetURL
				req.Host = targetURL.Host
				
				// If the target is on a different host, we need to proxy to it
				if targetURL.Host != host {
					// Create a new TLS connection to the target host
					targetConfig := new(tls.Config)
					if p.TLSClientConfig != nil {
						*targetConfig = *p.TLSClientConfig
					}
					targetConfig.ServerName = targetURL.Host
					
					targetConn, err := tls.Dial("tcp", targetURL.Host+":443", targetConfig)
					if err != nil {
						log.Printf("[%s] Failed to connect to redirect target %s: %v", connID, targetURL.Host, err)
						// Send error response to client
						tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
						break
					}
					defer targetConn.Close()
					
					// Apply custom headers for the target domain
					targetDomain := targetURL.Host
					// Strip port if present
					if h, _, splitErr := net.SplitHostPort(targetDomain); splitErr == nil {
						targetDomain = h
					}
					applyCustomHeaders(req, targetDomain)
					
					// Forward the request to the target
					err = req.Write(targetConn)
					if err != nil {
						log.Printf("[%s] Error forwarding request to redirect target: %v", connID, err)
						tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
						break
					}
					
					// Read response from target
					targetReader := bufio.NewReader(targetConn)
					resp, err := http.ReadResponse(targetReader, req)
					if err != nil {
						log.Printf("[%s] Error reading response from redirect target: %v", connID, err)
						tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
						break
					}
					
					// Forward response to client
					err = resp.Write(tlsConn)
					if err != nil {
						log.Printf("[%s] Error writing redirect response to client: %v", connID, err)
						resp.Body.Close()
						break
					}
					resp.Body.Close()
					
					// Continue to next request
					continue
				}
			}
		}
		
		// Forward request to server directly
		req.RequestURI = "" // Must be cleared for client requests
		
		// Apply custom headers for the domain
		domain := req.Host
		if domain == "" {
			domain = host
		}
		// Strip port if present
		if h, _, err := net.SplitHostPort(domain); err == nil {
			domain = h
		}
		applyCustomHeaders(req, domain)
		
		// Write request to server
		err = req.Write(serverConn)
		if err != nil {
			log.Printf("[%s] Error writing request to server: %v", connID, err)
			// Send error response to client
			tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			break
		}
		
		// Read response from server
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			log.Printf("[%s] Error reading response from server: %v", connID, err)
			// Send error response to client
			tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			break
		}
		
		// Write response back to client
		err = resp.Write(tlsConn)
		if err != nil {
			log.Printf("[%s] Error writing response to client: %v", connID, err)
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		
		// Check if connection should be closed
		if req.Close || resp.Close {
			break
		}
	}
	
	// Close connections
	tlsConn.Close()
	serverConn.Close()
}

// singleUseListener implements net.Listener for a single connection
type singleUseListener struct {
	conn   net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *singleUseListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, io.EOF
	default:
		l.once.Do(func() {
			close(l.closed)
		})
		return l.conn, nil
	}
}

func (l *singleUseListener) Close() error {
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
		return nil
	}
}

func (l *singleUseListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// serveMITM handles a connection in MITM mode with TLS interception
func (p *Proxy) serveMITM(clientConn net.Conn, host, name string, clientHello *clientHelloInfo, connID string) {
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
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("[%s] TLS handshake error: %v", connID, err)
		tlsConn.Close()
		return
	}
	
	// Set up client TLS config for upstream connection
	cConfig := new(tls.Config)
	if p.TLSClientConfig != nil {
		*cConfig = *p.TLSClientConfig
	}
	cConfig.ServerName = name
	
	// Connect to the real server
	serverConn, err := tls.Dial("tcp", host, cConfig)
	if err != nil {
		// Check if there are redirects for this domain
		domain := host
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			domain = h
		}
		
		redirectMutex.RLock()
		rules, hasRedirects := redirectRules[domain]
		redirectMutex.RUnlock()
		
		// If there are redirects, try connecting to the first redirect target
		if hasRedirects && len(rules) > 0 {
			// Get the first redirect rule's target host
			targetHost := rules[0].toURL.Host
			if targetHost != "" && targetHost != domain {
				// Add port if not present
				if _, _, err := net.SplitHostPort(targetHost); err != nil {
					targetHost = targetHost + ":443"
				}
				
				log.Printf("[%s] Original connection failed, trying redirect target: %s", connID, targetHost)
				
				// Update TLS config for new host
				redirectConfig := new(tls.Config)
				*redirectConfig = *cConfig
				redirectConfig.ServerName = rules[0].toURL.Host
				
				// Try connecting to redirect target
				redirectConn, redirectErr := tls.Dial("tcp", targetHost, redirectConfig)
				if redirectErr == nil {
					// Success! Use this connection
					serverConn = redirectConn
					err = nil
					log.Printf("[%s] Successfully connected to redirect target: %s", connID, targetHost)
				} else {
					log.Printf("[%s] Failed to connect to redirect target %s: %v", connID, targetHost, redirectErr)
					// Fall through to original error handling
				}
			}
		}
		
		// If we still have an error (no redirects or redirect failed)
		if err != nil {
			// Only if there's a certificate error, retry to capture the chain
			var unknownAuthorityErr x509.UnknownAuthorityError
			if errors.As(err, &unknownAuthorityErr) {
				// Retry with InsecureSkipVerify to capture the chain
				var capturedChain []*x509.Certificate
				retryConfig := new(tls.Config)
				*retryConfig = *cConfig
				retryConfig.InsecureSkipVerify = true
				
				// Quick connection just to get the chain
				if retryConn, retryErr := tls.Dial("tcp", host, retryConfig); retryErr == nil {
					// tls.Dial returns a *tls.Conn directly
					capturedChain = retryConn.ConnectionState().PeerCertificates
					retryConn.Close()
					log.Printf("[%s] Failed to connect to upstream host: %v%s", connID, err, extractCertificateChainInfo(err, capturedChain))
				} else {
					log.Printf("[%s] Failed to connect to upstream host: %v", connID, err)
				}
			} else {
				log.Printf("[%s] Failed to connect to upstream host: %v", connID, err)
			}
			tlsConn.Close()
			return
		}
	}
	
	// Check if domain has redirect rules
	// Extract domain without port
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}
	
	redirectMutex.RLock()
	hasRedirects := redirectDomains[domain]
	redirectMutex.RUnlock()
	
	// Check if domain has custom headers
	headerMutex.RLock()
	_, hasHeaders := headerRules[domain]
	headerMutex.RUnlock()
	
	// If URL logging is enabled OR domain has redirects OR domain has headers, parse HTTP requests
	if *logURLs || hasRedirects || hasHeaders {
		// Parse and handle HTTP requests
		p.handleMITMWithLogging(tlsConn, serverConn, host, connID, hasRedirects)
	} else {
		// Use efficient raw TCP/TLS forwarding (original behavior)
		done := make(chan bool, 2)
		
		// Client to server
		go func() {
			copyData(serverConn, tlsConn, connID, "Client→Server")
			// For TLS connections, we can't use half-close, but we avoid closing
			// the connection until both directions are done
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
	
	// Use a more compatible signature algorithm for older clients
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.SHA256WithRSA, // More compatible than ECDSA with SHA512
	}
	
	// Get a pre-generated key from the pool instead of generating a new one
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