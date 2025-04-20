// +build ignore

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"
)

var (
	hostname, _ = os.Hostname()

	// Use certificates in current directory
	keyFile  = "legacy-mac-proxy-key.pem"
	certFile = "legacy-mac-proxy-cert.pem"
	
	// In-memory cache for certificates fetched via AIA
	aiaCertCache = make(map[string]*x509.Certificate)
	aiaCacheMutex sync.RWMutex
)

func main() {
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

	log.Println("Starting MITM proxy on port 6531")
	log.Println("Using certificate from:", certFile)
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
			log.Println("Using cached AIA certificate for URL:", url)
			intermediates.AddCert(cachedCert)
			downloadedCerts = append(downloadedCerts, cachedCert)
			continue
		}
		
		log.Println("Fetching AIA certificate from:", url)
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
		// Clear encoding to avoid compression issues with older clients
		r.Header.Set("Accept-Encoding", "")
		upstream.ServeHTTP(w, r)
	})
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
		err   error
		sconn *tls.Conn
		name  = dnsName(r.Host)
	)

	if name == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	provisionalCert, err := p.cert(name)
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if p.TLSServerConfig != nil {
		*sConfig = *p.TLSServerConfig
	}
	sConfig.Certificates = []tls.Certificate{*provisionalCert}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := new(tls.Config)
		if p.TLSClientConfig != nil {
			*cConfig = *p.TLSClientConfig
		}
		cConfig.ServerName = hello.ServerName
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}
		return p.cert(hello.ServerName)
	}

	cconn, err := handshake(w, sConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer cconn.Close()
	if sconn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer sconn.Close()

	od := &oneShotDialer{c: sconn}
	rp := &httputil.ReverseProxy{
		Director:      httpsDirector,
		Transport:     &http.Transport{DialTLS: od.Dial},
		FlushInterval: p.FlushInterval,
	}

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}
	http.Serve(&oneShotListener{wc}, p.Wrap(rp))
	<-ch
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	return genCert(p.CA, names)
}

var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// A oneShotDialer implements net.Dialer whos Dial only returns a
// net.Conn as specified by c followed by an error for each subsequent Dial.
type oneShotDialer struct {
	c  net.Conn
	mu sync.Mutex
}

func (d *oneShotDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		return nil, errors.New("closed")
	}
	c := d.c
	d.c = nil
	return c, nil
}

// A oneShotListener implements net.Listener whos Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
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
	
	// Use RSA keys for better compatibility with older systems
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
