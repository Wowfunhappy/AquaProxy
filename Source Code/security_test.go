package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- SMTP: a malformed line must not take the process down ----------------

// A blank line is what every HTTP request sends between its headers and its
// body, so reaching this parser takes nothing more than a cross-origin
// <img src="http://127.0.0.1:6533/"> in any page the browser loads. Indexing
// field 0 of a line with no fields panicked, and each connection runs on its own
// goroutine, so the panic ended the process — HTTP proxy, mail sessions and all.
func TestSMTPBlankLineDoesNotPanic(t *testing.T) {
	mp := &MailProxy{Protocol: "SMTP", DefaultRemotePort: 587}
	client, server := net.Pipe()
	defer client.Close()

	mc := &MailConnection{
		id:         "test",
		clientConn: server,
		protocol:   "SMTP",
		reader:     bufio.NewReader(server),
		writer:     bufio.NewWriter(server),
	}

	done := make(chan interface{}, 1)
	go func() {
		defer func() { done <- recover() }()
		mp.handleSMTP(mc)
	}()

	br := bufio.NewReader(client)
	readLine(t, br) // greeting

	// Exactly what a browser sends: a request line, a header, then a blank line.
	client.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:6533\r\n\r\n"))

	for i := 0; i < 3; i++ {
		line := readLine(t, br)
		if !strings.HasPrefix(line, "5") {
			t.Fatalf("reply %d = %q; want a 5xx refusal", i, line)
		}
	}

	client.Close()
	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("handleSMTP panicked: %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleSMTP did not return")
	}
}

// recover() only takes effect when the function invoking it is the one that was
// deferred, so `defer recoverConn(id)` works but wrapping it in a closure would
// silently stop containing anything.
func TestRecoverConnContainsPanic(t *testing.T) {
	reached := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped recoverConn: %v", r)
			}
		}()
		func() {
			defer recoverConn("test")
			panic("boom")
		}()
		reached = true
	}()
	if !reached {
		t.Error("execution did not resume after the recovered panic")
	}
}

// --- SMTP: STARTTLS is used whenever it is on offer -----------------------

// Deliberate, and the important half of the pair below: when a server advertises
// no STARTTLS, unencrypted AUTH is the only form it accepts, and a provider that
// never gained STARTTLS is exactly what this proxy exists to keep reachable.
// Refusing would not protect the password, it would only make the account
// unusable. The accepted cost is that an attacker who can strip the capability
// from the EHLO response harvests the credentials.
func TestSMTPSendsPlaintextAuthWhenServerOffersNoSTARTTLS(t *testing.T) {
	sawAuth := make(chan string, 1)
	addr, closeSrv := fakeSMTPServer(t, false, sawAuth, nil)
	defer closeSrv()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	mc := newTestMailConn(conn, "127.0.0.1")
	if err := mc.authenticateSMTP("PLAIN", "victim@example.com", "hunter2", nil); err != nil {
		t.Fatalf("authenticateSMTP should fall back to plaintext AUTH, got: %v", err)
	}
	if mc.tlsEnabled {
		t.Error("tlsEnabled set even though the server offered no STARTTLS")
	}

	select {
	case got := <-sawAuth:
		if !strings.HasPrefix(got, "AUTH PLAIN ") {
			t.Errorf("upstream saw %q; want an AUTH PLAIN command", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received AUTH")
	}
}

// The half that must never regress: when STARTTLS *is* offered it has to be
// used. The fallback above must stay a fallback, not become the default path.
func TestSMTPAuthenticatesAfterStartTLS(t *testing.T) {
	root, rootKey := testRootCA(t)
	serverCert := testServerCert(t, root, rootKey, "127.0.0.1")

	sawAuth := make(chan string, 1)
	addr, closeSrv := fakeSMTPServer(t, true, sawAuth, serverCert)
	defer closeSrv()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(root)

	mc := newTestMailConn(conn, "127.0.0.1")
	if err := mc.authenticateSMTP("PLAIN", "victim@example.com", "hunter2", &tls.Config{RootCAs: roots}); err != nil {
		t.Fatalf("authenticateSMTP over STARTTLS: %v", err)
	}
	if !mc.tlsEnabled {
		t.Fatal("tlsEnabled not set after a successful STARTTLS upgrade")
	}

	select {
	case got := <-sawAuth:
		if !strings.HasPrefix(got, "AUTH PLAIN ") {
			t.Errorf("upstream saw %q; want an AUTH PLAIN command", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received AUTH")
	}
}

// --- IMAP: only the tagged line may report success ------------------------

// The result of an IMAP command is carried by its tagged line alone. Scanning
// the whole response for "<tag> OK" let a server report failure in the tagged
// line while smuggling the same text through an untagged data line, and be
// believed — turning a rejected login into an authenticated session.
func TestReadIMAPResponseIgnoresUntaggedOK(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		wantOK   bool
	}{
		{"untagged line impersonates success", "* OK A001 OK smuggled\r\nA001 NO Authentication failed\r\n", false},
		{"genuine success", "* CAPABILITY IMAP4rev1\r\nA001 OK LOGIN completed\r\n", true},
		{"genuine failure", "A001 NO Authentication failed\r\n", false},
		{"BAD is not OK", "A001 BAD Command unknown\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := &MailConnection{id: "test", serverReader: bufio.NewReader(strings.NewReader(tc.response))}
			got, ok, err := mc.readIMAPResponse("A001")
			if err != nil {
				t.Fatalf("readIMAPResponse: %v", err)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (response %q)", ok, tc.wantOK, got)
			}
			if got != tc.response {
				t.Errorf("response = %q, want the full text %q", got, tc.response)
			}
		})
	}
}

// --- IMAP: arguments must survive quoting, and not escape it --------------

func TestParseIMAPArgsPreservesQuotedSpaces(t *testing.T) {
	got := parseIMAPArgs(`A001 LOGIN "user@host@imap.example.com" "correct horse battery"` + "\r\n")
	want := []string{"A001", "LOGIN", "user@host@imap.example.com", "correct horse battery"}
	if len(got) != len(want) {
		t.Fatalf("parsed %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A password is interpolated into the LOGIN command sent upstream. Quoting it
// raw let a quote close the string and a CRLF start a command of the client's
// choosing.
func TestIMAPQuoteContainsInjection(t *testing.T) {
	hostile := `x" ` + "\r\n" + `A002 DELETE INBOX`
	quoted := imapQuote(hostile)

	if strings.Count(quoted, `"`)-strings.Count(quoted, `\"`) != 2 {
		t.Fatalf("imapQuote(%q) = %s; the value escaped its own quotes", hostile, quoted)
	}
	// Re-parsing must yield the original string as a single argument, proving no
	// command boundary was created.
	args := parseIMAPArgs("A001 LOGIN " + imapQuote("user") + " " + quoted)
	if len(args) != 4 {
		t.Fatalf("re-parsed into %d args (%q); want 4", len(args), args)
	}
	if args[3] != hostile {
		t.Errorf("round-tripped password = %q, want %q", args[3], hostile)
	}
}

func TestValidIMAPTagRejectsInjection(t *testing.T) {
	for _, bad := range []string{"", "a b", "a\r\nB LOGOUT", `a"b`, `a\b`, "a{5}", strings.Repeat("a", 33)} {
		if validIMAPTag(bad) {
			t.Errorf("validIMAPTag(%q) = true; want false", bad)
		}
	}
	for _, good := range []string{"A001", "a1", "tag-7", "."} {
		if !validIMAPTag(good) {
			t.Errorf("validIMAPTag(%q) = false; want true", good)
		}
	}
}

// The username arrives base64-decoded from the AUTH exchange, so it can carry
// anything; both halves end up inside commands sent upstream, and the second
// half also decides where the proxy connects.
func TestParseUsernameRejectsControlCharacters(t *testing.T) {
	for _, bad := range []string{
		"user@host@mail.example.com\r\nA002 LOGOUT",
		"user@host@mail.example.com with space",
		"user\x00@host@mail.example.com",
		"user@host@mail.example.com/path",
		"user@host@localhost",
		"user@host@localhost:993",
	} {
		mc := &MailConnection{id: "test"}
		if err := mc.parseUsername(bad); err == nil {
			t.Errorf("parseUsername(%q) accepted it (server=%q)", bad, mc.targetServer)
		}
	}

	mc := &MailConnection{id: "test"}
	if err := mc.parseUsername("user@example.com@mail.example.com"); err != nil {
		t.Fatalf("parseUsername rejected a valid username: %v", err)
	}
	if mc.realUsername != "user@example.com" || mc.targetServer != "mail.example.com" {
		t.Errorf("parsed to user=%q server=%q", mc.realUsername, mc.targetServer)
	}
}

// serverName must drop the port, or certificate verification is matched against
// "host:993" and never succeeds.
func TestServerNameStripsPort(t *testing.T) {
	mc := &MailConnection{targetServer: "mail.example.com:993"}
	if got := mc.serverName(); got != "mail.example.com" {
		t.Errorf("serverName() = %q, want mail.example.com", got)
	}
}

// --- AIA: fetches are attacker-directed and must be fenced in -------------

// The caIssuers URL comes from a certificate presented by a server we have not
// yet decided to trust, and the proxy runs on the user's own machine — which is
// what makes it a useful place from which to reach loopback and LAN services.
func TestAIAFetchRefusesNonPublicAddresses(t *testing.T) {
	var reached int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.StoreInt32(&reached, 1)
	}))
	defer srv.Close()

	resetAIACache()
	defer func() { aiaAllowPrivateHosts = true }()
	aiaAllowPrivateHosts = false // production setting

	if certs := aiaFetch(srv.URL); certs != nil {
		t.Errorf("aiaFetch returned %d certs from a loopback URL", len(certs))
	}
	if atomic.LoadInt32(&reached) != 0 {
		t.Error("the loopback AIA server was contacted")
	}
}

func TestAIAFetchRejectsUnsupportedSchemes(t *testing.T) {
	resetAIACache()
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com/ca.crt", "gopher://example.com/"} {
		if certs := aiaFetch(u); certs != nil {
			t.Errorf("aiaFetch(%q) returned certificates", u)
		}
	}
}

// A hostile bundle can hand back certificates carrying fresh AIA URLs at every
// level; the visited set alone stops repeats, not an endless supply of new ones.
func TestAIAChaseIsBounded(t *testing.T) {
	var fetches int32

	root, rootKey := testRootCA(t)

	// Every request returns a fresh CA certificate whose AIA points somewhere new.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&fetches, 1)

		cert, _ := makeCert(t, &x509.Certificate{
			SerialNumber:          big.NewInt(int64(1000 + n)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("Filler %d", n)},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IssuingCertificateURL: []string{fmt.Sprintf("%s/next/%d", srv.URL, n)},
		}, root, rootKey)
		w.Write(cert.Raw)
	}))
	defer srv.Close()

	leaf, _ := makeCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"leaf.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{srv.URL + "/start"},
	}, root, rootKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	resetAIACache()

	done := make(chan struct{})
	go func() {
		chaseAIA([]*x509.Certificate{leaf}, roots, "leaf.test")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("chaseAIA did not terminate against an endless AIA chain")
	}

	n := int(atomic.LoadInt32(&fetches))
	if n > aiaMaxFetches {
		t.Errorf("chase issued %d fetches; limit is %d", n, aiaMaxFetches)
	}
	// Guard against the test going vacuous: the chain must actually have been
	// followed for a few hops, otherwise nothing is being bounded.
	if n < 2 {
		t.Errorf("chase issued only %d fetch(es); the endless-chain scenario did not occur", n)
	}
	t.Logf("chase terminated after %d fetches", n)
}

func TestAIACacheIsBounded(t *testing.T) {
	resetAIACache()
	cert, _ := testRootCA(t)
	for i := 0; i < aiaMaxCacheEntries+50; i++ {
		cacheAIACerts(fmt.Sprintf("http://example.test/%d", i), []*x509.Certificate{cert})
	}
	aiaCacheMutex.RLock()
	n := len(aiaCertCache)
	aiaCacheMutex.RUnlock()
	if n > aiaMaxCacheEntries {
		t.Errorf("AIA cache holds %d entries; limit is %d", n, aiaMaxCacheEntries)
	}
	resetAIACache()
}

// --- Upstream verification: extended key usage ----------------------------

// ExtKeyUsageAny switched off EKU checking entirely, so a certificate a public
// CA issued for client authentication or S/MIME was accepted as proof of a
// server's identity.
func TestDialUpstreamRejectsNonServerAuthCert(t *testing.T) {
	root, rootKey := testRootCA(t)

	for _, tc := range []struct {
		name       string
		eku        []x509.ExtKeyUsage
		wantAccept bool
	}{
		{"server auth", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true},
		{"no EKU extension is unconstrained", nil, true},
		{"client auth only", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false},
		{"email protection only", []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, leafKey := makeCert(t, &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "example.test"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				DNSNames:     []string{"example.test"},
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  tc.eku,
			}, root, rootKey)

			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			ts.TLS = &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}},
			}
			ts.StartTLS()
			defer ts.Close()
			u, _ := url.Parse(ts.URL)

			roots := x509.NewCertPool()
			roots.AddCert(root)
			p := &Proxy{TLSClientConfig: &tls.Config{RootCAs: roots}}

			resetAIACache()
			conn, err := p.dialUpstream(u.Host, true, "example.test", "test")
			if err == nil {
				conn.Close()
			}
			if accepted := err == nil; accepted != tc.wantAccept {
				t.Errorf("accepted = %v, want %v (err=%v)", accepted, tc.wantAccept, err)
			}
		})
	}
}

// --- Generated leaf certificates ------------------------------------------

// The cache key is the name the client asked for via SNI, so a page provoking
// connections to endless distinct subdomains grew this map without limit.
func TestLeafCertCacheIsBounded(t *testing.T) {
	origMax, origLen := leafCertCacheMax, RSAKeyLength
	defer func() {
		leafCertCacheMax, RSAKeyLength = origMax, origLen
		leafCertMutex.Lock()
		leafCertCache, leafCertOrder = make(map[string]*tls.Certificate), nil
		leafCertMutex.Unlock()
	}()
	leafCertCacheMax = 4
	RSAKeyLength = 512 // keep the test fast; irrelevant to what it proves

	leafCertMutex.Lock()
	leafCertCache, leafCertOrder = make(map[string]*tls.Certificate), nil
	leafCertMutex.Unlock()

	p := &Proxy{CA: testProxyCA(t)}
	for i := 0; i < 20; i++ {
		if _, err := p.cert(fmt.Sprintf("host%d.attacker.test", i)); err != nil {
			t.Fatalf("cert %d: %v", i, err)
		}
	}

	leafCertMutex.RLock()
	n, order := len(leafCertCache), len(leafCertOrder)
	leafCertMutex.RUnlock()
	if n > leafCertCacheMax {
		t.Errorf("leaf cache holds %d entries; limit is %d", n, leafCertCacheMax)
	}
	// The eviction list must stay in step with the map, or it becomes a leak of
	// its own.
	if order != n {
		t.Errorf("eviction list holds %d keys but the cache holds %d", order, n)
	}
}

func TestCertRejectsEmptyName(t *testing.T) {
	p := &Proxy{CA: testProxyCA(t)}
	if _, err := p.cert(""); err == nil {
		t.Error("p.cert(\"\") generated a certificate for the empty name")
	}
}

// --- Listeners -------------------------------------------------------------

// The per-request loopback checks stay, but binding loopback only means the
// network never reaches the HTTP and mail parsers in the first place.
func TestProxyListenersBindLoopbackOnly(t *testing.T) {
	orig := *allowRemoteConnections
	defer func() { *allowRemoteConnections = orig }()
	*allowRemoteConnections = false

	listeners, err := proxyListeners(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) == 0 {
		t.Fatal("no listeners")
	}
	for _, l := range listeners {
		defer l.Close()
		host, _, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			t.Errorf("listener bound to %s; want a loopback address", l.Addr())
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.1.1", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "224.0.0.1"} {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("isPublicIP(%s) = true; want false", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "172.32.0.1", "192.167.1.1", "2606:4700::1111"} {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("isPublicIP(%s) = false; want true", s)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func readLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	return strings.TrimSpace(line)
}

func newTestMailConn(conn net.Conn, target string) *MailConnection {
	return &MailConnection{
		id:           "test",
		protocol:     "SMTP",
		serverConn:   conn,
		serverReader: bufio.NewReader(conn),
		serverWriter: bufio.NewWriter(conn),
		targetServer: target,
	}
}

// fakeSMTPServer answers one connection. When offerStartTLS is false it
// advertises no STARTTLS — a server that genuinely lacks it, and equally what a
// network attacker's stripped EHLO response looks like. Any AUTH command it
// receives is reported on sawAuth.
func fakeSMTPServer(t *testing.T, offerStartTLS bool, sawAuth chan<- string, cert *tls.Certificate) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)

		fmt.Fprint(c, "220 mail.example.com ESMTP ready\r\n")
		if _, err := r.ReadString('\n'); err != nil { // EHLO
			return
		}
		if offerStartTLS {
			fmt.Fprint(c, "250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
		} else {
			fmt.Fprint(c, "250-mail.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
		}

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case cmd == "STARTTLS":
				fmt.Fprint(c, "220 Go ahead\r\n")
				tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				defer tlsConn.Close()
				c, r = tlsConn, bufio.NewReader(tlsConn)
			case strings.HasPrefix(cmd, "EHLO"):
				fmt.Fprint(c, "250-mail.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
			case strings.HasPrefix(cmd, "AUTH"):
				select {
				case sawAuth <- strings.TrimSpace(line):
				default:
				}
				fmt.Fprint(c, "235 Authentication successful\r\n")
			default:
				fmt.Fprint(c, "250 OK\r\n")
			}
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func testRootCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	cert, key := makeCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Security Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil, nil)
	return cert, key
}

func testServerCert(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, ip string) *tls.Certificate {
	t.Helper()
	leaf, leafKey := makeCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: ip},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP(ip)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root, rootKey)
	return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey, Leaf: leaf}
}

// testProxyCA builds an RSA signing CA of the shape genCert expects (it signs
// with SHA256WithRSA, so the CA key has to be RSA).
func testProxyCA(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AquaProxy Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
