package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Keep proxy log output from cluttering test results.
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

// --- unit tests for the pure helpers -------------------------------------

// two rules for the same host must each be selected by the request path, not by being first
// in the list.
func TestCheckRedirectSelectsRuleByPath(t *testing.T) {
	defer resetRedirects()
	resetRedirects()
	addRedirectRule("https://foo.com/a/", "http://baz.example/")
	addRedirectRule("https://foo.com/b/", "http://qux.example/")

	got, ok := checkRedirectURL(t, "https://foo.com/a/page")
	if !ok || got.Host != "baz.example" || got.Path != "/page" {
		t.Errorf("/a/page resolved to %v (ok=%v); want host baz.example path /page", got, ok)
	}
	got, ok = checkRedirectURL(t, "https://foo.com/b/page")
	if !ok || got.Host != "qux.example" || got.Path != "/page" {
		t.Errorf("/b/page resolved to %v (ok=%v); want host qux.example path /page", got, ok)
	}
}

// --- integration tests for handleMITMWithProxy ---------------------------

// TestMITMRoutesEachRequestToCorrectRedirectTarget proves the handler resolves
// the redirect target per request rather than committing to one target for the
// whole connection.
func TestMITMRoutesEachRequestToCorrectRedirectTarget(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	a := httptest.NewServer(bodyHandler("A"))
	defer a.Close()
	b := httptest.NewServer(bodyHandler("B"))
	defer b.Close()

	addRedirectRule("https://foo.com/a/", a.URL+"/")
	addRedirectRule("https://foo.com/b/", b.URL+"/")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	if _, body := sendGet(t, client, br, "/a/", "foo.com"); body != "A" {
		t.Errorf("first request served by %q; want A", body)
	}
	if _, body := sendGet(t, client, br, "/b/", "foo.com"); body != "B" {
		t.Errorf("second request served by %q; want B", body)
	}
}

// TestMITMReusesUpstreamConnection proves repeated requests to the same target
// reuse a single upstream connection instead of redialing each time (the wart
// krackers flagged).
func TestMITMReusesUpstreamConnection(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	var conns int64
	ts := httptest.NewUnstartedServer(bodyHandler("ok"))
	ts.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&conns, 1)
		}
	}
	ts.Start()
	defer ts.Close()

	addRedirectRule("https://foo.com/", ts.URL+"/")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	for _, path := range []string{"/x", "/y", "/z"} {
		resp, body := sendGet(t, client, br, path, "foo.com")
		if resp.StatusCode != 200 || body != "ok" {
			t.Fatalf("request %s: got %d %q", path, resp.StatusCode, body)
		}
	}

	if got := atomic.LoadInt64(&conns); got != 1 {
		t.Errorf("upstream opened %d connections for 3 requests; want 1 (reuse)", got)
	}
}

// TestMITMDeadOriginalHost covers the scenario PR #16 set out to fix: a request
// whose redirect points at a live host succeeds even though the original host
// is down, while a non-redirected request to the dead host returns 502 (rather
// than being silently sent to a guessed redirect target).
func TestMITMDeadOriginalHost(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	live := httptest.NewServer(bodyHandler("LIVE"))
	defer live.Close()

	dead := deadAddr(t)
	addRedirectRule("https://"+dead+"/live/", live.URL+"/")

	client, cleanup := startMITM(t, &Proxy{}, dead, true)
	defer cleanup()
	br := bufio.NewReader(client)

	t.Run("redirected path served despite dead origin", func(t *testing.T) {
		resp, body := sendGet(t, client, br, "/live/", dead)
		if resp.StatusCode != 200 || body != "LIVE" {
			t.Fatalf("got %d %q; want 200 LIVE", resp.StatusCode, body)
		}
	})

	t.Run("non-redirected path to dead host returns 502", func(t *testing.T) {
		resp, _ := sendGet(t, client, br, "/missing", dead)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("got %d; want 502", resp.StatusCode)
		}
	})
}

// TestMITMRetriesStaleUpstreamConnection proves a reused connection that the
// server has since closed is transparently re-dialed for an idempotent request.
func TestMITMRetriesStaleUpstreamConnection(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	addr, count, stop := oneShotUpstream(t, "ok")
	defer stop()
	addRedirectRule("https://foo.com/", "http://"+addr+"/")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	// First request opens connection #1; the server replies then closes it.
	if resp, body := sendGet(t, client, br, "/one", "foo.com"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("first request: got %d %q", resp.StatusCode, body)
	}
	// Second request finds the cached connection dead and must redial.
	if resp, body := sendGet(t, client, br, "/two", "foo.com"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("second request: got %d %q (stale-connection retry failed)", resp.StatusCode, body)
	}

	if got := atomic.LoadInt64(count); got != 2 {
		t.Errorf("upstream accepted %d connections; want 2 (one redial after the stale one)", got)
	}
}

// --- test helpers --------------------------------------------------------

func addRedirectRule(from, to string) {
	f, _ := url.Parse(from)
	tt, _ := url.Parse(to)
	redirectMutex.Lock()
	redirectRules[f.Host] = append(redirectRules[f.Host], redirectRule{fromURL: f, toURL: tt})
	redirectDomains[f.Host] = true
	redirectMutex.Unlock()
}

func resetRedirects() {
	redirectMutex.Lock()
	redirectRules = make(map[string][]redirectRule)
	redirectDomains = make(map[string]bool)
	redirectMutex.Unlock()
}

func checkRedirectURL(t *testing.T, raw string) (*url.URL, bool) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return checkRedirect(u)
}

func bodyHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body))
	}
}

// startMITM runs handleMITMWithProxy against an accepted TLS connection and
// returns the client end of that TLS connection plus a cleanup function.
func startMITM(t *testing.T, p *Proxy, defaultHost string, checkRedirects bool) (*tls.Conn, func()) {
	t.Helper()
	// In production the constructor sets this; tests build a bare Proxy, so give
	// it the shared upstream transport handleMITMWithProxy relies on.
	if p.upstreamTransport == nil {
		p.upstreamTransport = p.newUpstreamTransport()
	}
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.handleMITMWithProxy(conn, defaultHost, "test", checkRedirects)
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	return client, func() { client.Close(); ln.Close() }
}

// sendGet writes one HTTP/1.1 GET over conn and reads the response, returning
// the response and its body as a string.
func sendGet(t *testing.T, conn net.Conn, br *bufio.Reader, target, host string) (*http.Response, string) {
	t.Helper()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// deadAddr returns a loopback address with nothing listening on it.
func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// oneShotUpstream accepts connections, serves exactly one request per
// connection, then closes it — forcing the proxy to redial on every reuse.
func oneShotUpstream(t *testing.T, body string) (addr string, count *int64, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var n int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&n, 1)
			go func(c net.Conn) {
				http.ReadRequest(bufio.NewReader(c))
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String(), &n, func() { ln.Close() }
}

// wsEchoUpstream accepts one connection, reads the HTTP upgrade request,
// replies with 101 Switching Protocols, then echoes everything that follows —
// simulating a WebSocket server after the handshake.
func wsEchoUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			conn.Close()
			return
		}
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		io.Copy(conn, br) // echo post-handshake bytes back to the client
		conn.Close()
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// TestMITMTunnelsWebSocketUpgrade proves a 101 Switching Protocols response
// flips the connection into a raw bidirectional tunnel instead of the proxy
// trying to parse the next bytes as HTTP. Like a real WebSocket client, the
// test waits for the 101 before sending a frame, then expects it echoed back.
func TestMITMTunnelsWebSocketUpgrade(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	addr, stop := wsEchoUpstream(t)
	defer stop()
	addRedirectRule("https://foo.com/ws", "http://"+addr+"/ws")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	upgrade := "GET /ws HTTP/1.1\r\nHost: foo.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	if _, err := client.Write([]byte(upgrade)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("got status %d; want 101 Switching Protocols", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header = %q; want websocket", got)
	}

	// The connection is now a raw tunnel: send a frame and expect it echoed.
	payload := "hello-ws"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read tunneled bytes: %v", err)
	}
	if string(echoed) != payload {
		t.Errorf("tunneled bytes = %q; want %q (bidirectional tunnel failed)", echoed, payload)
	}
}

// TestMITMHandlesExpect100Continue proves a client withholding its body behind
// Expect: 100-continue gets a 100 from the proxy, then its body is forwarded
// and the final response relayed — without deadlocking.
func TestMITMHandlesExpect100Continue(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		io.WriteString(w, "got:"+string(body))
	}))
	defer ts.Close()
	addRedirectRule("https://foo.com/submit", ts.URL+"/submit")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	// Send headers only, then wait for the proxy's 100 before sending the body.
	headers := "POST /submit HTTP/1.1\r\nHost: foo.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
	if _, err := client.Write([]byte(headers)); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	interim, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read interim response: %v", err)
	}
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("got status %d; want 100 Continue", interim.StatusCode)
	}
	interim.Body.Close()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write body: %v", err)
	}

	final, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read final response: %v", err)
	}
	body, _ := ioutil.ReadAll(final.Body)
	final.Body.Close()
	if final.StatusCode != 200 || string(body) != "got:hello" {
		t.Fatalf("got %d %q; want 200 got:hello", final.StatusCode, body)
	}
}

// TestMITMOmitsXForwardedFor proves the proxy stays transparent and does not
// add an X-Forwarded-For header to forwarded requests.
func TestMITMOmitsXForwardedFor(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	gotXFF := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF <- r.Header.Get("X-Forwarded-For")
		io.WriteString(w, "ok")
	}))
	defer ts.Close()
	addRedirectRule("https://foo.com/", ts.URL+"/")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	if resp, body := sendGet(t, client, br, "/thing", "foo.com"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("got %d %q; want 200 ok", resp.StatusCode, body)
	}
	if xff := <-gotXFF; xff != "" {
		t.Errorf("upstream saw X-Forwarded-For %q; want it absent", xff)
	}
}

// TestMITMBoundsUpstreamPool proves the shared upstream pool reuses connections
// across many separate client connections and stays bounded, rather than
// opening (and leaking) a new upstream connection per client connection.
func TestMITMBoundsUpstreamPool(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	var open int64
	ts := httptest.NewUnstartedServer(bodyHandler("ok"))
	ts.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			atomic.AddInt64(&open, 1)
		case http.StateClosed:
			atomic.AddInt64(&open, -1)
		}
	}
	ts.Start()
	defer ts.Close()
	addRedirectRule("https://foo.com/", ts.URL+"/")

	// One Proxy → one shared upstream pool reused across all client connections.
	p := &Proxy{}

	for i := 0; i < 25; i++ {
		client, cleanup := startMITM(t, p, "foo.com:443", true)
		br := bufio.NewReader(client)
		if resp, body := sendGet(t, client, br, "/x", "foo.com"); resp.StatusCode != 200 || body != "ok" {
			t.Fatalf("cycle %d: got %d %q; want 200 ok", i, resp.StatusCode, body)
		}
		cleanup()
	}

	if n := atomic.LoadInt64(&open); n > 4 {
		t.Errorf("upstream pool holds %d connections after 25 client connections; want bounded reuse (≤4)", n)
	}
}

// TestMITMClosesIdleClientConnection proves an idle keep-alive connection is
// closed by the proxy after the idle timeout, so connections a client opens and
// then abandons (without closing) don't accumulate and exhaust file descriptors.
func TestMITMClosesIdleClientConnection(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	old := mitmIdleTimeout
	mitmIdleTimeout = 150 * time.Millisecond
	defer func() { mitmIdleTimeout = old }()

	ts := httptest.NewServer(bodyHandler("ok"))
	defer ts.Close()
	addRedirectRule("https://foo.com/", ts.URL+"/")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	// One request to establish a keep-alive connection.
	if resp, body := sendGet(t, client, br, "/x", "foo.com"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("got %d %q; want 200 ok", resp.StatusCode, body)
	}

	// Leave the connection idle; the proxy should close it after the timeout, so
	// a read returns EOF rather than blocking until our own deadline.
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := br.ReadByte()
	if err == nil {
		t.Fatal("expected idle connection to be closed by the proxy")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle connection still open 2s after a 150ms idle timeout")
	}
}

// TestPlainHTTPReusesUpstreamConnection proves the non-MITM (plain HTTP) path
// reuses a pooled upstream connection across requests instead of opening — and
// leaking — a new one per request. This is the path OCSP checks flow through;
// the per-request transport it used to create leaked a connection each time.
func TestPlainHTTPReusesUpstreamConnection(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	var conns int64
	ts := httptest.NewUnstartedServer(bodyHandler("ok"))
	ts.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&conns, 1)
		}
	}
	ts.Start()
	defer ts.Close()

	p := &Proxy{Wrap: func(h http.Handler) http.Handler { return h }}
	p.upstreamTransport = p.newUpstreamTransport()

	for i := 0; i < 12; i++ {
		req := httptest.NewRequest("GET", ts.URL+"/x", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.String() != "ok" {
			t.Fatalf("request %d: got %d %q; want 200 ok", i, rec.Code, rec.Body.String())
		}
	}

	if got := atomic.LoadInt64(&conns); got > 2 {
		t.Errorf("plain HTTP opened %d upstream connections for 12 requests; want pooled reuse (≤2)", got)
	}
}

// interimContinueUpstream accepts one connection, reads the request, then sends
// an interim 100 Continue immediately followed by a final 200, then closes —
// simulating an upstream that emits an interim response of its own.
func interimContinueUpstream(t *testing.T, body string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		http.ReadRequest(bufio.NewReader(conn))
		io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n")
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		conn.Close()
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// TestMITMSkipsInterimContinueFromUpstream proves an interim 100 Continue sent
// by the upstream is skipped, so the client sees only the final response.
func TestMITMSkipsInterimContinueFromUpstream(t *testing.T) {
	defer resetRedirects()
	resetRedirects()

	addr, stop := interimContinueUpstream(t, "ok")
	defer stop()
	addRedirectRule("https://foo.com/", "http://"+addr+"/")

	client, cleanup := startMITM(t, &Proxy{}, "foo.com:443", true)
	defer cleanup()
	br := bufio.NewReader(client)

	resp, body := sendGet(t, client, br, "/thing", "foo.com")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("got %d %q; want 200 ok (interim 100 not skipped)", resp.StatusCode, body)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"foo.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// makeCert creates a certificate from tmpl signed by parent/parentKey. Passing a
// nil parentKey makes a self-signed certificate (a root).
func makeCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, signee := parentKey, parent
	if signer == nil { // self-signed
		signer, signee = key, tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signee, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

func resetAIACache() {
	aiaCacheMutex.Lock()
	aiaCertCache = make(map[string][]*x509.Certificate)
	aiaCacheMutex.Unlock()
}

// TestDialUpstreamChasesAIA proves the proxy completes an incomplete certificate
// chain by fetching the missing intermediate via the leaf's AIA URL — and still
// rejects a certificate presented for the wrong hostname.
func TestDialUpstreamChasesAIA(t *testing.T) {
	caCert, caKey := makeCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, nil, nil)

	interCert, interKey := makeCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, caCert, caKey)

	// Serve the intermediate at an AIA URL as a PKCS#7 (.p7c) bundle — the format
	// real CAs such as Sectigo use, which is what broke chain completion.
	p7c := makePKCS7CertsOnly(t, interCert)
	aiaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(p7c)
	}))
	defer aiaSrv.Close()

	leafCert, leafKey := makeCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{aiaSrv.URL},
	}, interCert, interKey)

	// TLS server presenting ONLY the leaf — an incomplete chain (no intermediate).
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafCert.Raw}, PrivateKey: leafKey}},
	}
	ts.StartTLS()
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	addr := u.Host

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	p := &Proxy{TLSClientConfig: &tls.Config{RootCAs: roots}}

	// Correct hostname: the chain is incomplete, so success proves the proxy
	// fetched the missing intermediate via AIA.
	resetAIACache()
	conn, err := p.dialUpstream(addr, true, "example.test", "test")
	if err != nil {
		t.Fatalf("dialUpstream should complete the chain via AIA chasing, got: %v", err)
	}
	conn.Close()

	// Wrong hostname: must still be rejected — InsecureSkipVerify disabled Go's
	// hostname check, so our verifier has to enforce it.
	resetAIACache()
	if conn, err := p.dialUpstream(addr, true, "wrong.test", "test"); err == nil {
		conn.Close()
		t.Errorf("dialUpstream accepted a certificate for the wrong hostname")
	}
}

// makePKCS7CertsOnly builds a minimal PKCS#7 "certs-only" SignedData bundle
// wrapping the given certificates — the format CAs serve at .p7c AIA URLs.
func makePKCS7CertsOnly(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var certBytes []byte
	for _, c := range certs {
		certBytes = append(certBytes, c.Raw...)
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
	}
	type signedData struct {
		Version          int
		DigestAlgorithms []asn1.RawValue `asn1:"set"`
		ContentInfo      contentInfo
		Certificates     asn1.RawValue
		SignerInfos      []asn1.RawValue `asn1:"set"`
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{},
		ContentInfo:      contentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}, // data
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certBytes},
		SignerInfos:      []asn1.RawValue{},
	}
	type outer struct {
		ContentType asn1.ObjectIdentifier
		Content     signedData `asn1:"explicit,tag:0"`
	}
	der, err := asn1.Marshal(outer{ContentType: oidPKCS7SignedData, Content: sd})
	if err != nil {
		t.Fatalf("marshal PKCS#7: %v", err)
	}
	return der
}

// TestParseAIACerts checks that AIA responses are parsed whether they are a
// single DER certificate or a PKCS#7 bundle of several certificates.
func TestParseAIACerts(t *testing.T) {
	a, _ := makeCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Cert A"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}, nil, nil)
	b, _ := makeCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Cert B"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}, nil, nil)

	// Single DER certificate.
	if certs, err := parseAIACerts(a.Raw); err != nil || len(certs) != 1 || certs[0].Subject.CommonName != "Cert A" {
		t.Fatalf("DER: got %d certs, err=%v", len(certs), err)
	}

	// PKCS#7 bundle with two certificates.
	certs, err := parseAIACerts(makePKCS7CertsOnly(t, a, b))
	if err != nil {
		t.Fatalf("PKCS#7: %v", err)
	}
	got := map[string]bool{}
	for _, c := range certs {
		got[c.Subject.CommonName] = true
	}
	if !got["Cert A"] || !got["Cert B"] {
		t.Errorf("PKCS#7 bundle parsed to %v; want both Cert A and Cert B", got)
	}
}

// TestChaseAIATerminatesOnCycle proves AIA chasing terminates (and still
// completes the chain) when a fetched certificate's AIA points back into the
// chain — a cross-signing cycle. Without the visited-set guard this recurses
// forever; the test's timeout would catch that regression.
func TestChaseAIATerminatesOnCycle(t *testing.T) {
	caCert, caKey := makeCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Cycle Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}, nil, nil)

	// The intermediate's AIA must reference the URL that serves it, so set up the
	// server first and fill in the bytes once the cert exists.
	var xDER []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(xDER)
	}))
	defer srv.Close()

	xCert, xKey := makeCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Cycle Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
		IssuingCertificateURL: []string{srv.URL}, // points at itself
	}, caCert, caKey)
	xDER = xCert.Raw

	leafCert, _ := makeCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{srv.URL},
	}, xCert, xKey)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	resetAIACache()

	if _, err := chaseAIA([]*x509.Certificate{leafCert}, roots, ""); err != nil {
		t.Fatalf("chaseAIA should complete despite the self-referential AIA: %v", err)
	}
}
