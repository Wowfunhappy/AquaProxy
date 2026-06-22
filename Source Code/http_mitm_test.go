package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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

func TestUpstreamTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantTLS  bool
		wantSNI  string
	}{
		{"https://example.com", "example.com:443", true, "example.com"},
		{"https://example.com:443", "example.com:443", true, "example.com"},
		{"https://example.com:8443", "example.com:8443", true, "example.com"},
		{"http://example.com", "example.com:80", false, "example.com"},
		{"http://example.com:8080", "example.com:8080", false, "example.com"},
	}
	for _, c := range cases {
		u, err := url.Parse(c.in)
		if err != nil {
			t.Fatalf("parse %q: %v", c.in, err)
		}
		addr, isTLS, sni := upstreamTarget(u)
		if addr != c.wantAddr || isTLS != c.wantTLS || sni != c.wantSNI {
			t.Errorf("upstreamTarget(%q) = (%q, %v, %q); want (%q, %v, %q)",
				c.in, addr, isTLS, sni, c.wantAddr, c.wantTLS, c.wantSNI)
		}
	}
}

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

// --- integration tests for handleMITMWithLogging -------------------------

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

// startMITM runs handleMITMWithLogging against an accepted TLS connection and
// returns the client end of that TLS connection plus a cleanup function.
func startMITM(t *testing.T, p *Proxy, defaultHost string, checkRedirects bool) (*tls.Conn, func()) {
	t.Helper()
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
		p.handleMITMWithLogging(conn.(*tls.Conn), defaultHost, "test", checkRedirects)
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
