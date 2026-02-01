package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var (
	hostname, _ = os.Hostname()

	keyFile  = "AquaProxy-key.pem"
	certFile = "AquaProxy-cert.pem"

	// Generated certs are only used between the OS and the proxy. Prioritize speed.
	RSAKeyLength = 1024

	// Cache for certificates fetched via AIA
	aiaCertCache  = make(map[string]*x509.Certificate)
	aiaCacheMutex sync.RWMutex

	// Cache for generated leaf certificates
	leafCertCache = make(map[string]*tls.Certificate)
	leafCertMutex sync.RWMutex

	// Pre-generated RSA keys for fast certificate generation
	keyPool = make(chan *rsa.PrivateKey, 20)

	allowRemoteConnections = flag.Bool("allow-remote-connections", false, "Allow connections from non-localhost addresses")

	// Command line flags for HTTP proxy
	logURLs    = flag.Bool("log-urls", false, "Print every URL accessed in MITM mode (ignored by IMAP proxy)")
	forceMITM  = flag.Bool("force-mitm", false, "Force MITM mode for all connections (ignored by IMAP proxy)")
	cpuProfile = flag.Bool("cpu-profile", false, "Enable CPU profiling to legacy_proxy_cpu.prof (ignored by IMAP proxy)")

	// Command line flags for IMAP proxy
	imapPort    = flag.Int("imap-port", 6532, "IMAP proxy port")
	smtpPort    = flag.Int("smtp-port", 6533, "SMTP proxy port")
	debug       = flag.Bool("debug", false, "Enable debug logging (ignored by HTTP proxy)")
	disableIMAP = flag.Bool("no-imap", false, "Disable IMAP proxy")
	disableSMTP = flag.Bool("no-smtp", false, "Disable SMTP proxy")

	// URL redirect configuration
	redirectRules   = make(map[string][]redirectRule)
	redirectDomains = make(map[string]bool)
	redirectMutex   sync.RWMutex

	// MITM exclusion configuration
	excludedDomains = make(map[string]bool)
	excludedMutex   sync.RWMutex
)

func main() {
	IMAPMain()
	HTTPMain()
}

func isSnowLeopard() bool {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	version := strings.TrimSpace(string(output))
	// Snow Leopard is 10.6.x
	return strings.HasPrefix(version, "10.6.")
}

func loadSystemCertPool() (*x509.CertPool, error) {
	// Try the standard method first (unless we're on Snow Leopard)
	if !isSnowLeopard() {
		systemRoots, err := x509.SystemCertPool()
		if err == nil && systemRoots != nil {
			return systemRoots, nil
		}
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
