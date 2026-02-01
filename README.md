Based on code from https://github.com/kr/mitm.

To build:
1. Install [Go 1.19 (amd64)](https://go.dev/dl/go1.19.13.darwin-amd64.pkg), which requires macOS High Sierra 10.13 or higher.

  1.1 Additional Go versions can be found under "Archived versions" on the Go [releases page](https://go.dev/dl/).

  1.2 Although this could technically be built with an earlier version of Go, the advantage of using this version (at a minimum) is that it uses Apple's native system framework for certificate validation, which improves performance, and means the proxy respects the certificate trust settings in Keychain Access.

2. In `/usr/local/go/src/crypto/x509/root_darwin.go`, change:
```
-	policies := macOS.CFArrayCreateMutable()
-	defer macOS.ReleaseCFArray(policies)
 	sslPolicy := macOS.SecPolicyCreateSSL(opts.DNSName)
-	macOS.CFArrayAppendValue(policies, sslPolicy)
+	defer macOS.CFRelease(sslPolicy)
+	trustObj, err := macOS.SecTrustCreateWithCertificates(certs, sslPolicy)
-	trustObj, err := macOS.SecTrustCreateWithCertificates(certs, policies)
```

3. Build normally with `go build`.
4. Build [MacPorts Legacy Support](https://github.com/macports/macports-legacy-support/blob/master/BUILDING.txt) on Snow Leopard.
5. Build [wowfunhappy-legacy-support](https://github.com/Wowfunhappy/wowfunhappy-legacy-support) (contains fixes from https://trac.macports.org/ticket/66749#comment:2).
6. Place these dylibs in `Package/Aqua\ Proxy/AquaProxy`
7. Run `insert_dylib.sh` to inject the libraries.
