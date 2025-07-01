Based on code from https://codeload.github.com/kr/mitm.

To build:
1. Install Go 1.19 on High Sierra.
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
3. Build normally with `go build legacy_proxy.go`
4. Inject the MacPorts Legacy Support library and https://trac.macports.org/ticket/66749#comment:2 to make the binary run on Legacy OS X.