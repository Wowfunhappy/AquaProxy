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

Todo:
- Test on 10.6–10.8.
- Bundle into .pkg installer.
	- Create and import cert with:
		- `openssl req -x509 -newkey rsa:4096 -subj '/CN=Legacy Mac Proxy' -nodes -days 999999 -keyout legacy-mac-proxy-key.pem -out legacy-mac-proxy-cert.pem`
   		- `sudo security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain legacy-mac-proxy-cert.pem`
	- Because we use the system trust store, installer must ship common modern CAs:
 		- ISRG Root X1
		- GlobalSign Root R6
  		- Others?
