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

-	trustObj, err := macOS.SecTrustCreateWithCertificates(certs, policies)
+	trustObj, err := macOS.SecTrustCreateWithCertificates(certs, sslPolicy)
```

3. Build normally with `go build`.
4. Place the aquaproxy binary in `Package/Aqua\ Proxy/AquaProxy` as `aquaproxy-64`
5. Install Go 1.13. You may need to switch to an older OS at this point; the author uses Mavericks.
6. Use Go 1.13 to build 32-bit AquaProxy with `GOARCH=386 go build`.
7. Place the 32 bit aquaproxy binary in binary in `Package/Aqua\ Proxy/AquaProxy` as `aquaproxy-32`
8. Run `gen_compat_build.sh` to inject needed [compatibility](https://github.com/macports/macports-legacy-support/blob/master/BUILDING.txt) [libraries](https://trac.macports.org/ticket/66749#comment:2) and lipo the slices together. Afterwards, delete the individual `aquaproxy-64` and `aquaproxy-32`

Note: If you choose to rebuild libMacPortsLegacySupport, make sure to run the build on Snow Leopard and use `make ARCHS="i386 x86_64"` so the binary will be compatible with all supported systems.