In the near future, the Legacy Mac Proxy package will use this Go-based proxy instead of Squid.

Based on code from https://codeload.github.com/kr/mitm.

Build with Go 1.19. Then, use MacPorts Legacy Support and https://trac.macports.org/ticket/66749#comment:2 to make the binary run on Legacy OS X.

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
