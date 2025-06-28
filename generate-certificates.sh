#!/bin/sh

openssl req -x509 -newkey rsa:4096 -subj '/CN=AquaProxy' -nodes -days 999999 -keyout AquaProxy-key.pem -out AquaProxy-cert.pem
sudo security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain AquaProxy-cert.pem