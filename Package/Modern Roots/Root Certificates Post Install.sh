#!/bin/bash

CERTIFICATES=(
	"./ISRG Root X1.cer"
	"./USERTrust RSA Certification Authority.crt"
	"./DigiCert Global Root G2.cer"
	"./DigiCert Global Root G3.cer"
	"./COMODO ECC Certification Authority.crt"
)

for cert in "${CERTIFICATES[@]}"
do
	security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert"
done

if (( $(echo "${OSTYPE:6} < 11" | bc -l) ))
# Due to how Aqua Proxy loads root certs on Snow Leopard, it must be restarted after installing new certs.
then	
	for pid_uid in $(ps -axo pid,uid,args | grep -i "[l]oginwindow.app" | awk '{print $1 "," $2}'); do
		pid=$(echo $pid_uid | cut -d, -f1)
		uid=$(echo $pid_uid | cut -d, -f2)
		launchctl bsexec "$pid" chroot -u "$uid" / launchctl stop Wowfunhappy.AquaProxy.HTTP || true
		launchctl bsexec "$pid" chroot -u "$uid" / launchctl start Wowfunhappy.AquaProxy.HTTP
	done
fi