#!/bin/bash

# Clean up any old "Aqua Proxy" certificates from previous installations.
sudo security delete-certificate -c "Aqua Proxy" /Library/Keychains/System.keychain >/dev/null 2>&1

cd /Library/AquaProxy
openssl req -x509 -newkey rsa:4096 -subj '/CN=Aqua Proxy' -nodes -days 999999 -keyout AquaProxy-key.pem -out AquaProxy-cert.pem
security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /Library/AquaProxy/AquaProxy-cert.pem

sleep 10 # Make sure certificates are installed. Particularly necessary on Snow Leopard.

for pid_uid in $(ps -axo pid,uid,args | grep -i "[l]oginwindow.app" | awk '{print $1 "," $2}'); do
	pid=$(echo $pid_uid | cut -d, -f1)
	uid=$(echo $pid_uid | cut -d, -f2)
	if (( $(echo "${OSTYPE:6} > 13" | bc -l) ))
	then
		#Running OS X 10.10 or above
		launchctl bootstrap gui/$uid /Library/LaunchAgents/Wowfunhappy.AquaProxy.Proxy.plist
		launchctl bootstrap gui/$uid /Library/LaunchAgents/Wowfunhappy.AquaProxy.SyncProxiesWithShell.plist
		launchctl bootstrap gui/$uid /Library/LaunchAgents/Wowfunhappy.AquaProxy.Restarter.plist
	else
		#Running OS X 10.9 or below
		launchctl bsexec "$pid" chroot -u "$uid" / launchctl load /Library/LaunchAgents/Wowfunhappy.AquaProxy.Proxy.plist
		launchctl bsexec "$pid" chroot -u "$uid" / launchctl load /Library/LaunchAgents/Wowfunhappy.AquaProxy.SyncProxiesWithShell.plist
		launchctl bsexec "$pid" chroot -u "$uid" / launchctl load /Library/LaunchAgents/Wowfunhappy.AquaProxy.Restarter.plist
	fi
done
