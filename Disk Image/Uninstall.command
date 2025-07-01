#!/bin/bash

echo
echo "This script will completely remove Aqua Proxy from your computer."
echo "Please type in your administrator password and press return to continue."
sudo true || exit

# Clean Up Legacy Squid
sudo security remove-trusted-cert -d /Library/Squid/Certificates/squid.pem >/dev/null 2>&1
sudo security delete-certificate -c squid >/dev/null 2>&1
launchctl unload /Library/LaunchAgents/com.wowfunhappy.squid.plist >/dev/null 2>&1
sudo rm /Library/LaunchAgents/com.wowfunhappy.squid.plist >/dev/null 2>&1
launchctl unload /Library/LaunchAgents/com.wowfunhappy.squid-shutdown.plist >/dev/null 2>&1
sudo rm /Library/LaunchAgents/com.wowfunhappy.squid-shutdown.plist >/dev/null 2>&1
launchctl unload /Library/LaunchAgents/com.wowfunhappy.squid-chmod.plist >/dev/null 2>&1
sudo rm /Library/LaunchAgents/com.wowfunhappy.squid-chmod.plist >/dev/null 2>&1
sudo rm -r /Library/Squid/ >/dev/null 2>&1
sudo sed -i -e '/setenv HTTPS_PROXY \(https\{0,1\}:\/\/\)\{0,1\}localhost:3128/d' /etc/launchd.conf >/dev/null 2>&1
sudo sed -i -e '/setenv SSL_CERT_FILE \/Library\/Squid\/Certificates\/squid.pem/d' /etc/launchd.conf >/dev/null 2>&1
sudo sed -i -e '/setenv REQUESTS_CA_BUNDLE \/Library\/Squid\/Certificates\/squid.pem/d' /etc/launchd.conf >/dev/null 2>&1
sudo pkgutil --forget com.wowfunhappy.https-proxy.squid >/dev/null 2>&1
sudo pkgutil --forget com.wowfunhappy.https-proxy.squid-10.6 >/dev/null 2>&1
sudo pkgutil --forget com.wowfunhappy.https-proxy.squid-10.7 >/dev/null 2>&1
sudo pkgutil --forget com.wowfunhappy.https-proxy.dictionary-fixer >/dev/null 2>&1




# Unload LaunchAgents
launchctl unload /Library/LaunchAgents/Wowfunhappy.AquaProxy.HTTP.plist >/dev/null 2>&1
launchctl unload /Library/LaunchAgents/Wowfunhappy.AquaProxy.IMAP.plist >/dev/null 2>&1
launchctl unload /Library/LaunchAgents/Wowfunhappy.AquaProxy.SyncProxiesWithShell.plist >/dev/null 2>&1

# Remove LaunchAgents
sudo rm -f /Library/LaunchAgents/Wowfunhappy.AquaProxy.HTTP.plist
sudo rm -f /Library/LaunchAgents/Wowfunhappy.AquaProxy.IMAP.plist
sudo rm -f /Library/LaunchAgents/Wowfunhappy.AquaProxy.SyncProxiesWithShell.plist

# Remove AquaProxy directory
sudo rm -rf /Library/AquaProxy

# Remove Aqua Proxy certificate
sudo security delete-certificate -c "Aqua Proxy" /Library/Keychains/System.keychain >/dev/null 2>&1

# Remove the Dictionary patch
if [ -f /Applications/Dictionary.app/Contents/Frameworks/ProxyFix.dylib ]
then
	sudo defaults delete /Applications/Dictionary.app/Contents/Info LSEnvironment >/dev/null 2>&1
	sudo plutil -convert xml1 /Applications/Dictionary.app/Contents/Info.plist
	sudo chmod 644 /Applications/Dictionary.app/Contents/Info.plist
	
	sudo rm -f /Applications/Dictionary.app/Contents/Frameworks/ProxyFix.dylib
	if [ -d /Applications/Dictionary.app/Contents/Frameworks ] && [ -z "$(ls -A /Applications/Dictionary.app/Contents/Frameworks)" ]
	then
		sudo rmdir /Applications/Dictionary.app/Contents/Frameworks
	fi

	if [ -f /Applications/Dictionary.app/Contents/MacOS/Dictionary_backup ]
	then
		sudo mv /Applications/Dictionary.app/Contents/MacOS/Dictionary_backup /Applications/Dictionary.app/Contents/MacOS/Dictionary
	fi
fi

echo
echo "Aqua Proxy has been removed from your computer."

found_all_certs=true
security find-certificate -c "ISRG Root X1" /Library/Keychains/System.keychain >/dev/null 2>&1 || found_all_certs=false
security find-certificate -c "USERTrust RSA Certification Authority" /Library/Keychains/System.keychain >/dev/null 2>&1 || found_all_certs=false
security find-certificate -c "DigiCert Global Root G2" /Library/Keychains/System.keychain >/dev/null 2>&1 || found_all_certs=false
security find-certificate -c "DigiCert Global Root G3" /Library/Keychains/System.keychain >/dev/null 2>&1 || found_all_certs=false
security find-certificate -c "COMODO ECC Certification Authority" /Library/Keychains/System.keychain >/dev/null 2>&1 || found_all_certs=false
if [ "$found_all_certs" = true ]
then
	echo
	echo "Aqua Proxy also installs a set of contemporary root certificates:"
	echo "	• ISRG Root X1"
	echo "	• USERTrust RSA Certification Authority"
	echo "	• DigiCert Global Root G2"
	echo "	• DigiCert Global Root G3"
	echo "	• COMODO ECC Certification Authority"
	echo "Would you like to remove these certificates? "
	read -p "They may be used by other applications. (y/n) " -n 1 -r

	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		sudo security delete-certificate -c "ISRG Root X1" /Library/Keychains/System.keychain >/dev/null 2>&1
		sudo security delete-certificate -c "USERTrust RSA Certification Authority" /Library/Keychains/System.keychain >/dev/null 2>&1
		sudo security delete-certificate -c "DigiCert Global Root G2" /Library/Keychains/System.keychain >/dev/null 2>&1
		sudo security delete-certificate -c "DigiCert Global Root G3" /Library/Keychains/System.keychain >/dev/null 2>&1
		sudo security delete-certificate -c "COMODO ECC Certification Authority" /Library/Keychains/System.keychain >/dev/null 2>&1
		echo
		echo "Root certificates removed."
	else
		echo "Root certificates were not removed."
	fi
fi

echo
echo "Uninstall complete."
echo "Make sure to remove your proxy settings from System Preferences."
echo