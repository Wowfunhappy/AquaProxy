#!/bin/bash

cd ~/Desktop
insert_dylib --inplace libWowfunhappyLegacySupport.dylib Aqua-HTTP-Proxy
insert_dylib --inplace libMacportsLegacySupport.dylib Aqua-HTTP-Proxy
insert_dylib --inplace libWowfunhappyLegacySupport.dylib Aqua-IMAP-Proxy
insert_dylib --inplace libMacportsLegacySupport.dylib Aqua-IMAP-Proxyy