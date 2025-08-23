#!/bin/bash

cd /Users/Jonathan/Developer/AquaProxy/Package/Aqua\ Proxy/AquaProxy

insert_dylib --inplace libWowfunhappyLegacySupport.dylib Aqua-HTTP-Proxy
insert_dylib --inplace libMacportsLegacySupport.dylib Aqua-HTTP-Proxy
insert_dylib --inplace libWowfunhappyLegacySupport.dylib Aqua-IMAP-Proxy
insert_dylib --inplace libMacportsLegacySupport.dylib Aqua-IMAP-Proxy