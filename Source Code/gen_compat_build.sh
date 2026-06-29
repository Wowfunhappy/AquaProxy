#!/bin/bash

# insert_dylib needs to be in $PATH
# https://github.com/tyilo/insert_dylib

cd "$(dirname "$0")"

mkdir -p ../Package/Aqua\ Proxy/AquaProxy
cd ../Package/Aqua\ Proxy/AquaProxy

insert_dylib --inplace libWowfunhappyLegacySupport.dylib aquaproxy-64
insert_dylib --inplace libMacportsLegacySupport.dylib aquaproxy-64
insert_dylib --inplace libMacportsLegacySupport.dylib aquaproxy-32

lipo -create aquaproxy-64 aquaproxy-32 -output aquaproxy

codesign --force --sign - aquaproxy
