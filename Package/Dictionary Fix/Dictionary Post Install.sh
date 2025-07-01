#!/bin/bash

# If we're on Lion or newer, we need to remove the code signature from the Dictionary binary.
# Otherwise, Dictionary will refuse to launch with a modified Info.plist.
if (( $(echo "${OSTYPE:6} > 10" | bc -l) )) # If we're on Lion or newer
then
	if (! test -e /Applications/Dictionary.app/Contents/MacOS/Dictionary_backup)
	then
		mv /Applications/Dictionary.app/Contents/MacOS/Dictionary /Applications/Dictionary.app/Contents/MacOS/Dictionary_backup && \
		./unsign /Applications/Dictionary.app/Contents/MacOS/Dictionary_backup /Applications/Dictionary.app/Contents/MacOS/Dictionary
	fi
fi

# Modify Info.plist to inject ProxyFix at launch.
if ! defaults read /Applications/Dictionary.app/Contents/Info LSEnvironment | grep DYLD_INSERT_LIBRARIES
then
	defaults write /Applications/Dictionary.app/Contents/Info LSEnvironment -dict DYLD_INSERT_LIBRARIES @executable_path/../Frameworks/ProxyFix.dylib
fi
sleep 1
chmod 644 /Applications/Dictionary.app/Contents/Info.plist