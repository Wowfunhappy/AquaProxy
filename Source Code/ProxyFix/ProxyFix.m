#include <stdio.h>
#include <objc/runtime.h>
#include <Foundation/Foundation.h>
#include <dlfcn.h>
#include <AppKit/AppKit.h>

#define DYLD_INTERPOSE(_replacement,_replacee) \
	__attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
				__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

CFReadStreamRef myCFReadStreamCreateForHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef request) {
	CFReadStreamRef ref = CFReadStreamCreateForHTTPRequest(alloc, request);
	CFDictionaryRef systemProxyDict = CFNetworkCopySystemProxySettings();
	CFReadStreamSetProperty(ref, kCFStreamPropertyHTTPProxy, systemProxyDict);
	return ref;
}

DYLD_INTERPOSE(myCFReadStreamCreateForHTTPRequest, CFReadStreamCreateForHTTPRequest);

__attribute__((constructor))
static void initialization() {
	unsetenv("DYLD_INSERT_LIBRARIES");
}

int main() {}