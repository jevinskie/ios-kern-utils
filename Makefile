CFLAGS = -Wall -Wextra -Ilib/kernel -Ilib/binary lib/kernel/*.c lib/binary/*.c lib/binary/*/*.c
ifndef IGCC
IGCC = xcrun -sdk iphoneos gcc
endif
ifndef IGCC_FLAGS
IGCC_FLAGS = -F/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks -I/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include -L/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib -L/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib/system
endif
ifndef IGCC_TARGET
IGCC_TARGET = -arch arm64 -arch armv7
endif
ifndef SIGN
SIGN = codesign
endif

all: kdump kmap kmem kpatch

kdump: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kdump $(CFLAGS) tools/kdump.c
	$(SIGN) -s - --entitlements misc/ent.xml build/kdump

kmap: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kmap $(CFLAGS) tools/kmap.c
	$(SIGN) -s - --entitlements misc/ent.xml build/kmap

kmem: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kmem $(CFLAGS) tools/kmem.c
	$(SIGN) -s - --entitlements misc/ent.xml build/kmem

kpatch: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kpatch $(CFLAGS) tools/kpatch.c
	$(SIGN) -s - --entitlements misc/ent.xml build/kpatch

build:
	mkdir build

clean:
	rm -rf build
