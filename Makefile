ALL = kdump kmap kmem kpatch
CFLAGS = -Wall -Wno-unused-local-typedef -Ilib/kernel -Ilib/binary lib/kernel/*.c lib/binary/*.c lib/binary/*/*.c

ifndef IGCC
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			IGCC = xcrun -sdk iphoneos gcc
		else
			IGCC = clang
		endif
	else
		IGCC = ios-clang
	endif
endif
ifndef IGCC_SDKROOT
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			IGCC_SDKROOT = /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk
		else
			IGCC_SDKROOT = /var/sdk/sdk
		endif
	else
		IGCC_SDKROOT = /opt/ios-toolchain/share/iPhoneOS.sdk
	endif
endif
IGCC_FLAGS += -F$(IGCC_SDKROOT)/System/Library/Frameworks -I$(IGCC_SDKROOT)/usr/include -L$(IGCC_SDKROOT)/usr/lib -L$(IGCC_SDKROOT)/usr/lib/system
ifndef IGCC_TARGET
	IGCC_TARGET = -arch armv7 -arch arm64
endif
ifndef SIGN
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			SIGN = codesign
		else
			SIGN = ldid
		endif
	else
		SIGN = ldid
	endif
endif
ifndef SIGN_FLAGS
	ifeq ($(SIGN),codesign)
		SIGN_FLAGS = -s - --entitlements misc/ent.xml
	else
		ifeq ($(SIGN),ldid)
			SIGN_FLAGS = -Smisc/ent.xml
		endif
	endif
endif

all: $(ALL)

kdump: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kdump $(CFLAGS) tools/kdump.c
	$(SIGN) $(SIGN_FLAGS) build/kdump

kmap: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kmap $(CFLAGS) tools/kmap.c
	$(SIGN) $(SIGN_FLAGS) build/kmap

kmem: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kmem $(CFLAGS) tools/kmem.c
	$(SIGN) $(SIGN_FLAGS) build/kmem

kpatch: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/kpatch $(CFLAGS) tools/kpatch.c
	$(SIGN) $(SIGN_FLAGS) build/kpatch

build:
	mkdir build

clean:
	rm -rf build

package: all
	tar -cJf build/ios-kern-utils.tar.xz -C build $(ALL)
