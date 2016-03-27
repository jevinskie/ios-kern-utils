ALL = kdump khead kmap kmem kpatch
CFLAGS = -Wall -Wno-unused-local-typedef -Ilib/kernel -Ilib/binary lib/kernel/*.c lib/binary/*.c lib/binary/*/*.c

ifndef IGCC
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			IGCC = xcrun -sdk iphoneos gcc
		else
			IGCC = clang
		endif
		CFLAGS += -Wl,-dead_strip
	else
		IGCC = ios-clang
		CFLAGS += -Wl,--gc-sections
	endif
endif
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

khead: build
	$(IGCC) $(IGCC_FLAGS) $(IGCC_TARGET) -o build/khead $(CFLAGS) tools/khead.c
	$(SIGN) $(SIGN_FLAGS) build/khead

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
