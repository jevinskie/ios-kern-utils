ALL = kdump khead kmap kmem kpatch
DST = build
PKG = ios-kern-utils.tar.xz
CFLAGS = -O3 -Wall -Ilib lib/*.c

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
ifndef IGCC_ARCH
	IGCC_ARCH = -arch armv7 -arch arm64
endif
ifndef STRIP
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			STRIP = xcrun -sdk iphoneos strip
		else
			STRIP = $(shell which strip 2>/dev/null)
		endif
	else
		STRIP := $(shell which ios-strip 2>/dev/null)
	endif
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
		SIGN_FLAGS = -s - --entitlements misc/ent.plist
	else
		ifeq ($(SIGN),ldid)
			SIGN_FLAGS = -Smisc/ent.plist
		endif
	endif
endif

.PHONY: all clean package

all: $(addprefix $(DST)/, $(ALL))

$(DST)/%: $(filter-out $(wildcard $(DST)), $(DST))
	$(IGCC) $(IGCC_FLAGS) $(IGCC_ARCH) -o $@ $(CFLAGS) tools/$(@F).c
ifdef STRIP
	$(STRIP) $@
endif
	$(SIGN) $(SIGN_FLAGS) $@

$(DST):
	mkdir $(DST)

package: $(PKG)

$(PKG): $(addprefix $(DST)/, $(ALL))
	tar -cJf $(PKG) -C $(DST) $(ALL)

clean:
	rm -rf $(DST) $(PKG)
