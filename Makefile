VERSION = 1.2.0
ALL = $(patsubst src/tools/%.c,%,$(wildcard src/tools/*.c))
DST = build
PKG = pkg
XZ = ios-kern-utils.tar.xz
DEB = net.siguza.ios-kern-utils_$(VERSION)_iphoneos-arm.deb
CFLAGS = -O3 -Wall -Isrc/lib src/lib/*.c -miphoneos-version-min=6.0

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

.PHONY: all clean dist xz deb

all: $(addprefix $(DST)/, $(ALL))

$(DST)/%: $(filter-out $(wildcard $(DST)), $(DST)) $(wildcard src/lib/**) src/tools/%.c
	$(IGCC) $(IGCC_FLAGS) $(IGCC_ARCH) -o $@ $(CFLAGS) src/tools/$(@F).c
ifdef STRIP
	$(STRIP) $@
endif
	$(SIGN) $(SIGN_FLAGS) $@

$(DST):
	mkdir -p $(DST)

dist: xz deb

xz: $(XZ)

deb: $(DEB)

$(XZ): $(addprefix $(DST)/, $(ALL))
	tar -cJf $(XZ) -C $(DST) $(ALL)

$(DEB): $(PKG)/control.tar.gz $(PKG)/data.tar.lzma $(PKG)/debian-binary
	( cd "$(PKG)"; ar -cr "../$(DEB)" 'debian-binary' 'control.tar.gz' 'data.tar.lzma'; )

$(PKG)/control.tar.gz: $(PKG) $(PKG)/control
	tar -czf '$(PKG)/control.tar.gz' --exclude '.DS_Store' --exclude '._*' --include '$(PKG)' --include '$(PKG)/control' -s '%^$(PKG)%.%' $(PKG)

$(PKG)/data.tar.lzma: $(PKG) $(addprefix $(DST)/, $(ALL)) #misc/template.tar
	tar -c --lzma -f '$(PKG)/data.tar.lzma' --exclude '.DS_Store' --exclude '._*' -s '%^build%./usr/bin%' @misc/template.tar $(DST)

$(PKG)/debian-binary: $(PKG) $(addprefix $(DST)/, $(ALL))
	echo '2.0' > "$(PKG)/debian-binary"

$(PKG)/control: $(PKG) misc/control
	( echo "Version: $(VERSION)"; cat misc/control; ) > $(PKG)/control

$(PKG):
	mkdir -p $(PKG)

clean:
	rm -rf $(DST) $(PKG) $(XZ) $(DEB)
