VERSION = 1.3.0
BUILDDIR = build
OBJDIR = obj
SRCDIR = src
ALL = $(patsubst $(SRCDIR)/tools/%.c,%,$(wildcard $(SRCDIR)/tools/*.c))
LIB = kern
PKG = pkg
XZ = ios-kern-utils.tar.xz
DEB = net.siguza.ios-kern-utils_$(VERSION)_iphoneos-arm.deb
IGCC_FLAGS = -std=gnu99 -O3 -Wall -I$(SRCDIR)/lib -miphoneos-version-min=6.0 $(CFLAGS)
LD_FLAGS = -L.
LD_LIBS = -l$(LIB) $(LDFLAGS)
LIBTOOL_FLAGS ?= -static $(LIBS)

ifndef IGCC
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			IGCC = xcrun -sdk iphoneos gcc
		else
			IGCC = clang
		endif
		LD_FLAGS += -Wl,-dead_strip
	else
		IGCC = ios-clang
		LD_FLAGS += -Wl,--gc-sections
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
ifndef LIBTOOL
	ifeq ($(shell uname -s),Darwin)
		ifneq ($(HOSTTYPE),arm)
			LIBTOOL = xcrun -sdk iphoneos libtool
		else
			LIBTOOL = libtool
		endif
	else
		LIBTOOL = ios-libtool
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

.PHONY: all lib dist xz deb clean

all: $(addprefix $(BUILDDIR)/, $(ALL))

$(BUILDDIR)/%: lib$(LIB).a $(SRCDIR)/tools/%.c | $(BUILDDIR)
	$(IGCC) -o $@ $(IGCC_FLAGS) $(IGCC_ARCH) $(LD_FLAGS) $(LD_LIBS) $(SRCDIR)/tools/$(@F).c
ifdef STRIP
	$(STRIP) $@
endif
	$(SIGN) $(SIGN_FLAGS) $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

lib: lib$(LIB).a

lib$(LIB).a: $(patsubst $(SRCDIR)/lib/%.c,$(OBJDIR)/%.o,$(wildcard $(SRCDIR)/lib/*.c))
	$(LIBTOOL) $(LIBTOOL_FLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/lib/%.c | $(OBJDIR)
	$(IGCC) -c -o $@ $(IGCC_FLAGS) $(IGCC_ARCH) $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

dist: xz deb

xz: $(XZ)

deb: $(DEB)

$(XZ): $(addprefix $(BUILDDIR)/, $(ALL))
	tar -cJf $(XZ) -C $(BUILDDIR) $(ALL)

$(DEB): $(PKG)/control.tar.gz $(PKG)/data.tar.lzma $(PKG)/debian-binary
	( cd "$(PKG)"; ar -cr "../$(DEB)" 'debian-binary' 'control.tar.gz' 'data.tar.lzma'; )

$(PKG)/control.tar.gz: $(PKG)/control
	tar -czf '$(PKG)/control.tar.gz' --exclude '.DS_Store' --exclude '._*' --exclude 'control.tar.gz' --include '$(PKG)' --include '$(PKG)/control' -s '%^$(PKG)%.%' $(PKG)

$(PKG)/data.tar.lzma: $(addprefix $(BUILDDIR)/, $(ALL)) | $(PKG) #misc/template.tar
	tar -c --lzma -f '$(PKG)/data.tar.lzma' --exclude '.DS_Store' --exclude '._*' -s '%^build%./usr/bin%' @misc/template.tar $(BUILDDIR)

$(PKG)/debian-binary: $(addprefix $(BUILDDIR)/, $(ALL)) | $(PKG)
	echo '2.0' > "$(PKG)/debian-binary"

$(PKG)/control: misc/control | $(PKG)
	( echo "Version: $(VERSION)"; cat misc/control; ) > $(PKG)/control

$(PKG):
	mkdir -p $(PKG)

clean:
	rm -rf $(BUILDDIR) $(OBJDIR) lib$(LIB).a $(PKG) $(XZ) $(DEB)
