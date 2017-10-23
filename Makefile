VERSION = 1.4.0
PKGNAME = net.siguza.ios-kern-utils
BINDIR = bin
OBJDIR = obj
SRCDIR = src
ALL = $(patsubst $(SRCDIR)/tools/%.c,%,$(wildcard $(SRCDIR)/tools/*.c))
LIB = kutil
PKG = pkg
XZ = ios-kern-utils.tar.xz
DEB = $(PKGNAME)_$(VERSION)_iphoneos-arm.deb

# Constants
GCC_FLAGS        = -std=gnu99 -O3 -Wall -I$(SRCDIR)/lib
LD_FLAGS         = -L. -l$(LIB) -framework CoreFoundation -Wl,-dead_strip

# Universal defaults
LIBTOOL_FLAGS   ?= -static
IOS_GCC_ARCH    ?= -arch armv7 -arch arm64 -miphoneos-version-min=6.0
MACOS_GCC_ARCH  ?= -arch x86_64 -mmacosx-version-min=10.10
IOS_GCC_FLAGS   ?= $(GCC_FLAGS)
MACOS_GCC_FLAGS ?= $(GCC_FLAGS)
IOS_LD_FLAGS    ?= $(LD_FLAGS)
MACOS_LD_FLAGS  ?= $(LD_FLAGS)

# Host-specific defaults
# H_{HOST}_{TARGET}_{THING}
H_MACOS_LIBTOOL         = libtool
H_MACOS_LIPO            = lipo
H_MACOS_STRIP           = strip
H_MACOS_SIGN            = codesign
H_MACOS_SIGN_FLAGS      = -s - --entitlements misc/ent.plist
H_MACOS_IOS_GCC         = xcrun -sdk iphoneos gcc
H_MACOS_MACOS_GCC       = xcrun -sdk macosx gcc

H_IOS_LIBTOOL           = libtool
H_IOS_LIPO              = lipo
H_IOS_STRIP             = strip
H_IOS_SIGN              = ldid
H_IOS_SIGN_FLAGS        = -Smisc/ent.plist
H_IOS_IOS_GCC           = clang

H_UNIX_SIGN             = ldid
H_UNIX_SIGN_FLAGS       = -Smisc/ent.plist

ifeq ($(shell uname -s),Darwin)
	ifneq ($(HOSTTYPE),arm)
		HOST = MACOS
	else
		HOST = IOS
	endif
else
	HOST = UNIX
endif

# Employ defaults if desirable
LIBTOOL     ?= $(H_$(HOST)_LIBTOOL)
LIPO        ?= $(H_$(HOST)_LIPO)
STRIP       ?= $(H_$(HOST)_STRIP)
SIGN        ?= $(H_$(HOST)_SIGN)
SIGN_FLAGS  ?= $(H_$(HOST)_SIGN_FLAGS)
IOS_GCC     ?= $(H_$(HOST)_IOS_GCC)
MACOS_GCC   ?= $(H_$(HOST)_MACOS_GCC)

#ifndef IGCC
#	ifeq ($(shell uname -s),Darwin)
#		ifneq ($(HOSTTYPE),arm)
#			IGCC = xcrun -sdk iphoneos gcc
#		else
#			IGCC = clang
#		endif
#		LD_FLAGS += -Wl,-dead_strip
#	else
#		IGCC = ios-clang
#		LD_FLAGS += -Wl,--gc-sections
#	endif
#endif
#ifndef IGCC_ARCH
#	IGCC_ARCH = -arch armv7 -arch arm64 -miphoneos-version-min=6.0
#endif
## We need libtool here because ar can't deal with fat libraries
#ifndef LIBTOOL
#	ifeq ($(shell uname -s),Darwin)
#		ifneq ($(HOSTTYPE),arm)
#			LIBTOOL = xcrun -sdk iphoneos libtool
#		else
#			LIBTOOL = libtool
#		endif
#	else
#		LIBTOOL = ios-libtool
#	endif
#endif
#ifndef STRIP
#	ifeq ($(shell uname -s),Darwin)
#		ifneq ($(HOSTTYPE),arm)
#			STRIP = xcrun -sdk iphoneos strip
#		else
#			STRIP = $(shell which strip 2>/dev/null)
#		endif
#	else
#		STRIP := $(shell which ios-strip 2>/dev/null)
#	endif
#endif
#ifndef SIGN
#	ifeq ($(shell uname -s),Darwin)
#		ifneq ($(HOSTTYPE),arm)
#			SIGN = codesign
#		else
#			SIGN = ldid
#		endif
#	else
#		SIGN = ldid
#	endif
#endif
#ifndef SIGN_FLAGS
#	ifeq ($(SIGN),codesign)
#		SIGN_FLAGS = -s - --entitlements misc/ent.plist
#	else
#		ifeq ($(SIGN),ldid)
#			SIGN_FLAGS = -Smisc/ent.plist
#		endif
#	endif
#endif

#SUFFIXES =
#ifdef IOS_GCC
#	SUFFIXES := $(SUFFIXES) ios
#endif
#ifdef MACOS_GCC
#	SUFFIXES := $(SUFFIXES) macos
#endif

SUF_all     = ios macos
SUF_ios     = ios
SUF_macos   = macos

SUFFIXES :=
ifdef TARGET
	SUFFIXES := $(SUF_$(TARGET))
endif
ifndef SUFFIXES
	ifdef IOS_GCC
		SUFFIXES := $(SUFFIXES) $(SUF_ios)
	endif
	ifdef MACOS_GCC
		SUFFIXES := $(SUFFIXES) $(SUF_macos)
	endif
endif

.PHONY: help all lib dist xz deb clean

all: $(addprefix $(BINDIR)/, $(ALL))

lib: lib$(LIB).a

help:
	@echo 'Usage:'
	@echo '    TARGET=all make     Build for all architectures'
	@echo '    TARGET=ios make     Build for iOS only'
	@echo '    TARGET=macos make   Build for macOS only'
	@echo ''
	@echo 'Targets:'
	@echo '    all                 Build everything'
	@echo '    lib                 Build lib$(LIB) only'
	@echo '    dist                xz + deb'
	@echo '    xz                  Create xz tarball'
	@echo '    deb                 Create deb for dpkg/Cydia'
	@echo '    clean               Clean up'
	@echo ''
	@echo 'Variables:'
	@echo '    CFLAGS              Passed during all phases of compilation'
	@echo '    LDFLAGS             Passed during linking phase only'
	@echo '    IOS_GCC             Compiler targeting iOS'
	@echo '    IOS_GCC_FLAGS       Passed to iOS compiler only'
	@echo '    IOS_LD_FLAGS        Passed to iOS linker only'
	@echo '    MACOS_GCC           Compiler targeting macOS'
	@echo '    MACOS_GCC_FLAGS     Passed to macOS compiler only'
	@echo '    MACOS_LD_FLAGS      Passed to macOS linker only'
	@echo '    LIBTOOL             Not to be confused with GNU libtool'
	@echo '    LIBTOOL_FLAGS'
	@echo '    LIPO'
	@echo '    STRIP'
	@echo '    SIGN                Code signing utility (only used for iOS)'
	@echo '    SIGN_FLAGS          Must include path to entitlements file'
	@echo '    '
	@echo 'Variables you should never have to touch:'
	@echo '    IOS_GCC_ARCH        iOS architecture flags'
	@echo '    MACOS_GCC_ARCH      macOS architecture flags'

$(BINDIR)/%: $(addprefix $(OBJDIR)/%., $(SUFFIXES)) | $(BINDIR)
	$(LIPO) -create -output $@ $^

#$(BINDIR)/%: lib$(LIB).a $(SRCDIR)/tools/%.c | $(BINDIR)
#	$(IGCC) -o $@ $(IGCC_FLAGS) $(IGCC_ARCH) $(LD_FLAGS) $(LD_LIBS) $(SRCDIR)/tools/$(@F).c
#ifdef STRIP
#	$(STRIP) $@
#endif
#	$(SIGN) $(SIGN_FLAGS) $@

$(OBJDIR)/%.ios: $(SRCDIR)/tools/%.c lib$(LIB).a | $(OBJDIR)
	$(IOS_GCC) -o $@ $(IOS_GCC_FLAGS) $(CFLAGS) $(IOS_LD_FLAGS) $(LDFLAGS) $(IOS_GCC_ARCH) $<
	$(STRIP) $@
	$(SIGN) $(SIGN_FLAGS) $@

$(OBJDIR)/%.macos: $(SRCDIR)/tools/%.c lib$(LIB).a | $(OBJDIR)
	$(MACOS_GCC) -o $@ $(MACOS_GCC_FLAGS) $(CFLAGS) $(MACOS_LD_FLAGS) $(LDFLAGS) $(MACOS_GCC_ARCH) $<
	$(STRIP) $@

lib$(LIB).a: $(patsubst $(SRCDIR)/lib/%.c,$(OBJDIR)/%.o,$(wildcard $(SRCDIR)/lib/*.c))
	$(LIBTOOL) $(LIBTOOL_FLAGS) -o $@ $^

#$(OBJDIR)/%.o: $(SRCDIR)/lib/%.c | $(OBJDIR)
#	$(IGCC) -c -o $@ $(IGCC_FLAGS) $(IGCC_ARCH) $<

$(OBJDIR)/%.ios.o: $(SRCDIR)/lib/%.c | $(OBJDIR)
	$(IOS_GCC) -c -o $@ $(IOS_GCC_FLAGS) $(CFLAGS) $(IOS_GCC_ARCH) $<

$(OBJDIR)/%.macos.o: $(SRCDIR)/lib/%.c | $(OBJDIR)
	$(MACOS_GCC) -c -o $@ $(MACOS_GCC_FLAGS) $(CFLAGS) $(MACOS_GCC_ARCH) $<

$(OBJDIR)/%.o: $(addsuffix .o, $(addprefix $(OBJDIR)/%., $(SUFFIXES)))
	$(LIPO) -create -output $@ $^

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

dist: xz deb

xz: $(XZ)

deb: $(DEB)

$(XZ): $(addprefix $(BINDIR)/, $(ALL))
	tar -cJf $(XZ) -C $(BINDIR) $(ALL)

$(DEB): $(PKG)/control.tar.gz $(PKG)/data.tar.lzma $(PKG)/debian-binary
	( cd "$(PKG)"; ar -cr "../$(DEB)" 'debian-binary' 'control.tar.gz' 'data.tar.lzma'; )

$(PKG)/control.tar.gz: $(PKG)/control
	tar -czf '$(PKG)/control.tar.gz' --exclude '.DS_Store' --exclude '._*' --exclude 'control.tar.gz' --include '$(PKG)' --include '$(PKG)/control' -s '%^$(PKG)%.%' $(PKG)

$(PKG)/data.tar.lzma: $(addprefix $(BINDIR)/, $(ALL)) | $(PKG) #misc/template.tar
	tar -c --lzma -f '$(PKG)/data.tar.lzma' --exclude '.DS_Store' --exclude '._*' -s '%^$(BINDIR)%./usr/bin%' @misc/template.tar $(BINDIR)

$(PKG)/debian-binary: $(addprefix $(BINDIR)/, $(ALL)) | $(PKG)
	echo '2.0' > "$(PKG)/debian-binary"

$(PKG)/control: misc/control | $(PKG)
	( echo "Version: $(VERSION)"; cat misc/control; ) > $(PKG)/control

$(PKG):
	mkdir -p $(PKG)

clean:
	rm -rf $(BINDIR) $(OBJDIR) lib$(LIB).a $(PKG) $(XZ) $(PKGNAME)_*_iphoneos-arm.deb
