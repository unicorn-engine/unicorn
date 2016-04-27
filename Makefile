# Unicorn Emulator Engine
# By Dang Hoang Vu <dang.hvu -at- gmail.com>, 2015


.PHONY: all clean install uninstall dist header

include config.mk
include pkgconfig.mk	# package version

LIBNAME = unicorn

GENOBJ = $(shell find qemu/$(1) -name "*.o" 2>/dev/null) $(wildcard qemu/util/*.o) $(wildcard qemu/*.o) $(wildcard qemu/qom/*.o)\
		 $(wildcard qemu/hw/core/*.o) $(wildcard qemu/qapi/*.o) $(wildcard qemu/qobject/*.o)

ifneq (,$(findstring x86,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(call GENOBJ,x86_64-softmmu)
	UNICORN_CFLAGS += -DUNICORN_HAS_X86
	UNICORN_TARGETS += x86_64-softmmu,
endif
ifneq (,$(findstring arm,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(call GENOBJ,arm-softmmu)
	UNICORN_CFLAGS += -DUNICORN_HAS_ARM
	UNICORN_TARGETS += arm-softmmu,
endif
ifneq (,$(findstring m68k,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(call GENOBJ,m68k-softmmu)
	UNICORN_CFLAGS += -DUNICORN_HAS_M68K
	UNICORN_TARGETS += m68k-softmmu,
endif
ifneq (,$(findstring aarch64,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(call GENOBJ,aarch64-softmmu)
	UNICORN_CFLAGS += -DUNICORN_HAS_ARM64
	UNICORN_TARGETS += aarch64-softmmu,
endif
ifneq (,$(findstring mips,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(call GENOBJ,mips-softmmu)
	UC_TARGET_OBJ += $(call GENOBJ,mipsel-softmmu)
	UC_TARGET_OBJ += $(call GENOBJ,mips64-softmmu)
	UC_TARGET_OBJ += $(call GENOBJ,mips64el-softmmu)
	UNICORN_CFLAGS += -DUNICORN_HAS_MIPS
	UNICORN_CFLAGS += -DUNICORN_HAS_MIPSEL
	UNICORN_CFLAGS += -DUNICORN_HAS_MIPS64
	UNICORN_CFLAGS += -DUNICORN_HAS_MIPS64EL
	UNICORN_TARGETS += mips-softmmu,
	UNICORN_TARGETS += mipsel-softmmu,
	UNICORN_TARGETS += mips64-softmmu,
	UNICORN_TARGETS += mips64el-softmmu,
endif
ifneq (,$(findstring sparc,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(call GENOBJ,sparc-softmmu)
	UC_TARGET_OBJ += $(call GENOBJ,sparc64-softmmu)
	UNICORN_CFLAGS += -DUNICORN_HAS_SPARC
	UNICORN_TARGETS += sparc-softmmu,sparc64-softmmu,
endif

UNICORN_CFLAGS += -fPIC

# Verbose output?
V ?= 0

ifeq ($(UNICORN_DEBUG),yes)
CFLAGS += -g
else
CFLAGS += -O3
endif

ifeq ($(UNICORN_ASAN),yes)
CC = clang -fsanitize=address -fno-omit-frame-pointer
CXX = clang++ -fsanitize=address -fno-omit-frame-pointer
AR = llvm-ar
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

ifeq ($(CROSS),)
CC ?= cc
AR ?= ar
RANLIB ?= ranlib
STRIP ?= strip
else
CC = $(CROSS)-gcc
AR = $(CROSS)-ar
RANLIB = $(CROSS)-ranlib
STRIP = $(CROSS)-strip
GLIB = "-L/usr/$(CROSS)/lib/ -lglib-2.0"
endif

# Find GLIB
ifndef GLIB
GLIB = `pkg-config --libs glib-2.0`
endif

ifeq ($(PKG_EXTRA),)
PKG_VERSION = $(PKG_MAJOR).$(PKG_MINOR)
else
PKG_VERSION = $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA)
endif

API_MAJOR=$(shell echo `grep -e UC_API_MAJOR include/unicorn/unicorn.h | grep -v = | awk '{print $$3}'` | awk '{print $$1}')
VERSION_EXT =

BIN_EXT =

IS_APPLE := $(shell $(CC) -dM -E - < /dev/null | grep -cm 1 -e __apple_build_version__ -e __APPLE_CC__)
ifeq ($(IS_APPLE),1)
EXT = dylib
VERSION_EXT = $(API_MAJOR).$(EXT)
$(LIBNAME)_LDFLAGS += -dynamiclib -install_name lib$(LIBNAME).$(VERSION_EXT) -current_version $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA) -compatibility_version $(PKG_MAJOR).$(PKG_MINOR)
AR_EXT = a
UNICORN_CFLAGS += -fvisibility=hidden
else
# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
EXT = dll
AR_EXT = a
BIN_EXT = .exe
UNICORN_CFLAGS := $(UNICORN_CFLAGS:-fPIC=)
#UNICORN_QEMU_FLAGS += --disable-stack-protector
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
EXT = dll
AR_EXT = lib
BIN_EXT = .exe
else
# Linux, *BSD
EXT = so
VERSION_EXT = $(EXT).$(API_MAJOR)
AR_EXT = a
$(LIBNAME)_LDFLAGS += -Wl,-Bsymbolic-functions,-soname,lib$(LIBNAME).$(VERSION_EXT)
UNICORN_CFLAGS += -fvisibility=hidden
endif
endif
endif

ifeq ($(UNICORN_SHARED),yes)
ifeq ($(IS_MINGW),1)
LIBRARY = $(BLDIR)/$(LIBNAME).$(EXT)
else ifeq ($(IS_CYGWIN),1)
LIBRARY = $(BLDIR)/cyg$(LIBNAME).$(EXT)
LIBRARY_DLLA = $(BLDIR)/lib$(LIBNAME).$(EXT).$(AR_EXT)
$(LIBNAME)_LDFLAGS += -Wl,--out-implib=$(LIBRARY_DLLA)
$(LIBNAME)_LDFLAGS += -lssp
else	# *nix
LIBRARY = $(BLDIR)/lib$(LIBNAME).$(VERSION_EXT)
LIBRARY_SYMLINK = $(BLDIR)/lib$(LIBNAME).$(EXT)
endif
endif

ifeq ($(UNICORN_STATIC),yes)
ifeq ($(IS_MINGW),1)
ARCHIVE = $(BLDIR)/$(LIBNAME).$(AR_EXT)
else ifeq ($(IS_CYGWIN),1)
ARCHIVE = $(BLDIR)/lib$(LIBNAME).$(AR_EXT)
else
ARCHIVE = $(BLDIR)/lib$(LIBNAME).$(AR_EXT)
endif
endif

INSTALL_BIN ?= install
INSTALL_DATA ?= $(INSTALL_BIN) -m0644
INSTALL_LIB ?= $(INSTALL_BIN) -m0755
PKGCFGF = $(LIBNAME).pc
PREFIX ?= /usr
DESTDIR ?=
BLDIR = .
OBJDIR = .
UNAME_S := $(shell uname -s)

LIBDIRARCH ?= lib
# Uncomment the below line to installs x86_64 libs to lib64/ directory.
# Or better, pass 'LIBDIRARCH=lib64' to 'make install/uninstall' via 'make.sh'.
#LIBDIRARCH ?= lib64

LIBDIR ?= $(PREFIX)/$(LIBDIRARCH)
INCDIR ?= $(PREFIX)/include
BINDIR ?= $(PREFIX)/bin

LIBDATADIR ?= $(LIBDIR)

# Don't redefine $LIBDATADIR when global environment variable
# USE_GENERIC_LIBDATADIR is set. This is used by the pkgsrc framework.

ifndef USE_GENERIC_LIBDATADIR
ifeq ($(UNAME_S), FreeBSD)
LIBDATADIR = $(DESTDIR)$(PREFIX)/libdata
endif
ifeq ($(UNAME_S), DragonFly)
LIBDATADIR = $(DESTDIR)$(PREFIX)/libdata
endif
endif

ifeq ($(PKG_EXTRA),)
PKGCFGDIR = $(LIBDATADIR)/pkgconfig
else
PKGCFGDIR ?= $(LIBDATADIR)/pkgconfig
endif

all: compile_lib
ifeq (,$(findstring yes,$(UNICORN_BUILD_CORE_ONLY)))
ifeq ($(UNICORN_SHARED),yes)
ifeq ($(V),0)
	@$(INSTALL_LIB) $(LIBRARY) $(BLDIR)/samples/
else
	$(INSTALL_LIB) $(LIBRARY) $(BLDIR)/samples/
endif
endif

ifndef BUILDDIR
	@cd samples && $(MAKE)
else
	@cd samples && $(MAKE) BUILDDIR=$(BLDIR)
endif
endif

config:
	if [ "$(UNICORN_ARCHS)" != "`cat config.log`" ]; then $(MAKE) clean; fi

qemu/config-host.h-timestamp:
ifeq ($(UNICORN_DEBUG),yes)
	cd qemu && \
	./configure --cc="${CC}" --extra-cflags="$(UNICORN_CFLAGS)" --target-list="$(UNICORN_TARGETS)" ${UNICORN_QEMU_FLAGS}
	printf "$(UNICORN_ARCHS)" > config.log
else
	cd qemu && \
	./configure --cc="${CC}" --disable-debug-info --extra-cflags="$(UNICORN_CFLAGS)" --target-list="$(UNICORN_TARGETS)" ${UNICORN_QEMU_FLAGS}
	printf "$(UNICORN_ARCHS)" > config.log
endif

compile_lib: config qemu/config-host.h-timestamp
	rm -rf lib$(LIBNAME)* $(LIBNAME)*.lib $(LIBNAME)*.dll cyg$(LIBNAME)*.dll && cd qemu && $(MAKE) -j 4
	$(MAKE) unicorn

unicorn: $(LIBRARY) $(ARCHIVE)

$(LIBRARY): $(UC_TARGET_OBJ) uc.o list.o
ifeq ($(UNICORN_SHARED),yes)
ifeq ($(V),0)
	$(call log,GEN,$(LIBRARY))
	@$(CC) $(CFLAGS) -shared $^ -o $(LIBRARY) $(GLIB) -lm $($(LIBNAME)_LDFLAGS)
else
	$(CC) $(CFLAGS) -shared $^ -o $(LIBRARY) $(GLIB) -lm $($(LIBNAME)_LDFLAGS)
endif
ifneq (,$(LIBRARY_SYMLINK))
	@ln -sf $(LIBRARY) $(LIBRARY_SYMLINK)
endif
endif

$(ARCHIVE): $(UC_TARGET_OBJ) uc.o list.o
ifeq ($(UNICORN_STATIC),yes)
ifeq ($(V),0)
	$(call log,GEN,$(ARCHIVE))
	@$(create-archive)
else
	$(create-archive)
endif
endif


$(PKGCFGF):
ifeq ($(V),0)
	$(call log,GEN,$(@:$(BLDIR)/%=%))
	@$(generate-pkgcfg)
else
	$(generate-pkgcfg)
endif


.PHONY: test
test: all
	$(MAKE) -C tests/unit test

install: compile_lib $(PKGCFGF)
	mkdir -p $(DESTDIR)$(LIBDIR)
ifeq ($(UNICORN_SHARED),yes)
ifeq ($(IS_CYGWIN),1)
	$(INSTALL_LIB) $(LIBRARY) $(DESTDIR)$(BINDIR)
	$(INSTALL_DATA) $(LIBRARY_DLLA) $(DESTDIR)$(LIBDIR)
else
	$(INSTALL_LIB) $(LIBRARY) $(DESTDIR)$(LIBDIR)
endif
ifneq ($(VERSION_EXT),)
	cd $(DESTDIR)$(LIBDIR) && \
	ln -sf lib$(LIBNAME).$(VERSION_EXT) lib$(LIBNAME).$(EXT)
endif
endif
ifeq ($(UNICORN_STATIC),yes)
	$(INSTALL_DATA) $(ARCHIVE) $(DESTDIR)$(LIBDIR)
endif
	mkdir -p $(DESTDIR)$(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/unicorn/*.h $(DESTDIR)$(INCDIR)/$(LIBNAME)
	mkdir -p $(DESTDIR)$(PKGCFGDIR)
	$(INSTALL_DATA) $(PKGCFGF) $(DESTDIR)$(PKGCFGDIR)/


TAG ?= HEAD
ifeq ($(TAG), HEAD)
DIST_VERSION = latest
else
DIST_VERSION = $(TAG)
endif

dist:
	git archive --format=tar.gz --prefix=unicorn-$(DIST_VERSION)/ $(TAG) > unicorn-$(DIST_VERSION).tgz
	git archive --format=zip --prefix=unicorn-$(DIST_VERSION)/ $(TAG) > unicorn-$(DIST_VERSION).zip


header: FORCE
	$(eval TARGETS := m68k arm aarch64 mips mipsel mips64 mips64el\
		powerpc sparc sparc64 x86_64)
	$(foreach var,$(TARGETS),\
		$(shell python qemu/header_gen.py $(var) > qemu/$(var).h;))
	@echo "Generated headers for $(TARGETS)."


uninstall:
	rm -rf $(INCDIR)/$(LIBNAME)
	rm -f $(LIBDIR)/lib$(LIBNAME).*
	rm -f $(BINDIR)/cyg$(LIBNAME).*
	rm -f $(PKGCFGDIR)/$(LIBNAME).pc


clean:
	$(MAKE) -C qemu clean
	rm -rf *.d *.o
	rm -rf lib$(LIBNAME)* $(LIBNAME)*.lib $(LIBNAME)*.dll cyg$(LIBNAME)*.dll
ifeq (,$(findstring yes,$(UNICORN_BUILD_CORE_ONLY)))
	cd samples && $(MAKE) clean
	rm -f $(BLDIR)/samples/lib$(LIBNAME).$(EXT)
endif
	$(MAKE) -C tests/unit clean

ifdef BUILDDIR
	rm -rf $(BUILDDIR)
endif


define generate-pkgcfg
	echo 'Name: unicorn' > $(PKGCFGF)
	echo 'Description: Unicorn emulator engine' >> $(PKGCFGF)
	echo 'Version: $(PKG_VERSION)' >> $(PKGCFGF)
	echo 'libdir=$(LIBDIR)' >> $(PKGCFGF)
	echo 'includedir=$(INCDIR)' >> $(PKGCFGF)
	echo 'archive=$${libdir}/libunicorn.a' >> $(PKGCFGF)
	echo 'Libs: -L$${libdir} -lunicorn' >> $(PKGCFGF)
	echo 'Cflags: -I$${includedir}' >> $(PKGCFGF)
endef


define log
	@printf "  %-7s %s\n" "$(1)" "$(2)"
endef


define create-archive
	$(AR) q $(ARCHIVE) $^
	$(RANLIB) $(ARCHIVE)
endef

FORCE:
