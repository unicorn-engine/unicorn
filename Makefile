# Unicorn Emulator Engine
# By Dang Hoang Vu <dang.hvu -at- gmail.com>, 2015


.PHONY: all clean install uninstall dist header

include config.mk
include pkgconfig.mk	# package version

LIBNAME = unicorn
UNAME_S := $(shell uname -s)
# SMP_MFLAGS is used for controlling the amount of parallelism used
# in external 'make' invocations. If the user doesn't override it, it
# does "-j4". That is, it uses 4 job threads. If you want to use more or less,
# pass in a different -jX, with X being the number of threads.
# For example, to completely disable parallel building, pass "-j1".
# If you want to use 16 job threads, use "-j16".
SMP_MFLAGS := -j4

UC_GET_OBJ = $(shell for i in \
    $$(grep '$(1)' $(2) | \
    grep '\.o' | cut -d '=' -f 2); do \
    echo $$i | grep '\.o' > /dev/null 2>&1; \
    if [ $$? = 0 ]; then \
    echo '$(3)'$$i; \
    fi; done; echo)

UC_TARGET_OBJ = $(filter-out qemu/../%,$(call UC_GET_OBJ,obj-,qemu/Makefile.objs, qemu/))
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-,qemu/hw/core/Makefile.objs, qemu/hw/core/)
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-,qemu/qapi/Makefile.objs, qemu/qapi/)
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-,qemu/qobject/Makefile.objs, qemu/qobject/)
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-,qemu/qom/Makefile.objs, qemu/qom/)
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-y,qemu/util/Makefile.objs, qemu/util/)
ifneq ($(filter MINGW%,$(UNAME_S)),)
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-$$(CONFIG_WIN32),qemu/util/Makefile.objs, qemu/util/)
else
UC_TARGET_OBJ += $(call UC_GET_OBJ,obj-$$(CONFIG_POSIX),qemu/util/Makefile.objs, qemu/util/)
endif

UC_TARGET_OBJ_X86 = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/x86_64-softmmu/)
UC_TARGET_OBJ_X86 += $(call UC_GET_OBJ,obj-,qemu/hw/i386/Makefile.objs, qemu/x86_64-softmmu/hw/i386/)
UC_TARGET_OBJ_X86 += $(call UC_GET_OBJ,obj-,qemu/hw/intc/Makefile.objs, qemu/x86_64-softmmu/hw/intc/)
UC_TARGET_OBJ_X86 += $(call UC_GET_OBJ,obj-,qemu/target-i386/Makefile.objs, qemu/x86_64-softmmu/target-i386/)

UC_TARGET_OBJ_ARM = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/arm-softmmu/)
UC_TARGET_OBJ_ARM += $(call UC_GET_OBJ,obj-,qemu/hw/arm/Makefile.objs, qemu/arm-softmmu/hw/arm/)
UC_TARGET_OBJ_ARM += $(call UC_GET_OBJ,obj-y,qemu/target-arm/Makefile.objs, qemu/arm-softmmu/target-arm/)
UC_TARGET_OBJ_ARM += $(call UC_GET_OBJ,obj-$$(CONFIG_SOFTMMU),qemu/target-arm/Makefile.objs, qemu/arm-softmmu/target-arm/)
UC_TARGET_OBJ_ARM += $(call UC_GET_OBJ,obj-$$(TARGET_ARM),qemu/target-arm/Makefile.objs, qemu/arm-softmmu/target-arm/)

UC_TARGET_OBJ_ARMEB = $(subst /arm-softmmu/,/armeb-softmmu/,$(UC_TARGET_OBJ_ARM))

UC_TARGET_OBJ_M68K = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/m68k-softmmu/)
UC_TARGET_OBJ_M68K += $(call UC_GET_OBJ,obj-,qemu/hw/m68k/Makefile.objs, qemu/m68k-softmmu/hw/m68k/)
UC_TARGET_OBJ_M68K += $(call UC_GET_OBJ,obj-,qemu/target-m68k/Makefile.objs, qemu/m68k-softmmu/target-m68k/)

UC_TARGET_OBJ_AARCH64 = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/aarch64-softmmu/)
UC_TARGET_OBJ_AARCH64 += $(call UC_GET_OBJ,obj-,qemu/hw/arm/Makefile.objs, qemu/aarch64-softmmu/hw/arm/)
UC_TARGET_OBJ_AARCH64 += $(call UC_GET_OBJ,obj-y,qemu/target-arm/Makefile.objs, qemu/aarch64-softmmu/target-arm/)
UC_TARGET_OBJ_AARCH64 += $(call UC_GET_OBJ,obj-$$(CONFIG_SOFTMMU),qemu/target-arm/Makefile.objs, qemu/aarch64-softmmu/target-arm/)
UC_TARGET_OBJ_AARCH64 += $(call UC_GET_OBJ,obj-$$(TARGET_AARCH64),qemu/target-arm/Makefile.objs, qemu/aarch64-softmmu/target-arm/)

UC_TARGET_OBJ_AARCH64EB = $(subst /aarch64-softmmu/,/aarch64eb-softmmu/,$(UC_TARGET_OBJ_AARCH64))

UC_TARGET_OBJ_MIPS = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/mips-softmmu/)
UC_TARGET_OBJ_MIPS += $(call UC_GET_OBJ,obj-,qemu/hw/mips/Makefile.objs, qemu/mips-softmmu/hw/mips/)
UC_TARGET_OBJ_MIPS += $(call UC_GET_OBJ,obj-,qemu/target-mips/Makefile.objs, qemu/mips-softmmu/target-mips/)

UC_TARGET_OBJ_MIPSEL = $(subst /mips-softmmu/,/mipsel-softmmu/,$(UC_TARGET_OBJ_MIPS))

UC_TARGET_OBJ_MIPS64 = $(subst /mips-softmmu/,/mips64-softmmu/,$(UC_TARGET_OBJ_MIPS))

UC_TARGET_OBJ_MIPS64EL = $(subst /mips-softmmu/,/mips64el-softmmu/,$(UC_TARGET_OBJ_MIPS))

UC_TARGET_OBJ_SPARC = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/sparc-softmmu/)
UC_TARGET_OBJ_SPARC += $(call UC_GET_OBJ,obj-,qemu/hw/sparc/Makefile.objs, qemu/sparc-softmmu/hw/sparc/)
UC_TARGET_OBJ_SPARC += $(call UC_GET_OBJ,obj-y,qemu/target-sparc/Makefile.objs, qemu/sparc-softmmu/target-sparc/)
UC_TARGET_OBJ_SPARC += $(call UC_GET_OBJ,obj-$$(TARGET_SPARC),qemu/target-sparc/Makefile.objs, qemu/sparc-softmmu/target-sparc/)

UC_TARGET_OBJ_SPARC64 = $(call UC_GET_OBJ,obj-,qemu/Makefile.target, qemu/sparc64-softmmu/)
UC_TARGET_OBJ_SPARC64 += $(call UC_GET_OBJ,obj-,qemu/hw/sparc64/Makefile.objs, qemu/sparc64-softmmu/hw/sparc64/)
UC_TARGET_OBJ_SPARC64 += $(call UC_GET_OBJ,obj-y,qemu/target-sparc/Makefile.objs, qemu/sparc64-softmmu/target-sparc/)
UC_TARGET_OBJ_SPARC64 += $(call UC_GET_OBJ,obj-$$(TARGET_SPARC64),qemu/target-sparc/Makefile.objs, qemu/sparc64-softmmu/target-sparc/)

ifneq (,$(findstring x86,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_X86)
	UNICORN_CFLAGS += -DUNICORN_HAS_X86
	UNICORN_TARGETS += x86_64-softmmu,
endif
ifneq (,$(findstring arm,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_ARM)
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_ARMEB)
	UNICORN_CFLAGS += -DUNICORN_HAS_ARM
	UNICORN_CFLAGS += -DUNICORN_HAS_ARMEB
	UNICORN_TARGETS += arm-softmmu,
	UNICORN_TARGETS += armeb-softmmu,
endif
ifneq (,$(findstring m68k,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_M68K)
	UNICORN_CFLAGS += -DUNICORN_HAS_M68K
	UNICORN_TARGETS += m68k-softmmu,
endif
ifneq (,$(findstring aarch64,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_AARCH64)
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_AARCH64EB)
	UNICORN_CFLAGS += -DUNICORN_HAS_ARM64
	UNICORN_CFLAGS += -DUNICORN_HAS_ARM64EB
	UNICORN_TARGETS += aarch64-softmmu,
	UNICORN_TARGETS += aarch64eb-softmmu,
endif
ifneq (,$(findstring mips,$(UNICORN_ARCHS)))
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_MIPS)
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_MIPSEL)
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_MIPS64)
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_MIPS64EL)
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
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_SPARC)
	UC_TARGET_OBJ += $(UC_TARGET_OBJ_SPARC64)
	UNICORN_CFLAGS += -DUNICORN_HAS_SPARC
	UNICORN_TARGETS += sparc-softmmu,sparc64-softmmu,
endif

UC_OBJ_ALL = $(UC_TARGET_OBJ) list.o uc.o

UNICORN_CFLAGS += -fPIC

# Verbose output?
V ?= 0

# on MacOS, by default do not compile in Universal format
MACOS_UNIVERSAL ?= no

ifeq ($(UNICORN_DEBUG),yes)
CFLAGS += -g
else
CFLAGS += -O3
UNICORN_QEMU_FLAGS += --disable-debug-info
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
endif

ifeq ($(PKG_EXTRA),)
PKG_VERSION = $(PKG_MAJOR).$(PKG_MINOR)
else
PKG_VERSION = $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA)
endif

API_MAJOR=$(shell echo `grep -e UC_API_MAJOR include/unicorn/unicorn.h | grep -v = | awk '{print $$3}'` | awk '{print $$1}')

# Apple?
ifeq ($(UNAME_S),Darwin)
EXT = dylib
VERSION_EXT = $(API_MAJOR).$(EXT)
$(LIBNAME)_LDFLAGS += -dynamiclib -install_name @rpath/lib$(LIBNAME).$(VERSION_EXT) -current_version $(PKG_MAJOR).$(PKG_MINOR).$(PKG_EXTRA) -compatibility_version $(PKG_MAJOR).$(PKG_MINOR)
AR_EXT = a
UNICORN_CFLAGS += -fvisibility=hidden

ifeq ($(MACOS_UNIVERSAL),yes)
$(LIBNAME)_LDFLAGS += -m32 -arch i386 -m64 -arch x86_64
UNICORN_CFLAGS += -m32 -arch i386 -m64 -arch x86_64
endif

# Cygwin?
else ifneq ($(filter CYGWIN%,$(UNAME_S)),)
EXT = dll
AR_EXT = a
BIN_EXT = .exe
UNICORN_CFLAGS := $(UNICORN_CFLAGS:-fPIC=)
#UNICORN_QEMU_FLAGS += --disable-stack-protector

# mingw?
else ifneq ($(filter MINGW%,$(UNAME_S)),)
EXT = dll
AR_EXT = a
BIN_EXT = .exe
UNICORN_QEMU_FLAGS += --disable-stack-protector
UNICORN_CFLAGS := $(UNICORN_CFLAGS:-fPIC=)
$(LIBNAME)_LDFLAGS += -Wl,--output-def,unicorn.def
DO_WINDOWS_EXPORT = 1

# Haiku
else ifneq ($(filter Haiku%,$(UNAME_S)),)
EXT = so
VERSION_EXT = $(EXT).$(API_MAJOR)
AR_EXT = a
$(LIBNAME)_LDFLAGS += -Wl,-Bsymbolic-functions,-soname,lib$(LIBNAME).$(VERSION_EXT)
UNICORN_CFLAGS := $(UNICORN_CFLAGS:-fPIC=)
UNICORN_QEMU_FLAGS += --disable-stack-protector

# Linux, Darwin
else
EXT = so
VERSION_EXT = $(EXT).$(API_MAJOR)
AR_EXT = a
$(LIBNAME)_LDFLAGS += -Wl,-Bsymbolic-functions,-soname,lib$(LIBNAME).$(VERSION_EXT)
UNICORN_CFLAGS += -fvisibility=hidden
endif

ifeq ($(UNICORN_SHARED),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
LIBRARY = $(LIBNAME).$(EXT)
else ifneq ($(filter CYGWIN%,$(UNAME_S)),)
LIBRARY = cyg$(LIBNAME).$(EXT)
LIBRARY_DLLA = lib$(LIBNAME).$(EXT).$(AR_EXT)
$(LIBNAME)_LDFLAGS += -Wl,--out-implib=$(LIBRARY_DLLA)
$(LIBNAME)_LDFLAGS += -lssp
# Linux, Darwin
else
LIBRARY = lib$(LIBNAME).$(VERSION_EXT)
LIBRARY_SYMLINK = lib$(LIBNAME).$(EXT)
endif
endif

ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
ARCHIVE = $(LIBNAME).$(AR_EXT)
# Cygwin, Linux, Darwin
else
ARCHIVE = lib$(LIBNAME).$(AR_EXT)
endif
endif

INSTALL_BIN ?= install
INSTALL_DATA ?= $(INSTALL_BIN) -m0644
INSTALL_LIB ?= $(INSTALL_BIN) -m0755
PKGCFGF = $(LIBNAME).pc
PREFIX ?= /usr
DESTDIR ?=

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
LIBDATADIR = $(PREFIX)/libdata
else ifeq ($(UNAME_S), DragonFly)
LIBDATADIR = $(PREFIX)/libdata
endif
endif

ifeq ($(PKG_EXTRA),)
PKGCFGDIR = $(LIBDATADIR)/pkgconfig
else
PKGCFGDIR ?= $(LIBDATADIR)/pkgconfig
endif

$(LIBNAME)_LDFLAGS += -lm

.PHONY: test fuzz bindings clean FORCE

all: unicorn
	$(MAKE) -C samples

qemu/config-host.mak: qemu/configure
	cd qemu && \
	./configure --cc="${CC}" --extra-cflags="$(UNICORN_CFLAGS)" --target-list="$(UNICORN_TARGETS)" ${UNICORN_QEMU_FLAGS}
	@printf "$(UNICORN_ARCHS)" > config.log

uc.o: qemu/config-host.mak FORCE
	$(MAKE) -C qemu $(SMP_MFLAGS)

$(UC_TARGET_OBJ) list.o: uc.o
	@echo "--- $^ $@" > /dev/null

unicorn: $(LIBRARY) $(ARCHIVE)

$(LIBRARY): $(UC_OBJ_ALL)
ifeq ($(UNICORN_SHARED),yes)
ifeq ($(V),0)
	$(call log,GEN,$(LIBRARY))
	@$(CC) $(CFLAGS) -shared $(UC_OBJ_ALL) -o $(LIBRARY) $($(LIBNAME)_LDFLAGS)
	@-ln -sf $(LIBRARY) $(LIBRARY_SYMLINK)
else
	$(CC) $(CFLAGS) -shared $(UC_OBJ_ALL) -o $(LIBRARY) $($(LIBNAME)_LDFLAGS)
	-ln -sf $(LIBRARY) $(LIBRARY_SYMLINK)
endif
ifeq ($(DO_WINDOWS_EXPORT),1)
ifneq ($(filter MINGW32%,$(UNAME_S)),)
	cmd //C "windows_export.bat x86"
else
	cmd //C "windows_export.bat x64"
endif
endif
endif

$(ARCHIVE): $(UC_OBJ_ALL)
ifeq ($(UNICORN_STATIC),yes)
ifeq ($(V),0)
	$(call log,GEN,$(ARCHIVE))
	@$(AR) q $(ARCHIVE) $(UC_OBJ_ALL)
	@$(RANLIB) $(ARCHIVE)
else
	$(AR) q $(ARCHIVE) $(UC_OBJ_ALL)
	$(RANLIB) $(ARCHIVE)
endif
endif

$(PKGCFGF):
	$(generate-pkgcfg)


fuzz: all
	$(MAKE) -C tests/fuzz all

test: all
	$(MAKE) -C tests/unit test
	$(MAKE) -C tests/regress test
	$(MAKE) -C bindings test

install: $(LIBRARY) $(ARCHIVE) $(PKGCFGF)
	install -d $(DESTDIR)$(LIBDIR)
ifeq ($(UNICORN_SHARED),yes)
ifneq ($(filter CYGWIN%,$(UNAME_S)),)
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
	install -d $(DESTDIR)$(INCDIR)/$(LIBNAME)
	$(INSTALL_DATA) include/unicorn/*.h $(DESTDIR)$(INCDIR)/$(LIBNAME)
	install -d $(DESTDIR)$(PKGCFGDIR)
	$(INSTALL_DATA) $(PKGCFGF) $(DESTDIR)$(PKGCFGDIR)/


TAG ?= HEAD
ifeq ($(TAG), HEAD)
DIST_VERSION = latest
else
DIST_VERSION = $(TAG)
endif

bindings: all
	$(MAKE) -C bindings build
	$(MAKE) -C bindings samples

dist:
	git archive --format=tar.gz --prefix=unicorn-$(DIST_VERSION)/ $(TAG) > unicorn-$(DIST_VERSION).tgz
	git archive --format=zip --prefix=unicorn-$(DIST_VERSION)/ $(TAG) > unicorn-$(DIST_VERSION).zip


# run "make header" whenever qemu/header_gen.py is modified
header:
	$(eval TARGETS := m68k arm armeb aarch64 aarch64eb mips mipsel mips64 mips64el\
		sparc sparc64 x86_64)
	$(foreach var,$(TARGETS),\
		$(shell python qemu/header_gen.py $(var) > qemu/$(var).h;))
	@echo "Generated headers for $(TARGETS)."


uninstall:
	rm -rf $(INCDIR)/$(LIBNAME)
	rm -f $(LIBDIR)/lib$(LIBNAME).*
	rm -f $(BINDIR)/cyg$(LIBNAME).*
	rm -f $(PKGCFGDIR)/$(LIBNAME).pc


clean:
	$(MAKE) -C qemu distclean
	rm -rf *.d *.o
	rm -rf lib$(LIBNAME)* $(LIBNAME)*.lib $(LIBNAME)*.dll $(LIBNAME)*.a $(LIBNAME)*.def $(LIBNAME)*.exp cyg$(LIBNAME)*.dll
	$(MAKE) -C samples clean
	$(MAKE) -C tests/unit clean


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
