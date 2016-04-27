# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

include ../config.mk

LIBNAME = unicorn

# Find GLIB
ifndef GLIB
GLIB = $(shell pkg-config --libs glib-2.0)
endif

UNICORN_DEP_LIBS_STATIC += -lpthread -lm $(GLIB)

# Verbose output?
V ?= 0

INCDIR = ../include
ifndef BUILDDIR
SAMPLEDIR = .
OBJDIR = .
LIBDIR = ..
else
SAMPLEDIR = $(BUILDDIR)/samples
OBJDIR = $(BUILDDIR)/obj/samples
LIBDIR = $(BUILDDIR)
endif

CFLAGS += -Wall -I$(INCDIR)
LDFLAGS += -lpthread -L$(LIBDIR) -l$(LIBNAME)
LDFLAGS_STATIC += $(UNICORN_DEP_LIBS_STATIC)

ifeq ($(CROSS),)
CC ?= cc
LDFLAGS += -lm $(GLIB)
else
CC = $(CROSS)gcc
endif

ifeq ($(UNICORN_ASAN),yes)
CC = clang -fsanitize=address -fno-omit-frame-pointer
CXX = clang++ -fsanitize=address -fno-omit-frame-pointer
AR = llvm-ar
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif


#CFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
#LDFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))

BIN_EXT =
AR_EXT = a

# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
CFLAGS := $(CFLAGS:-fPIC=)
LDFLAGS += -lssp
LDFLAGS_STATIC += -lssp
BIN_EXT = .exe
AR_EXT = a
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = lib
endif
endif

ifeq ($(UNICORN_STATIC),yes)
ifeq ($(IS_MINGW),1)
ARCHIVE = $(LIBDIR)/$(LIBNAME).$(AR_EXT)
else ifeq ($(IS_CYGWIN),1)
ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)
else
ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)
#ARCHIVE_X86 = $(LIBDIR)/lib$(LIBNAME)_x86.$(AR_EXT)
#ARCHIVE_ARM = $(LIBDIR)/lib$(LIBNAME)_arm.$(AR_EXT)
#ARCHIVE_ARM64 = $(LIBDIR)/lib$(LIBNAME)_arm64.$(AR_EXT)
endif
endif

.PHONY: all clean clean_bins clean_libs

UNICORN_ARCHS := $(shell if [ -e ../config.log ]; then cat ../config.log;\
				 else printf "$(UNICORN_ARCHS)"; fi)

SOURCES =
ifneq (,$(findstring arm,$(UNICORN_ARCHS)))
SOURCES += sample_arm.c
endif
ifneq (,$(findstring aarch64,$(UNICORN_ARCHS)))
SOURCES += sample_arm64.c
endif
ifneq (,$(findstring mips,$(UNICORN_ARCHS)))
SOURCES += sample_mips.c
endif
ifneq (,$(findstring ppc,$(UNICORN_ARCHS)))
#SOURCES += sample_ppc.c
endif
ifneq (,$(findstring sparc,$(UNICORN_ARCHS)))
SOURCES += sample_sparc.c
endif
ifneq (,$(findstring x86,$(UNICORN_ARCHS)))
SOURCES += sample_x86.c
SOURCES += shellcode.c
SOURCES += mem_apis.c
SOURCES += sample_x86_32_gdt_and_seg_regs.c
SOURCES += sample_batch_reg.c
endif
ifneq (,$(findstring m68k,$(UNICORN_ARCHS)))
SOURCES += sample_m68k.c
endif

OBJS = $(addprefix $(OBJDIR)/,$(SOURCES:.c=.o))
OBJS_ELF = $(addprefix $(OBJDIR)/,$(SOURCES:.c=))
BINARY = $(addprefix $(SAMPLEDIR)/,$(SOURCES:.c=$(BIN_EXT)))

all: clean_bins $(BINARY)

clean_bins:
	rm -rf *.o $(OBJS_ELF) $(BINARY) $(SAMPLEDIR)/*.exe $(SAMPLEDIR)/*.static $(OBJDIR)/lib$(LIBNAME)* $(OBJDIR)/$(LIBNAME)*
	rm -rf sample_x86 sample_arm sample_arm64 sample_mips sample_sparc sample_ppc sample_m68k shellcode mem_apis sample_x86_32_gdt_and_seg_regs sample_batch_reg

clean_libs:
	rm -rf libunicorn*.so libunicorn*.lib libunicorn*.dylib unicorn*.dll unicorn*.lib

clean: clean_bins clean_libs

$(BINARY): $(OBJS)

$(SAMPLEDIR)/%$(BIN_EXT): $(OBJDIR)/%.o
	@mkdir -p $(@D)
ifeq ($(V),0)
ifeq ($(UNICORN_SHARED),yes)
	$(call log,LINK,$(notdir $@))
	@$(link-dynamic)
endif
ifeq ($(UNICORN_STATIC),yes)
ifneq ($(IS_MINGW),1)
	$(call log,LINK,$(notdir $(call staticname,$@)))
	@$(link-static)
endif
endif
else
ifeq ($(UNICORN_SHARED),yes)
	$(link-dynamic)
endif
ifeq ($(UNICORN_STATIC),yes)
ifneq ($(IS_MINGW),1)
	$(link-static)
endif
endif
endif

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:$(OBJDIR)/%=%))
	@$(compile)
else
	$(compile)
endif


define link-dynamic
	$(CC) $< $(LDFLAGS) -o $@
endef


define link-static
	$(CC) $< $(ARCHIVE) $(LDFLAGS_STATIC) -o $(call staticname,$@)
endef


staticname = $(subst $(BIN_EXT),,$(1)).static$(BIN_EXT)

define log
	@printf "  %-7s %s\n" "$(1)" "$(2)"
endef

define compile
	${CC} ${CFLAGS} -c $< -o $@
endef
