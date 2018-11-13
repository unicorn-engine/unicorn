# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

include ../config.mk

UNAME_S := $(shell uname -s)

LIBDIR = ..
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../include

LDFLAGS += -L$(LIBDIR) -lunicorn -lpthread -lm
ifeq ($(UNAME_S), Linux)
LDFLAGS += -lrt
endif

LDLIBS += -lpthread -lunicorn -lm

ifneq ($(CROSS),)
CC = $(CROSS)gcc
endif

ifeq ($(UNICORN_ASAN),yes)
CC = clang 
CXX = clang++
AR = llvm-ar
CFLAGS += -fsanitize=address -fno-omit-frame-pointer
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

# Cygwin?
ifneq ($(filter CYGWIN%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
LDLIBS += -lssp
BIN_EXT = .exe
AR_EXT = a
# mingw?
else ifneq ($(filter MINGW%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = a
endif

ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
ARCHIVE = $(LIBDIR)/unicorn.$(AR_EXT)
else ifneq ($(filter CYGWIN%,$(UNAME_S)),)
ARCHIVE = $(LIBDIR)/libunicorn.$(AR_EXT)
else
ARCHIVE = $(LIBDIR)/libunicorn.$(AR_EXT)
endif
endif

.PHONY: all clean

UNICORN_ARCHS := $(shell if [ -e ../config.log ]; then cat ../config.log;\
				 else printf "$(UNICORN_ARCHS)"; fi)

SOURCES =
ifneq (,$(findstring arm,$(UNICORN_ARCHS)))
SOURCES += sample_arm.c
SOURCES += sample_armeb.c
endif
ifneq (,$(findstring aarch64,$(UNICORN_ARCHS)))
SOURCES += sample_arm64.c
SOURCES += sample_arm64eb.c
endif
ifneq (,$(findstring mips,$(UNICORN_ARCHS)))
SOURCES += sample_mips.c
endif
#ifneq (,$(findstring ppc,$(UNICORN_ARCHS)))
#SOURCES += sample_ppc.c
#endif
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

BINS = $(SOURCES:.c=$(BIN_EXT))
OBJS = $(SOURCES:.c=.o)

all: $(BINS)

$(BINS): $(OBJS)

clean:		
	rm -rf *.o $(BINS)

%$(BIN_EXT): %.o
	@mkdir -p $(@D)
ifeq ($(V),0)
ifeq ($(UNICORN_SHARED),yes)
	$(call log,LINK,$(notdir $@))
	@$(link-dynamic)
endif
ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
	$(call log,LINK,$(notdir $(call staticname,$@)))
	@$(link-static)
endif
endif
else
ifeq ($(UNICORN_SHARED),yes)
	$(link-dynamic)
endif
ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
	$(link-static)
endif
endif
endif

%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:%=%))
	@$(compile)
else
	$(compile)
endif


define link-dynamic
	$(CC) $< ${CFLAGS} $(LDFLAGS) -o $@
endef


define link-static
	$(CC) $< $(ARCHIVE) ${CFLAGS} $(LDFLAGS) -o $(call staticname,$@)
endef


staticname = $(subst $(BIN_EXT),,$(1)).static$(BIN_EXT)

define log
	@printf "  %-7s %s\n" "$(1)" "$(2)"
endef

define compile
	${CC} ${CFLAGS} -c $< -o $@
endef
