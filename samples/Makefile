# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

include ../config.mk

UNAME_S := $(shell uname -s)

# Find GLIB
ifndef GLIB
GLIB = $(shell pkg-config --libs glib-2.0)
endif

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../include
LDFLAGS += -L.. 
LDLIBS += -lpthread -lunicorn -lm $(GLIB)

ifneq ($(CROSS),)
CC = $(CROSS)gcc
endif

ifeq ($(UNICORN_ASAN),yes)
CC = clang 
CXX = clang++
AR = llvm-ar
CFLAGS += -fsanitize=address -fno-omit-frame-pointer
endif

# Cygwin?
ifneq ($(filter CYGWIN%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
LDLIBS += -lssp
# mingw?
else ifneq ($(filter MINGW%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
endif

.PHONY: all clean

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

BINS = $(SOURCES:.c=)

all: $(BINS)

clean:		
	rm -rf *.o $(BINS)
