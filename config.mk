# Unicorn Emulator Engine
# By Nguyen Anh Quynh, 2015

# This file contains all customized compile options for Unicorn emulator.
# Consult docs/COMPILE.md & docs/README.md for more details.

################################################################################
# Compile with debug info when you want to debug code.
# Change this to 'no' for release edition.

UNICORN_DEBUG ?= yes

################################################################################
# Specify which archs you want to compile in. By default, we build all archs.

UNICORN_ARCHS ?= x86 m68k arm aarch64 mips sparc


################################################################################
# Change 'UNICORN_STATIC = yes' to 'UNICORN_STATIC = no' to avoid building
# a static library.

UNICORN_STATIC ?= yes


################################################################################
# Change 'UNICORN_SHARED = yes' to 'UNICORN_SHARED = no' to avoid building
# a shared library.

UNICORN_SHARED ?= yes
