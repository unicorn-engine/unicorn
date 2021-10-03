#!/bin/sh

# Unicorn Emulator Engine (www.unicorn-engine.org)
# Usage: cmake.sh [mingw|msys] [x86] [arm] [aarch64] [m68k] [mips] [sparc] [ppc] [riscv]
# By chenhuitao 2019

# FLAGS="-DCMAKE_BUILD_TYPE=Release"
FLAGS="-DCMAKE_BUILD_TYPE=Debug"
TOOLCHAIN=""
GENERATOR="Unix Makefiles"
CMAKE="cmake"
COMPILER=""

# process arguments
case "$1" in
  "mingw" )
  TOOLCHAIN="-DCMAKE_TOOLCHAIN_FILE=../mingw-w64.cmake"
  shift
  UNICORN_ARCH="${*}";;
  "msys" )
  shift
  UNICORN_ARCH="${*}"
  CMAKE="/mingw64/bin/cmake"
  GENERATOR="MSYS Makefiles";;
  * )
  UNICORN_ARCH="${*}";;
esac

if [ -n "${COMPILER}" ]; then
    TOOLCHAIN="${TOOLCHAIN} -DCMAKE_C_COMPILER=${COMPILER}"
fi

if [ -z "${UNICORN_ARCH}" ]; then
    ${CMAKE} "${FLAGS}" ${TOOLCHAIN} -G "${GENERATOR}" ..
else
    ${CMAKE} "${FLAGS}" ${TOOLCHAIN} "-DUNICORN_ARCH=${UNICORN_ARCH}" -G "${GENERATOR}" ..
fi

# now build
make -j8
