#!/bin/sh

# Unicorn Emulator Engine (www.unicorn-engine.org)
# Usage: cmake.sh [x86] [arm] [aarch64] [m68k] [mips] [sparc]
# By chenhuitao 2019

FLAGS="-DCMAKE_BUILD_TYPE=Release"

UNICORN_ARCH="${*}"

if [ -z "${UNICORN_ARCH}" ]; then
    cmake "${FLAGS}" ..
else
    cmake "${FLAGS}" "-DUNICORN_ARCH=${UNICORN_ARCH}" ..
fi

make -j8
