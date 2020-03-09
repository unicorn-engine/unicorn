#!/bin/sh

# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

usage() {
    cat 1>&2 <<EOF
make.sh - The build script for unicorn engine
USAGE:
    $ ./make.sh [OPTIONS]
OPTIONS:
                            Build the project
    asan                    Build for ASan
    install                 Install the project
    uninstall               Uninstall the project
    macos-universal         Build universal binaries on macOS
    macos-universal-no      Build non-universal binaries that includes only 64-bit code on macOS
    cross-win32             Cross-compile Windows 32-bit binary with MinGW
    cross-win64             Cross-compile Windows 64-bit binary with MinGW
    cross-android_arm       Cross-compile for Android Arm
    cross-android_arm64     Cross-compile for Android Arm64
    linux32                 Cross-compile Unicorn on 64-bit Linux to target 32-bit binary
    msvc_update_genfiles    Generate files for MSVC projects
EOF
}

MAKE_JOBS=$((MAKE_JOBS+0))
[ ${MAKE_JOBS} -lt 1 ] && \
  MAKE_JOBS=4

# build for ASAN
asan() {
  env UNICORN_DEBUG=yes UNICORN_ASAN=yes "${MAKE}" V=1
}

build_cross() {
  [ "$UNAME" = Darwin ] && LIBARCHS="i386 x86_64"
  CROSS=$1
  CC=$CROSS-gcc \
  AR=$CROSS-gcc-ar \
  RANLIB=$CROSS-gcc-ranlib \
  ${MAKE}
}

build_linux32() {
  PKG_CONFIG_PATH="/usr/lib/i386-linux-gnu/pkgconfig" \
  CFLAGS=-m32 \
  LDFLAGS=-m32 \
  LDFLAGS_STATIC=-m32 \
  LIBRARY_PATH="/usr/lib/i386-linux-gnu" \
  UNICORN_QEMU_FLAGS="--cpu=i386 ${UNICORN_QEMU_FLAGS}" \
  ${MAKE}
}

install() {
  # Mac OSX needs to find the right directory for pkgconfig
  if [ "$UNAME" = Darwin ]; then
    # we are going to install into /usr/local, so remove old installs under /usr
    rm -rf /usr/lib/libunicorn*
    rm -rf /usr/include/unicorn
    # install into /usr/local
    PREFIX=${PREFIX:-/usr/local}
    ${MAKE} install
  else  # not OSX
    test -d /usr/lib64 && LIBDIRARCH=lib64
    ${MAKE} install
  fi
}

uninstall() {
  # Mac OSX needs to find the right directory for pkgconfig
  if [ "$UNAME" = "Darwin" ]; then
    # find the directory automatically, so we can support both Macport & Brew
    PKGCFGDIR="$(pkg-config --variable pc_path pkg-config | cut -d ':' -f 1)"
    PREFIX=${PREFIX:-/usr/local}
    ${MAKE} uninstall
  else  # not OSX
    test -d /usr/lib64 && LIBDIRARCH=lib64
    ${MAKE} uninstall
  fi
}

msvc_update_genfiles() {
  ${MAKE}
  cp qemu/qapi-types.h  msvc/unicorn/qapi-types.h
  cp qemu/qapi-visit.h  msvc/unicorn/qapi-visit.h
  cp qemu/qapi-types.c  msvc/unicorn/qapi-types.c
  cp qemu/qapi-visit.c  msvc/unicorn/qapi-visit.c
  cp qemu/config-host.h msvc/unicorn/config-host.h
  cp qemu/aarch64-softmmu/config-target.h  msvc/unicorn/aarch64-softmmu/config-target.h
  cp qemu/aarch64eb-softmmu/config-target.h  msvc/unicorn/aarch64eb-softmmu/config-target.h
  cp qemu/arm-softmmu/config-target.h      msvc/unicorn/arm-softmmu/config-target.h
  cp qemu/armeb-softmmu/config-target.h    msvc/unicorn/armeb-softmmu/config-target.h
  cp qemu/m68k-softmmu/config-target.h     msvc/unicorn/m68k-softmmu/config-target.h
  cp qemu/mips64el-softmmu/config-target.h msvc/unicorn/mips64el-softmmu/config-target.h
  cp qemu/mips64-softmmu/config-target.h   msvc/unicorn/mips64-softmmu/config-target.h
  cp qemu/mipsel-softmmu/config-target.h   msvc/unicorn/mipsel-softmmu/config-target.h
  cp qemu/mips-softmmu/config-target.h     msvc/unicorn/mips-softmmu/config-target.h
  cp qemu/sparc64-softmmu/config-target.h  msvc/unicorn/sparc64-softmmu/config-target.h
  cp qemu/sparc-softmmu/config-target.h    msvc/unicorn/sparc-softmmu/config-target.h
  cp qemu/x86_64-softmmu/config-target.h   msvc/unicorn/x86_64-softmmu/config-target.h
}

UNAME=${UNAME:-$(uname)}
MAKE=${MAKE:-make}
#[ -n "${MAKE_JOBS}" ] && MAKE="$MAKE -j${MAKE_JOBS}"


if [ "$UNAME" = SunOS ]; then
  MAKE=${MAKE:-gmake}
  INSTALL_BIN=ginstall
  CC=gcc
fi

if echo "$UNAME" | grep -q BSD; then
  MAKE=gmake
  PREFIX=${PREFIX:-/usr/local}
fi

export CC INSTALL_BIN PREFIX PKGCFGDIR LIBDIRARCH LIBARCHS CFLAGS LDFLAGS

case "$1" in
  "" ) ${MAKE};;
  "asan" ) asan;;
  "install" ) install;;
  "uninstall" ) uninstall;;
  "macos-universal" ) MACOS_UNIVERSAL=yes ${MAKE};;
  "macos-universal-no" ) MACOS_UNIVERSAL=no ${MAKE};;
  "cross-win32" ) build_cross i686-w64-mingw32;;
  "cross-win64" ) build_cross x86_64-w64-mingw32;;
  "cross-android_arm" ) CROSS=arm-linux-androideabi ${MAKE};;
  "cross-android_arm64" ) CROSS=aarch64-linux-android ${MAKE};;
  "linux32" ) build_linux32;;
  "msvc_update_genfiles" ) msvc_update_genfiles;;
  * )
    usage;
    exit 1;;
esac
