#!/bin/sh

[ -z "${UNAME}" ] && UNAME=$(uname)

DIR=`dirname $0`

if [ "$UNAME" = Darwin ]; then
  export DYLD_LIBRARY_PATH=.
else
  export LD_LIBRARY_PATH=.
fi

if test -e $DIR/sample_x86; then
  echo "=========================="
  $DIR/sample_x86 -32
  echo "=========================="
  $DIR/sample_x86 -64
fi
if test -e $DIR/sample_arm; then
  echo "=========================="
  $DIR/sample_arm
fi
if test -e $DIR/sample_arm64; then
  echo "=========================="
  $DIR/sample_arm64
fi
if test -e $DIR/sample_mips; then
  echo "=========================="
  $DIR/sample_mips
fi
if test -e $DIR/sample_sparc; then
  echo "=========================="
  $DIR/sample_sparc
fi
if test -e $DIR/sample_m68k; then
  echo "=========================="
  $DIR/sample_m68k
fi
