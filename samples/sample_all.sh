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
  echo "=========================="
  $DIR/sample_x86 -16
  echo "=========================="
  $DIR/shellcode -32
  echo "=========================="
  $DIR/mem_apis
fi
if test -e $DIR/sample_arm; then
  echo "=========================="
  $DIR/sample_arm
  $DIR/sample_armeb
fi
if test -e $DIR/sample_arm64; then
  echo "=========================="
  $DIR/sample_arm64
  $DIR/sample_arm64eb
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

if test -e $DIR/mem_apis; then
  echo "=========================="
  $DIR/mem_apis
fi

if test -e $DIR/sample_batch_reg; then
  echo "=========================="
  $DIR/sample_batch_reg
fi

if test -e $DIR/sample_x86_32_gdt_and_seg_regs; then
  echo "=========================="
  $DIR/sample_x86_32_gdt_and_seg_regs
fi
