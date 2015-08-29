#!/bin/sh

./sample_x86.py
echo "=========================="
./shellcode.py
echo "=========================="
./sample_arm.py
echo "=========================="
./sample_arm64.py
echo "=========================="
./sample_mips.py
echo "=========================="
./sample_sparc.py
echo "=========================="
./sample_m68k.py
