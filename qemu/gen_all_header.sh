#!/bin/sh
for d in x86_64 arm m68k aarch64 mips mipsel mips64 mips64el sparc sparc64; do
	python header_gen.py $d > $d.h
done
