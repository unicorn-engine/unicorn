#!/bin/sh
for d in x86_64 arm armeb ppc ppcle ppc64 ppc64le m68k aarch64 aarch64eb mips mipsel mips64 mips64el sparc sparc64; do
	python header_gen.py $d > $d.h
done
