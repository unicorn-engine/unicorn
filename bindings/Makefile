# Unicorn Engine
# By Nguyen Anh Quynh & Dang Hoang Vu, 2015
TMP_DIR = /tmp/unicorn_sample

DIFF = diff -u -w

SAMPLE_ARM = $(TMP_DIR)/sample_arm
SAMPLE_ARM64 = $(TMP_DIR)/sample_arm64
SAMPLE_MIPS = $(TMP_DIR)/sample_mips
SAMPLE_M68K = $(TMP_DIR)/sample_m68k
SAMPLE_SPARC = $(TMP_DIR)/sample_sparc
SAMPLE_X86 = $(TMP_DIR)/sample_x86

.PHONY: build install samples sample_python expected python sample_diff clean check

build:
	cd python && $(MAKE) gen_const
	cd go && $(MAKE) gen_const
	cd java && $(MAKE) gen_const
	python const_generator.py dotnet

install: build
	cd python && $(MAKE) install
	cd java && $(MAKE) install

samples: expected python

sample_python: expected python

expected:
	cd ../samples && $(MAKE)
	mkdir -p $(TMP_DIR)
	../samples/sample_arm > $(SAMPLE_ARM)_e
	../samples/sample_arm64 > $(SAMPLE_ARM64)_e
	../samples/sample_mips > $(SAMPLE_MIPS)_e
	../samples/sample_sparc > $(SAMPLE_SPARC)_e
	../samples/sample_m68k > $(SAMPLE_M68K)_e
	../samples/sample_x86 > $(SAMPLE_X86)_e

python: FORCE
	cd python && $(MAKE)
	python python/sample_arm.py > $(SAMPLE_ARM)_o
	python python/sample_arm64.py > $(SAMPLE_ARM64)_o
	python python/sample_mips.py > $(SAMPLE_MIPS)_o
	python python/sample_sparc.py > $(SAMPLE_SPARC)_o
	python python/sample_m68k.py > $(SAMPLE_M68K)_o
	python python/sample_x86.py > $(SAMPLE_X86)_o
	$(MAKE) sample_diff

sample_diff: FORCE
	$(DIFF) $(SAMPLE_ARM)_e $(SAMPLE_ARM)_o
	$(DIFF) $(SAMPLE_ARM64)_e $(SAMPLE_ARM64)_o
	$(DIFF) $(SAMPLE_MIPS)_e $(SAMPLE_MIPS)_o
	$(DIFF) $(SAMPLE_SPARC)_e $(SAMPLE_SPARC)_o
	$(DIFF) $(SAMPLE_M68K)_e $(SAMPLE_M68K)_o
	$(DIFF) $(SAMPLE_X86)_e $(SAMPLE_X86)_o

clean:
	rm -rf $(TMP_DIR)
	cd python && $(MAKE) clean
	cd java && $(MAKE) clean

check:
	make -C python check

FORCE:
