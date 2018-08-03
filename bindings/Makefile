# Unicorn Engine
# By Nguyen Anh Quynh & Dang Hoang Vu, 2015
DIFF = diff

SAMPLE_SOURCE = $(wildcard ../samples/*.c)
SAMPLE = $(SAMPLE_SOURCE:../samples/%.c=%)
SAMPLE := $(SAMPLE:mem_apis=)
SAMPLE := $(SAMPLE:sample_batch_reg=)
SAMPLE := $(SAMPLE:sample_x86_32_gdt_and_seg_regs=)
SAMPLE := $(SAMPLE:shellcode=)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
ENV_VARS = LD_PRELOAD=librt.so LD_LIBRARY_PATH=../ DYLD_LIBRARY_PATH=../
else
ENV_VARS = LD_LIBRARY_PATH=../ DYLD_LIBRARY_PATH=../ LIBUNICORN_PATH=$(TRAVIS_BUILD_DIR)
endif


.PHONY: build install python c clean check test

build:
	$(MAKE) -C python gen_const
	$(MAKE) -C go gen_const
	$(MAKE) -C java gen_const
	$(MAKE) -C ruby gen_const
	python const_generator.py dotnet
	python const_generator.py pascal

install: build
	$(MAKE) -C python install
	$(MAKE) -C java install

test: $(SAMPLE:%=%.py.test)

c:
	$(MAKE) -C ../samples
python:
	$(MAKE) -C python
%.c.txt: c
	$(ENV_VARS) ../samples/$(@:%.c.txt=%) > $@
%.py.txt: python
	$(ENV_VARS) python python/$(@:%.txt=%) > $@

%.py.test: %.c.txt %.py.txt
	$(DIFF) -u $(@:%.py.test=%.c.txt) $(@:%.py.test=%.py.txt)

clean:
#	rm -rf *.txt
	$(MAKE) -C python clean
	$(MAKE) -C java clean

check:
	make -C python check
