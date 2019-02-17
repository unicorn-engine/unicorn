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

TEMPDIR = tmp

HEADERS = $(wildcard ../include/unicorn/*.h)
HEADERS_DIR = ../include/unicorn
HEADERS_PREPROC_DIR = $(TEMPDIR)
HEADERS_PREPROC  := $(HEADERS:$(HEADERS_DIR)/%.h=$(HEADERS_PREPROC_DIR)/%.h)

.PHONY: build install python c clean check test

tmp_headers: $(TEMPDIR) $(HEADERS_PREPROC)

build: $(TEMPDIR) $(HEADERS_PREPROC)

	$(MAKE) -C python gen_const
	$(MAKE) -C go gen_const
	$(MAKE) -C java gen_const
	$(MAKE) -C ruby gen_const
	python const_generator.py dotnet
	python const_generator.py pascal

$(TEMPDIR):
	-mkdir $(TEMPDIR)

$(HEADERS_PREPROC): $(HEADERS_PREPROC_DIR)/%.h : $(HEADERS_DIR)/%.h
# To generate header file with macro expanded. '-C' to keep comments
	$(CC) -E -C $< -o $@
	@echo "Preprocess "$<" in "$@" successfully!"

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
	-rm -rf $(TEMPDIR)

check:
	make -C python check
