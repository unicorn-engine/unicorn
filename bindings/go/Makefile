# Go binding for Unicorn engine. Ryan Hileman <lunixbochs@gmail.com>

.PHONY: all gen_const test

all: gen_const
	cd unicorn && go build

gen_const:
	cd .. && python const_generator.py go

test: all
	cd unicorn && LD_LIBRARY_PATH=../../../ DYLD_LIBRARY_PATH=../../../ go test
