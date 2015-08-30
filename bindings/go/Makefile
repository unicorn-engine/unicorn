# Go binding for Unicorn engine. Ryan Hileman <lunixbochs@gmail.com>

.PHONY: gen_const test

all:
	$(MAKE) gen_const
	cd unicorn && go build
	$(MAKE) test

gen_const:
	cd .. && python const_generator.py go

test:
	cd unicorn && go test
