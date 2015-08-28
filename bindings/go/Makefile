# Go binding for Unicorn engine. Ryan Hileman <lunixbochs@gmail.com>

.PHONY: gen_const test

gen_const:
	cd .. && python const_generator.py go
	cd unicorn && go build

test:
	cd unicorn && go test
