# Ruby binding for Unicorn engine. Sascha Schirra <sashs@scoding.de>

.PHONY: gen_const

install:
	$(MAKE) gen_const
	cd unicorn_gem && rake build
	cd unicorn_gem && gem install --local pkg/unicorn-0.9.0.gem

gen_const:
	cd .. && python const_generator.py ruby
