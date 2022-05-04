# Ruby binding for Unicorn engine. Sascha Schirra <sashs@scoding.de>

.PHONY: gen_const

# Use bundle install && rake to install gem and test
install: gen_const
	cd unicorn_gem && rake build
	cd unicorn_gem && gem install --local pkg/unicorn-engine-2.0.0.gem

gen_const:
	cd .. && python3 const_generator.py ruby
