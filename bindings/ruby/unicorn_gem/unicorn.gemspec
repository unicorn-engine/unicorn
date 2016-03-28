# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'unicorn/version'

Gem::Specification.new do |spec|
  spec.name          = "unicorn"
  spec.version       = Unicorn::VERSION
  spec.authors       = ["Sascha Schirra"]
  spec.email         = ["sashs@scoding.de"]
  spec.license       = 'GPL-2.0'
  spec.summary       = %q{Ruby binding for Unicorn-Engine}
  spec.description   = %q{Ruby binding for Unicorn-Engine <unicorn-engine.org>}
  spec.homepage      = "https://unicorn-engine.org"

  spec.files         = Dir["lib/unicorn/*.rb"] + Dir["ext/unicorn.c"] + Dir["ext/unicorn.h"] + Dir["ext/extconf.rb"]
  spec.require_paths = ["lib","ext"]
  spec.extensions    = ["ext/extconf.rb"]
  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
end
