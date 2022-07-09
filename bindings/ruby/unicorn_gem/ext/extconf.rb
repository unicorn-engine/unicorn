require 'mkmf'

extension_name = 'unicorn_engine'

dir_config(extension_name)
pkg_config('unicorn')
have_library('unicorn')

create_makefile(extension_name)
