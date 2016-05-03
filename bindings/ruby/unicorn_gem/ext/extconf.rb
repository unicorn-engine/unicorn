require 'mkmf'

extension_name = 'unicorn'

dir_config(extension_name)
have_library('unicorn')

create_makefile(extension_name)