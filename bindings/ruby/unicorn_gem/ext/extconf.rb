require 'mkmf'

extension_name = 'unicornengine'

dir_config(extension_name)
have_library('unicorn')

create_makefile(extension_name)
