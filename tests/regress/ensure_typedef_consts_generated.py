#!/usr/bin/python

"""See https://github.com/unicorn-engine/unicorn/issues/161

Ensure that constants which are specified via a typedef, rather than an enum,
are included in the bindings by the script for autogenerating mappings for
constants.
"""

import unicorn

try:
    unicorn.UC_HOOK_MEM_UNMAPPED
except AttributeError:
    assert(False and "Definition for UC_HOOK_MEM_UNMAPPED not generated")
