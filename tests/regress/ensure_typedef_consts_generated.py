"""
See https://github.com/unicorn-engine/unicorn/issues/161

Ensure that constants which are specified via a typedef, rather than an enum,
are included in the bindings by the script for autogenerating mappings for
constants.
"""

import regress
import unicorn


class TestTypedefs(regress.RegressTest):
    def runTest(self):
        prop = 'UC_HOOK_MEM_UNMAPPED'

        try:
            getattr(unicorn, prop)
        except AttributeError:
            self.fail("Definition for %s not generated" % prop)


if __name__ == '__main__':
    regress.main()
