import sys

if sys.version_info[0] == 2:
    from .unicorn_py2 import *
else:
    from .unicorn_py3 import *

__version__ = "%u.%u.%u" % (uc.UC_VERSION_MAJOR, uc.UC_VERSION_MINOR, uc.UC_VERSION_PATCH)