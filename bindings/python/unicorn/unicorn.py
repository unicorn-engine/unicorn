import sys as _sys

from .unicorn_const import (
    UC_VERSION_MAJOR as __MAJOR,
    UC_VERSION_MINOR as __MINOR,
    UC_VERSION_PATCH as __PATCH
)

__version__ = "%u.%u.%u" % (__MAJOR, __MINOR, __PATCH)

if _sys.version_info.major == 2:
    from .unicorn_py2 import *
else:
    from .unicorn_py3 import *
