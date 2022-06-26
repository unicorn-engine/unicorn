from typing import Any, Callable
import weakref
from .. import Uc

class UcImplGeneric:
    """Abstract base class for Unicorn arch-specific impl
    """
    def __init__(self, uc: Uc) -> None:
        # This is important, we must avoid create cyclic ref inside the bindings.
        self._uc = weakref.ref(uc)

    @property
    def uc(self) -> Uc:
        # This might return None when the reference is invalid but the class including
        # all subclasses are not intended for external use so we can make sure Uc lives
        # longer than UcRegGeneric manually.
        return self._uc()

class UcRegImplGeneric(UcImplGeneric):
    """Abstract class for Unicorn reigster implementation
    """

    def __init__(self, uc: Uc) -> None:
        super().__init__(uc)
    
    def reg_read(self, reg_id: int, aux: Any = None):
        return self.uc._reg_read(reg_id, Uc._DEFAULT_REGTYPE)

    def reg_write(self, reg_id: int, value) -> None:
        self.uc._reg_write(reg_id, Uc._DEFAULT_REGTYPE, value)

class UcHookImplGeneric(UcImplGeneric):
    """Abstract class for Unicorn reigster implementation
    """

    def __init__(self, uc: Uc) -> None:
        super().__init__(uc)

    @property
    def _hook_exception(self):
        return self.uc._hook_exception
    
    @_hook_exception.setter
    def _hook_exception(self, e):
        self.uc._hook_exception = e

    def hook_add(self, htype: int, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0, aux1: int = 0, aux2: int = 0) -> int:
        return self.uc._hook_add(htype, callback, user_data, begin, end, aux1, aux2)