# AArch32 classes and structures.
#
# @author elicn

from typing import Any, Tuple

import ctypes
import weakref

from unicorn.arch.generic import UcRegImplGeneric

from .. import Uc, UcError
from .. import arm_const as const
from ..unicorn_const import UC_ERR_ARG

ARMCPReg = Tuple[int, int, int, int, int, int, int]
ARMCPRegValue = Tuple[int, int, int, int, int, int, int, int]

class UcRegCP(ctypes.Structure):
    """ARM coprocessors registers for instructions MRC, MCR, MRRC, MCRR
    """

    _fields_ = (
        ('cp',   ctypes.c_uint32),
        ('is64', ctypes.c_uint32),
        ('sec',  ctypes.c_uint32),
        ('crn',  ctypes.c_uint32),
        ('crm',  ctypes.c_uint32),
        ('opc1', ctypes.c_uint32),
        ('opc2', ctypes.c_uint32),
        ('val',  ctypes.c_uint64)
    )

    @property
    def value(self) -> int:
        return self.val

    @classmethod
    def from_param(cls, param: ARMCPRegValue):
        assert type(param) is tuple and len(param) == len(cls._fields_)

        return cls(*param)


class UcAArch32RegImpl(UcRegImplGeneric):
    """Unicorn registers subclass for ARM architecture.
    """

    def __init__(self, uc: Uc) -> None:
        super().__init__(uc)

    def reg_read(self, reg_id: int, aux: Any = None):
        if reg_id == const.UC_ARM_REG_CP_REG:
            return self.uc._reg_read(reg_id, UcRegCP, *aux)

        # fallback to default reading method
        return super().reg_read(reg_id, aux)

    def reg_write(self, reg_id: int, value) -> None:
        if reg_id == const.UC_ARM_REG_CP_REG:
            self._uc()._reg_write(reg_id, UcRegCP, value)
            return

        # fallback to default writing method
        super().reg_write(reg_id, value)
