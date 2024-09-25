"""AArch64 classes and structures.
"""
# @author elicn

from typing import Any, Callable, NamedTuple, Tuple

import ctypes

# traditional unicorn imports
from unicorn import arm64_const as const
from unicorn.unicorn_const import UC_ERR_ARG, UC_HOOK_INSN

# newly introduced unicorn imports
from ..unicorn import Uc, UcError, uccallback
from .types import uc_engine, UcTupledReg, UcReg128

ARM64CPReg = Tuple[int, int, int, int, int, int]

HOOK_INSN_SYS_CFUNC = ctypes.CFUNCTYPE(ctypes.c_uint32, uc_engine, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p)


class UcRegCP64(UcTupledReg[ARM64CPReg]):
    """ARM64 coprocessors registers for instructions MRS, MSR
    """

    _fields_ = (
        ('crn', ctypes.c_uint32),
        ('crm', ctypes.c_uint32),
        ('op0', ctypes.c_uint32),
        ('op1', ctypes.c_uint32),
        ('op2', ctypes.c_uint32),
        ('val', ctypes.c_uint64)
    )

    @property
    def value(self) -> int:
        return self.val


class UcAArch64(Uc):
    """Unicorn subclass for ARM64 architecture.
    """

    REG_RANGE_Q = range(const.UC_ARM64_REG_Q0, const.UC_ARM64_REG_Q31 + 1)
    REG_RANGE_V = range(const.UC_ARM64_REG_V0, const.UC_ARM64_REG_V31 + 1)

    def hook_add(self, htype: int, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0, aux1: int = 0, aux2: int = 0) -> int:
        if htype != UC_HOOK_INSN:
            return super().hook_add(htype, callback, user_data, begin, end, aux1, aux2)

        insn = ctypes.c_int(aux1)

        def __hook_insn_sys():
            @uccallback(self, HOOK_INSN_SYS_CFUNC)
            def __hook_insn_sys_cb(uc: Uc, reg: int, pcp_reg: Any, key: int) -> int:
                cp_reg = ctypes.cast(pcp_reg, ctypes.POINTER(UcRegCP64)).contents

                class CpReg(NamedTuple):
                    crn: int
                    crm: int
                    op0: int
                    op1: int
                    op2: int
                    val: int

                cp_reg = CpReg(cp_reg.crn, cp_reg.crm, cp_reg.op0, cp_reg.op1, cp_reg.op2, cp_reg.val)

                return callback(uc, reg, cp_reg, user_data)

            return __hook_insn_sys_cb

        handlers = {
            const.UC_ARM64_INS_MRS  : __hook_insn_sys,
            const.UC_ARM64_INS_MSR  : __hook_insn_sys,
            const.UC_ARM64_INS_SYS  : __hook_insn_sys,
            const.UC_ARM64_INS_SYSL : __hook_insn_sys
        }

        handler = handlers.get(insn.value)

        if handler is None:
            raise UcError(UC_ERR_ARG)

        fptr = handler()

        return getattr(self, '_Uc__do_hook_add')(htype, fptr, begin, end, insn)

    @staticmethod
    def __select_reg_class(reg_id: int):
        """Select class for special architectural registers.
        """

        reg_class = (
            (UcAArch64.REG_RANGE_Q, UcReg128),
            (UcAArch64.REG_RANGE_V, UcReg128)
        )

        return next((cls for rng, cls in reg_class if reg_id in rng), None)

    def reg_read(self, reg_id: int, aux: Any = None):
        # select register class for special cases
        reg_cls = UcAArch64.__select_reg_class(reg_id)

        if reg_cls is None:
            if reg_id == const.UC_ARM64_REG_CP_REG:
                return self._reg_read(reg_id, UcRegCP64, *aux)

            else:
                # fallback to default reading method
                return super().reg_read(reg_id, aux)

        return self._reg_read(reg_id, reg_cls)

    def reg_write(self, reg_id: int, value) -> None:
        # select register class for special cases
        reg_cls = UcAArch64.__select_reg_class(reg_id)

        if reg_cls is None:
            if reg_id == const.UC_ARM64_REG_CP_REG:
                self._reg_write(reg_id, UcRegCP64, value)

            else:
                # fallback to default writing method
                super().reg_write(reg_id, value)

        else:
            self._reg_write(reg_id, reg_cls, value)

__all__ = ['UcRegCP64', 'UcAArch64']
