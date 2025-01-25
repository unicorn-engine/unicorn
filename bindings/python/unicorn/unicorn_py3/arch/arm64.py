"""AArch64 classes and structures.
"""
# @author elicn

from typing import Any, Callable, NamedTuple, Tuple, Type

import ctypes

# traditional unicorn imports
from unicorn import arm64_const as const
from unicorn.unicorn_const import UC_ERR_ARG, UC_HOOK_INSN

# newly introduced unicorn imports
from ..unicorn import Uc, UcError, uccallback, check_maxbits
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


class CpReg(NamedTuple):
    crn: int
    crm: int
    op0: int
    op1: int
    op2: int
    val: int


class UcAArch64(Uc):
    """Unicorn subclass for ARM64 architecture.
    """

    REG_RANGE_CP = (const.UC_ARM64_REG_CP_REG,)

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

    @classmethod
    def _select_reg_class(cls, reg_id: int) -> Type:
        """Select the appropriate class for the specified architectural register.
        """

        reg_class = (
            (UcAArch64.REG_RANGE_CP, UcRegCP64),
            (UcAArch64.REG_RANGE_Q,  UcReg128),
            (UcAArch64.REG_RANGE_V,  UcReg128)
        )

        return next((c for rng, c in reg_class if reg_id in rng), cls._DEFAULT_REGTYPE)

    # to learn more about accessing aarch64 coprocessor registers, refer to:
    # https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers

    def cpr_read(self, op0: int, op1: int, crn: int, crm: int, op2: int) -> int:
        """Read a coprocessor register value.

        Args:
            op0		: opcode 0, value varies between 0 and 3
            op1 	: opcode 1, value varies between 0 and 7
            crn 	: coprocessor register to access (CRn), value varies between 0 and 15
            crm 	: additional coprocessor register to access (CRm), value varies between 0 and 15
            op2 	: opcode 2, value varies between 0 and 7

        Returns: value of coprocessor register
        """

        assert check_maxbits(op0, 2)
        assert check_maxbits(op1, 3)
        assert check_maxbits(crn, 4)
        assert check_maxbits(crm, 4)
        assert check_maxbits(op2, 3)

        return self.reg_read(const.UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2))

    def cpr_write(self, op0: int, op1: int, crn: int, crm: int, op2: int, value: int) -> None:
        """Write a coprocessor register value.

        Args:
            op0		: opcode 0, value varies between 0 and 3
            op1 	: opcode 1, value varies between 0 and 7
            crn 	: coprocessor register to access (CRn), value varies between 0 and 15
            crm 	: additional coprocessor register to access (CRm), value varies between 0 and 15
            op2 	: opcode 2, value varies between 0 and 7
            value	: value to write
        """

        assert check_maxbits(op0, 2)
        assert check_maxbits(op1, 3)
        assert check_maxbits(crn, 4)
        assert check_maxbits(crm, 4)
        assert check_maxbits(op2, 3)

        self.reg_write(const.UC_ARM64_REG_CP_REG, (crn, crm, op0, op1, op2, value))


__all__ = ['UcRegCP64', 'UcAArch64']
