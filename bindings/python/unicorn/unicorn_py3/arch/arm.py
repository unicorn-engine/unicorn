"""AArch32 classes and structures.
"""
# @author elicn

from typing import Tuple, Type

import ctypes

# traditional unicorn imports
from unicorn import arm_const as const

# newly introduced unicorn imports
from ..unicorn import Uc, check_maxbits
from .types import UcTupledReg, UcReg128

ARMCPReg = Tuple[int, int, int, int, int, int, int, int]


class UcRegCP(UcTupledReg[ARMCPReg]):
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


class UcAArch32(Uc):
    """Unicorn subclass for ARM architecture.
    """

    REG_RANGE_CP = (const.UC_ARM_REG_CP_REG,)

    REG_RANGE_Q = range(const.UC_ARM_REG_Q0, const.UC_ARM_REG_Q15 + 1)

    @classmethod
    def _select_reg_class(cls, reg_id: int) -> Type:
        """Select the appropriate class for the specified architectural register.
        """

        reg_class = (
            (UcAArch32.REG_RANGE_CP, UcRegCP),
            (UcAArch32.REG_RANGE_Q, UcReg128)
        )

        return next((c for rng, c in reg_class if reg_id in rng), cls._DEFAULT_REGTYPE)

    # to learn more about accessing aarch32 coprocessor registers, refer to:
    # https://developer.arm.com/documentation/ddi0601/latest/AArch32-Registers

    def cpr_read(self, coproc: int, opc1: int, crn: int, crm: int, opc2: int, el: int, is_64: bool) -> int:
        """Read a coprocessor register value.

        Args:
            coproc  : coprocessor to access, value varies between 0 and 15
            opc1    : opcode 1, value varies between 0 and 7
            crn     : coprocessor register to access (CRn), value varies between 0 and 15
            crm     : additional coprocessor register to access (CRm), value varies between 0 and 15
            opc2    : opcode 2, value varies between 0 and 7
            el      : the exception level the coprocessor register belongs to, value varies between 0 and 3
            is_64   : indicates whether this is a 64-bit register

        Returns: value of coprocessor register
        """

        assert check_maxbits(coproc, 4)
        assert check_maxbits(opc1,   3)
        assert check_maxbits(crn,    4)
        assert check_maxbits(crm,    4)
        assert check_maxbits(opc2,   3)
        assert check_maxbits(el,     2)  # note that unicorn currently supports only EL0 and EL1

        return self.reg_read(const.UC_ARM_REG_CP_REG, (coproc, int(is_64), el, crn, crm, opc1, opc2))

    def cpr_write(self, coproc: int, opc1: int, crn: int, crm: int, opc2: int, el: int, is_64: bool, value: int) -> None:
        """Write a coprocessor register value.

        Args:
            coproc  : coprocessor to access, value varies between 0 and 15
            opc1    : opcode 1, value varies between 0 and 7
            crn     : coprocessor register to access (CRn), value varies between 0 and 15
            crm     : additional coprocessor register to access (CRm), value varies between 0 and 15
            opc2    : opcode 2, value varies between 0 and 7
            el      : the exception level the coprocessor register belongs to, value varies between 0 and 3
            is_64   : indicates whether this is a 64-bit register
            value   : value to write
        """

        assert check_maxbits(coproc, 4)
        assert check_maxbits(opc1,   3)
        assert check_maxbits(crn,    4)
        assert check_maxbits(crm,    4)
        assert check_maxbits(opc2,   3)
        assert check_maxbits(el,     2)  # note that unicorn currently supports only EL0 and EL1

        self.reg_write(const.UC_ARM_REG_CP_REG, (coproc, int(is_64), el, crn, crm, opc1, opc2, value))


__all__ = ['UcRegCP', 'UcAArch32']
