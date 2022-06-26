# Intel architecture classes and structures.
#
# @author elicn

from typing import Any, Callable, Tuple

import ctypes
import weakref

from unicorn.arch.generic import UcHookImplGeneric, UcRegImplGeneric

from .. import Uc, UcError
from .. import x86_const as const

from ..unicorn import _catch_hook_exception, _cast_func
from ..unicorn_const import UC_ERR_ARG, UC_HOOK_INSN
from .types import uc_engine, UcReg128, UcReg256, UcReg512

X86MMRReg = Tuple[int, int, int, int]
X86FPReg = Tuple[int, int]

HOOK_INSN_IN_CFUNC      = ctypes.CFUNCTYPE(ctypes.c_uint32, uc_engine, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p)
HOOK_INSN_OUT_CFUNC     = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p)
HOOK_INSN_SYSCALL_CFUNC = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_void_p)
HOOK_INSN_CPUID_CFUNC   = ctypes.CFUNCTYPE(ctypes.c_uint32, uc_engine, ctypes.c_void_p)


class UcRegMMR(ctypes.Structure):
    """Memory-Management Register for instructions IDTR, GDTR, LDTR, TR.
    """

    _fields_ = (
        ('selector', ctypes.c_uint16),  # not used by GDTR and IDTR
        ('base',     ctypes.c_uint64),  # handle 32 or 64 bit CPUs
        ('limit',    ctypes.c_uint32),
        ('flags',    ctypes.c_uint32)   # not used by GDTR and IDTR
    )

    @property
    def value(self) -> X86MMRReg:
        return tuple(getattr(self, fname) for fname, _ in self._fields_)

    @classmethod
    def from_param(cls, param: X86MMRReg):
        assert type(param) is tuple and len(param) == len(cls._fields_)

        return cls(*param)


class UcRegMSR(ctypes.Structure):
    _fields_ = (
        ('rid', ctypes.c_uint32),
        ('val', ctypes.c_uint64)
    )

    @property
    def value(self) -> int:
        return self.val

    @classmethod
    def from_param(cls, param: Tuple[int, int]):
        assert type(param) is tuple and len(param) == len(cls._fields_)

        return cls(*param)


class UcRegFPR(ctypes.Structure):
    _fields_ = (
        ('mantissa', ctypes.c_uint64),
        ('exponent', ctypes.c_uint16)
    )

    @property
    def value(self) -> X86FPReg:
        return tuple(getattr(self, fname) for fname, _ in self._fields_)

    @classmethod
    def from_param(cls, param: X86FPReg):
        assert type(param) is tuple and len(param) == len(cls._fields_)

        return cls(*param)

class UcIntelRegImpl(UcRegImplGeneric):
    """Unicorn Intel subclass for Intel architecture.
    """

    REG_RANGE_MMR = (
        const.UC_X86_REG_IDTR,
        const.UC_X86_REG_GDTR,
        const.UC_X86_REG_LDTR,
        const.UC_X86_REG_TR
    )

    REG_RANGE_FP  = range(const.UC_X86_REG_FP0,  const.UC_X86_REG_FP7   + 1)
    REG_RANGE_XMM = range(const.UC_X86_REG_XMM0, const.UC_X86_REG_XMM31 + 1)
    REG_RANGE_YMM = range(const.UC_X86_REG_YMM0, const.UC_X86_REG_YMM31 + 1)
    REG_RANGE_ZMM = range(const.UC_X86_REG_ZMM0, const.UC_X86_REG_ZMM31 + 1)

    def __init__(self, uc: Uc) -> None:
        super().__init__(uc)

    @staticmethod
    def __select_reg_class(reg_id: int):
        """Select class for special architectural registers.
        """

        reg_class = (
            (UcIntelRegImpl.REG_RANGE_MMR, UcRegMMR),
            (UcIntelRegImpl.REG_RANGE_FP,  UcRegFPR),
            (UcIntelRegImpl.REG_RANGE_XMM, UcReg128),
            (UcIntelRegImpl.REG_RANGE_YMM, UcReg256),
            (UcIntelRegImpl.REG_RANGE_ZMM, UcReg512)
        )

        return next((cls for rng, cls in reg_class if reg_id in rng), None)


    def reg_read(self, reg_id: int, aux: Any = None):
        # select register class for special cases
        reg_cls = UcIntelRegImpl.__select_reg_class(reg_id)

        if reg_cls is None:
            # backward compatibility: msr read through reg_read
            if reg_id == const.UC_X86_REG_MSR:
                if type(aux) is not int:
                    raise UcError(UC_ERR_ARG)

                value = self.msr_read(aux)

            else:
                value = super().reg_read(reg_id, aux)
        else:
            value = self.uc._reg_read(reg_id, reg_cls)

        return value

    def reg_write(self, reg_id: int, value) -> None:
        # select register class for special cases
        reg_cls = UcIntelRegImpl.__select_reg_class(reg_id)

        if reg_cls is None:
            # backward compatibility: msr write through reg_write
            if reg_id == const.UC_X86_REG_MSR:
                if type(value) is not tuple or len(value) != 2:
                    raise UcError(UC_ERR_ARG)

                self.msr_write(*value)
                return

            super().reg_write(reg_id, value)
        else:
            self.uc._reg_write(reg_id, reg_cls, value)


    def msr_read(self, msr_id: int) -> int:
        return self.uc._reg_read(const.UC_X86_REG_MSR, UcRegMSR, msr_id)


    def msr_write(self, msr_id: int, value: int) -> None:
        self.uc._reg_write(const.UC_X86_REG_MSR, UcRegMSR, (msr_id, value))

class UcIntelHookImpl(UcHookImplGeneric):
    """Unicorn hook subclass for Intel architecture.
    """

    def __init__(self, uc: Uc) -> None:
        super().__init__(uc)

    def hook_add(self, htype: int, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0, aux1: int = 0, aux2: int = 0) -> int:
        if htype != UC_HOOK_INSN:
            return super().hook_add(htype, callback, user_data, begin, end, aux1, aux2)

        insn = ctypes.c_int(aux1)

        def __hook_insn_in():
            @_catch_hook_exception
            def __hook_insn_in_cb(handle: int, port: int, size: int, key: int) -> int:
                return callback(self, port, size, user_data)

            return _cast_func(HOOK_INSN_IN_CFUNC, __hook_insn_in_cb)

        def __hook_insn_out():
            @_catch_hook_exception
            def __hook_insn_out_cb(handle: int, port: int, size: int, value: int, key: int):
                callback(self, port, size, value, user_data)

            return _cast_func(HOOK_INSN_OUT_CFUNC, __hook_insn_out_cb)

        def __hook_insn_syscall():
            @_catch_hook_exception
            def __hook_insn_syscall_cb(handle: int, key: int):
                callback(self, user_data)

            return _cast_func(HOOK_INSN_SYSCALL_CFUNC, __hook_insn_syscall_cb)

        def __hook_insn_cpuid():
            @_catch_hook_exception
            def __hook_insn_cpuid_cb(handle: int, key: int) -> int:
                return callback(self, user_data)

            return _cast_func(HOOK_INSN_CPUID_CFUNC, __hook_insn_cpuid_cb)

        handlers = {
            const.UC_X86_INS_IN       : __hook_insn_in,
            const.UC_X86_INS_OUT      : __hook_insn_out,
            const.UC_X86_INS_SYSCALL  : __hook_insn_syscall,
            const.UC_X86_INS_SYSENTER : __hook_insn_syscall,
            const.UC_X86_INS_CPUID    : __hook_insn_cpuid
        }

        handler = handlers.get(insn.value)

        if handler is None:
            raise UcError(UC_ERR_ARG)

        fptr = handler()

        return self.uc._do_hook_add(htype, fptr, begin, end, insn)

