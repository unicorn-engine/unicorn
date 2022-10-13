# Common types and structures.
#
# @author elicn

import ctypes

uc_err	   = ctypes.c_int
uc_mode	   = ctypes.c_int
uc_arch	   = ctypes.c_int
uc_engine  = ctypes.c_void_p
uc_context = ctypes.c_void_p
uc_hook_h  = ctypes.c_size_t


class UcLargeReg(ctypes.Structure):
    """A base class for large registers that are internally represented as
    an array of multiple qwords.

    This class is meant to be inherited, not instantiated directly.
    """

    qwords: ctypes.Array

    @property
    def value(self) -> int:
        return sum(qword << (64 * i) for i, qword in enumerate(self.qwords))

    @classmethod
    def from_param(cls, param: int):
        assert type(param) is int

        mask = (1 << 64) - 1
        size = cls._fields_[0][1]._length_

        return cls(tuple((param >> (64 * i)) & mask for i in range(size)))


class UcReg128(UcLargeReg):
    _fields_ = [('qwords', ctypes.c_uint64 * 2)]


class UcReg256(UcLargeReg):
    _fields_ = [('qwords', ctypes.c_uint64 * 4)]


class UcReg512(UcLargeReg):
    _fields_ = [('qwords', ctypes.c_uint64 * 8)]
