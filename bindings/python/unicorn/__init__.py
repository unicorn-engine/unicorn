# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
import sys
_python2 = sys.version_info[0] < 3
if _python2:
    range = xrange
from . import arm_const, arm64_const, mips_const, sparc_const, m68k_const, x86_const

__all__ = [
    'Uc',

    'uc_version',
    'uc_support',
    'version_bind',
    'debug',

    'UC_API_MAJOR',
    'UC_API_MINOR',

    'UC_ARCH_ARM',
    'UC_ARCH_ARM64',
    'UC_ARCH_MIPS',
    'UC_ARCH_X86',
    'UC_ARCH_SPARC',
    'UC_ARCH_M68K',
    'UC_ARCH_ALL',

    'UC_MODE_LITTLE_ENDIAN',
    'UC_MODE_BIG_ENDIAN',
    'UC_MODE_16',
    'UC_MODE_32',
    'UC_MODE_64',
    'UC_MODE_ARM',
    'UC_MODE_THUMB',
    'UC_MODE_MCLASS',
    'UC_MODE_MICRO',
    'UC_MODE_MIPS3',
    'UC_MODE_MIPS32R6',
    'UC_MODE_MIPSGP64',
    'UC_MODE_V8',
    'UC_MODE_V9',
    'UC_MODE_MIPS32',
    'UC_MODE_MIPS64',

    'UC_ERR_OK',
    'UC_ERR_OOM',
    'UC_ERR_ARCH',
    'UC_ERR_HANDLE',
    'UC_ERR_UCH',
    'UC_ERR_MODE',
    'UC_ERR_VERSION',
    'UC_ERR_MEM_READ',
    'UC_ERR_MEM_WRITE',
    'UC_ERR_CODE_INVALID',
    'UC_ERR_HOOK',
    'UC_ERR_INSN_INVALID',
    'UC_ERR_MAP',

    'UC_HOOK_INTR',
    'UC_HOOK_INSN',
    'UC_HOOK_CODE',
    'UC_HOOK_BLOCK',
    'UC_HOOK_MEM_INVALID',
    'UC_HOOK_MEM_READ',
    'UC_HOOK_MEM_WRITE',
    'UC_HOOK_MEM_READ_WRITE',

    'UC_MEM_READ',
    'UC_MEM_WRITE',
    'UC_MEM_READ_WRITE',

    'UC_SECOND_SCALE',
    'UC_MILISECOND_SCALE',

    'UcError',
]

# Unicorn C interface

# API version
UC_API_MAJOR = 0
UC_API_MINOR = 9

# Architectures
UC_ARCH_ARM = 1
UC_ARCH_ARM64 = 2
UC_ARCH_MIPS = 3
UC_ARCH_X86 = 4
UC_ARCH_PPC = 5
UC_ARCH_SPARC = 6
UC_ARCH_M68K = 7
UC_ARCH_MAX = 8
UC_ARCH_ALL = 0xFFFF

# Hardware modes
UC_MODE_LITTLE_ENDIAN = 0      # little-endian mode (default mode)
UC_MODE_ARM = 0                # ARM mode
UC_MODE_16 = (1 << 1)          # 16-bit mode (for X86)
UC_MODE_32 = (1 << 2)          # 32-bit mode (for X86)
UC_MODE_64 = (1 << 3)          # 64-bit mode (for X86, PPC)
UC_MODE_THUMB = (1 << 4)       # ARM's Thumb mode, including Thumb-2
UC_MODE_MCLASS = (1 << 5)      # ARM's Cortex-M series
UC_MODE_V8 = (1 << 6)          # ARMv8 A32 encodings for ARM
UC_MODE_MICRO = (1 << 4)       # MicroMips mode (MIPS architecture)
UC_MODE_MIPS3 = (1 << 5)       # Mips III ISA
UC_MODE_MIPS32R6 = (1 << 6)    # Mips32r6 ISA
UC_MODE_MIPSGP64 = (1 << 7)    # General Purpose Registers are 64-bit wide (MIPS arch)
UC_MODE_V9 = (1 << 4)          # Sparc V9 mode (for Sparc)
UC_MODE_BIG_ENDIAN = (1 << 31) # big-endian mode
UC_MODE_MIPS32 = UC_MODE_32    # Mips32 ISA
UC_MODE_MIPS64 = UC_MODE_64    # Mips64 ISA


# Unicorn error type
UC_ERR_OK = 0           # No error: everything was fine
UC_ERR_OOM = 1           # Out-Of-Memory error: uc_open(), uc_emulate()
UC_ERR_ARCH = 2          # Unsupported architecture: uc_open()
UC_ERR_HANDLE = 3        # Invalid handle
UC_ERR_UCH = 4           # Invalid handle (uch)
UC_ERR_MODE = 5          # Invalid/unsupported mode: uc_open()
UC_ERR_VERSION = 6       # Unsupported version (bindings)
UC_ERR_MEM_READ = 7      # Quit emulation due to invalid memory READ: uc_emu_start()
UC_ERR_MEM_WRITE = 8     # Quit emulation due to invalid memory WRITE: uc_emu_start()
UC_ERR_CODE_INVALID = 9  # Quit emulation due to invalid code address: uc_emu_start()
UC_ERR_HOOK = 10         # Invalid hook type: uc_hook_add()
UC_ERR_INSN_INVALID = 11 # Invalid instruction
UC_ERR_MAP = 12          # Invalid memory mapping


# All type of hooks for uc_hook_add() API.
UC_HOOK_INTR = 32           # Hook all interrupt events
UC_HOOK_INSN = 33           # Hook a particular instruction
UC_HOOK_CODE = 34           # Hook a range of code
UC_HOOK_BLOCK = 35          # Hook basic blocks
UC_HOOK_MEM_INVALID = 36    # Hook for all invalid memory access events
UC_HOOK_MEM_READ = 37       # Hook all memory read events.
UC_HOOK_MEM_WRITE = 38      # Hook all memory write events.
UC_HOOK_MEM_READ_WRITE = 39 # Hook all memory accesses (either READ or WRITE).


# All type of memory accesses for UC_HOOK_MEM_*
UC_MEM_READ = 16         # Memory is read from
UC_MEM_WRITE = 17        # Memory is written to
UC_MEM_READ_WRITE = 18   # Memory is accessed (either READ or WRITE)


# Time scales to calculate timeout on microsecond unit
# This is for Uc.emu_start()
UC_SECOND_SCALE = 1000000 # 1 second = 1000,000 microseconds
UC_MILISECOND_SCALE = 1000 # 1 milisecond = 1000 nanoseconds


import ctypes, ctypes.util, sys
from os.path import split, join, dirname
import distutils.sysconfig


import inspect
if not hasattr(sys.modules[__name__], '__file__'):
    __file__ = inspect.getfile(inspect.currentframe())

_lib_path = split(__file__)[0]
_all_libs = ['unicorn.dll', 'libunicorn.so', 'libunicorn.dylib']
_found = False

for _lib in _all_libs:
    try:
        _lib_file = join(_lib_path, _lib)
        # print "Trying to load:", _lib_file
        _uc = ctypes.cdll.LoadLibrary(_lib_file)
        _found = True
        break
    except OSError:
        pass

if _found == False:
    # try loading from default paths
    for _lib in _all_libs:
        try:
            _uc = ctypes.cdll.LoadLibrary(_lib)
            _found = True
            break
        except OSError:
            pass

if _found == False:
    # last try: loading from python lib directory
    _lib_path = distutils.sysconfig.get_python_lib()
    for _lib in _all_libs:
        try:
            _lib_file = join(_lib_path, 'unicorn', _lib)
            # print "Trying to load:", _lib_file
            _uc = ctypes.cdll.LoadLibrary(_lib_file)
            _found = True
            break
        except OSError:
            pass
    if _found == False:
        raise ImportError("ERROR: fail to load the dynamic library.")


# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

_setup_prototype(_uc, "uc_version", ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_uc, "uc_support", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_uc, "uc_open", ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_close", ctypes.c_int, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_strerror", ctypes.c_char_p, ctypes.c_int)
_setup_prototype(_uc, "uc_errno", ctypes.c_int, ctypes.c_size_t)
_setup_prototype(_uc, "uc_reg_read", ctypes.c_int, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_reg_write", ctypes.c_int, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_read", ctypes.c_int, ctypes.c_size_t, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_write", ctypes.c_int, ctypes.c_size_t, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_start", ctypes.c_int, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_stop", ctypes.c_int, ctypes.c_size_t)
_setup_prototype(_uc, "uc_hook_del", ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_mem_map", ctypes.c_int, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_size_t)

# uc_hook_add is special due to variable number of arguments
_uc.uc_hook_add = getattr(_uc, "uc_hook_add")
_uc.uc_hook_add.restype = ctypes.c_int

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(None, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p)
UC_HOOK_MEM_INVALID_CB = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_size_t, ctypes.c_int, \
        ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p)
UC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(None, ctypes.c_size_t, ctypes.c_int, \
        ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p)
UC_HOOK_INTR_CB = ctypes.CFUNCTYPE(None, ctypes.c_size_t, ctypes.c_uint32, \
        ctypes.c_void_p)
UC_HOOK_INSN_IN_CB = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_size_t, ctypes.c_uint32, \
        ctypes.c_int, ctypes.c_void_p)
UC_HOOK_INSN_OUT_CB = ctypes.CFUNCTYPE(None, ctypes.c_size_t, ctypes.c_uint32, \
        ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p)
UC_HOOK_INSN_SYSCALL_CB = ctypes.CFUNCTYPE(None, ctypes.c_size_t, ctypes.c_void_p)


# access to error code via @errno of UcError
class UcError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return _uc.uc_strerror(self.errno)


# return the core's version
def uc_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    combined = _uc.uc_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (UC_API_MAJOR, UC_API_MINOR, (UC_API_MAJOR << 8) + UC_API_MINOR)


# check to see if this engine supports a particular arch
def uc_support(query):
    return _uc.uc_support(query)


class Uc(object):
    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = uc_version()
        if major != UC_API_MAJOR or minor != UC_API_MINOR:
            self._uch = None
            # our binding version is different from the core's API version
            raise UcError(UC_ERR_VERSION)

        self._arch, self._mode = arch, mode
        self._uch = ctypes.c_size_t()
        status = _uc.uc_open(arch, mode, ctypes.byref(self._uch))
        if status != UC_ERR_OK:
            self._uch = None
            raise UcError(status)
        # internal mapping table to save callback & userdata
        self._callbacks = {}
        self._callback_count = 0


    # destructor to be called automatically when object is destroyed.
    def __del__(self):
        if self._uch:
            try:
                status = _uc.uc_close(ctypes.byref(self._uch))
                if status != UC_ERR_OK:
                    raise UcError(status)
            except: # _uc might be pulled from under our feet
                pass


    # emulate from @begin, and stop when reaching address @until
    def emu_start(self, begin, until, timeout=0, count=0):
        status = _uc.uc_emu_start(self._uch, begin, until, timeout, count)
        if status != UC_ERR_OK:
            raise UcError(status)


    # stop emulation
    def emu_stop(self):
        status = _uc.uc_emu_stop(self._uch)
        if status != UC_ERR_OK:
            raise UcError(status)


    # return the value of a register
    def reg_read(self, reg_id):
        # read to 64bit number to be safe
        reg = ctypes.c_int64(0)
        status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
        if status != UC_ERR_OK:
            raise UcError(status)
        return reg.value


    # write to a register
    def reg_write(self, reg_id, value):
        # convert to 64bit number to be safe
        reg = ctypes.c_int64(value)
        status = _uc.uc_reg_write(self._uch, reg_id, ctypes.byref(reg))
        if status != UC_ERR_OK:
            raise UcError(status)


    # read data from memory
    def mem_read(self, address, size):
        data = ctypes.create_string_buffer(size)
        status = _uc.uc_mem_read(self._uch, address, data, size)
        if status != UC_ERR_OK:
            raise UcError(status)
        return bytearray(data)


    # write to memory
    def mem_write(self, address, data):
        status = _uc.uc_mem_write(self._uch, address, data, len(data))
        if status != UC_ERR_OK:
            raise UcError(status)


    # map a range of memory
    def mem_map(self, address, size):
        status = _uc.uc_mem_map(self._uch, address, size)
        if status != UC_ERR_OK:
            raise UcError(status)


    def _hookcode_cb(self, handle, address, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, address, size, data)


    def _hook_mem_invalid_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, access, address, size, value, data)


    def _hook_mem_access_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, access, address, size, value, data)


    def _hook_intr_cb(self, handle, intno, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, intno, data)


    def _hook_insn_in_cb(self, handle, port, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, port, size, data)


    def _hook_insn_out_cb(self, handle, port, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, port, size, value, data)


    def _hook_insn_syscall_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, data)


    # add a hook
    def hook_add(self, htype, callback, user_data=None, arg1=1, arg2=0):
        _h2 = ctypes.c_size_t()

        # save callback & user_data
        self._callback_count += 1
        self._callbacks[self._callback_count] = (callback, user_data)

        if htype in (UC_HOOK_BLOCK, UC_HOOK_CODE):
            begin = ctypes.c_uint64(arg1)
            end = ctypes.c_uint64(arg2)
            # set callback with wrapper, so it can be called
            # with this object as param
            cb = ctypes.cast(UC_HOOK_CODE_CB(self._hookcode_cb), UC_HOOK_CODE_CB)
            status = _uc.uc_hook_add(self._uch, ctypes.byref(_h2), htype, cb, \
                    ctypes.cast(self._callback_count, ctypes.c_void_p), begin, end)
        elif htype == UC_HOOK_MEM_INVALID:
            cb = ctypes.cast(UC_HOOK_MEM_INVALID_CB(self._hook_mem_invalid_cb), UC_HOOK_MEM_INVALID_CB)
            status = _uc.uc_hook_add(self._uch, ctypes.byref(_h2), htype, \
                    cb, ctypes.cast(self._callback_count, ctypes.c_void_p))
        elif htype in (UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ_WRITE):
            cb = ctypes.cast(UC_HOOK_MEM_ACCESS_CB(self._hook_mem_access_cb), UC_HOOK_MEM_ACCESS_CB)
            status = _uc.uc_hook_add(self._uch, ctypes.byref(_h2), htype, \
                    cb, ctypes.cast(self._callback_count, ctypes.c_void_p))
        elif htype == UC_HOOK_INSN:
            insn = ctypes.c_int(arg1)
            if arg1 == x86_const.X86_INS_IN:  # IN instruction
                cb = ctypes.cast(UC_HOOK_INSN_IN_CB(self._hook_insn_in_cb), UC_HOOK_INSN_IN_CB)
            if arg1 == x86_const.X86_INS_OUT: # OUT instruction
                cb = ctypes.cast(UC_HOOK_INSN_OUT_CB(self._hook_insn_out_cb), UC_HOOK_INSN_OUT_CB)
            if arg1 in (x86_const.X86_INS_SYSCALL, x86_const.X86_INS_SYSENTER): # SYSCALL/SYSENTER instruction
                cb = ctypes.cast(UC_HOOK_INSN_SYSCALL_CB(self._hook_insn_syscall_cb), UC_HOOK_INSN_SYSCALL_CB)
            status = _uc.uc_hook_add(self._uch, ctypes.byref(_h2), htype, \
                    cb, ctypes.cast(self._callback_count, ctypes.c_void_p), insn)
        elif htype == UC_HOOK_INTR:
            cb = ctypes.cast(UC_HOOK_INTR_CB(self._hook_intr_cb), UC_HOOK_INTR_CB)
            status = _uc.uc_hook_add(self._uch, ctypes.byref(_h2), htype, \
                    cb, ctypes.cast(self._callback_count, ctypes.c_void_p))

        if status != UC_ERR_OK:
            raise UcError(status)

        return _h2.value


    # delete a hook
    def hook_del(self, h):
        _h = ctypes.c_size_t(h)
        status = _uc.uc_hook_del(self._uch, ctypes.byref(_h))
        if status != UC_ERR_OK:
            raise UcError(status)
        h = 0


# print out debugging info
def debug():
    archs = { "arm": UC_ARCH_ARM, "arm64": UC_ARCH_ARM64, \
        "mips": UC_ARCH_MIPS, "sparc": UC_ARCH_SPARC, \
        "m68k": UC_ARCH_M68K }

    all_archs = ""
    keys = archs.keys()
    keys.sort()
    for k in keys:
        if uc_support(archs[k]):
            all_archs += "-%s" % k

    if uc_support(UC_ARCH_X86):
        all_archs += "-x86"
        if uc_support(UC_SUPPORT_X86_REDUCE):
            all_archs += "_reduce"

    (major, minor, _combined) = uc_version()

    return "python-%s-c%u.%u-b%u.%u" % (all_archs, major, minor, UC_API_MAJOR, UC_API_MINOR)
