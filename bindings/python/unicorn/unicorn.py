# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import annotations
import ctypes
import ctypes.util
import distutils.sysconfig
from functools import wraps
from typing import Any, Callable, List, Tuple, Union
import pkg_resources
import inspect
import os.path
import sys
import weakref
import functools
from collections import namedtuple

from . import x86_const, arm_const, arm64_const, unicorn_const as uc

if not hasattr(sys.modules[__name__], "__file__"):
    __file__ = inspect.getfile(inspect.currentframe())

_python2 = sys.version_info[0] < 3
if _python2:
    range = xrange

_lib = { 'darwin': 'libunicorn.2.dylib',
         'win32': 'unicorn.dll',
         'cygwin': 'cygunicorn.dll',
         'linux': 'libunicorn.so.2',
         'linux2': 'libunicorn.so.2' }


# Windows DLL in dependency order
_all_windows_dlls = (
    "libwinpthread-1.dll",
    "libgcc_s_seh-1.dll",
    "libgcc_s_dw2-1.dll",
)

_loaded_windows_dlls = set()

def _load_win_support(path):
    for dll in _all_windows_dlls:
        if dll in _loaded_windows_dlls:
            continue

        lib_file = os.path.join(path, dll)
        if ('/' not in path and '\\' not in path) or os.path.exists(lib_file):
            try:
                #print('Trying to load Windows library', lib_file)
                ctypes.cdll.LoadLibrary(lib_file)
                #print('SUCCESS')
                _loaded_windows_dlls.add(dll)
            except OSError as e:
                #print('FAIL to load %s' %lib_file, e)
                continue

# Initial attempt: load all dlls globally
if sys.platform in ('win32', 'cygwin'):
    _load_win_support('')

def _load_lib(path, lib_name):
    try:
        if sys.platform in ('win32', 'cygwin'):
            _load_win_support(path)

        lib_file = os.path.join(path, lib_name)
        dll = ctypes.cdll.LoadLibrary(lib_file)
        #print('SUCCESS')
        return dll
    except OSError as e:
        #print('FAIL to load %s' %lib_file, e)
        return None

_uc = None

# Loading attempts, in order
# - user-provided environment variable
# - pkg_resources can get us the path to the local libraries
# - we can get the path to the local libraries by parsing our filename
# - global load
# - python's lib directory
# - last-gasp attempt at some hardcoded paths on darwin and linux

_path_list = [os.getenv('LIBUNICORN_PATH', None),
              pkg_resources.resource_filename(__name__, 'lib'),
              os.path.join(os.path.split(__file__)[0], 'lib'),
              '',
              distutils.sysconfig.get_python_lib(),
              "/usr/local/lib/" if sys.platform == 'darwin' else '/usr/lib64',
              os.getenv('PATH', '')]

#print(_path_list)
#print("-" * 80)

for _path in _path_list:
    if _path is None: continue
    _uc = _load_lib(_path, _lib.get(sys.platform, "libunicorn.so"))
    if _uc is not None:
        break

# Try to search old unicorn1 library without SONAME
if _uc is None:
    for _path in _path_list:
        if _path is None:
            continue
        
        _uc = _load_lib(_path, "libunicorn.so")
        if _uc is not None:
            # In this case, show a warning for users
            print("Found an old style dynamic library libunicorn.so, consider checking your installation", file=sys.stderr)
            break

if _uc is None:
    raise ImportError("ERROR: fail to load the dynamic library.")

__version__ = "%u.%u.%u" % (uc.UC_VERSION_MAJOR, uc.UC_VERSION_MINOR, uc.UC_VERSION_PATCH)

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    try:
        getattr(lib, fname).restype = restype
        getattr(lib, fname).argtypes = argtypes
    except AttributeError:
        raise ImportError("ERROR: Fail to setup some function prototypes. Make sure you have cleaned your unicorn1 installation.")

ucerr = ctypes.c_int
uc_mode = ctypes.c_int
uc_arch = ctypes.c_int
uc_engine = ctypes.c_void_p
uc_context = ctypes.c_void_p
uc_hook_h = ctypes.c_size_t

class _uc_mem_region(ctypes.Structure):
    _fields_ = [
        ("begin", ctypes.c_uint64),
        ("end",   ctypes.c_uint64),
        ("perms", ctypes.c_uint32),
    ]

class uc_tb(ctypes.Structure):
    """"TranslationBlock"""
    _fields_ = [
        ("pc", ctypes.c_uint64),
        ("icount", ctypes.c_uint16),
        ("size", ctypes.c_uint16)
    ]

_setup_prototype(_uc, "uc_version", ctypes.c_uint, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_uc, "uc_arch_supported", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_uc, "uc_open", ucerr, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(uc_engine))
_setup_prototype(_uc, "uc_close", ucerr, uc_engine)
_setup_prototype(_uc, "uc_strerror", ctypes.c_char_p, ucerr)
_setup_prototype(_uc, "uc_errno", ucerr, uc_engine)
_setup_prototype(_uc, "uc_reg_read", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_reg_write", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_read", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_write", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_start", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_stop", ucerr, uc_engine)
_setup_prototype(_uc, "uc_hook_del", ucerr, uc_engine, uc_hook_h)
_setup_prototype(_uc, "uc_mmio_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_mem_map_ptr", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_unmap", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_protect", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_query", ucerr, uc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_context_alloc", ucerr, uc_engine, ctypes.POINTER(uc_context))
_setup_prototype(_uc, "uc_free", ucerr, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_save", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_restore", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_size", ctypes.c_size_t, uc_engine)
_setup_prototype(_uc, "uc_context_reg_read", ucerr, uc_context, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_reg_write", ucerr, uc_context, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_free", ucerr, uc_context)
_setup_prototype(_uc, "uc_mem_regions", ucerr, uc_engine, ctypes.POINTER(ctypes.POINTER(_uc_mem_region)), ctypes.POINTER(ctypes.c_uint32))
# https://bugs.python.org/issue42880
_setup_prototype(_uc, "uc_hook_add", ucerr, uc_engine, ctypes.POINTER(uc_hook_h), ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)
_setup_prototype(_uc, "uc_ctl", ucerr, uc_engine, ctypes.c_int)

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p)
UC_HOOK_INSN_INVALID_CB = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ctypes.c_void_p)
UC_HOOK_MEM_INVALID_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
UC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
UC_HOOK_INTR_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32, ctypes.c_void_p
)
UC_HOOK_INSN_IN_CB = ctypes.CFUNCTYPE(
    ctypes.c_uint32, uc_engine, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
)
UC_HOOK_INSN_OUT_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32,
    ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p
)
UC_HOOK_INSN_SYSCALL_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_void_p)
UC_HOOK_INSN_SYS_CB = ctypes.CFUNCTYPE(ctypes.c_uint32, uc_engine, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p)
UC_HOOK_INSN_CPUID_CB = ctypes.CFUNCTYPE(ctypes.c_uint32, uc_engine, ctypes.c_void_p)
UC_MMIO_READ_CB = ctypes.CFUNCTYPE(
    ctypes.c_uint64, uc_engine, ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p
)
UC_MMIO_WRITE_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint64, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p
)
UC_HOOK_EDGE_GEN_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.POINTER(uc_tb), ctypes.POINTER(uc_tb), ctypes.c_void_p
)
UC_HOOK_TCG_OPCODE_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p
)

# access to error code via @errno of UcError
class UcError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return _uc.uc_strerror(self.errno).decode('ascii')


# return the core's version
def uc_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    combined = _uc.uc_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (
        uc.UC_API_MAJOR, uc.UC_API_MINOR,
        (uc.UC_API_MAJOR << 8) + uc.UC_API_MINOR,
    )


# check to see if this engine supports a particular arch
def uc_arch_supported(query):
    return _uc.uc_arch_supported(query)

ARMCPReg = Tuple[int, int, int, int, int, int, int]
ARM64CPReg = Tuple[int, int, int, int, int]
ARMCPRegValue = Tuple[int, int, int, int, int, int, int, int]
ARM64CPRegValue = Tuple[int, int, int, int, int, int]
X86MMRReg = Tuple[int, int, int, int]
X86FPReg = Tuple[int, int]

# uc_reg_read/write and uc_context_reg_read/write.
def reg_read(reg_read_func, arch, reg_id, opt=None):
    if arch == uc.UC_ARCH_X86:
        if reg_id in [x86_const.UC_X86_REG_IDTR, x86_const.UC_X86_REG_GDTR, x86_const.UC_X86_REG_LDTR, x86_const.UC_X86_REG_TR]:
            reg = uc_x86_mmr()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.selector, reg.base, reg.limit, reg.flags
        if reg_id in range(x86_const.UC_X86_REG_FP0, x86_const.UC_X86_REG_FP0+8):
            reg = uc_x86_float80()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.mantissa, reg.exponent
        if reg_id in range(x86_const.UC_X86_REG_XMM0, x86_const.UC_X86_REG_XMM0+8):
            reg = uc_x86_xmm()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.low_qword | (reg.high_qword << 64)
        if reg_id in range(x86_const.UC_X86_REG_YMM0, x86_const.UC_X86_REG_YMM0+16):
            reg = uc_x86_ymm()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.first_qword | (reg.second_qword << 64) | (reg.third_qword << 128) | (reg.fourth_qword << 192)
        if reg_id is x86_const.UC_X86_REG_MSR:
            if opt is None:
                raise UcError(uc.UC_ERR_ARG)
            reg = uc_x86_msr()
            reg.rid = opt
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.value

    if arch == uc.UC_ARCH_ARM:
        if reg_id == arm_const.UC_ARM_REG_CP_REG:
            reg = uc_arm_cp_reg()
            if not isinstance(opt, tuple) or len(opt) != 7:
                raise UcError(uc.UC_ERR_ARG)
            reg.cp, reg.is64, reg.sec, reg.crn, reg.crm, reg.opc1, reg.opc2 = opt
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.val

    if arch == uc.UC_ARCH_ARM64:
        if reg_id == arm64_const.UC_ARM64_REG_CP_REG:
            reg = uc_arm64_cp_reg()
            if not isinstance(opt, tuple) or len(opt) != 5:
                raise UcError(uc.UC_ERR_ARG)
            reg.crn, reg.crm, reg.op0, reg.op1, reg.op2 = opt
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.val

        elif reg_id in range(arm64_const.UC_ARM64_REG_Q0, arm64_const.UC_ARM64_REG_Q31+1) or reg_id in range(arm64_const.UC_ARM64_REG_V0, arm64_const.UC_ARM64_REG_V31+1):
            reg = uc_arm64_neon128()
            status = reg_read_func(reg_id, ctypes.byref(reg))
            if status != uc.UC_ERR_OK:
                raise UcError(status)
            return reg.low_qword | (reg.high_qword << 64)

    # read to 64bit number to be safe
    reg = ctypes.c_uint64(0)
    status = reg_read_func(reg_id, ctypes.byref(reg))
    if status != uc.UC_ERR_OK:
        raise UcError(status)
    return reg.value

def reg_write(reg_write_func, arch, reg_id, value):
    reg = None

    if arch == uc.UC_ARCH_X86:
        if reg_id in [x86_const.UC_X86_REG_IDTR, x86_const.UC_X86_REG_GDTR, x86_const.UC_X86_REG_LDTR, x86_const.UC_X86_REG_TR]:
            assert isinstance(value, tuple) and len(value) == 4
            reg = uc_x86_mmr()
            reg.selector = value[0]
            reg.base = value[1]
            reg.limit = value[2]
            reg.flags = value[3]
        if reg_id in range(x86_const.UC_X86_REG_FP0, x86_const.UC_X86_REG_FP0+8):
            reg = uc_x86_float80()
            reg.mantissa = value[0]
            reg.exponent = value[1]
        if reg_id in range(x86_const.UC_X86_REG_XMM0, x86_const.UC_X86_REG_XMM0+8):
            reg = uc_x86_xmm()
            reg.low_qword = value & 0xffffffffffffffff
            reg.high_qword = value >> 64
        if reg_id in range(x86_const.UC_X86_REG_YMM0, x86_const.UC_X86_REG_YMM0+16):
            reg = uc_x86_ymm()
            reg.first_qword = value & 0xffffffffffffffff
            reg.second_qword = (value >> 64) & 0xffffffffffffffff
            reg.third_qword = (value >> 128) & 0xffffffffffffffff
            reg.fourth_qword = value >> 192
        if reg_id is x86_const.UC_X86_REG_MSR:
            reg = uc_x86_msr()
            reg.rid = value[0]
            reg.value = value[1]

    if arch == uc.UC_ARCH_ARM64:
        if reg_id in range(arm64_const.UC_ARM64_REG_Q0, arm64_const.UC_ARM64_REG_Q31+1) or reg_id in range(arm64_const.UC_ARM64_REG_V0, arm64_const.UC_ARM64_REG_V31+1):
            reg = uc_arm64_neon128()
            reg.low_qword = value & 0xffffffffffffffff
            reg.high_qword = value >> 64
        elif reg_id == arm64_const.UC_ARM64_REG_CP_REG:
            reg = uc_arm64_cp_reg()
            if not isinstance(value, tuple) or len(value) != 6:
                raise UcError(uc.UC_ERR_ARG)
            reg.crn, reg.crm, reg.op0, reg.op1, reg.op2, reg.val = value

    if arch == uc.UC_ARCH_ARM:
        if reg_id == arm_const.UC_ARM_REG_CP_REG:
            reg = uc_arm_cp_reg()
            if not isinstance(value, tuple) or len(value) != 8:
                raise UcError(uc.UC_ERR_ARG)
            reg.cp, reg.is64, reg.sec, reg.crn, reg.crm, reg.opc1, reg.opc2, reg.val = value

    if reg is None:
        # convert to 64bit number to be safe
        reg = ctypes.c_uint64(value)

    status = reg_write_func(reg_id, ctypes.byref(reg))
    if status != uc.UC_ERR_OK:
        raise UcError(status)

    return

def _catch_hook_exception(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        """Catches exceptions raised in hook functions.

        If an exception is raised, it is saved to the Uc object and a call to stop
        emulation is issued.
        """
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            # If multiple hooks raise exceptions, just use the first one
            if self._hook_exception is None:
                self._hook_exception = e

            self.emu_stop()

    return wrapper


class uc_arm_cp_reg(ctypes.Structure):
    """ARM coprocessors registers for instructions MRC, MCR, MRRC, MCRR"""
    _fields_ = [
        ("cp", ctypes.c_uint32),
        ("is64", ctypes.c_uint32),
        ("sec", ctypes.c_uint32),
        ("crn", ctypes.c_uint32),
        ("crm", ctypes.c_uint32),
        ("opc1", ctypes.c_uint32),
        ("opc2", ctypes.c_uint32),
        ("val", ctypes.c_uint64)
    ]

class uc_arm64_cp_reg(ctypes.Structure):
    """ARM64 coprocessors registers for instructions MRS, MSR"""
    _fields_ = [
        ("crn", ctypes.c_uint32),
        ("crm", ctypes.c_uint32),
        ("op0", ctypes.c_uint32),
        ("op1", ctypes.c_uint32),
        ("op2", ctypes.c_uint32),
        ("val", ctypes.c_uint64)
    ]

class uc_x86_mmr(ctypes.Structure):
    """Memory-Management Register for instructions IDTR, GDTR, LDTR, TR."""
    _fields_ = [
        ("selector", ctypes.c_uint16),  # not used by GDTR and IDTR
        ("base", ctypes.c_uint64),      # handle 32 or 64 bit CPUs
        ("limit", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),     # not used by GDTR and IDTR
    ]

class uc_x86_msr(ctypes.Structure):
    _fields_ = [
        ("rid", ctypes.c_uint32),
        ("value", ctypes.c_uint64),
    ]

class uc_x86_float80(ctypes.Structure):
    """Float80"""
    _fields_ = [
        ("mantissa", ctypes.c_uint64),
        ("exponent", ctypes.c_uint16),
    ]


class uc_x86_xmm(ctypes.Structure):
    """128-bit xmm register"""
    _fields_ = [
        ("low_qword", ctypes.c_uint64),
        ("high_qword", ctypes.c_uint64),
    ]

class uc_x86_ymm(ctypes.Structure):
    """256-bit ymm register"""
    _fields_ = [
        ("first_qword", ctypes.c_uint64),
        ("second_qword", ctypes.c_uint64),
        ("third_qword", ctypes.c_uint64),
        ("fourth_qword", ctypes.c_uint64),
    ]

class uc_arm64_neon128(ctypes.Structure):
    """128-bit neon register"""
    _fields_ = [
        ("low_qword", ctypes.c_uint64),
        ("high_qword", ctypes.c_uint64),
    ]

# Subclassing ref to allow property assignment.
class UcRef(weakref.ref):
    pass

# This class tracks Uc instance destruction and releases handles.
class UcCleanupManager(object):
    def __init__(self):
        self._refs = {}

    def register(self, uc):
        ref = UcRef(uc, self._finalizer)
        ref._uch = uc._uch
        ref._class = uc.__class__
        self._refs[id(ref)] = ref

    def _finalizer(self, ref):
        # note: this method must be completely self-contained and cannot have any references
        # to anything else in this module.
        #
        # This is because it may be called late in the Python interpreter's shutdown phase, at
        # which point the module's variables may already have been deinitialized and set to None.
        #
        # Not respecting that can lead to errors such as:
        #     Exception AttributeError:
        #       "'NoneType' object has no attribute 'release_handle'"
        #       in <bound method UcCleanupManager._finalizer of
        #       <unicorn.unicorn.UcCleanupManager object at 0x7f0bb83e4310>> ignored
        #
        # For that reason, we do not try to access the `Uc` class directly here but instead use
        # the saved `._class` reference.
        del self._refs[id(ref)]
        ref._class.release_handle(ref._uch)

class Uc(object):
    _cleanup = UcCleanupManager()

    def __init__(self, arch: int, mode: int):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = uc_version()
        # print("core version =", uc_version())
        # print("binding version =", uc.UC_API_MAJOR, uc.UC_API_MINOR)
        if major != uc.UC_API_MAJOR or minor != uc.UC_API_MINOR:
            self._uch = None
            # our binding version is different from the core's API version
            raise UcError(uc.UC_ERR_VERSION)

        self._arch, self._mode = arch, mode
        self._uch = ctypes.c_void_p()
        status = _uc.uc_open(arch, mode, ctypes.byref(self._uch))
        if status != uc.UC_ERR_OK:
            self._uch = None
            raise UcError(status)
        # internal mapping table to save callback & userdata
        self._callbacks = {}
        self._ctype_cbs = []
        self._callback_count = 0
        self._cleanup.register(self)
        self._hook_exception = None  # The exception raised in a hook

    @staticmethod
    def release_handle(uch: ctypes.CDLL):
        if uch:
            try:
                status = _uc.uc_close(uch)
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
            except:  # _uc might be pulled from under our feet
                pass

    # emulate from @begin, and stop when reaching address @until
    def emu_start(self, begin: int, until: int, timeout: int=0, count: int=0) -> None:
        self._hook_exception = None
        status = _uc.uc_emu_start(self._uch, begin, until, timeout, count)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        if self._hook_exception is not None:
            raise self._hook_exception

    # stop emulation
    def emu_stop(self) -> None:
        status = _uc.uc_emu_stop(self._uch)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return the value of a register, for @opt parameter, specify int for x86 msr, tuple for arm cp/neon regs.
    def reg_read(self, reg_id: int, opt: Union[None, int, ARMCPReg, ARM64CPReg]=None) -> Union[int, X86MMRReg, X86FPReg]:
        return reg_read(functools.partial(_uc.uc_reg_read, self._uch), self._arch, reg_id, opt)

    # write to a register, tuple for arm cp regs.
    def reg_write(self, reg_id: int, value: Union[int, ARMCPRegValue, ARM64CPRegValue, X86MMRReg, X86FPReg]):
        return reg_write(functools.partial(_uc.uc_reg_write, self._uch), self._arch, reg_id, value)

    # read from MSR - X86 only
    def msr_read(self, msr_id: int):
        return self.reg_read(x86_const.UC_X86_REG_MSR, msr_id)

    # write to MSR - X86 only
    def msr_write(self, msr_id, value: int):
        return self.reg_write(x86_const.UC_X86_REG_MSR, (msr_id, value))

    # read data from memory
    def mem_read(self, address: int, size: int):
        data = ctypes.create_string_buffer(size)
        status = _uc.uc_mem_read(self._uch, address, data, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return bytearray(data)

    # write to memory
    def mem_write(self, address: int, data: bytes):
        status = _uc.uc_mem_write(self._uch, address, data, len(data))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def _mmio_map_read_cb(self, handle, offset, size, user_data):
        (cb, data) = self._callbacks[user_data]
        return cb(self, offset, size, data)

    def _mmio_map_write_cb(self, handle, offset, size, value, user_data):
        (cb, data) = self._callbacks[user_data]
        cb(self, offset, size, value, data)

    def mmio_map(self, address: int, size: int, 
                 read_cb: UC_MMIO_READ_TYPE, user_data_read: Any,
                 write_cb: UC_MMIO_WRITE_TYPE, user_data_write: Any):
        internal_read_cb = ctypes.cast(UC_MMIO_READ_CB(self._mmio_map_read_cb), UC_MMIO_READ_CB)
        internal_write_cb = ctypes.cast(UC_MMIO_WRITE_CB(self._mmio_map_write_cb), UC_MMIO_WRITE_CB)

        self._callback_count += 1
        self._callbacks[self._callback_count] = (read_cb, user_data_read)
        read_count = self._callback_count
        self._callback_count += 1
        self._callbacks[self._callback_count] = (write_cb, user_data_write)
        write_count = self._callback_count

        status = _uc.uc_mmio_map(self._uch, address, size, internal_read_cb, read_count, internal_write_cb, write_count)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        
        # https://docs.python.org/3/library/ctypes.html#callback-functions
        self._ctype_cbs.append(internal_read_cb)
        self._ctype_cbs.append(internal_write_cb)

    # map a range of memory
    def mem_map(self, address: int, size: int, perms: int=uc.UC_PROT_ALL):
        status = _uc.uc_mem_map(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory from a raw host memory address
    def mem_map_ptr(self, address: int, size: int, perms: int, ptr: int):
        status = _uc.uc_mem_map_ptr(self._uch, address, size, perms, ptr)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # unmap a range of memory
    def mem_unmap(self, address: int, size: int):
        status = _uc.uc_mem_unmap(self._uch, address, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # protect a range of memory
    def mem_protect(self, address: int, size: int, perms: int=uc.UC_PROT_ALL):
        status = _uc.uc_mem_protect(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return CPU mode at runtime
    def query(self, query_mode: int):
        result = ctypes.c_size_t(0)
        status = _uc.uc_query(self._uch, query_mode, ctypes.byref(result))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return result.value

    @_catch_hook_exception
    def _hook_tcg_op_cb(self, handle, address, arg1, arg2, user_data):
        (cb, data) = self._callbacks[user_data]
        cb(self, address, arg1, arg2, user_data)

    @_catch_hook_exception
    def _hook_edge_gen_cb(self, handle, cur, prev, user_data):
        (cb, data) = self._callbacks[user_data]
        cb(self, cur.contents, prev.contents, user_data)

    @_catch_hook_exception
    def _hookcode_cb(self, handle, address, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, address, size, data)

    @_catch_hook_exception
    def _hook_mem_invalid_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, access, address, size, value, data)

    @_catch_hook_exception
    def _hook_mem_access_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, access, address, size, value, data)

    @_catch_hook_exception
    def _hook_intr_cb(self, handle, intno, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, intno, data)

    @_catch_hook_exception
    def _hook_insn_invalid_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, data)

    @_catch_hook_exception
    def _hook_insn_in_cb(self, handle, port, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, port, size, data)

    @_catch_hook_exception
    def _hook_insn_sys_cb(self, handle, reg, pcp_reg, user_data):
        cp_reg = ctypes.cast(pcp_reg, ctypes.POINTER(uc_arm64_cp_reg)).contents

        uc_arm64_cp_reg_tuple = namedtuple("uc_arm64_cp_reg_tuple", ["crn", "crm", "op0", "op1", "op2", "val"])

        (cb, data) = self._callbacks[user_data]

        return cb(self, reg, uc_arm64_cp_reg_tuple(cp_reg.crn, cp_reg.crm, cp_reg.op0, cp_reg.op1, cp_reg.op2, cp_reg.val), data)

    @_catch_hook_exception
    def _hook_insn_out_cb(self, handle, port, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, port, size, value, data)

    @_catch_hook_exception
    def _hook_insn_syscall_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, data)

    @_catch_hook_exception
    def _hook_insn_cpuid_cb(self, handle: int, user_data: int) -> int:
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, data)

    def ctl(self, control: int, *args):
        status = _uc.uc_ctl(self._uch, control, *args)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return status

    def __ctl(self, ctl, nr, rw):
        return ctl | (nr << 26) | (rw << 30)

    def __ctl_r(self, ctl, nr):
        return self.__ctl(ctl, nr, uc.UC_CTL_IO_READ)
    
    def __ctl_w(self, ctl, nr):
        return self.__ctl(ctl, nr, uc.UC_CTL_IO_WRITE)
    
    def __ctl_rw(self, ctl, nr):
        return self.__ctl(ctl, nr, uc.UC_CTL_IO_READ_WRITE) 

    def __ctl_r_1_arg(self, ctl, ctp):
        arg = ctp()
        self.ctl(self.__ctl_r(ctl, 1), ctypes.byref(arg))
        return arg.value

    def __ctl_w_1_arg(self, ctl, val, ctp):
        arg = ctp(val)
        self.ctl(self.__ctl_w(ctl, 1), arg)
    
    def __ctl_w_2_arg(self, ctl, val1, val2, ctp1, ctp2):
        arg1 = ctp1(val1)
        arg2 = ctp2(val2)
        self.ctl(self.__ctl_w(ctl, 2), arg1, arg2)

    def __ctl_rw_1_1_arg(self, ctl, val, ctp1, ctp2):
        arg1 = ctp1(val)
        arg2 = ctp2()
        self.ctl(self.__ctl_rw(ctl, 2), arg1, ctypes.byref(arg2))
        return arg2

    def ctl_get_mode(self):
        return self.__ctl_r_1_arg(uc.UC_CTL_UC_MODE, ctypes.c_int)

    def ctl_get_page_size(self):
        return self.__ctl_r_1_arg(uc.UC_CTL_UC_PAGE_SIZE, ctypes.c_uint32)
    
    def ctl_set_page_size(self, val: int):
        self.__ctl_w_1_arg(uc.UC_CTL_UC_PAGE_SIZE, val, ctypes.c_uint32)

    def ctl_get_arch(self):
        return self.__ctl_r_1_arg(uc.UC_CTL_UC_ARCH, ctypes.c_int)

    def ctl_get_timeout(self):
        return self.__ctl_r_1_arg(uc.UC_CTL_UC_TIMEOUT, ctypes.c_uint64)
    
    def ctl_exits_enabled(self, val: bool):
        self.__ctl_w_1_arg(uc.UC_CTL_UC_USE_EXITS, val, ctypes.c_int)
    
    def ctl_get_exits_cnt(self):
        return self.__ctl_r_1_arg(uc.UC_CTL_UC_EXITS_CNT, ctypes.c_size_t)

    def ctl_get_exits(self):
        l = self.ctl_get_exits_cnt()
        arr = (ctypes.c_uint64 * l)()
        self.ctl(self.__ctl_r(uc.UC_CTL_UC_EXITS, 2), ctypes.cast(arr, ctypes.c_void_p), ctypes.c_size_t(l))
        return [i for i in arr]

    def ctl_set_exits(self, exits: List[int]):
        arr = (ctypes.c_uint64 * len(exits))()
        for idx, exit in enumerate(exits):
            arr[idx] = exit
        self.ctl(self.__ctl_w(uc.UC_CTL_UC_EXITS, 2), ctypes.cast(arr, ctypes.c_void_p), ctypes.c_size_t(len(exits)))

    def ctl_get_cpu_model(self):
        return self.__ctl_r_1_arg(uc.UC_CTL_CPU_MODEL, ctypes.c_int)
    
    def ctl_set_cpu_model(self, val: int):
        self.__ctl_w_1_arg(uc.UC_CTL_CPU_MODEL, val, ctypes.c_int)

    def ctl_remove_cache(self, addr: int, end: int):
        self.__ctl_w_2_arg(uc.UC_CTL_TB_REMOVE_CACHE, addr, end, ctypes.c_uint64, ctypes.c_uint64)

    def ctl_request_cache(self, addr: int):
        return self.__ctl_rw_1_1_arg(uc.UC_CTL_TB_REQUEST_CACHE, addr, ctypes.c_uint64, uc_tb)
    
    def ctl_flush_tb(self):
        self.ctl(self.__ctl_w(uc.UC_CTL_TB_FLUSH, 0))

    # add a hook
    def hook_add(self, htype: int, callback: UC_HOOK_CALLBACK_TYPE , user_data: Any=None, begin: int=1, end: int=0, arg1: int=0, arg2: int=0):
        _h2 = uc_hook_h()

        # save callback & user_data
        self._callback_count += 1
        self._callbacks[self._callback_count] = (callback, user_data)
        cb = None

        if htype == uc.UC_HOOK_INSN:
            insn = ctypes.c_int(arg1)
            if arg1 == x86_const.UC_X86_INS_IN:  # IN instruction
                cb = ctypes.cast(UC_HOOK_INSN_IN_CB(self._hook_insn_in_cb), UC_HOOK_INSN_IN_CB)
            if arg1 == x86_const.UC_X86_INS_OUT:  # OUT instruction
                cb = ctypes.cast(UC_HOOK_INSN_OUT_CB(self._hook_insn_out_cb), UC_HOOK_INSN_OUT_CB)
            if arg1 in (x86_const.UC_X86_INS_SYSCALL, x86_const.UC_X86_INS_SYSENTER):  # SYSCALL/SYSENTER instruction
                cb = ctypes.cast(UC_HOOK_INSN_SYSCALL_CB(self._hook_insn_syscall_cb), UC_HOOK_INSN_SYSCALL_CB)
            if arg1 == x86_const.UC_X86_INS_CPUID:  # CPUID instruction
                cb = ctypes.cast(UC_HOOK_INSN_CPUID_CB(self._hook_insn_cpuid_cb), UC_HOOK_INSN_CPUID_CB)
            if arg1 in (arm64_const.UC_ARM64_INS_MRS, arm64_const.UC_ARM64_INS_MSR, arm64_const.UC_ARM64_INS_SYS, arm64_const.UC_ARM64_INS_SYSL):
                cb = ctypes.cast(UC_HOOK_INSN_SYS_CB(self._hook_insn_sys_cb), UC_HOOK_INSN_SYS_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), insn
            )
        elif htype == uc.UC_HOOK_TCG_OPCODE:
            opcode = ctypes.c_int(arg1)
            flags = ctypes.c_int(arg2)

            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, ctypes.cast(UC_HOOK_TCG_OPCODE_CB(self._hook_tcg_op_cb), UC_HOOK_TCG_OPCODE_CB),
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), opcode, flags
            )
        elif htype == uc.UC_HOOK_INTR:
            cb = ctypes.cast(UC_HOOK_INTR_CB(self._hook_intr_cb), UC_HOOK_INTR_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        elif htype == uc.UC_HOOK_INSN_INVALID:
            cb = ctypes.cast(UC_HOOK_INSN_INVALID_CB(self._hook_insn_invalid_cb), UC_HOOK_INSN_INVALID_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        elif htype == uc.UC_HOOK_EDGE_GENERATED:
            cb = ctypes.cast(UC_HOOK_EDGE_GEN_CB(self._hook_edge_gen_cb), UC_HOOK_EDGE_GEN_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        else:
            if htype in (uc.UC_HOOK_BLOCK, uc.UC_HOOK_CODE):
                # set callback with wrapper, so it can be called
                # with this object as param
                cb = ctypes.cast(UC_HOOK_CODE_CB(self._hookcode_cb), UC_HOOK_CODE_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            elif htype & (uc.UC_HOOK_MEM_READ_UNMAPPED |
                          uc.UC_HOOK_MEM_WRITE_UNMAPPED |
                          uc.UC_HOOK_MEM_FETCH_UNMAPPED |
                          uc.UC_HOOK_MEM_READ_PROT |
                          uc.UC_HOOK_MEM_WRITE_PROT |
                          uc.UC_HOOK_MEM_FETCH_PROT):
                cb = ctypes.cast(UC_HOOK_MEM_INVALID_CB(self._hook_mem_invalid_cb), UC_HOOK_MEM_INVALID_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            else:
                cb = ctypes.cast(UC_HOOK_MEM_ACCESS_CB(self._hook_mem_access_cb), UC_HOOK_MEM_ACCESS_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )

        # save the ctype function so gc will leave it alone.
        self._ctype_cbs.append(cb)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return _h2.value

    # delete a hook
    def hook_del(self, h: int):
        _h = uc_hook_h(h)
        status = _uc.uc_hook_del(self._uch, _h)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        h = 0

    def context_save(self):
        context = UcContext(self._uch, self._arch, self._mode)
        status = _uc.uc_context_save(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return context

    def context_update(self, context: UcContext):
        status = _uc.uc_context_save(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def context_restore(self, context: UcContext):
        status = _uc.uc_context_restore(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # this returns a generator of regions in the form (begin, end, perms)
    def mem_regions(self):
        regions = ctypes.POINTER(_uc_mem_region)()
        count = ctypes.c_uint32()
        status = _uc.uc_mem_regions(self._uch, ctypes.byref(regions), ctypes.byref(count))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        try:
            for i in range(count.value):
                yield (regions[i].begin, regions[i].end, regions[i].perms)
        finally:
            _uc.uc_free(regions)


class UcContext:
    def __init__(self, h, arch, mode):
        self._context = uc_context()
        self._size = _uc.uc_context_size(h)
        self._to_free = True
        status = _uc.uc_context_alloc(h, ctypes.byref(self._context))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        self._arch = arch
        self._mode = mode

    @property
    def context(self):
        return self._context

    @property
    def size(self):
        return self._size

    @property
    def arch(self):
        return self._arch
    
    @property
    def mode(self):
        return self._mode

    # return the value of a register
    def reg_read(self, reg_id, opt=None):
        return reg_read(functools.partial(_uc.uc_context_reg_read, self._context), self.arch, reg_id, opt)

    # write to a register
    def reg_write(self, reg_id, value):
        return reg_write(functools.partial(_uc.uc_context_reg_write, self._context), self.arch, reg_id, value)

    # Make UcContext picklable
    def __getstate__(self):
        return (bytes(self), self.size, self.arch, self.mode)

    def __setstate__(self, state):
        self._size = state[1]
        self._context = ctypes.cast(ctypes.create_string_buffer(state[0], self._size), uc_context)
        # __init__ won'e be invoked, so we are safe to set it here.
        self._to_free = False
        self._arch = state[2]
        self._mode = state[3]

    def __bytes__(self):
        return ctypes.string_at(self.context, self.size)

    def __del__(self):
        # We need this property since we shouldn't free it if the object is constructed from pickled bytes.
        if self._to_free:
            _uc.uc_context_free(self._context)

UC_HOOK_CODE_TYPE = Callable[[Uc, int, int, Any], None]
UC_HOOK_INSN_INVALID_TYPE = Callable[[Uc, Any], bool]
UC_HOOK_MEM_INVALID_TYPE = Callable[[Uc, int, int, int, int, Any], bool]
UC_HOOK_MEM_ACCESS_TYPE = Callable[[Uc, int, int, int, int, Any], None]
UC_HOOK_INTR_TYPE = Callable[[Uc, int, Any], None]
UC_HOOK_INSN_IN_TYPE = Callable[[Uc, int, int, Any], int]
UC_HOOK_INSN_OUT_TYPE = Callable[[Uc, int, int, int, Any], None]
UC_HOOK_INSN_SYSCALL_TYPE = Callable[[Uc, Any], None]
UC_HOOK_INSN_SYS_TYPE = Callable[[Uc, int, Tuple[int, int, int, int, int, int], Any], int]
UC_HOOK_INSN_CPUID_TYPE = Callable[[Uc, Any], int]
UC_MMIO_READ_TYPE = Callable[[Uc, int, int, Any], int]
UC_MMIO_WRITE_TYPE = Callable[[Uc, int, int, int, Any], None]
UC_HOOK_EDGE_GEN_TYPE = Callable[[Uc, uc_tb, uc_tb, Any], None]
UC_HOOK_TCG_OPCODE_TYPE = Callable[[Uc, int, int, int, Any], None]

UC_HOOK_CALLBACK_TYPE = Union[
    UC_HOOK_CODE_TYPE, 
    UC_HOOK_INSN_INVALID_TYPE, 
    UC_HOOK_MEM_INVALID_TYPE, 
    UC_HOOK_MEM_ACCESS_TYPE, 
    UC_HOOK_INSN_IN_TYPE, 
    UC_HOOK_INSN_OUT_TYPE,
    UC_HOOK_INSN_SYSCALL_TYPE,
    UC_HOOK_INSN_SYS_TYPE,
    UC_HOOK_INSN_CPUID_TYPE,
    UC_HOOK_EDGE_GEN_TYPE,
    UC_HOOK_TCG_OPCODE_TYPE
]

# print out debugging info
def debug():
    archs = {
        "arm": uc.UC_ARCH_ARM,
        "arm64": uc.UC_ARCH_ARM64,
        "mips": uc.UC_ARCH_MIPS,
        "sparc": uc.UC_ARCH_SPARC,
        "m68k": uc.UC_ARCH_M68K,
        "x86": uc.UC_ARCH_X86,
        "riscv": uc.UC_ARCH_RISCV,
        "ppc": uc.UC_ARCH_PPC,
    }

    all_archs = ""
    keys = archs.keys()
    for k in sorted(keys):
        if uc_arch_supported(archs[k]):
            all_archs += "-%s" % k

    major, minor, _combined = uc_version()

    return "python-%s-c%u.%u-b%u.%u" % (
        all_archs, major, minor, uc.UC_API_MAJOR, uc.UC_API_MINOR
    )
