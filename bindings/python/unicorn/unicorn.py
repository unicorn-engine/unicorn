# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
import ctypes.util
import distutils.sysconfig
import inspect
import os.path
import platform
import sys

from . import x86_const, unicorn_const as uc

if not hasattr(sys.modules[__name__], "__file__"):
    __file__ = inspect.getfile(inspect.currentframe())

_python2 = sys.version_info[0] < 3
if _python2:
    range = xrange

_lib_path = os.path.split(__file__)[0]
_all_libs = (
    "unicorn.dll",
    "libunicorn.so",
    "libunicorn.dylib",
)

# Windows DLL in dependency order
_all_windows_dlls = (
    "libwinpthread-1.dll",
    "libgcc_s_seh-1.dll",
    "libgcc_s_dw2-1.dll",
    "libiconv-2.dll",
    "libintl-8.dll",
    "libglib-2.0-0.dll",
)
_found = False

for _lib in _all_libs:
    try:
        if _lib == "unicorn.dll":
            for dll in _all_windows_dlls:    # load all the rest DLLs first
                _lib_file = os.path.join(_lib_path, dll)
                if os.path.exists(_lib_file):
                    ctypes.cdll.LoadLibrary(_lib_file)
        _lib_file = os.path.join(_lib_path, _lib)
        _uc = ctypes.cdll.LoadLibrary(_lib_file)
        _found = True
        break
    except OSError:
        pass

if not _found:
    # try loading from default paths
    for _lib in _all_libs:
        try:
            _uc = ctypes.cdll.LoadLibrary(_lib)
            _found = True
            break
        except OSError:
            pass

if not _found:
    # last try: loading from python lib directory
    _lib_path = distutils.sysconfig.get_python_lib()
    for _lib in _all_libs:
        try:
            if _lib == "unicorn.dll":
                for dll in _all_windows_dlls:    # load all the rest DLLs first
                    _lib_file = os.path.join(_lib_path, "unicorn", dll)
                    if os.path.exists(_lib_file):
                        ctypes.cdll.LoadLibrary(_lib_file)
            _lib_file = os.path.join(_lib_path, "unicorn", _lib)
            _uc = ctypes.cdll.LoadLibrary(_lib_file)
            _found = True
            break
        except OSError:
            pass

# Attempt Darwin specific load (10.11 specific),
# since LD_LIBRARY_PATH is not guaranteed to exist
if not _found and platform.system() == "Darwin":
    _lib_path = "/usr/local/lib/"
    for _lib in _all_libs:
        try:
            _lib_file = os.path.join(_lib_path, _lib)
            # print "Trying to load:", _lib_file
            _uc = ctypes.cdll.LoadLibrary(_lib_file)
            _found = True
            break
        except OSError:
            pass

if not _found:
    raise ImportError("ERROR: fail to load the dynamic library.")


__version__ = "%s.%s" % (uc.UC_API_MAJOR, uc.UC_API_MINOR)

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

ucerr = ctypes.c_int
uc_engine = ctypes.c_void_p
uc_hook_h = ctypes.c_size_t

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
_setup_prototype(_uc, "uc_mem_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_mem_map_ptr", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_unmap", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_protect", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_query", ucerr, uc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))

# uc_hook_add is special due to variable number of arguments
_uc.uc_hook_add = _uc.uc_hook_add
_uc.uc_hook_add.restype = ucerr

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p)
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
    return (
        uc.UC_API_MAJOR, uc.UC_API_MINOR,
        (uc.UC_API_MAJOR << 8) + uc.UC_API_MINOR,
    )


# check to see if this engine supports a particular arch
def uc_arch_supported(query):
    return _uc.uc_arch_supported(query)


class uc_x86_mmr(ctypes.Structure):
    """Memory-Management Register for instructions IDTR, GDTR, LDTR, TR."""
    _fields_ = [
        ("selector", ctypes.c_uint16),  # not used by GDTR and IDTR
        ("base", ctypes.c_uint64),      # handle 32 or 64 bit CPUs
        ("limit", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),     # not used by GDTR and IDTR
    ]


class uc_x86_float80(ctypes.Structure):
    """Float80"""
    _fields_ = [
        ("mantissa", ctypes.c_uint64),
        ("exponent", ctypes.c_uint16),
    ]


class Uc(object):
    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = uc_version()
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
        self._ctype_cbs = {}
        self._callback_count = 0

    # destructor to be called automatically when object is destroyed.
    def __del__(self):
        if self._uch:
            try:
                status = _uc.uc_close(self._uch)
                self._uch = None
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
            except:  # _uc might be pulled from under our feet
                pass

    # emulate from @begin, and stop when reaching address @until
    def emu_start(self, begin, until, timeout=0, count=0):
        status = _uc.uc_emu_start(self._uch, begin, until, timeout, count)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # stop emulation
    def emu_stop(self):
        status = _uc.uc_emu_stop(self._uch)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return the value of a register
    def reg_read(self, reg_id):
        if self._arch == uc.UC_ARCH_X86:
            if reg_id in [x86_const.UC_X86_REG_IDTR, x86_const.UC_X86_REG_GDTR, x86_const.UC_X86_REG_LDTR, x86_const.UC_X86_REG_TR]:
                reg = uc_x86_mmr()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.selector, reg.base, reg.limit, reg.flags
            if reg_id in range(x86_const.UC_X86_REG_FP0, x86_const.UC_X86_REG_FP0+8):
                reg = uc_x86_float80()
                status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
                return reg.mantissa, reg.exponent

        # read to 64bit number to be safe
        reg = ctypes.c_int64(0)
        status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return reg.value

    # write to a register
    def reg_write(self, reg_id, value):
        reg = None

        if self._arch == uc.UC_ARCH_X86:
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

        if reg is None:
            # convert to 64bit number to be safe
            reg = ctypes.c_int64(value)

        status = _uc.uc_reg_write(self._uch, reg_id, ctypes.byref(reg))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # read data from memory
    def mem_read(self, address, size):
        data = ctypes.create_string_buffer(size)
        status = _uc.uc_mem_read(self._uch, address, data, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return bytearray(data)

    # write to memory
    def mem_write(self, address, data):
        status = _uc.uc_mem_write(self._uch, address, data, len(data))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory
    def mem_map(self, address, size, perms=uc.UC_PROT_ALL):
        status = _uc.uc_mem_map(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory from a raw host memory address
    def mem_map_ptr(self, address, size, perms, ptr):
        status = _uc.uc_mem_map_ptr(self._uch, address, size, perms, ptr)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # unmap a range of memory
    def mem_unmap(self, address, size):
        status = _uc.uc_mem_unmap(self._uch, address, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # protect a range of memory
    def mem_protect(self, address, size, perms=uc.UC_PROT_ALL):
        status = _uc.uc_mem_protect(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return CPU mode at runtime
    def query(self, query_mode):
        result = ctypes.c_size_t(0)
        status = _uc.uc_query(self._uch, query_mode, ctypes.byref(result))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return result.value

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
    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0):
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
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), insn
            )
        elif htype == uc.UC_HOOK_INTR:
            cb = ctypes.cast(UC_HOOK_INTR_CB(self._hook_intr_cb), UC_HOOK_INTR_CB)
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
        self._ctype_cbs[self._callback_count] = cb

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return _h2.value

    # delete a hook
    def hook_del(self, h):
        _h = uc_hook_h(h)
        status = _uc.uc_hook_del(self._uch, _h)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        h = 0


# print out debugging info
def debug():
    archs = {
        "arm": uc.UC_ARCH_ARM,
        "arm64": uc.UC_ARCH_ARM64,
        "mips": uc.UC_ARCH_MIPS,
        "sparc": uc.UC_ARCH_SPARC,
        "m68k": uc.UC_ARCH_M68K,
        "x86": uc.UC_ARCH_X86,
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
