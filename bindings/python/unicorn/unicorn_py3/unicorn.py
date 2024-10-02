"""New and improved Unicorn Python bindings by elicn
based on Nguyen Anh Quynnh's work
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Mapping, MutableMapping, Optional, Sequence, Tuple, Type, TypeVar

import ctypes
import functools
import weakref

from unicorn import unicorn_const as uc
from .arch.types import uc_err, uc_engine, uc_context, uc_hook_h, UcReg

# __version__ = f'{uc.UC_VERSION_MAJOR}.{uc.UC_VERSION_MINOR}.{uc.UC_VERSION_PATCH}'


class _uc_mem_region(ctypes.Structure):
    _fields_ = (
        ('begin', ctypes.c_uint64),
        ('end',   ctypes.c_uint64),
        ('perms', ctypes.c_uint32),
    )

    @property
    def value(self) -> Tuple[int, int, int]:
        return tuple(getattr(self, fname) for fname, *_ in self._fields_)


class uc_tb(ctypes.Structure):
    """"TranslationBlock
    """

    _fields_ = (
        ('pc',     ctypes.c_uint64),
        ('icount', ctypes.c_uint16),
        ('size',   ctypes.c_uint16)
    )


def __load_uc_lib() -> ctypes.CDLL:
    from pathlib import Path, PurePath

    import inspect
    import os
        
    import sys

    loaded_dlls = set()

    def __load_win_support(path: Path) -> None:
        # Windows DLL in dependency order
        all_dlls = (
            'libwinpthread-1.dll',
            'libgcc_s_seh-1.dll',
            'libgcc_s_dw2-1.dll'
        )

        for dllname in all_dlls:
            if dllname not in loaded_dlls:
                lib_file = path / dllname

                if str(path.parent) == '.' or lib_file.exists():
                    try:
                        ctypes.cdll.LoadLibrary(str(lib_file))
                    except OSError:
                        continue
                    else:
                        loaded_dlls.add(dllname)

    platform = sys.platform

    # Initial attempt: load all dlls globally
    if platform in ('win32', 'cygwin'):
        __load_win_support(Path())

    def _load_lib(path: Path, lib_name: str):
        if platform in ('win32', 'cygwin'):
            __load_win_support(path)

        lib_file = path / lib_name

        try:
            return ctypes.cdll.LoadLibrary(str(lib_file))
        except OSError:
            return None

    # Loading attempts, in order
    # - user-provided environment variable
    # - pkg_resources can get us the path to the local libraries
    # - we can get the path to the local libraries by parsing our filename
    # - global load
    # - python's lib directory
    canonicals = []
    
    try:
        from importlib import resources
        canonicals.append(
            resources.files("unicorn") / 'lib'
        )
    except ImportError:
        try:
            import pkg_resources
            canonicals.append(
                pkg_resources.resource_filename("unicorn", 'lib')
            )
        except ImportError:
            # maybe importlib_resources, but ignore for now
            pass
    
    lib_locations = [
        os.getenv('LIBUNICORN_PATH'),
    ] + canonicals + [
        PurePath(inspect.getfile(__load_uc_lib)).parent / 'lib',
        '',
        r'/usr/local/lib' if sys.platform == 'darwin' else r'/usr/lib64',
    ] + [PurePath(p) / 'unicorn' / 'lib' for p in sys.path]

    # filter out None elements
    lib_locations = tuple(Path(loc) for loc in lib_locations if loc is not None)

    lib_name = {
        'cygwin': 'cygunicorn.dll',
        'darwin': 'libunicorn.2.dylib',
        'linux':  'libunicorn.so.2',
        'linux2': 'libunicorn.so.2',
        'win32':  'unicorn.dll'
    }.get(platform, "libunicorn.so")

    def __attempt_load(libname: str):
        T = TypeVar('T')

        def __pick_first_valid(it: Iterable[T]) -> Optional[T]:
            """Iterate till encountering a non-None element and return it.
            """

            return next((elem for elem in it if elem is not None), None)

        return __pick_first_valid(_load_lib(loc, libname) for loc in lib_locations)

    lib = __attempt_load(lib_name) or __attempt_load('libunicorn.so')

    if lib is None:
        raise ImportError('Failed to load the Unicorn dynamic library')

    return lib


def __set_lib_prototypes(lib: ctypes.CDLL) -> None:
    """Set up library functions prototypes.

    Args:
        lib: unicorn library instance
    """

    def __set_prototype(fname: str, restype: Type[ctypes._CData], *argtypes: Type[ctypes._CData]) -> None:
        func: Optional[ctypes._FuncPointer] = getattr(lib, fname, None)

        if func is None:
            raise ImportError('Failed to setup function prototypes; make sure you have cleaned your unicorn1 installation')

        func.restype = restype
        func.argtypes = argtypes

    __set_prototype('uc_version', ctypes.c_uint, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
    __set_prototype('uc_arch_supported', ctypes.c_bool, ctypes.c_int)
    __set_prototype('uc_open', uc_err, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(uc_engine))
    __set_prototype('uc_close', uc_err, uc_engine)
    __set_prototype('uc_strerror', ctypes.c_char_p, uc_err)
    __set_prototype('uc_errno', uc_err, uc_engine)
    __set_prototype('uc_reg_read', uc_err, uc_engine, ctypes.c_int, ctypes.c_void_p)
    __set_prototype('uc_reg_write', uc_err, uc_engine, ctypes.c_int, ctypes.c_void_p)
    __set_prototype('uc_reg_read_batch', uc_err, uc_engine, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_void_p), ctypes.c_int)
    __set_prototype('uc_mem_read', uc_err, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
    __set_prototype('uc_mem_write', uc_err, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
    __set_prototype('uc_emu_start', uc_err, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
    __set_prototype('uc_emu_stop', uc_err, uc_engine)
    __set_prototype('uc_hook_del', uc_err, uc_engine, uc_hook_h)
    __set_prototype('uc_mmio_map', uc_err, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    __set_prototype('uc_mem_map', uc_err, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
    __set_prototype('uc_mem_map_ptr', uc_err, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
    __set_prototype('uc_mem_unmap', uc_err, uc_engine, ctypes.c_uint64, ctypes.c_size_t)
    __set_prototype('uc_mem_protect', uc_err, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
    __set_prototype('uc_query', uc_err, uc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))
    __set_prototype('uc_context_alloc', uc_err, uc_engine, ctypes.POINTER(uc_context))
    __set_prototype('uc_free', uc_err, ctypes.c_void_p)
    __set_prototype('uc_context_save', uc_err, uc_engine, uc_context)
    __set_prototype('uc_context_restore', uc_err, uc_engine, uc_context)
    __set_prototype('uc_context_size', ctypes.c_size_t, uc_engine)
    __set_prototype('uc_context_reg_read', uc_err, uc_context, ctypes.c_int, ctypes.c_void_p)
    __set_prototype('uc_context_reg_write', uc_err, uc_context, ctypes.c_int, ctypes.c_void_p)
    __set_prototype('uc_context_reg_read_batch', uc_err, uc_context, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_void_p), ctypes.c_int)
    __set_prototype('uc_context_free', uc_err, uc_context)
    __set_prototype('uc_mem_regions', uc_err, uc_engine, ctypes.POINTER(ctypes.POINTER(_uc_mem_region)), ctypes.POINTER(ctypes.c_uint32))
    # https://bugs.python.org/issue42880
    __set_prototype('uc_hook_add', uc_err, uc_engine, ctypes.POINTER(uc_hook_h), ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)
    __set_prototype('uc_ctl', uc_err, uc_engine, ctypes.c_int)


uclib = __load_uc_lib()
__set_lib_prototypes(uclib)


# native hook callback signatures
HOOK_INTR_CFUNC         = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint32, ctypes.c_void_p)
HOOK_CODE_CFUNC         = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p)
HOOK_MEM_INVALID_CFUNC  = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ctypes.c_int, ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p)
HOOK_MEM_ACCESS_CFUNC   = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_int, ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p)
HOOK_INSN_INVALID_CFUNC = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ctypes.c_void_p)
HOOK_EDGE_GEN_CFUNC     = ctypes.CFUNCTYPE(None, uc_engine, ctypes.POINTER(uc_tb), ctypes.POINTER(uc_tb), ctypes.c_void_p)
HOOK_TCG_OPCODE_CFUNC   = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p)

# mmio callback signatures
MMIO_READ_CFUNC  = ctypes.CFUNCTYPE(ctypes.c_uint64, uc_engine, ctypes.c_uint64, ctypes.c_uint, ctypes.c_void_p)
MMIO_WRITE_CFUNC = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_uint, ctypes.c_uint64, ctypes.c_void_p)


class UcError(Exception):
    """Unicorn base exception.

    Error context is specified through `errno` and `args`.
    """

    def __init__(self, errno: int, *args):
        super().__init__(*args)

        self.errno = errno

    def __str__(self) -> str:
        return uclib.uc_strerror(self.errno).decode('ascii')


def uc_version() -> Tuple[int, int, int]:
    """Retrieve Unicorn library version.

    Returns: a tuple containing major, minor and a combined verion number
    """

    major = ctypes.c_int()
    minor = ctypes.c_int()

    combined = uclib.uc_version(
        ctypes.byref(major),
        ctypes.byref(minor)
    )

    return (major.value, minor.value, combined)


def version_bind() -> Tuple[int, int, int]:
    """Retrieve Unicorn bindings version.

    Returns: a tuple containing major, minor and a combined verion number
    """

    major = uc.UC_API_MAJOR
    minor = uc.UC_API_MINOR

    combined = (major << 8) + minor

    return (major, minor, combined)


def uc_arch_supported(atype: int) -> bool:
    """Check whether Unicorn library supports a particular arch.
    """

    return bool(uclib.uc_arch_supported(atype))


def debug() -> str:
    """Get verbose verion string.
    """

    archs = (
        ('arm',     uc.UC_ARCH_ARM),
        ('arm64',   uc.UC_ARCH_ARM64),
        ('mips',    uc.UC_ARCH_MIPS),
        ('x86',     uc.UC_ARCH_X86),
        ('ppc',     uc.UC_ARCH_PPC),
        ('sparc',   uc.UC_ARCH_SPARC),
        ('m68k',    uc.UC_ARCH_M68K),
        ('riscv',   uc.UC_ARCH_RISCV),
        ('s390x',   uc.UC_ARCH_S390X),
        ('tricore', uc.UC_ARCH_TRICORE)
    )

    all_archs = ''.join(f'-{name}' for name, atype in archs if uc_arch_supported(atype))
    lib_maj, lib_min, _ = uc_version()
    bnd_maj, bnd_min, _ = version_bind()

    return f'python-{all_archs}-c{lib_maj}.{lib_min}-b{bnd_maj}.{bnd_min}'


if TYPE_CHECKING:
    # _FuncPointer is not recognized at runtime; use it only for type annotation
    _CFP = TypeVar('_CFP', bound=ctypes._FuncPointer)


def uccallback(uc: Uc, functype: Type[_CFP]):
    """Unicorn callback decorator.

    Wraps a Python function meant to be dispatched by Unicorn as a hook callback.
    The function call is wrapped with an exception guard to catch and record
    exceptions thrown during hook handling.

    If an exception occurs, it is saved to the Uc object and emulation is stopped.
    """

    def decorate(func) -> _CFP:

        @functools.wraps(func)
        def wrapper(handle: Uc, *args, **kwargs):
            try:
                return func(uc, *args, **kwargs)
            except Exception as e:
                # If multiple hooks raise exceptions, just use the first one
                if uc._hook_exception is None:
                    uc._hook_exception = e

                uc.emu_stop()

        return ctypes.cast(functype(wrapper), functype)

    return decorate


class RegStateManager:
    """Registers state manager.

    Designed as a mixin class; not to be instantiated directly.
    Some methods must be implemented by mixin instances
    """

    _DEFAULT_REGTYPE = ctypes.c_uint64

    def _do_reg_read(self, reg_id: int, reg_obj) -> int:
        """Private register read implementation.
        Must be implemented by the mixin object
        """

        raise NotImplementedError

    def _do_reg_write(self, reg_id: int, reg_obj) -> int:
        """Private register write implementation.
        Must be implemented by the mixin object
        """

        raise NotImplementedError

    def _do_reg_read_batch(self, reglist, vallist, count) -> int:
        """Private batch register read implementation.
        Must be implemented by the mixin object
        """

        raise NotImplementedError

    def _do_reg_write_batch(self, reglist, count) -> int:
        """Private batch register write implementation.
        Must be implemented by the mixin object
        """

        raise NotImplementedError

    @staticmethod
    def __get_reg_read_arg(regtype: Type, *args):
        return regtype(*args)

    @staticmethod
    def __get_reg_write_arg(regtype: Type, value):
        return regtype.from_value(value) if issubclass(regtype, UcReg) else regtype(value)

    def _reg_read(self, reg_id: int, regtype: Type, *args):
        """Register read helper method.
        """

        reg = self.__get_reg_read_arg(regtype, *args)
        status = self._do_reg_read(reg_id, ctypes.byref(reg))

        if status != uc.UC_ERR_OK:
            raise UcError(status, reg_id)

        return reg.value

    def _reg_write(self, reg_id: int, regtype: Type, value) -> None:
        """Register write helper method.
        """

        reg = self.__get_reg_write_arg(regtype, value)
        status = self._do_reg_write(reg_id, ctypes.byref(reg))

        if status != uc.UC_ERR_OK:
            raise UcError(status, reg_id)

    def _reg_read_batch(self, reg_ids: Sequence[int], reg_types: Sequence[Type]) -> Tuple:
        """Batch register read helper method.
        """

        assert len(reg_ids) == len(reg_types)

        count = len(reg_ids)
        reg_list = (ctypes.c_int * count)(*reg_ids)
        val_list = [rtype() for rtype in reg_types]
        ptr_list = (ctypes.c_void_p * count)(*(ctypes.c_void_p(ctypes.addressof(elem)) for elem in val_list))

        status = self._do_reg_read_batch(reg_list, ptr_list, ctypes.c_int(count))

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return tuple(v.value for v in val_list)

    def reg_read(self, reg_id: int, aux: Any = None):
        """Read architectural register value.

        Args:
            reg_id : register identifier (architecture-specific enumeration)
            aux    : auxiliary data (register specific)

        Returns: register value (register-specific format)

        Raises: `UcError` in case of invalid register id or auxiliary data
        """

        return self._reg_read(reg_id, self._DEFAULT_REGTYPE)

    def reg_write(self, reg_id: int, value) -> None:
        """Write to architectural register.

        Args:
            reg_id : register identifier (architecture-specific enumeration)
            value  : value to write (register-specific format)

        Raises: `UcError` in case of invalid register id or value format
        """

        self._reg_write(reg_id, self._DEFAULT_REGTYPE, value)

    def reg_read_batch(self, reg_ids: Sequence[int]) -> Tuple:
        """Read a sequence of architectural registers.

        Args:
            reg_ids: a sequence of register identifiers (architecture-specific enumeration)

        Returns: a tuple of registers values (register-specific format)

        Raises: `UcError` in case of invalid register id
        """

        reg_types = [self._DEFAULT_REGTYPE for _ in range(len(reg_ids))]

        return self._reg_read_batch(reg_ids, reg_types)

    def reg_write_batch(self, reg_info: Sequence[Tuple[int, Any]]) -> None:
        """Write a sequece of architectural registers.

        Args:
            regs_info: a sequence of tuples consisting of register identifiers and values

        Raises: `UcError` in case of invalid register id or value format
        """

        # TODO
        ...

def ucsubclass(cls):
    """Uc subclass decorator.

    Use it to decorate user-defined Uc subclasses.

    Example:
    >>> @ucsubclass
    ... class Pegasus(Uc):
    ...     '''A Unicorn impl with wings
    ...     '''
    ...     pass
    """

    # to maintain proper inheritance for user-defined Uc subclasses, the Uc
    # base class is replaced with the appropriate Uc pre-defined subclass on
    # first instantiation.
    #
    # for example, if the Pegasus class from the example above instantiates
    # with Intel arch and 64-bit mode, the Pegasus class will be modified to
    # inherit from UcIntel and only then Uc, instead of Uc directly. that is:
    # Pegasus -> UcIntel -> Uc -> RegStateManager -> object
    #
    # note that all Pegasus subclasses will have the same inheritence chain,
    # regardless of the arch and mode the might use to initialize.

    def __replace(seq: Tuple, item, repl) -> Tuple:
        if item not in seq:
            return seq

        i = seq.index(item)

        return seq[:i] + tuple([repl]) + seq[i + 1:]

    def __new_uc_subclass(cls, arch: int, mode: int):
        # resolve the appropriate Uc subclass
        subcls = Uc.__new__(cls, arch, mode)

        # set the resolved subclass as base class instead of Uc (if there)
        cls.__bases__ = __replace(cls.__bases__, Uc, type(subcls))

        return object.__new__(cls)

    setattr(cls, '__new__', __new_uc_subclass)

    return cls


class Uc(RegStateManager):
    """Unicorn Engine class.
    """

    @staticmethod
    def __is_compliant() -> bool:
        """Checks whether Unicorn binding version complies with Unicorn library.

        Returns: `True` if versions match, `False` otherwise
        """

        uc_maj, uc_min, _ = uc_version()
        bnd_maj, bnd_min, _ = version_bind()

        return (uc_maj, uc_min) == (bnd_maj, bnd_min)

    def __new__(cls, arch: int, mode: int, cpu: Optional[int] = None):
        # verify version compatibility with the core before doing anything
        if not Uc.__is_compliant():
            raise UcError(uc.UC_ERR_VERSION)

        import importlib

        def __uc_subclass(pkgname: str, clsname: str):
            """Use a lazy subclass instantiation to avoid importing unnecessary arch
            classes.
            """

            def __wrapped() -> Type[Uc]:
                archmod = importlib.import_module(f'.arch.{pkgname}', 'unicorn.unicorn_py3')

                return getattr(archmod, clsname)

            return __wrapped

        def __uc_generic():
            return Uc

        wrapped: Callable[[], Type[Uc]] = {
            uc.UC_ARCH_ARM     : __uc_subclass('arm', 'UcAArch32'),
            uc.UC_ARCH_ARM64   : __uc_subclass('arm64', 'UcAArch64'),
            uc.UC_ARCH_MIPS    : __uc_generic,
            uc.UC_ARCH_X86     : __uc_subclass('intel', 'UcIntel'),
            uc.UC_ARCH_PPC     : __uc_generic,
            uc.UC_ARCH_SPARC   : __uc_generic,
            uc.UC_ARCH_M68K    : __uc_generic,
            uc.UC_ARCH_RISCV   : __uc_generic,
            uc.UC_ARCH_S390X   : __uc_generic,
            uc.UC_ARCH_TRICORE : __uc_generic
        }[arch]

        subclass = wrapped()

        # return the appropriate unicorn subclass type
        return super(Uc, cls).__new__(subclass)

    def __init__(self, arch: int, mode: int, cpu: Optional[int] = None) -> None:
        """Initialize a Unicorn engine instance.

        Args:
            arch: emulated architecture identifier (see UC_ARCH_* constants)
            mode: emulated processor mode (see UC_MODE_* constants)
            cpu: emulated cpu model (see UC_CPU_* constants) [optional]
        """

        self._arch = arch
        self._mode = mode

        # initialize the unicorn instance
        self._uch = uc_engine()
        status = uclib.uc_open(arch, mode, ctypes.byref(self._uch))

        if status != uc.UC_ERR_OK:
            self._uch = None
            raise UcError(status)

        if cpu is not None:
            self.ctl_set_cpu_model(cpu)

        # we have to keep a reference to the callbacks so they do not get gc-ed
        # see: https://docs.python.org/3/library/ctypes.html#callback-functions
        self._callbacks: MutableMapping[int, ctypes._FuncPointer] = {}
        self._mmio_callbacks: MutableMapping[Tuple[int, int], Tuple[Optional[MMIO_READ_CFUNC], Optional[MMIO_WRITE_CFUNC]]] = {}

        self._hook_exception: Optional[Exception] = None

        # create a finalizer object that will apropriately free up resources when
        # this instance undergoes garbage collection.
        self.__finalizer = weakref.finalize(self, Uc.release_handle, self._uch)

    @staticmethod
    def release_handle(uch: uc_engine) -> None:
        # this method and its arguments must not have any reference to the Uc instance being
        # destroyed. namely, this method cannot be a bound method.

        if uch:
            try:
                status = uclib.uc_close(uch)

            # _uc might be pulled from under our feet
            except:
                pass

            else:
                if status != uc.UC_ERR_OK:
                    raise UcError(status)

    ###########################
    #  Emulation controllers  #
    ###########################

    def emu_start(self, begin: int, until: int, timeout: int = 0, count: int = 0) -> None:
        """Start emulation from a specified address to another.

        Args:
            begin   : emulation starting address
            until   : emulation ending address
            timeout : limit emulation to a certain amount of time (milliseconds)
            count   : limit emulation to a certain amount of instructions

        Raises:
            `UcError`   : in case emulation could not be started properly
            `Exception` : in case an error has been encountered during emulation
        """

        self._hook_exception = None
        status = uclib.uc_emu_start(self._uch, begin, until, timeout, count)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        if self._hook_exception is not None:
            raise self._hook_exception

    def emu_stop(self) -> None:
        """Stop emulation.

        Raises: `UcError` in case emulation could not be stopped properly
        """

        status = uclib.uc_emu_stop(self._uch)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    ###########################
    #  CPU state accessors    #
    ###########################

    def _do_reg_read(self, reg_id: int, reg_obj) -> int:
        """Private register read implementation.
        Do not call directly.
        """

        return uclib.uc_reg_read(self._uch, reg_id, reg_obj)

    def _do_reg_write(self, reg_id: int, reg_obj) -> int:
        """Private register write implementation.
        Do not call directly.
        """

        return uclib.uc_reg_write(self._uch, reg_id, reg_obj)

    def _do_reg_read_batch(self, reglist, vallist, count) -> int:
        """Private batch register read implementation.
        Do not call directly.
        """

        return uclib.uc_reg_read_batch(self._uch, reglist, vallist, count)

    ###########################
    #  Memory management      #
    ###########################

    def mem_map(self, address: int, size: int, perms: int = uc.UC_PROT_ALL) -> None:
        """Map a memory range.

        Args:
            address : range base address
            size    : range size (in bytes)
            perms   : access protection bitmask

        Raises: `UcError` in case memory could not be mapped
        """

        assert (perms & ~uc.UC_PROT_ALL) == 0, 'unexpected perms bitmask'

        status = uclib.uc_mem_map(self._uch, address, size, perms)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def mem_map_ptr(self, address: int, size: int, perms: int, ptr: int) -> None:
        """Map a memory range and point to existing data on host memory.

        Args:
            address : range base address
            size    : range size (in bytes)
            perms   : access protection bitmask
            ptr     : address of data on host memory

        Raises: `UcError` in case memory could not be mapped
        """

        assert (perms & ~uc.UC_PROT_ALL) == 0, 'unexpected perms bitmask'

        status = uclib.uc_mem_map_ptr(self._uch, address, size, perms, ptr)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def mem_unmap(self, address: int, size: int) -> None:
        """Reclaim a mapped memory range.

        Args:
            address : range base address
            size    : range size (in bytes)

        Raises: `UcError` in case memory could not be unmapped
        """

        status = uclib.uc_mem_unmap(self._uch, address, size)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        # TODO: this is where mmio callbacks need to be released from cache,
        # but we cannot tell whether this is an mmio range. also, memory ranges
        # might be splitted by 'map_protect' after they were mapped, so the
        # (start, end) tuple may not be suitable for retrieving the callbacks.
        #
        # here we try to do that on a best-effort basis:

        rng = (address, address + size)

        if rng in self._mmio_callbacks:
            del self._mmio_callbacks[rng]

    def mem_protect(self, address: int, size: int, perms: int = uc.UC_PROT_ALL) -> None:
        """Modify access protection bitmask of a mapped memory range.

        Args:
            address : range base address
            size    : range size (in bytes)
            perms   : new access protection bitmask

        Raises: `UcError` in case access protection bitmask could not be changed
        """

        assert (perms & ~uc.UC_PROT_ALL) == 0, 'unexpected perms bitmask'

        status = uclib.uc_mem_protect(self._uch, address, size, perms)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def mmio_map(self, address: int, size: int,
            read_cb: Optional[UC_MMIO_READ_TYPE], user_data_read: Any,
            write_cb: Optional[UC_MMIO_WRITE_TYPE], user_data_write: Any) -> None:

        @uccallback(self, MMIO_READ_CFUNC)
        def __mmio_map_read_cb(uc: Uc, offset: int, size: int, key: int) -> int:
            assert read_cb is not None

            return read_cb(uc, offset, size, user_data_read)

        @uccallback(self, MMIO_WRITE_CFUNC)
        def __mmio_map_write_cb(uc: Uc, offset: int, size: int, value: int, key: int) -> None:
            assert write_cb is not None

            write_cb(uc, offset, size, value, user_data_write)

        read_cb_fptr = read_cb and __mmio_map_read_cb
        write_cb_fptr = write_cb and __mmio_map_write_cb

        status = uclib.uc_mmio_map(self._uch, address, size, read_cb_fptr, 0, write_cb_fptr, 0)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        # hold a reference to mmio callbacks
        rng = (address, address + size)

        self._mmio_callbacks[rng] = (read_cb_fptr, write_cb_fptr)

    def mem_regions(self) -> Iterator[Tuple[int, int, int]]:
        """Iterate through mapped memory regions.

        Returns: an iterator whose elements contain begin, end and perms  properties of each range

        Raises: `UcError` in case an itnernal error has been encountered
        """

        regions = ctypes.POINTER(_uc_mem_region)()
        count = ctypes.c_uint32()
        status = uclib.uc_mem_regions(self._uch, ctypes.byref(regions), ctypes.byref(count))

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        try:
            for i in range(count.value):
                yield regions[i].value

        finally:
            uclib.uc_free(regions)

    def mem_read(self, address: int, size: int) -> bytearray:
        """Read data from emulated memory subsystem.

        Args:
            address : source memory location
            size    : amount of bytes to read

        Returns: data bytes

        Raises: `UcError` in case of an invalid memory access
        """

        data = ctypes.create_string_buffer(size)
        status = uclib.uc_mem_read(self._uch, address, data, size)

        if status != uc.UC_ERR_OK:
            raise UcError(status, address, size)

        return bytearray(data)

    def mem_write(self, address: int, data: bytes) -> None:
        """Write data to emulated memory subsystem.

        Args:
            address : target memory location
            data    : data bytes to write

        Raises: `UcError` in case of an invalid memory access
        """

        size = len(data)
        status = uclib.uc_mem_write(self._uch, address, data, size)

        if status != uc.UC_ERR_OK:
            raise UcError(status, address, size)

    ###########################
    #  Event hooks management #
    ###########################

    def __do_hook_add(self, htype: int, fptr: ctypes._FuncPointer, begin: int, end: int, *args: ctypes.c_int) -> int:
        handle = uc_hook_h()

        # TODO: we do not need a callback counter to reference the callback and user data anymore,
        # so just pass a dummy value. that value will become the unused 'key' argument
        dummy = 0

        status = uclib.uc_hook_add(
            self._uch,
            ctypes.byref(handle),
            htype,
            fptr,
            ctypes.cast(dummy, ctypes.c_void_p),
            ctypes.c_uint64(begin),
            ctypes.c_uint64(end),
            *args
        )

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        # hold a reference to the funcion pointer to prevent it from being gc-ed
        self._callbacks[handle.value] = fptr

        return handle.value

    def hook_add(self, htype: int, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0, aux1: int = 0, aux2: int = 0) -> int:
        """Hook emulated events of a certain type.

        Args:
            htype     : event type(s) to hook (see UC_HOOK_* constants)
            callback  : a method to call each time the hooked event occurs
            user_data : an additional context to pass to the callback when it is called
            begin     : address where hook scope starts
            end       : address where hook scope ends
            aux1      : auxiliary parameter; needed for some hook types
            aux2      : auxiliary parameter; needed for some hook types

        Returns: hook handle

        Raises: `UcError` in case of an invalid htype value
        """

        def __hook_intr():
            @uccallback(self, HOOK_INTR_CFUNC)
            def __hook_intr_cb(uc: Uc, intno: int, key: int):
                callback(uc, intno, user_data)

            return __hook_intr_cb,

        def __hook_insn():
            # each arch is expected to overload hook_add and implement this handler on their own.
            # if we got here, it means this particular architecture does not support hooking any
            # instruction and so we fail
            raise UcError(uc.UC_ERR_ARG)

        def __hook_code():
            @uccallback(self, HOOK_CODE_CFUNC)
            def __hook_code_cb(uc: Uc, address: int, size: int, key: int):
                callback(uc, address, size, user_data)

            return __hook_code_cb,

        def __hook_invalid_mem():
            @uccallback(self, HOOK_MEM_INVALID_CFUNC)
            def __hook_mem_invalid_cb(uc: Uc, access: int, address: int, size: int, value: int, key: int) -> bool:
                return callback(uc, access, address, size, value, user_data)

            return __hook_mem_invalid_cb,

        def __hook_mem():
            @uccallback(self, HOOK_MEM_ACCESS_CFUNC)
            def __hook_mem_access_cb(uc: Uc, access: int, address: int, size: int, value: int, key: int) -> None:
                callback(uc, access, address, size, value, user_data)

            return __hook_mem_access_cb,

        def __hook_invalid_insn():
            @uccallback(self, HOOK_INSN_INVALID_CFUNC)
            def __hook_insn_invalid_cb(uc: Uc, key: int) -> bool:
                return callback(uc, user_data)

            return __hook_insn_invalid_cb,

        def __hook_edge_gen():
            @uccallback(self, HOOK_EDGE_GEN_CFUNC)
            def __hook_edge_gen_cb(uc: Uc, cur: ctypes._Pointer[uc_tb], prev: ctypes._Pointer[uc_tb], key: int):
                callback(uc, cur.contents, prev.contents, user_data)

            return __hook_edge_gen_cb,

        def __hook_tcg_opcode():
            @uccallback(self, HOOK_TCG_OPCODE_CFUNC)
            def __hook_tcg_op_cb(uc: Uc, address: int, arg1: int, arg2: int, size: int, key: int):
                callback(uc, address, arg1, arg2, size, user_data)

            opcode = ctypes.c_uint64(aux1)
            flags = ctypes.c_uint64(aux2)

            return __hook_tcg_op_cb, opcode, flags

        handlers: Mapping[int, Callable[[], Tuple]] = {
            uc.UC_HOOK_INTR               : __hook_intr,
            uc.UC_HOOK_INSN               : __hook_insn,
            uc.UC_HOOK_CODE               : __hook_code,
            uc.UC_HOOK_BLOCK              : __hook_code,
            uc.UC_HOOK_MEM_READ_UNMAPPED  : __hook_invalid_mem,
            uc.UC_HOOK_MEM_WRITE_UNMAPPED : __hook_invalid_mem,
            uc.UC_HOOK_MEM_FETCH_UNMAPPED : __hook_invalid_mem,
            uc.UC_HOOK_MEM_READ_PROT      : __hook_invalid_mem,
            uc.UC_HOOK_MEM_WRITE_PROT     : __hook_invalid_mem,
            uc.UC_HOOK_MEM_FETCH_PROT     : __hook_invalid_mem,
            uc.UC_HOOK_MEM_READ           : __hook_mem,
            uc.UC_HOOK_MEM_WRITE          : __hook_mem,
            uc.UC_HOOK_MEM_FETCH          : __hook_mem,
            # uc.UC_HOOK_MEM_READ_AFTER
            uc.UC_HOOK_INSN_INVALID       : __hook_invalid_insn,
            uc.UC_HOOK_EDGE_GENERATED     : __hook_edge_gen,
            uc.UC_HOOK_TCG_OPCODE         : __hook_tcg_opcode
        }

        # the same callback may be registered for multiple hook types if they
        # share the same handling method. here we iterate through htype set bits
        # and collect all unique handlers it refers to (no duplicates)
        matched = set(handlers.get(1 << n) for n in range(32) if htype & (1 << n))

        # the set of matched handlers is expected to include exactly one element.
        # more than one member indicates that htype refers to more than one handler
        # at the same time, whereas callbacks cannot be assigned to different handlers.
        # an empty set indicates a matching handler was not found, probably due to
        # an invalid htype value
        if len(matched) != 1:
            raise UcError(uc.UC_ERR_ARG)

        handler = matched.pop()

        # a None element indicates that htype has an unrecognized bit set
        if handler is None:
            raise UcError(uc.UC_ERR_ARG)

        fptr, *aux = handler()

        return self.__do_hook_add(htype, fptr, begin, end, *aux)

    def hook_del(self, handle: int) -> None:
        """Remove an existing hook.

        Args:
            handle: hook handle
        """

        h = uc_hook_h(handle)
        status = uclib.uc_hook_del(self._uch, h)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        del self._callbacks[handle]

    def query(self, prop: int) -> int:
        """Query an internal Unicorn property.

        Args:
            prop: property identifier (see: UC_QUERY_* constants)

        Returns: property value
        """

        result = ctypes.c_size_t()
        status = uclib.uc_query(self._uch, prop, ctypes.byref(result))

        if status != uc.UC_ERR_OK:
            raise UcError(status, prop)

        return result.value

    def context_save(self) -> UcContext:
        context = UcContext(self._uch, self._arch, self._mode)
        status = uclib.uc_context_save(self._uch, context.context)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return context

    def context_update(self, context: UcContext) -> None:
        status = uclib.uc_context_save(self._uch, context.context)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def context_restore(self, context: UcContext) -> None:
        status = uclib.uc_context_restore(self._uch, context.context)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    @staticmethod
    def __ctl_encode(ctl: int, op: int, nargs: int) -> int:
        assert nargs and (nargs & ~0b1111) == 0, f'nargs must not exceed value of 15 (got {nargs})'
        assert op and (op & ~0b11) == 0, f'op must not exceed value of 3 (got {op})'

        return (op << 30) | (nargs << 26) | ctl

    def ctl(self, ctl: int, op: int, *args):
        code = Uc.__ctl_encode(ctl, op, len(args))

        status = uclib.uc_ctl(self._uch, code, *args)

        if status != uc.UC_ERR_OK:
            raise UcError(status)

    Arg = Tuple[Type, Optional[int]]

    def __ctl_r(self, ctl: int, arg0: Arg):
        atype, _ = arg0
        carg = atype()

        self.ctl(ctl, uc.UC_CTL_IO_READ, ctypes.byref(carg))

        return carg.value

    def __ctl_w(self, ctl: int, *args: Arg):
        cargs = (atype(avalue) for atype, avalue in args)

        self.ctl(ctl, uc.UC_CTL_IO_WRITE, *cargs)

    def __ctl_wr(self, ctl: int, arg0: Arg, arg1: Arg):
        atype, avalue = arg0
        carg0 = atype(avalue)

        atype, _ = arg1
        carg1 = atype()

        self.ctl(ctl, uc.UC_CTL_IO_READ_WRITE, carg0, ctypes.byref(carg1))

        return carg1

    def ctl_get_mode(self) -> int:
        return self.__ctl_r(uc.UC_CTL_UC_MODE,
            (ctypes.c_int, None)
        )

    def ctl_get_page_size(self) -> int:
        return self.__ctl_r(uc.UC_CTL_UC_PAGE_SIZE,
            (ctypes.c_uint32, None)
        )

    def ctl_set_page_size(self, val: int) -> None:
        self.__ctl_w(uc.UC_CTL_UC_PAGE_SIZE,
            (ctypes.c_uint32, val)
        )

    def ctl_get_arch(self) -> int:
        return self.__ctl_r(uc.UC_CTL_UC_ARCH,
            (ctypes.c_int, None)
        )

    def ctl_get_timeout(self) -> int:
        return self.__ctl_r(uc.UC_CTL_UC_TIMEOUT,
            (ctypes.c_uint64, None)
        )

    def ctl_exits_enabled(self, val: bool) -> None:
        self.__ctl_w(uc.UC_CTL_UC_USE_EXITS,
            (ctypes.c_int, val)
        )

    def ctl_get_exits_cnt(self) -> int:
        return self.__ctl_r(uc.UC_CTL_UC_EXITS_CNT,
            (ctypes.c_size_t, None)
        )

    def ctl_get_exits(self) -> Sequence[int]:
        count = self.ctl_get_exits_cnt()
        arr = (ctypes.c_uint64 * count)()

        self.ctl(uc.UC_CTL_UC_EXITS, uc.UC_CTL_IO_READ, ctypes.cast(arr, ctypes.c_void_p), ctypes.c_size_t(count))

        return tuple(i for i in arr)

    def ctl_set_exits(self, exits: Sequence[int]) -> None:
        arr = (ctypes.c_uint64 * len(exits))()

        for idx, exit in enumerate(exits):
            arr[idx] = exit

        self.ctl(uc.UC_CTL_UC_EXITS, uc.UC_CTL_IO_WRITE, ctypes.cast(arr, ctypes.c_void_p), ctypes.c_size_t(len(exits)))

    def ctl_get_cpu_model(self) -> int:
        return self.__ctl_r(uc.UC_CTL_CPU_MODEL,
            (ctypes.c_int, None)
        )

    def ctl_set_cpu_model(self, val: int) -> None:
        self.__ctl_w(uc.UC_CTL_CPU_MODEL,
            (ctypes.c_int, val)
        )

    def ctl_remove_cache(self, addr: int, end: int) -> None:
        self.__ctl_w(uc.UC_CTL_TB_REMOVE_CACHE,
            (ctypes.c_uint64, addr),
            (ctypes.c_uint64, end)
        )

    def ctl_request_cache(self, addr: int):
        return self.__ctl_wr(uc.UC_CTL_TB_REQUEST_CACHE,
            (ctypes.c_uint64, addr),
            (uc_tb, None)
        )

    def ctl_flush_tb(self) -> None:
        self.__ctl_w(uc.UC_CTL_TB_FLUSH)

    def ctl_tlb_mode(self, mode: int) -> None:
        self.__ctl_w(uc.UC_CTL_TLB_TYPE,
            (ctypes.c_uint, mode)
        )


class UcContext(RegStateManager):
    def __init__(self, h, arch: int, mode: int):
        self._context = uc_context()
        self._size = uclib.uc_context_size(h)

        status = uclib.uc_context_alloc(h, ctypes.byref(self._context))

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        self._to_free = True
        self._arch = arch
        self._mode = mode

    @property
    def context(self):
        return self._context

    @property
    def size(self) -> int:
        return self._size

    @property
    def arch(self) -> int:
        return self._arch

    @property
    def mode(self) -> int:
        return self._mode

    # RegStateManager mixin method implementation
    def _do_reg_read(self, reg_id: int, reg_obj) -> int:
        """Private register read implementation.
        """

        return uclib.uc_context_reg_read(self._context, reg_id, reg_obj)

    # RegStateManager mixin method implementation
    def _do_reg_write(self, reg_id: int, reg_obj) -> int:
        """Private register write implementation.
        """

        return uclib.uc_context_reg_write(self._context, reg_id, reg_obj)

    def _do_reg_read_batch(self, reglist, vallist, count) -> int:
        """Private batch register read implementation.
        """

        return uclib.uc_context_reg_read_batch(self._context, reglist, vallist, count)

    # Make UcContext picklable
    def __getstate__(self):
        return bytes(self), self.size, self.arch, self.mode

    def __setstate__(self, state) -> None:
        context, size, arch, mode = state

        self._context = ctypes.cast(ctypes.create_string_buffer(context, size), uc_context)
        self._size = size
        self._arch = arch
        self._mode = mode

        # __init__ won't be invoked, so we are safe to set it here.
        self._to_free = False

    def __bytes__(self) -> bytes:
        return ctypes.string_at(self.context, self.size)

    def __del__(self) -> None:
        # We need this property since we shouldn't free it if the object is constructed from pickled bytes.
        if self._to_free:
            uclib.uc_context_free(self._context)


UC_MMIO_READ_TYPE = Callable[[Uc, int, int, Any], int]
UC_MMIO_WRITE_TYPE = Callable[[Uc, int, int, int, Any], None]


__all__ = ['Uc', 'UcContext', 'ucsubclass', 'UcError', 'uc_version', 'version_bind', 'uc_arch_supported', 'debug']


