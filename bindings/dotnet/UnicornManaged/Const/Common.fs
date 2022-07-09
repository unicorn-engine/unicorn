// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

namespace UnicornManaged.Const

open System

[<AutoOpen>]
module Common =
    let UC_API_MAJOR = 2

    let UC_API_MINOR = 0

    let UC_API_PATCH = 0
    let UC_API_EXTRA = 255
    let UC_VERSION_MAJOR = 2

    let UC_VERSION_MINOR = 0

    let UC_VERSION_PATCH = 0
    let UC_VERSION_EXTRA = 255
    let UC_SECOND_SCALE = 1000000
    let UC_MILISECOND_SCALE = 1000
    let UC_ARCH_ARM = 1
    let UC_ARCH_ARM64 = 2
    let UC_ARCH_MIPS = 3
    let UC_ARCH_X86 = 4
    let UC_ARCH_PPC = 5
    let UC_ARCH_SPARC = 6
    let UC_ARCH_M68K = 7
    let UC_ARCH_RISCV = 8
    let UC_ARCH_S390X = 9
    let UC_ARCH_TRICORE = 10
    let UC_ARCH_MAX = 11

    let UC_MODE_LITTLE_ENDIAN = 0
    let UC_MODE_BIG_ENDIAN = 1073741824

    let UC_MODE_ARM = 0
    let UC_MODE_THUMB = 16
    let UC_MODE_MCLASS = 32
    let UC_MODE_V8 = 64
    let UC_MODE_ARMBE8 = 1024
    let UC_MODE_ARM926 = 128
    let UC_MODE_ARM946 = 256
    let UC_MODE_ARM1176 = 512
    let UC_MODE_MICRO = 16
    let UC_MODE_MIPS3 = 32
    let UC_MODE_MIPS32R6 = 64
    let UC_MODE_MIPS32 = 4
    let UC_MODE_MIPS64 = 8
    let UC_MODE_16 = 2
    let UC_MODE_32 = 4
    let UC_MODE_64 = 8
    let UC_MODE_PPC32 = 4
    let UC_MODE_PPC64 = 8
    let UC_MODE_QPX = 16
    let UC_MODE_SPARC32 = 4
    let UC_MODE_SPARC64 = 8
    let UC_MODE_V9 = 16
    let UC_MODE_RISCV32 = 4
    let UC_MODE_RISCV64 = 8

    let UC_ERR_OK = 0
    let UC_ERR_NOMEM = 1
    let UC_ERR_ARCH = 2
    let UC_ERR_HANDLE = 3
    let UC_ERR_MODE = 4
    let UC_ERR_VERSION = 5
    let UC_ERR_READ_UNMAPPED = 6
    let UC_ERR_WRITE_UNMAPPED = 7
    let UC_ERR_FETCH_UNMAPPED = 8
    let UC_ERR_HOOK = 9
    let UC_ERR_INSN_INVALID = 10
    let UC_ERR_MAP = 11
    let UC_ERR_WRITE_PROT = 12
    let UC_ERR_READ_PROT = 13
    let UC_ERR_FETCH_PROT = 14
    let UC_ERR_ARG = 15
    let UC_ERR_READ_UNALIGNED = 16
    let UC_ERR_WRITE_UNALIGNED = 17
    let UC_ERR_FETCH_UNALIGNED = 18
    let UC_ERR_HOOK_EXIST = 19
    let UC_ERR_RESOURCE = 20
    let UC_ERR_EXCEPTION = 21
    let UC_MEM_READ = 16
    let UC_MEM_WRITE = 17
    let UC_MEM_FETCH = 18
    let UC_MEM_READ_UNMAPPED = 19
    let UC_MEM_WRITE_UNMAPPED = 20
    let UC_MEM_FETCH_UNMAPPED = 21
    let UC_MEM_WRITE_PROT = 22
    let UC_MEM_READ_PROT = 23
    let UC_MEM_FETCH_PROT = 24
    let UC_MEM_READ_AFTER = 25

    let UC_TCG_OP_SUB = 0
    let UC_TCG_OP_FLAG_CMP = 1
    let UC_TCG_OP_FLAG_DIRECT = 2
    let UC_HOOK_INTR = 1
    let UC_HOOK_INSN = 2
    let UC_HOOK_CODE = 4
    let UC_HOOK_BLOCK = 8
    let UC_HOOK_MEM_READ_UNMAPPED = 16
    let UC_HOOK_MEM_WRITE_UNMAPPED = 32
    let UC_HOOK_MEM_FETCH_UNMAPPED = 64
    let UC_HOOK_MEM_READ_PROT = 128
    let UC_HOOK_MEM_WRITE_PROT = 256
    let UC_HOOK_MEM_FETCH_PROT = 512
    let UC_HOOK_MEM_READ = 1024
    let UC_HOOK_MEM_WRITE = 2048
    let UC_HOOK_MEM_FETCH = 4096
    let UC_HOOK_MEM_READ_AFTER = 8192
    let UC_HOOK_INSN_INVALID = 16384
    let UC_HOOK_EDGE_GENERATED = 32768
    let UC_HOOK_TCG_OPCODE = 65536
    let UC_HOOK_MEM_UNMAPPED = 112
    let UC_HOOK_MEM_PROT = 896
    let UC_HOOK_MEM_READ_INVALID = 144
    let UC_HOOK_MEM_WRITE_INVALID = 288
    let UC_HOOK_MEM_FETCH_INVALID = 576
    let UC_HOOK_MEM_INVALID = 1008
    let UC_HOOK_MEM_VALID = 7168
    let UC_QUERY_MODE = 1
    let UC_QUERY_PAGE_SIZE = 2
    let UC_QUERY_ARCH = 3
    let UC_QUERY_TIMEOUT = 4

    let UC_CTL_IO_NONE = 0
    let UC_CTL_IO_WRITE = 1
    let UC_CTL_IO_READ = 2
    let UC_CTL_IO_READ_WRITE = 3

    let UC_CTL_UC_MODE = 0
    let UC_CTL_UC_PAGE_SIZE = 1
    let UC_CTL_UC_ARCH = 2
    let UC_CTL_UC_TIMEOUT = 3
    let UC_CTL_UC_USE_EXITS = 4
    let UC_CTL_UC_EXITS_CNT = 5
    let UC_CTL_UC_EXITS = 6
    let UC_CTL_CPU_MODEL = 7
    let UC_CTL_TB_REQUEST_CACHE = 8
    let UC_CTL_TB_REMOVE_CACHE = 9
    let UC_CTL_TB_FLUSH = 10

    let UC_PROT_NONE = 0
    let UC_PROT_READ = 1
    let UC_PROT_WRITE = 2
    let UC_PROT_EXEC = 4
    let UC_PROT_ALL = 7

