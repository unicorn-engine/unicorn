#![allow(non_camel_case_types)]
use bitflags::bitflags;

pub const API_MAJOR: u64 = 2;
pub const API_MINOR: u64 = 0;
pub const VERSION_MAJOR: u64 = 2;
pub const VERSION_MINOR: u64 = 0;
pub const VERSION_PATCH: u64 = 0;
pub const VERSION_EXTRA: u64 = 7;
pub const SECOND_SCALE: u64 = 1_000_000;
pub const MILISECOND_SCALE: u64 = 1_000;

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum uc_error {
    OK = 0,
    NOMEM = 1,
    ARCH = 2,
    HANDLE = 3,
    MODE = 4,
    VERSION = 5,
    READ_UNMAPPED = 6,
    WRITE_UNMAPPED = 7,
    FETCH_UNMAPPED = 8,
    HOOK = 9,
    INSN_INVALID = 10,
    MAP = 11,
    WRITE_PROT = 12,
    READ_PROT = 13,
    FETCH_PROT = 14,
    ARG = 15,
    READ_UNALIGNED = 16,
    WRITE_UNALIGNED = 17,
    FETCH_UNALIGNED = 18,
    HOOK_EXIST = 19,
    RESOURCE = 20,
    EXCEPTION = 21,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum MemType {
    READ = 16,
    WRITE = 17,
    FETCH = 18,
    READ_UNMAPPED = 19,
    WRITE_UNMAPPED = 20,
    FETCH_UNMAPPED = 21,
    WRITE_PROT = 22,
    READ_PROT = 23,
    FETCH_PROT = 24,
    READ_AFTER = 25,
}

bitflags! {
    #[repr(C)]
    pub struct HookType: i32 {
        const INTR = 1;
        const INSN = 2;
        const CODE = 4;
        const BLOCK = 8;

        const MEM_READ_UNMAPPED = 0x10;
        const MEM_WRITE_UNMAPPED = 0x20;
        const MEM_FETCH_UNMAPPED = 0x40;
        const MEM_UNMAPPED = Self::MEM_READ_UNMAPPED.bits | Self::MEM_WRITE_UNMAPPED.bits | Self::MEM_FETCH_UNMAPPED.bits;

        const MEM_READ_PROT = 0x80;
        const MEM_WRITE_PROT = 0x100;
        const MEM_FETCH_PROT = 0x200;
        const MEM_PROT = Self::MEM_READ_PROT.bits | Self::MEM_WRITE_PROT.bits | Self::MEM_FETCH_PROT.bits;

        const MEM_READ = 0x400;
        const MEM_WRITE = 0x800;
        const MEM_FETCH = 0x1000;
        const MEM_VALID = Self::MEM_READ.bits | Self::MEM_WRITE.bits | Self::MEM_FETCH.bits;

        const MEM_READ_AFTER = 0x2000;

        const INSN_INVALID = 0x4000;

        const MEM_READ_INVALID = Self::MEM_READ_UNMAPPED.bits | Self::MEM_READ_PROT.bits;
        const MEM_WRITE_INVALID = Self::MEM_WRITE_UNMAPPED.bits | Self::MEM_WRITE_PROT.bits;
        const MEM_FETCH_INVALID = Self::MEM_FETCH_UNMAPPED.bits | Self::MEM_FETCH_PROT.bits;
        const MEM_INVALID = Self::MEM_READ_INVALID.bits | Self::MEM_WRITE_INVALID.bits | Self::MEM_FETCH_INVALID.bits;

        const MEM_ALL = Self::MEM_VALID.bits | Self::MEM_INVALID.bits;
    }
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum Query {
    MODE = 1,
    PAGE_SIZE = 2,
    ARCH = 3,
    TIMEOUT = 4,
}

bitflags! {
#[repr(C)]
pub struct Permission : u32 {
        const NONE = 0;
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const ALL = Self::READ.bits | Self::WRITE.bits | Self::EXEC.bits;
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemRegion {
    pub begin: u64,
    pub end: u64,
    pub perms: Permission,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Arch {
    ARM = 1,
    ARM64 = 2,
    MIPS = 3,
    X86 = 4,
    PPC = 5,
    SPARC = 6,
    M68K = 7,
    RISCV = 8,
    S390X = 9,
    TRICORE = 10,
    MAX = 11,
}

impl TryFrom<usize> for Arch {
    type Error = uc_error;

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::ARM as usize => Ok(Self::ARM),
            x if x == Self::ARM64 as usize => Ok(Self::ARM64),
            x if x == Self::MIPS as usize => Ok(Self::MIPS),
            x if x == Self::X86 as usize => Ok(Self::X86),
            x if x == Self::PPC as usize => Ok(Self::PPC),
            x if x == Self::SPARC as usize => Ok(Self::SPARC),
            x if x == Self::M68K as usize => Ok(Self::M68K),
            x if x == Self::RISCV as usize => Ok(Self::RISCV),
            x if x == Self::S390X as usize => Ok(Self::S390X),
            x if x == Self::TRICORE as usize => Ok(Self::TRICORE),
            x if x == Self::MAX as usize => Ok(Self::MAX),
            _ => Err(uc_error::ARCH),
        }
    }
}

bitflags! {
    #[repr(C)]
    pub struct Mode: i32 {
        const LITTLE_ENDIAN = 0;
        const BIG_ENDIAN = 0x4000_0000;

        const ARM = 0;
        const THUMB = 0x10;
        const MCLASS = 0x20;
        const V8 = 0x40;
        const ARMBE8 = 0x400;
        const ARM926 = 0x80;
        const ARM946 = 0x100;
        const ARM1176 = 0x200;
        const MICRO = Self::THUMB.bits;
        const MIPS3 = Self::MCLASS.bits;
        const MIPS32R6 = Self::V8.bits;
        const MIPS32 = 4;
        const MIPS64 = 8;
        const MODE_16 = 2;
        const MODE_32 = Self::MIPS32.bits;
        const MODE_64 = Self::MIPS64.bits;
        const PPC32 = Self::MIPS32.bits;
        const PPC64 = Self::MIPS64.bits;
        const QPX = Self::THUMB.bits;
        const SPARC32 = Self::MIPS32.bits;
        const SPARC64 = Self::MIPS64.bits;
        const V9 = Self::THUMB.bits;
        const RISCV32 = Self::MIPS32.bits;
        const RISCV64 = Self::MIPS64.bits;
    }
}

// Represent a TranslationBlock.
#[repr(C)]
pub struct TranslationBlock {
    pub pc: u64,
    pub icount: u16,
    pub size: u16
}

macro_rules! UC_CTL_READ {
    ($expr:expr) => {
        $expr as u32 | ControlType::UC_CTL_IO_READ as u32
    };
}

macro_rules! UC_CTL_WRITE {
    ($expr:expr) => {
        $expr as u32 | ControlType::UC_CTL_IO_WRITE as u32
    };
}

macro_rules! UC_CTL_READ_WRITE {
    ($expr:expr) => {
        $expr as u32 | ControlType::UC_CTL_IO_WRITE as u32 | ControlType::UC_CTL_IO_READ as u32
    };
}

#[allow(clippy::upper_case_acronyms)]
pub enum ControlType {
    UC_CTL_UC_MODE = 0,
    UC_CTL_UC_PAGE_SIZE = 1,
    UC_CTL_UC_ARCH = 2,
    UC_CTL_UC_TIMEOUT = 3,
    UC_CTL_UC_USE_EXITS = 4,
    UC_CTL_UC_EXITS_CNT = 5,
    UC_CTL_UC_EXITS = 6,
    UC_CTL_CPU_MODEL = 7,
    UC_CTL_TB_REQUEST_CACHE = 8,
    UC_CTL_TB_REMOVE_CACHE = 9,
    UC_CTL_TB_FLUSH = 10,
    UC_CTL_IO_READ = 1<<31,
    UC_CTL_IO_WRITE = 1<<30,
}
