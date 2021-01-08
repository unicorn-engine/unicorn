#![allow(non_camel_case_types)]
use bitflags::bitflags;

pub const API_MAJOR: u64 = 1;
pub const API_MINOR: u64 = 0;
pub const VERSION_MAJOR: u64 = 1;
pub const VERSION_MINOR: u64 = 0;
pub const VERSION_EXTRA: u64 = 2;
pub const SECOND_SCALE: u64 = 1_000_000;
pub const MILISECOND_SCALE: u64 = 1_000;

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
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
pub enum Query {
    MODE = 1,
    PAGE_SIZE = 2,
    ARCH = 3,
}

bitflags! {
#[repr(C)]
pub struct Permission : u32 {
        const NONE = 0;
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const ALL = 7;
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
    MAX = 8,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Mode {

    LITTLE_ENDIAN = 0,
    BIG_ENDIAN = 1073741824,

    // use LITTLE_ENDIAN.
    // MODE_ARM = 0,
    THUMB = 16,
    MCLASS = 32,
    V8 = 64,
    ARM926 = 128,
    ARM946 = 256,
    ARM1176 = 512,
    // (assoc) MICRO = 16,
    // (assoc) MIPS3 = 32,
    // (assoc) MIPS32R6 = 64,
    MIPS32 = 4,
    MIPS64 = 8,
    MODE_16 = 2,
    // (assoc) MODE_32 = 4,
    // (assoc) MODE_64 = 8,
    // (assoc) PPC32 = 4,
    // (assoc) PPC64 = 8,
    // (assoc) QPX = 16,
    // (assoc) SPARC32 = 4,
    // (assoc) SPARC64 = 8,
    // (assoc) V9 = 16,
}

impl Mode {
    pub const MICRO: Mode = Mode::THUMB;
    pub const MIPS3: Mode = Mode::MCLASS;
    pub const MIPS32R6: Mode = Mode::V8;
    pub const MODE_32: Mode = Mode::MIPS32;
    pub const MODE_64: Mode = Mode::MIPS64;
    pub const PPC32: Mode = Mode::MIPS32;
    pub const PPC64: Mode = Mode::MIPS64;
    pub const QPX: Mode = Mode::THUMB;
    pub const SPARC32: Mode = Mode::MIPS32;
    pub const SPARC64: Mode = Mode::MIPS64;
    pub const V9: Mode = Mode::THUMB;
}