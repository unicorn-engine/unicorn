#![allow(non_camel_case_types)]

// RISCV registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterRISCV {
    INVALID = 0,

    // General purpose registers
    X0 = 1,
    X1 = 2,
    X2 = 3,
    X3 = 4,
    X4 = 5,
    X5 = 6,
    X6 = 7,
    X7 = 8,
    X8 = 9,
    X9 = 10,
    X10 = 11,
    X11 = 12,
    X12 = 13,
    X13 = 14,
    X14 = 15,
    X15 = 16,
    X16 = 17,
    X17 = 18,
    X18 = 19,
    X19 = 20,
    X20 = 21,
    X21 = 22,
    X22 = 23,
    X23 = 24,
    X24 = 25,
    X25 = 26,
    X26 = 27,
    X27 = 28,
    X28 = 29,
    X29 = 30,
    X30 = 31,
    X31 = 32,

    // CSR
    USTATUS = 33,
    UIE = 34,
    UTVEC = 35,
    USCRATCH = 36,
    UEPC = 37,
    UCAUSE = 38,
    UTVAL = 39,
    UIP = 40,
    FFLAGS = 41,
    FRM = 42,
    FCSR = 43,
    CYCLE = 44,
    TIME = 45,
    INSTRET = 46,
    HPMCOUNTER3 = 47,
    HPMCOUNTER4 = 48,
    HPMCOUNTER5 = 49,
    HPMCOUNTER6 = 50,
    HPMCOUNTER7 = 51,
    HPMCOUNTER8 = 52,
    HPMCOUNTER9 = 53,
    HPMCOUNTER10 = 54,
    HPMCOUNTER11 = 55,
    HPMCOUNTER12 = 56,
    HPMCOUNTER13 = 57,
    HPMCOUNTER14 = 58,
    HPMCOUNTER15 = 59,
    HPMCOUNTER16 = 60,
    HPMCOUNTER17 = 61,
    HPMCOUNTER18 = 62,
    HPMCOUNTER19 = 63,
    HPMCOUNTER20 = 64,
    HPMCOUNTER21 = 65,
    HPMCOUNTER22 = 66,
    HPMCOUNTER23 = 67,
    HPMCOUNTER24 = 68,
    HPMCOUNTER25 = 69,
    HPMCOUNTER26 = 70,
    HPMCOUNTER27 = 71,
    HPMCOUNTER28 = 72,
    HPMCOUNTER29 = 73,
    HPMCOUNTER30 = 74,
    HPMCOUNTER31 = 75,
    CYCLEH = 76,
    TIMEH = 77,
    INSTRETH = 78,
    HPMCOUNTER3H = 79,
    HPMCOUNTER4H = 80,
    HPMCOUNTER5H = 81,
    HPMCOUNTER6H = 82,
    HPMCOUNTER7H = 83,
    HPMCOUNTER8H = 84,
    HPMCOUNTER9H = 85,
    HPMCOUNTER10H = 86,
    HPMCOUNTER11H = 87,
    HPMCOUNTER12H = 88,
    HPMCOUNTER13H = 89,
    HPMCOUNTER14H = 90,
    HPMCOUNTER15H = 91,
    HPMCOUNTER16H = 92,
    HPMCOUNTER17H = 93,
    HPMCOUNTER18H = 94,
    HPMCOUNTER19H = 95,
    HPMCOUNTER20H = 96,
    HPMCOUNTER21H = 97,
    HPMCOUNTER22H = 98,
    HPMCOUNTER23H = 99,
    HPMCOUNTER24H = 100,
    HPMCOUNTER25H = 101,
    HPMCOUNTER26H = 102,
    HPMCOUNTER27H = 103,
    HPMCOUNTER28H = 104,
    HPMCOUNTER29H = 105,
    HPMCOUNTER30H = 106,
    HPMCOUNTER31H = 107,
    MCYCLE = 108,
    MINSTRET = 109,
    MCYCLEH = 110,
    MINSTRETH = 111,
    MVENDORID = 112,
    MARCHID = 113,
    MIMPID = 114,
    MHARTID = 115,
    MSTATUS = 116,
    MISA = 117,
    MEDELEG = 118,
    MIDELEG = 119,
    MIE = 120,
    MTVEC = 121,
    MCOUNTEREN = 122,
    MSTATUSH = 123,
    MUCOUNTEREN = 124,
    MSCOUNTEREN = 125,
    MHCOUNTEREN = 126,
    MSCRATCH = 127,
    MEPC = 128,
    MCAUSE = 129,
    MTVAL = 130,
    MIP = 131,
    MBADADDR = 132,
    SSTATUS = 133,
    SEDELEG = 134,
    SIDELEG = 135,
    SIE = 136,
    STVEC = 137,
    SCOUNTEREN = 138,
    SSCRATCH = 139,
    SEPC = 140,
    SCAUSE = 141,
    STVAL = 142,
    SIP = 143,
    SBADADDR = 144,
    SPTBR = 145,
    SATP = 146,
    HSTATUS = 147,
    HEDELEG = 148,
    HIDELEG = 149,
    HIE = 150,
    HCOUNTEREN = 151,
    HTVAL = 152,
    HIP = 153,
    HTINST = 154,
    HGATP = 155,
    HTIMEDELTA = 156,
    HTIMEDELTAH = 157,

    // Floating-point registers
    F0 = 158,
    F1 = 159,
    F2 = 160,
    F3 = 161,
    F4 = 162,
    F5 = 163,
    F6 = 164,
    F7 = 165,
    F8 = 166,
    F9 = 167,
    F10 = 168,
    F11 = 169,
    F12 = 170,
    F13 = 171,
    F14 = 172,
    F15 = 173,
    F16 = 174,
    F17 = 175,
    F18 = 176,
    F19 = 177,
    F20 = 178,
    F21 = 179,
    F22 = 180,
    F23 = 181,
    F24 = 182,
    F25 = 183,
    F26 = 184,
    F27 = 185,
    F28 = 186,
    F29 = 187,
    F30 = 188,
    F31 = 189,
    PC = 190,
    ENDING = 191,
}

impl RegisterRISCV {
    // Alias registers
    // (assoc) ZERO = 1,
    // (assoc) RA = 2,
    // (assoc) SP = 3,
    // (assoc) GP = 4,
    // (assoc) TP = 5,
    // (assoc) T0 = 6,
    // (assoc) T1 = 7,
    // (assoc) T2 = 8,
    // (assoc) S0 = 9,
    // (assoc) FP = 9,
    // (assoc) S1 = 10,
    // (assoc) A0 = 11,
    // (assoc) A1 = 12,
    // (assoc) A2 = 13,
    // (assoc) A3 = 14,
    // (assoc) A4 = 15,
    // (assoc) A5 = 16,
    // (assoc) A6 = 17,
    // (assoc) A7 = 18,
    // (assoc) S2 = 19,
    // (assoc) S3 = 20,
    // (assoc) S4 = 21,
    // (assoc) S5 = 22,
    // (assoc) S6 = 23,
    // (assoc) S7 = 24,
    // (assoc) S8 = 25,
    // (assoc) S9 = 26,
    // (assoc) S10 = 27,
    // (assoc) S11 = 28,
    // (assoc) T3 = 29,
    // (assoc) T4 = 30,
    // (assoc) T5 = 31,
    // (assoc) T6 = 32,
    // (assoc) FT0 = 158,
    // (assoc) FT1 = 159,
    // (assoc) FT2 = 160,
    // (assoc) FT3 = 161,
    // (assoc) FT4 = 162,
    // (assoc) FT5 = 163,
    // (assoc) FT6 = 164,
    // (assoc) FT7 = 165,
    // (assoc) FS0 = 166,
    // (assoc) FS1 = 167,
    // (assoc) FA0 = 168,
    // (assoc) FA1 = 169,
    // (assoc) FA2 = 170,
    // (assoc) FA3 = 171,
    // (assoc) FA4 = 172,
    // (assoc) FA5 = 173,
    // (assoc) FA6 = 174,
    // (assoc) FA7 = 175,
    // (assoc) FS2 = 176,
    // (assoc) FS3 = 177,
    // (assoc) FS4 = 178,
    // (assoc) FS5 = 179,
    // (assoc) FS6 = 180,
    // (assoc) FS7 = 181,
    // (assoc) FS8 = 182,
    // (assoc) FS9 = 183,
    // (assoc) FS10 = 184,
    // (assoc) FS11 = 185,
    // (assoc) FT8 = 186,
    // (assoc) FT9 = 187,
    // (assoc) FT10 = 188,
    // (assoc) FT11 = 189,
    pub const ZERO: RegisterRISCV = RegisterRISCV::X0;
    pub const RA: RegisterRISCV = RegisterRISCV::X1;
    pub const SP: RegisterRISCV = RegisterRISCV::X2;
    pub const GP: RegisterRISCV = RegisterRISCV::X3;
    pub const TP: RegisterRISCV = RegisterRISCV::X4;
    pub const T0: RegisterRISCV = RegisterRISCV::X5;
    pub const T1: RegisterRISCV = RegisterRISCV::X6;
    pub const T2: RegisterRISCV = RegisterRISCV::X7;
    pub const S0: RegisterRISCV = RegisterRISCV::X8;
    pub const FP: RegisterRISCV = RegisterRISCV::X8;
    pub const S1: RegisterRISCV = RegisterRISCV::X9;
    pub const A0: RegisterRISCV = RegisterRISCV::X10;
    pub const A1: RegisterRISCV = RegisterRISCV::X11;
    pub const A2: RegisterRISCV = RegisterRISCV::X12;
    pub const A3: RegisterRISCV = RegisterRISCV::X13;
    pub const A4: RegisterRISCV = RegisterRISCV::X14;
    pub const A5: RegisterRISCV = RegisterRISCV::X15;
    pub const A6: RegisterRISCV = RegisterRISCV::X16;
    pub const A7: RegisterRISCV = RegisterRISCV::X17;
    pub const S2: RegisterRISCV = RegisterRISCV::X18;
    pub const S3: RegisterRISCV = RegisterRISCV::X19;
    pub const S4: RegisterRISCV = RegisterRISCV::X20;
    pub const S5: RegisterRISCV = RegisterRISCV::X21;
    pub const S6: RegisterRISCV = RegisterRISCV::X22;
    pub const S7: RegisterRISCV = RegisterRISCV::X23;
    pub const S8: RegisterRISCV = RegisterRISCV::X24;
    pub const S9: RegisterRISCV = RegisterRISCV::X25;
    pub const S10: RegisterRISCV = RegisterRISCV::X26;
    pub const S11: RegisterRISCV = RegisterRISCV::X27;
    pub const T3: RegisterRISCV = RegisterRISCV::X28;
    pub const T4: RegisterRISCV = RegisterRISCV::X29;
    pub const T5: RegisterRISCV = RegisterRISCV::X30;
    pub const T6: RegisterRISCV = RegisterRISCV::X31;
    pub const FT0: RegisterRISCV = RegisterRISCV::F0;
    pub const FT1: RegisterRISCV = RegisterRISCV::F1;
    pub const FT2: RegisterRISCV = RegisterRISCV::F2;
    pub const FT3: RegisterRISCV = RegisterRISCV::F3;
    pub const FT4: RegisterRISCV = RegisterRISCV::F4;
    pub const FT5: RegisterRISCV = RegisterRISCV::F5;
    pub const FT6: RegisterRISCV = RegisterRISCV::F6;
    pub const FT7: RegisterRISCV = RegisterRISCV::F7;
    pub const FS0: RegisterRISCV = RegisterRISCV::F8;
    pub const FS1: RegisterRISCV = RegisterRISCV::F9;
    pub const FA0: RegisterRISCV = RegisterRISCV::F10;
    pub const FA1: RegisterRISCV = RegisterRISCV::F11;
    pub const FA2: RegisterRISCV = RegisterRISCV::F12;
    pub const FA3: RegisterRISCV = RegisterRISCV::F13;
    pub const FA4: RegisterRISCV = RegisterRISCV::F14;
    pub const FA5: RegisterRISCV = RegisterRISCV::F15;
    pub const FA6: RegisterRISCV = RegisterRISCV::F16;
    pub const FA7: RegisterRISCV = RegisterRISCV::F17;
    pub const FS2: RegisterRISCV = RegisterRISCV::F18;
    pub const FS3: RegisterRISCV = RegisterRISCV::F19;
    pub const FS4: RegisterRISCV = RegisterRISCV::F20;
    pub const FS5: RegisterRISCV = RegisterRISCV::F21;
    pub const FS6: RegisterRISCV = RegisterRISCV::F22;
    pub const FS7: RegisterRISCV = RegisterRISCV::F23;
    pub const FS8: RegisterRISCV = RegisterRISCV::F24;
    pub const FS9: RegisterRISCV = RegisterRISCV::F25;
    pub const FS10: RegisterRISCV = RegisterRISCV::F26;
    pub const FS11: RegisterRISCV = RegisterRISCV::F27;
    pub const FT8: RegisterRISCV = RegisterRISCV::F28;
    pub const FT9: RegisterRISCV = RegisterRISCV::F29;
    pub const FT10: RegisterRISCV = RegisterRISCV::F30;
    pub const FT11: RegisterRISCV = RegisterRISCV::F31;
}

impl From<RegisterRISCV> for i32 {
    fn from(r: RegisterRISCV) -> Self {
        r as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Riscv32CpuModel {
    UC_CPU_RISCV32_ANY = 0,
    UC_CPU_RISCV32_BASE32,
    UC_CPU_RISCV32_SIFIVE_E31,
    UC_CPU_RISCV32_SIFIVE_U34,
}

impl From<Riscv32CpuModel> for i32 {
    fn from(value: Riscv32CpuModel) -> Self {
        value as i32
    }
}

impl From<&Riscv32CpuModel> for i32 {
    fn from(value: &Riscv32CpuModel) -> Self {
        (*value) as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Riscv64CpuModel {
    UC_CPU_RISCV64_ANY = 0,
    UC_CPU_RISCV64_BASE64,
    UC_CPU_RISCV64_SIFIVE_E51,
    UC_CPU_RISCV64_SIFIVE_U54,
}

impl From<Riscv64CpuModel> for i32 {
    fn from(value: Riscv64CpuModel) -> Self {
        value as i32
    }
}

impl From<&Riscv64CpuModel> for i32 {
    fn from(value: &Riscv64CpuModel) -> Self {
        (*value) as i32
    }
}
