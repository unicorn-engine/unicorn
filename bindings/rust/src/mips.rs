#![allow(non_camel_case_types)]
// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

// MIPS registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterMIPS {
    INVALID = 0,

    // General purpose registers
    PC = 1,
    R0 = 2,
    R1 = 3,
    R2 = 4,
    R3 = 5,
    R4 = 6,
    R5 = 7,
    R6 = 8,
    R7 = 9,
    R8 = 10,
    R9 = 11,
    R10 = 12,
    R11 = 13,
    R12 = 14,
    R13 = 15,
    R14 = 16,
    R15 = 17,
    R16 = 18,
    R17 = 19,
    R18 = 20,
    R19 = 21,
    R20 = 22,
    R21 = 23,
    R22 = 24,
    R23 = 25,
    R24 = 26,
    R25 = 27,
    R26 = 28,
    R27 = 29,
    R28 = 30,
    R29 = 31,
    R30 = 32,
    R31 = 33,

    // DSP registers
    DSPCCOND = 34,
    DSPCARRY = 35,
    DSPEFI = 36,
    DSPOUTFLAG = 37,
    DSPOUTFLAG16_19 = 38,
    DSPOUTFLAG20 = 39,
    DSPOUTFLAG21 = 40,
    DSPOUTFLAG22 = 41,
    DSPOUTFLAG23 = 42,
    DSPPOS = 43,
    DSPSCOUNT = 44,

    // ACC registers
    AC0 = 45,
    AC1 = 46,
    AC2 = 47,
    AC3 = 48,

    // COP registers
    CC0 = 49,
    CC1 = 50,
    CC2 = 51,
    CC3 = 52,
    CC4 = 53,
    CC5 = 54,
    CC6 = 55,
    CC7 = 56,

    // FPU registers
    F0 = 57,
    F1 = 58,
    F2 = 59,
    F3 = 60,
    F4 = 61,
    F5 = 62,
    F6 = 63,
    F7 = 64,
    F8 = 65,
    F9 = 66,
    F10 = 67,
    F11 = 68,
    F12 = 69,
    F13 = 70,
    F14 = 71,
    F15 = 72,
    F16 = 73,
    F17 = 74,
    F18 = 75,
    F19 = 76,
    F20 = 77,
    F21 = 78,
    F22 = 79,
    F23 = 80,
    F24 = 81,
    F25 = 82,
    F26 = 83,
    F27 = 84,
    F28 = 85,
    F29 = 86,
    F30 = 87,
    F31 = 88,
    FCC0 = 89,
    FCC1 = 90,
    FCC2 = 91,
    FCC3 = 92,
    FCC4 = 93,
    FCC5 = 94,
    FCC6 = 95,
    FCC7 = 96,

    // AFPR128
    W0 = 97,
    W1 = 98,
    W2 = 99,
    W3 = 100,
    W4 = 101,
    W5 = 102,
    W6 = 103,
    W7 = 104,
    W8 = 105,
    W9 = 106,
    W10 = 107,
    W11 = 108,
    W12 = 109,
    W13 = 110,
    W14 = 111,
    W15 = 112,
    W16 = 113,
    W17 = 114,
    W18 = 115,
    W19 = 116,
    W20 = 117,
    W21 = 118,
    W22 = 119,
    W23 = 120,
    W24 = 121,
    W25 = 122,
    W26 = 123,
    W27 = 124,
    W28 = 125,
    W29 = 126,
    W30 = 127,
    W31 = 128,
    HI = 129,
    LO = 130,
    P0 = 131,
    P1 = 132,
    P2 = 133,
    MPL0 = 134,
    MPL1 = 135,
    MPL2 = 136,
    CP0_CONFIG3 = 137,
    CP0_USERLOCAL = 138,
    CP0_STATUS = 139,
    ENDING = 140,
}

impl RegisterMIPS {
    // alias registers
    // (assoc) ZERO = 2,
    // (assoc) AT = 3,
    // (assoc) V0 = 4,
    // (assoc) V1 = 5,
    // (assoc) A0 = 6,
    // (assoc) A1 = 7,
    // (assoc) A2 = 8,
    // (assoc) A3 = 9,
    // (assoc) T0 = 10,
    // (assoc) T1 = 11,
    // (assoc) T2 = 12,
    // (assoc) T3 = 13,
    // (assoc) T4 = 14,
    // (assoc) T5 = 15,
    // (assoc) T6 = 16,
    // (assoc) T7 = 17,
    // (assoc) S0 = 18,
    // (assoc) S1 = 19,
    // (assoc) S2 = 20,
    // (assoc) S3 = 21,
    // (assoc) S4 = 22,
    // (assoc) S5 = 23,
    // (assoc) S6 = 24,
    // (assoc) S7 = 25,
    // (assoc) T8 = 26,
    // (assoc) T9 = 27,
    // (assoc) K0 = 28,
    // (assoc) K1 = 29,
    // (assoc) GP = 30,
    // (assoc) SP = 31,
    // (assoc) FP = 32,
    // (assoc) S8 = 32,
    // (assoc) RA = 33,
    // (assoc) HI0 = 45,
    // (assoc) HI1 = 46,
    // (assoc) HI2 = 47,
    // (assoc) HI3 = 48,
    // (assoc) LO0 = 45,
    // (assoc) LO1 = 46,
    // (assoc) LO2 = 47,
    // (assoc) LO3 = 48,
    pub const ZERO: RegisterMIPS = RegisterMIPS::R0;
    pub const AT: RegisterMIPS = RegisterMIPS::R1;
    pub const V0: RegisterMIPS = RegisterMIPS::R2;
    pub const V1: RegisterMIPS = RegisterMIPS::R3;
    pub const A0: RegisterMIPS = RegisterMIPS::R4;
    pub const A1: RegisterMIPS = RegisterMIPS::R5;
    pub const A2: RegisterMIPS = RegisterMIPS::R6;
    pub const A3: RegisterMIPS = RegisterMIPS::R7;
    pub const T0: RegisterMIPS = RegisterMIPS::R8;
    pub const T1: RegisterMIPS = RegisterMIPS::R9;
    pub const T2: RegisterMIPS = RegisterMIPS::R10;
    pub const T3: RegisterMIPS = RegisterMIPS::R11;
    pub const T4: RegisterMIPS = RegisterMIPS::R12;
    pub const T5: RegisterMIPS = RegisterMIPS::R13;
    pub const T6: RegisterMIPS = RegisterMIPS::R14;
    pub const T7: RegisterMIPS = RegisterMIPS::R15;
    pub const S0: RegisterMIPS = RegisterMIPS::R16;
    pub const S1: RegisterMIPS = RegisterMIPS::R17;
    pub const S2: RegisterMIPS = RegisterMIPS::R18;
    pub const S3: RegisterMIPS = RegisterMIPS::R19;
    pub const S4: RegisterMIPS = RegisterMIPS::R20;
    pub const S5: RegisterMIPS = RegisterMIPS::R21;
    pub const S6: RegisterMIPS = RegisterMIPS::R22;
    pub const S7: RegisterMIPS = RegisterMIPS::R23;
    pub const T8: RegisterMIPS = RegisterMIPS::R24;
    pub const T9: RegisterMIPS = RegisterMIPS::R25;
    pub const K0: RegisterMIPS = RegisterMIPS::R26;
    pub const K1: RegisterMIPS = RegisterMIPS::R27;
    pub const GP: RegisterMIPS = RegisterMIPS::R28;
    pub const SP: RegisterMIPS = RegisterMIPS::R29;
    pub const FP: RegisterMIPS = RegisterMIPS::R30;
    pub const S8: RegisterMIPS = RegisterMIPS::R30;
    pub const RA: RegisterMIPS = RegisterMIPS::R31;
    pub const HI0: RegisterMIPS = RegisterMIPS::AC0;
    pub const HI1: RegisterMIPS = RegisterMIPS::AC1;
    pub const HI2: RegisterMIPS = RegisterMIPS::AC2;
    pub const HI3: RegisterMIPS = RegisterMIPS::AC3;
    pub const LO0: RegisterMIPS = RegisterMIPS::AC0;
    pub const LO1: RegisterMIPS = RegisterMIPS::AC1;
    pub const LO2: RegisterMIPS = RegisterMIPS::AC2;
    pub const LO3: RegisterMIPS = RegisterMIPS::AC3;
}

impl From<RegisterMIPS> for i32 {
    fn from(r: RegisterMIPS) -> Self {
        r as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Mips32CpuModel {
    UC_CPU_MIPS32_4KC = 0,
    UC_CPU_MIPS32_4KM = 1,
    UC_CPU_MIPS32_4KECR1 = 2,
    UC_CPU_MIPS32_4KEMR1 = 3,
    UC_CPU_MIPS32_4KEC = 4,
    UC_CPU_MIPS32_4KEM = 5,
    UC_CPU_MIPS32_24KC = 6,
    UC_CPU_MIPS32_24KEC = 7,
    UC_CPU_MIPS32_24KF = 8,
    UC_CPU_MIPS32_34KF = 9,
    UC_CPU_MIPS32_74KF = 10,
    UC_CPU_MIPS32_M14K = 11,
    UC_CPU_MIPS32_M14KC = 12,
    UC_CPU_MIPS32_P5600 = 13,
    UC_CPU_MIPS32_MIPS32R6_GENERIC = 14,
    UC_CPU_MIPS32_I7200 = 15,
}

impl From<Mips32CpuModel> for i32 {
    fn from(value: Mips32CpuModel) -> Self {
        value as i32
    }
}

impl From<&Mips32CpuModel> for i32 {
    fn from(value: &Mips32CpuModel) -> Self {
        *value as i32
    }
}
