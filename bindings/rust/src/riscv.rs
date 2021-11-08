#![allow(non_camel_case_types)]
// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

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

    // Floating-point registers
    F0 = 33,
    F1 = 34,
    F2 = 35,
    F3 = 36,
    F4 = 37,
    F5 = 38,
    F6 = 39,
    F7 = 40,
    F8 = 41,
    F9 = 42,
    F10 = 43,
    F11 = 44,
    F12 = 45,
    F13 = 46,
    F14 = 47,
    F15 = 48,
    F16 = 49,
    F17 = 50,
    F18 = 51,
    F19 = 52,
    F20 = 53,
    F21 = 54,
    F22 = 55,
    F23 = 56,
    F24 = 57,
    F25 = 58,
    F26 = 59,
    F27 = 60,
    F28 = 61,
    F29 = 62,
    F30 = 63,
    F31 = 64,
    PC = 65,
    ENDING = 66,
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
    // (assoc) FT0 = 33,
    // (assoc) FT1 = 34,
    // (assoc) FT2 = 35,
    // (assoc) FT3 = 36,
    // (assoc) FT4 = 37,
    // (assoc) FT5 = 38,
    // (assoc) FT6 = 39,
    // (assoc) FT7 = 40,
    // (assoc) FS0 = 41,
    // (assoc) FS1 = 42,
    // (assoc) FA0 = 43,
    // (assoc) FA1 = 44,
    // (assoc) FA2 = 45,
    // (assoc) FA3 = 46,
    // (assoc) FA4 = 47,
    // (assoc) FA5 = 48,
    // (assoc) FA6 = 49,
    // (assoc) FA7 = 50,
    // (assoc) FS2 = 51,
    // (assoc) FS3 = 52,
    // (assoc) FS4 = 53,
    // (assoc) FS5 = 54,
    // (assoc) FS6 = 55,
    // (assoc) FS7 = 56,
    // (assoc) FS8 = 57,
    // (assoc) FS9 = 58,
    // (assoc) FS10 = 59,
    // (assoc) FS11 = 60,
    // (assoc) FT8 = 61,
    // (assoc) FT9 = 62,
    // (assoc) FT10 = 63,
    // (assoc) FT11 = 64,
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
