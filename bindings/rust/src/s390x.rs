#![allow(non_camel_case_types)]

// S390X registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterS390X {
    INVALID = 0,

    // General purpose registers
    R0 = 1,
    R1 = 2,
    R2 = 3,
    R3 = 4,
    R4 = 5,
    R5 = 6,
    R6 = 7,
    R7 = 8,
    R8 = 9,
    R9 = 10,
    R10 = 11,
    R11 = 12,
    R12 = 13,
    R13 = 14,
    R14 = 15,
    R15 = 16,

    // Floating point registers
    F0 = 17,
    F1 = 18,
    F2 = 19,
    F3 = 20,
    F4 = 21,
    F5 = 22,
    F6 = 23,
    F7 = 24,
    F8 = 25,
    F9 = 26,
    F10 = 27,
    F11 = 28,
    F12 = 29,
    F13 = 30,
    F14 = 31,
    F15 = 32,
    F16 = 33,
    F17 = 34,
    F18 = 35,
    F19 = 36,
    F20 = 37,
    F21 = 38,
    F22 = 39,
    F23 = 40,
    F24 = 41,
    F25 = 42,
    F26 = 43,
    F27 = 44,
    F28 = 45,
    F29 = 46,
    F30 = 47,
    F31 = 48,

    // Access registers
    A0 = 49,
    A1 = 50,
    A2 = 51,
    A3 = 52,
    A4 = 53,
    A5 = 54,
    A6 = 55,
    A7 = 56,
    A8 = 57,
    A9 = 58,
    A10 = 59,
    A11 = 60,
    A12 = 61,
    A13 = 62,
    A14 = 63,
    A15 = 64,
    PC = 65,
    PSWM = 66,
    ENDING = 67,
}

impl From<RegisterS390X> for i32 {
    fn from(r: RegisterS390X) -> Self {
        r as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum S390xCpuModel {
    UC_CPU_S390X_Z900 = 0,
    UC_CPU_S390X_Z900_2,
    UC_CPU_S390X_Z900_3,
    UC_CPU_S390X_Z800,
    UC_CPU_S390X_Z990,
    UC_CPU_S390X_Z990_2,
    UC_CPU_S390X_Z990_3,
    UC_CPU_S390X_Z890,
    UC_CPU_S390X_Z990_4,
    UC_CPU_S390X_Z890_2,
    UC_CPU_S390X_Z990_5,
    UC_CPU_S390X_Z890_3,
    UC_CPU_S390X_Z9EC,
    UC_CPU_S390X_Z9EC_2,
    UC_CPU_S390X_Z9BC,
    UC_CPU_S390X_Z9EC_3,
    UC_CPU_S390X_Z9BC_2,
    UC_CPU_S390X_Z10EC,
    UC_CPU_S390X_Z10EC_2,
    UC_CPU_S390X_Z10BC,
    UC_CPU_S390X_Z10EC_3,
    UC_CPU_S390X_Z10BC_2,
    UC_CPU_S390X_Z196,
    UC_CPU_S390X_Z196_2,
    UC_CPU_S390X_Z114,
    UC_CPU_S390X_ZEC12,
    UC_CPU_S390X_ZEC12_2,
    UC_CPU_S390X_ZBC12,
    UC_CPU_S390X_Z13,
    UC_CPU_S390X_Z13_2,
    UC_CPU_S390X_Z13S,
    UC_CPU_S390X_Z14,
    UC_CPU_S390X_Z14_2,
    UC_CPU_S390X_Z14ZR1,
    UC_CPU_S390X_GEN15A,
    UC_CPU_S390X_GEN15B,
    UC_CPU_S390X_QEMU,
}

impl From<S390xCpuModel> for i32 {
    fn from(value: S390xCpuModel) -> Self {
        value as i32
    }
}

impl From<&S390xCpuModel> for i32 {
    fn from(value: &S390xCpuModel) -> Self {
        (*value) as i32
    }
}
