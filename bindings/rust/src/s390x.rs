// S390X registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
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
