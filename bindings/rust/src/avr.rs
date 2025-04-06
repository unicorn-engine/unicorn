#![allow(non_camel_case_types)]
// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterAVR {
    INVALID = 0,

    // General purpose registers (GPR)
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
    R16 = 17,
    R17 = 18,
    R18 = 19,
    R19 = 20,
    R20 = 21,
    R21 = 22,
    R22 = 23,
    R23 = 24,
    R24 = 25,
    R25 = 26,
    R26 = 27,
    R27 = 28,
    R28 = 29,
    R29 = 30,
    R30 = 31,
    R31 = 32,

    PC = 33,
    SP = 34,

    RAMPD = 57,
    RAMPX = 58,
    RAMPY = 59,
    RAMPZ = 60,
    EIND = 61,
    SPL = 62,
    SPH = 63,
    SREG = 64,

    // 16-bit coalesced registers
    R0W = 65,
    R1W = 66,
    R2W = 67,
    R3W = 68,
    R4W = 69,
    R5W = 70,
    R6W = 71,
    R7W = 72,
    R8W = 73,
    R9W = 74,
    R10W = 75,
    R11W = 76,
    R12W = 77,
    R13W = 78,
    R14W = 79,
    R15W = 80,
    R16W = 81,
    R17W = 82,
    R18W = 83,
    R19W = 84,
    R20W = 85,
    R21W = 86,
    R22W = 87,
    R23W = 88,
    R24W = 89,
    R25W = 90,
    R26W = 91,
    R27W = 92,
    R28W = 93,
    R29W = 94,
    R30W = 95,

    // 32-bit coalesced registers
    R0D = 97,
    R1D = 98,
    R2D = 99,
    R3D = 100,
    R4D = 101,
    R5D = 102,
    R6D = 103,
    R7D = 104,
    R8D = 105,
    R9D = 106,
    R10D = 107,
    R11D = 108,
    R12D = 109,
    R13D = 110,
    R14D = 111,
    R15D = 112,
    R16D = 113,
    R17D = 114,
    R18D = 115,
    R19D = 116,
    R20D = 117,
    R21D = 118,
    R22D = 119,
    R23D = 120,
    R24D = 121,
    R25D = 122,
    R26D = 123,
    R27D = 124,
    R28D = 125,
}

impl RegisterAVR {
    // alias registers
    // (assoc) Xhi = 28
    // (assoc) Xlo = 27
    // (assoc) Yhi = 30
    // (assoc) Ylo = 29
    // (assoc) Zhi = 32
    // (assoc) Zlo = 31
    pub const XHI: RegisterAVR = RegisterAVR::R27;
    pub const XLO: RegisterAVR = RegisterAVR::R26;
    pub const YHI: RegisterAVR = RegisterAVR::R29;
    pub const YLO: RegisterAVR = RegisterAVR::R28;
    pub const ZHI: RegisterAVR = RegisterAVR::R31;
    pub const ZLO: RegisterAVR = RegisterAVR::R30;

    // (assoc) X = 91
    // (assoc) Y = 93
    // (assoc) Z = 95
    pub const X: RegisterAVR = RegisterAVR::R26W;
    pub const Y: RegisterAVR = RegisterAVR::R28W;
    pub const Z: RegisterAVR = RegisterAVR::R30W;
}

impl From<RegisterAVR> for i32 {
    fn from(r: RegisterAVR) -> Self {
        r as i32
    }
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum AvrArch {
    UC_AVR_ARCH_AVR1 = 10,
    UC_AVR_ARCH_AVR2 = 20,
    UC_AVR_ARCH_AVR25 = 25,
    UC_AVR_ARCH_AVR3 = 30,
    UC_AVR_ARCH_AVR4 = 40,
    UC_AVR_ARCH_AVR5 = 50,
    UC_AVR_ARCH_AVR51 = 51,
    UC_AVR_ARCH_AVR6 = 60,
}

impl From<AvrArch> for i32 {
    fn from(value: AvrArch) -> Self {
        value as i32
    }
}

impl From<&AvrArch> for i32 {
    fn from(value: &AvrArch) -> Self {
        *value as i32
    }
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum AvrCpuModel {
    UC_CPU_AVR_ATMEGA16 = 50016,
    UC_CPU_AVR_ATMEGA32 = 50032,
    UC_CPU_AVR_ATMEGA64 = 50064,
    UC_CPU_AVR_ATMEGA128 = 51128,
    UC_CPU_AVR_ATMEGA128RFR2 = 51129,
    UC_CPU_AVR_ATMEGA1280 = 51130,
    UC_CPU_AVR_ATMEGA256 = 60256,
    UC_CPU_AVR_ATMEGA256RFR2 = 60257,
    UC_CPU_AVR_ATMEGA2560 = 60258,
}

impl From<AvrCpuModel> for i32 {
    fn from(value: AvrCpuModel) -> Self {
        value as i32
    }
}

impl From<&AvrCpuModel> for i32 {
    fn from(value: &AvrCpuModel) -> Self {
        *value as i32
    }
}

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AvrMem {
    // Flash program memory (code)
    FLASH = 0x08000000,
}

impl From<AvrMem> for i32 {
    fn from(r: AvrMem) -> Self {
        r as i32
    }
}
