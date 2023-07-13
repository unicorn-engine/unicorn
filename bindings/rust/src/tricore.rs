#![allow(non_camel_case_types)]

// TRICORE registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterTRICORE {
    INVALID = 0,
    A0 = 1,
    A1 = 2,
    A2 = 3,
    A3 = 4,
    A4 = 5,
    A5 = 6,
    A6 = 7,
    A7 = 8,
    A8 = 9,
    A9 = 10,
    A10 = 11,
    A11 = 12,
    A12 = 13,
    A13 = 14,
    A14 = 15,
    A15 = 16,
    D0 = 17,
    D1 = 18,
    D2 = 19,
    D3 = 20,
    D4 = 21,
    D5 = 22,
    D6 = 23,
    D7 = 24,
    D8 = 25,
    D9 = 26,
    D10 = 27,
    D11 = 28,
    D12 = 29,
    D13 = 30,
    D14 = 31,
    D15 = 32,
    PCXI = 33,
    PSW = 34,
    PSW_USB_C = 35,
    PSW_USB_V = 36,
    PSW_USB_SV = 37,
    PSW_USB_AV = 38,
    PSW_USB_SAV = 39,
    PC = 40,
    SYSCON = 41,
    CPU_ID = 42,
    BIV = 43,
    BTV = 44,
    ISP = 45,
    ICR = 46,
    FCX = 47,
    LCX = 48,
    COMPAT = 49,
    DPR0_U = 50,
    DPR1_U = 51,
    DPR2_U = 52,
    DPR3_U = 53,
    DPR0_L = 54,
    DPR1_L = 55,
    DPR2_L = 56,
    DPR3_L = 57,
    CPR0_U = 58,
    CPR1_U = 59,
    CPR2_U = 60,
    CPR3_U = 61,
    CPR0_L = 62,
    CPR1_L = 63,
    CPR2_L = 64,
    CPR3_L = 65,
    DPM0 = 66,
    DPM1 = 67,
    DPM2 = 68,
    DPM3 = 69,
    CPM0 = 70,
    CPM1 = 71,
    CPM2 = 72,
    CPM3 = 73,
    MMU_CON = 74,
    MMU_ASI = 75,
    MMU_TVA = 76,
    MMU_TPA = 77,
    MMU_TPX = 78,
    MMU_TFA = 79,
    BMACON = 80,
    SMACON = 81,
    DIEAR = 82,
    DIETR = 83,
    CCDIER = 84,
    MIECON = 85,
    PIEAR = 86,
    PIETR = 87,
    CCPIER = 88,
    DBGSR = 89,
    EXEVT = 90,
    CREVT = 91,
    SWEVT = 92,
    TR0EVT = 93,
    TR1EVT = 94,
    DMS = 95,
    DCX = 96,
    DBGTCR = 97,
    CCTRL = 98,
    CCNT = 99,
    ICNT = 100,
    M1CNT = 101,
    M2CNT = 102,
    M3CNT = 103,
    ENDING = 104,
}

impl RegisterTRICORE {
    // alias registers
    // (assoc) GA0 = 1,
    // (assoc) GA1 = 2,
    // (assoc) GA8 = 9,
    // (assoc) GA9 = 10,
    // (assoc) SP = 11,
    // (assoc) LR = 12,
    // (assoc) IA = 16,
    // (assoc) ID = 32,
    pub const GA0: RegisterTRICORE = RegisterTRICORE::A0;
    pub const GA1: RegisterTRICORE = RegisterTRICORE::A1;
    pub const GA8: RegisterTRICORE = RegisterTRICORE::A8;
    pub const GA9: RegisterTRICORE = RegisterTRICORE::A9;
    pub const SP: RegisterTRICORE = RegisterTRICORE::A10;
    pub const LR: RegisterTRICORE = RegisterTRICORE::A11;
    pub const IA: RegisterTRICORE = RegisterTRICORE::A15;
    pub const ID: RegisterTRICORE = RegisterTRICORE::D15;
}

impl From<RegisterTRICORE> for i32 {
    fn from(r: RegisterTRICORE) -> Self {
        r as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TricoreCpuModel {
    UC_CPU_TRICORE_TC1796,
    UC_CPU_TRICORE_TC1797,
    UC_CPU_TRICORE_TC27X,
}

impl From<TricoreCpuModel> for i32 {
    fn from(value: TricoreCpuModel) -> Self {
        value as i32
    }
}

impl From<&TricoreCpuModel> for i32 {
    fn from(value: &TricoreCpuModel) -> Self {
        (*value) as i32
    }
}
