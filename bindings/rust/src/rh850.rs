#![allow(non_camel_case_types)]

// RH850 registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterRH850 {
    INVALID = -1,

    // General purpose registers
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    R16 = 16,
    R17 = 17,
    R18 = 18,
    R19 = 19,
    R20 = 20,
    R21 = 21,
    R22 = 22,
    R23 = 23,
    R24 = 24,
    R25 = 25,
    R26 = 26,
    R27 = 27,
    R28 = 28,
    R29 = 29,
    R30 = 30,
    R31 = 31,

    // System registers
    EIPC = 32,
    EIPSW = 33,
    FEPC = 34,
    FEPSW = 35,
    ECR = 36,
    PSW = 37,
    FPSR = 38,
    FPEPC = 39,
    FPST = 40,
    FPCC = 41,
    FPCFG = 42,
    FPEC = 43,
    EIIC = 45,
    FEIC = 46,
    CTPC = 48,
    CTPSW = 49,
    CTBP = 52,
    EIWR = 60,
    FEWR = 61,
    BSEL = 63,

    // system registers, selection ID 1
    MCFG0 = 64,
    RBASE = 65,
    EBASE = 66,
    INTBP = 67,
    MCTL = 68,
    PID = 69,
    SCCFG = 75,
    SCBP = 76,

    // system registers, selection ID 2
    HTCFG0 = 96,
    MEA = 102,
    ASID = 103,
    MEI = 104,
    PC = 288,

    ENDING = 289,
}

impl RegisterRH850 {
    // Alias registers
    // (assoc) ZERO = 0,
    // (assoc) SP = 3,
    // (assoc) EP = 30,
    // (assoc) LP = 31,
    pub const ZERO: RegisterRH850 = RegisterRH850::R0;
    pub const SP: RegisterRH850 = RegisterRH850::R3;
    pub const EP: RegisterRH850 = RegisterRH850::R30;
    pub const LP: RegisterRH850 = RegisterRH850::R31;
}

impl From<RegisterRH850> for i32 {
    fn from(r: RegisterRH850) -> Self {
        r as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RH850CpuModel {
    UC_CPU_RH850_ANY = 0,
}

impl From<RH850CpuModel> for i32 {
    fn from(value: Riscv32CpuModel) -> Self {
        value as i32
    }
}

impl From<&RH850CpuModel> for i32 {
    fn from(value: &RH850CpuModel) -> Self {
        (*value) as i32
    }
}