#![allow(non_camel_case_types)]

// M68K registers
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RegisterM68K {
    INVALID = 0,
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    D0,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    SR,
    PC,
    ENDING,
}

impl From<RegisterM68K> for i32 {
    fn from(r: RegisterM68K) -> Self {
        r as i32
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum M68kCpuModel {
    UC_CPU_M68K_M5206 = 0,
    UC_CPU_M68K_M68000 = 1,
    UC_CPU_M68K_M68020 = 2,
    UC_CPU_M68K_M68030 = 3,
    UC_CPU_M68K_M68040 = 4,
    UC_CPU_M68K_M68060 = 5,
    UC_CPU_M68K_M5208 = 6,
    UC_CPU_M68K_CFV4E = 7,
    UC_CPU_M68K_ANY = 8,
}

impl From<M68kCpuModel> for i32 {
    fn from(value: M68kCpuModel) -> Self {
        value as i32
    }
}

impl From<&M68kCpuModel> for i32 {
    fn from(value: &M68kCpuModel) -> Self {
        (*value) as i32
    }
}
