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
}