// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

namespace UnicornManaged.Const

open System

[<AutoOpen>]
module Riscv =

    // RISCV32 CPU

    let UC_CPU_RISCV32_ANY = 0
    let UC_CPU_RISCV32_BASE32 = 1
    let UC_CPU_RISCV32_SIFIVE_E31 = 2
    let UC_CPU_RISCV32_SIFIVE_U34 = 3

    // RISCV64 CPU

    let UC_CPU_RISCV64_ANY = 0
    let UC_CPU_RISCV64_BASE64 = 1
    let UC_CPU_RISCV64_SIFIVE_E51 = 2
    let UC_CPU_RISCV64_SIFIVE_U54 = 3

    // RISCV registers

    let UC_RISCV_REG_INVALID = 0

    // General purpose registers
    let UC_RISCV_REG_X0 = 1
    let UC_RISCV_REG_X1 = 2
    let UC_RISCV_REG_X2 = 3
    let UC_RISCV_REG_X3 = 4
    let UC_RISCV_REG_X4 = 5
    let UC_RISCV_REG_X5 = 6
    let UC_RISCV_REG_X6 = 7
    let UC_RISCV_REG_X7 = 8
    let UC_RISCV_REG_X8 = 9
    let UC_RISCV_REG_X9 = 10
    let UC_RISCV_REG_X10 = 11
    let UC_RISCV_REG_X11 = 12
    let UC_RISCV_REG_X12 = 13
    let UC_RISCV_REG_X13 = 14
    let UC_RISCV_REG_X14 = 15
    let UC_RISCV_REG_X15 = 16
    let UC_RISCV_REG_X16 = 17
    let UC_RISCV_REG_X17 = 18
    let UC_RISCV_REG_X18 = 19
    let UC_RISCV_REG_X19 = 20
    let UC_RISCV_REG_X20 = 21
    let UC_RISCV_REG_X21 = 22
    let UC_RISCV_REG_X22 = 23
    let UC_RISCV_REG_X23 = 24
    let UC_RISCV_REG_X24 = 25
    let UC_RISCV_REG_X25 = 26
    let UC_RISCV_REG_X26 = 27
    let UC_RISCV_REG_X27 = 28
    let UC_RISCV_REG_X28 = 29
    let UC_RISCV_REG_X29 = 30
    let UC_RISCV_REG_X30 = 31
    let UC_RISCV_REG_X31 = 32

    // Floating-point registers
    let UC_RISCV_REG_F0 = 33
    let UC_RISCV_REG_F1 = 34
    let UC_RISCV_REG_F2 = 35
    let UC_RISCV_REG_F3 = 36
    let UC_RISCV_REG_F4 = 37
    let UC_RISCV_REG_F5 = 38
    let UC_RISCV_REG_F6 = 39
    let UC_RISCV_REG_F7 = 40
    let UC_RISCV_REG_F8 = 41
    let UC_RISCV_REG_F9 = 42
    let UC_RISCV_REG_F10 = 43
    let UC_RISCV_REG_F11 = 44
    let UC_RISCV_REG_F12 = 45
    let UC_RISCV_REG_F13 = 46
    let UC_RISCV_REG_F14 = 47
    let UC_RISCV_REG_F15 = 48
    let UC_RISCV_REG_F16 = 49
    let UC_RISCV_REG_F17 = 50
    let UC_RISCV_REG_F18 = 51
    let UC_RISCV_REG_F19 = 52
    let UC_RISCV_REG_F20 = 53
    let UC_RISCV_REG_F21 = 54
    let UC_RISCV_REG_F22 = 55
    let UC_RISCV_REG_F23 = 56
    let UC_RISCV_REG_F24 = 57
    let UC_RISCV_REG_F25 = 58
    let UC_RISCV_REG_F26 = 59
    let UC_RISCV_REG_F27 = 60
    let UC_RISCV_REG_F28 = 61
    let UC_RISCV_REG_F29 = 62
    let UC_RISCV_REG_F30 = 63
    let UC_RISCV_REG_F31 = 64
    let UC_RISCV_REG_PC = 65
    let UC_RISCV_REG_ENDING = 66

    // Alias registers
    let UC_RISCV_REG_ZERO = 1
    let UC_RISCV_REG_RA = 2
    let UC_RISCV_REG_SP = 3
    let UC_RISCV_REG_GP = 4
    let UC_RISCV_REG_TP = 5
    let UC_RISCV_REG_T0 = 6
    let UC_RISCV_REG_T1 = 7
    let UC_RISCV_REG_T2 = 8
    let UC_RISCV_REG_S0 = 9
    let UC_RISCV_REG_FP = 9
    let UC_RISCV_REG_S1 = 10
    let UC_RISCV_REG_A0 = 11
    let UC_RISCV_REG_A1 = 12
    let UC_RISCV_REG_A2 = 13
    let UC_RISCV_REG_A3 = 14
    let UC_RISCV_REG_A4 = 15
    let UC_RISCV_REG_A5 = 16
    let UC_RISCV_REG_A6 = 17
    let UC_RISCV_REG_A7 = 18
    let UC_RISCV_REG_S2 = 19
    let UC_RISCV_REG_S3 = 20
    let UC_RISCV_REG_S4 = 21
    let UC_RISCV_REG_S5 = 22
    let UC_RISCV_REG_S6 = 23
    let UC_RISCV_REG_S7 = 24
    let UC_RISCV_REG_S8 = 25
    let UC_RISCV_REG_S9 = 26
    let UC_RISCV_REG_S10 = 27
    let UC_RISCV_REG_S11 = 28
    let UC_RISCV_REG_T3 = 29
    let UC_RISCV_REG_T4 = 30
    let UC_RISCV_REG_T5 = 31
    let UC_RISCV_REG_T6 = 32
    let UC_RISCV_REG_FT0 = 33
    let UC_RISCV_REG_FT1 = 34
    let UC_RISCV_REG_FT2 = 35
    let UC_RISCV_REG_FT3 = 36
    let UC_RISCV_REG_FT4 = 37
    let UC_RISCV_REG_FT5 = 38
    let UC_RISCV_REG_FT6 = 39
    let UC_RISCV_REG_FT7 = 40
    let UC_RISCV_REG_FS0 = 41
    let UC_RISCV_REG_FS1 = 42
    let UC_RISCV_REG_FA0 = 43
    let UC_RISCV_REG_FA1 = 44
    let UC_RISCV_REG_FA2 = 45
    let UC_RISCV_REG_FA3 = 46
    let UC_RISCV_REG_FA4 = 47
    let UC_RISCV_REG_FA5 = 48
    let UC_RISCV_REG_FA6 = 49
    let UC_RISCV_REG_FA7 = 50
    let UC_RISCV_REG_FS2 = 51
    let UC_RISCV_REG_FS3 = 52
    let UC_RISCV_REG_FS4 = 53
    let UC_RISCV_REG_FS5 = 54
    let UC_RISCV_REG_FS6 = 55
    let UC_RISCV_REG_FS7 = 56
    let UC_RISCV_REG_FS8 = 57
    let UC_RISCV_REG_FS9 = 58
    let UC_RISCV_REG_FS10 = 59
    let UC_RISCV_REG_FS11 = 60
    let UC_RISCV_REG_FT8 = 61
    let UC_RISCV_REG_FT9 = 62
    let UC_RISCV_REG_FT10 = 63
    let UC_RISCV_REG_FT11 = 64

