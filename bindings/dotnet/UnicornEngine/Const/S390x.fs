// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

namespace UnicornEngine.Const

open System

[<AutoOpen>]
module S390x =

    // S390X CPU

    let UC_CPU_S390X_Z900 = 0
    let UC_CPU_S390X_Z900_2 = 1
    let UC_CPU_S390X_Z900_3 = 2
    let UC_CPU_S390X_Z800 = 3
    let UC_CPU_S390X_Z990 = 4
    let UC_CPU_S390X_Z990_2 = 5
    let UC_CPU_S390X_Z990_3 = 6
    let UC_CPU_S390X_Z890 = 7
    let UC_CPU_S390X_Z990_4 = 8
    let UC_CPU_S390X_Z890_2 = 9
    let UC_CPU_S390X_Z990_5 = 10
    let UC_CPU_S390X_Z890_3 = 11
    let UC_CPU_S390X_Z9EC = 12
    let UC_CPU_S390X_Z9EC_2 = 13
    let UC_CPU_S390X_Z9BC = 14
    let UC_CPU_S390X_Z9EC_3 = 15
    let UC_CPU_S390X_Z9BC_2 = 16
    let UC_CPU_S390X_Z10EC = 17
    let UC_CPU_S390X_Z10EC_2 = 18
    let UC_CPU_S390X_Z10BC = 19
    let UC_CPU_S390X_Z10EC_3 = 20
    let UC_CPU_S390X_Z10BC_2 = 21
    let UC_CPU_S390X_Z196 = 22
    let UC_CPU_S390X_Z196_2 = 23
    let UC_CPU_S390X_Z114 = 24
    let UC_CPU_S390X_ZEC12 = 25
    let UC_CPU_S390X_ZEC12_2 = 26
    let UC_CPU_S390X_ZBC12 = 27
    let UC_CPU_S390X_Z13 = 28
    let UC_CPU_S390X_Z13_2 = 29
    let UC_CPU_S390X_Z13S = 30
    let UC_CPU_S390X_Z14 = 31
    let UC_CPU_S390X_Z14_2 = 32
    let UC_CPU_S390X_Z14ZR1 = 33
    let UC_CPU_S390X_GEN15A = 34
    let UC_CPU_S390X_GEN15B = 35
    let UC_CPU_S390X_QEMU = 36
    let UC_CPU_S390X_MAX = 37
    let UC_CPU_S390X_ENDING = 38

    // S390X registers

    let UC_S390X_REG_INVALID = 0

    // General purpose registers
    let UC_S390X_REG_R0 = 1
    let UC_S390X_REG_R1 = 2
    let UC_S390X_REG_R2 = 3
    let UC_S390X_REG_R3 = 4
    let UC_S390X_REG_R4 = 5
    let UC_S390X_REG_R5 = 6
    let UC_S390X_REG_R6 = 7
    let UC_S390X_REG_R7 = 8
    let UC_S390X_REG_R8 = 9
    let UC_S390X_REG_R9 = 10
    let UC_S390X_REG_R10 = 11
    let UC_S390X_REG_R11 = 12
    let UC_S390X_REG_R12 = 13
    let UC_S390X_REG_R13 = 14
    let UC_S390X_REG_R14 = 15
    let UC_S390X_REG_R15 = 16

    // Floating point registers
    let UC_S390X_REG_F0 = 17
    let UC_S390X_REG_F1 = 18
    let UC_S390X_REG_F2 = 19
    let UC_S390X_REG_F3 = 20
    let UC_S390X_REG_F4 = 21
    let UC_S390X_REG_F5 = 22
    let UC_S390X_REG_F6 = 23
    let UC_S390X_REG_F7 = 24
    let UC_S390X_REG_F8 = 25
    let UC_S390X_REG_F9 = 26
    let UC_S390X_REG_F10 = 27
    let UC_S390X_REG_F11 = 28
    let UC_S390X_REG_F12 = 29
    let UC_S390X_REG_F13 = 30
    let UC_S390X_REG_F14 = 31
    let UC_S390X_REG_F15 = 32

    // Not real registers, low half of vr16-vr31
    let UC_S390X_REG_F16 = 33
    let UC_S390X_REG_F17 = 34
    let UC_S390X_REG_F18 = 35
    let UC_S390X_REG_F19 = 36
    let UC_S390X_REG_F20 = 37
    let UC_S390X_REG_F21 = 38
    let UC_S390X_REG_F22 = 39
    let UC_S390X_REG_F23 = 40
    let UC_S390X_REG_F24 = 41
    let UC_S390X_REG_F25 = 42
    let UC_S390X_REG_F26 = 43
    let UC_S390X_REG_F27 = 44
    let UC_S390X_REG_F28 = 45
    let UC_S390X_REG_F29 = 46
    let UC_S390X_REG_F30 = 47
    let UC_S390X_REG_F31 = 48

    // Access registers
    let UC_S390X_REG_A0 = 49
    let UC_S390X_REG_A1 = 50
    let UC_S390X_REG_A2 = 51
    let UC_S390X_REG_A3 = 52
    let UC_S390X_REG_A4 = 53
    let UC_S390X_REG_A5 = 54
    let UC_S390X_REG_A6 = 55
    let UC_S390X_REG_A7 = 56
    let UC_S390X_REG_A8 = 57
    let UC_S390X_REG_A9 = 58
    let UC_S390X_REG_A10 = 59
    let UC_S390X_REG_A11 = 60
    let UC_S390X_REG_A12 = 61
    let UC_S390X_REG_A13 = 62
    let UC_S390X_REG_A14 = 63
    let UC_S390X_REG_A15 = 64
    let UC_S390X_REG_PC = 65
    let UC_S390X_REG_PSWM = 66

    // pseudo registers, high half of vr16-vr31
    let UC_S390X_REG_F0_HI = 67
    let UC_S390X_REG_F1_HI = 68
    let UC_S390X_REG_F2_HI = 69
    let UC_S390X_REG_F3_HI = 70
    let UC_S390X_REG_F4_HI = 71
    let UC_S390X_REG_F5_HI = 72
    let UC_S390X_REG_F6_HI = 73
    let UC_S390X_REG_F7_HI = 74
    let UC_S390X_REG_F8_HI = 75
    let UC_S390X_REG_F9_HI = 76
    let UC_S390X_REG_F10_HI = 77
    let UC_S390X_REG_F11_HI = 78
    let UC_S390X_REG_F12_HI = 79
    let UC_S390X_REG_F13_HI = 80
    let UC_S390X_REG_F14_HI = 81
    let UC_S390X_REG_F15_HI = 82
    let UC_S390X_REG_F16_HI = 83
    let UC_S390X_REG_F17_HI = 84
    let UC_S390X_REG_F18_HI = 85
    let UC_S390X_REG_F19_HI = 86
    let UC_S390X_REG_F20_HI = 87
    let UC_S390X_REG_F21_HI = 88
    let UC_S390X_REG_F22_HI = 89
    let UC_S390X_REG_F23_HI = 90
    let UC_S390X_REG_F24_HI = 91
    let UC_S390X_REG_F25_HI = 92
    let UC_S390X_REG_F26_HI = 93
    let UC_S390X_REG_F27_HI = 94
    let UC_S390X_REG_F28_HI = 95
    let UC_S390X_REG_F29_HI = 96
    let UC_S390X_REG_F30_HI = 97
    let UC_S390X_REG_F31_HI = 98

    // float control register
    let UC_S390X_REG_FPC = 99

    // control registers
    let UC_S390X_REG_CR0 = 100
    let UC_S390X_REG_CR1 = 101
    let UC_S390X_REG_CR2 = 102
    let UC_S390X_REG_CR3 = 103
    let UC_S390X_REG_CR4 = 104
    let UC_S390X_REG_CR5 = 105
    let UC_S390X_REG_CR6 = 106
    let UC_S390X_REG_CR7 = 107
    let UC_S390X_REG_CR8 = 108
    let UC_S390X_REG_CR9 = 109
    let UC_S390X_REG_CR10 = 110
    let UC_S390X_REG_CR11 = 111
    let UC_S390X_REG_CR12 = 112
    let UC_S390X_REG_CR13 = 113
    let UC_S390X_REG_CR14 = 114
    let UC_S390X_REG_CR15 = 115
    let UC_S390X_REG_ENDING = 116

    // Alias registers

