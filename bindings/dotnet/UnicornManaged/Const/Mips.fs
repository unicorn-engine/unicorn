// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

namespace UnicornManaged.Const

open System

[<AutoOpen>]
module Mips =

    // MIPS registers

    let UC_MIPS_REG_INVALID = 0

    // General purpose registers
    let UC_MIPS_REG_PC = 1
    let UC_MIPS_REG_0 = 2
    let UC_MIPS_REG_1 = 3
    let UC_MIPS_REG_2 = 4
    let UC_MIPS_REG_3 = 5
    let UC_MIPS_REG_4 = 6
    let UC_MIPS_REG_5 = 7
    let UC_MIPS_REG_6 = 8
    let UC_MIPS_REG_7 = 9
    let UC_MIPS_REG_8 = 10
    let UC_MIPS_REG_9 = 11
    let UC_MIPS_REG_10 = 12
    let UC_MIPS_REG_11 = 13
    let UC_MIPS_REG_12 = 14
    let UC_MIPS_REG_13 = 15
    let UC_MIPS_REG_14 = 16
    let UC_MIPS_REG_15 = 17
    let UC_MIPS_REG_16 = 18
    let UC_MIPS_REG_17 = 19
    let UC_MIPS_REG_18 = 20
    let UC_MIPS_REG_19 = 21
    let UC_MIPS_REG_20 = 22
    let UC_MIPS_REG_21 = 23
    let UC_MIPS_REG_22 = 24
    let UC_MIPS_REG_23 = 25
    let UC_MIPS_REG_24 = 26
    let UC_MIPS_REG_25 = 27
    let UC_MIPS_REG_26 = 28
    let UC_MIPS_REG_27 = 29
    let UC_MIPS_REG_28 = 30
    let UC_MIPS_REG_29 = 31
    let UC_MIPS_REG_30 = 32
    let UC_MIPS_REG_31 = 33

    // DSP registers
    let UC_MIPS_REG_DSPCCOND = 34
    let UC_MIPS_REG_DSPCARRY = 35
    let UC_MIPS_REG_DSPEFI = 36
    let UC_MIPS_REG_DSPOUTFLAG = 37
    let UC_MIPS_REG_DSPOUTFLAG16_19 = 38
    let UC_MIPS_REG_DSPOUTFLAG20 = 39
    let UC_MIPS_REG_DSPOUTFLAG21 = 40
    let UC_MIPS_REG_DSPOUTFLAG22 = 41
    let UC_MIPS_REG_DSPOUTFLAG23 = 42
    let UC_MIPS_REG_DSPPOS = 43
    let UC_MIPS_REG_DSPSCOUNT = 44

    // ACC registers
    let UC_MIPS_REG_AC0 = 45
    let UC_MIPS_REG_AC1 = 46
    let UC_MIPS_REG_AC2 = 47
    let UC_MIPS_REG_AC3 = 48

    // COP registers
    let UC_MIPS_REG_CC0 = 49
    let UC_MIPS_REG_CC1 = 50
    let UC_MIPS_REG_CC2 = 51
    let UC_MIPS_REG_CC3 = 52
    let UC_MIPS_REG_CC4 = 53
    let UC_MIPS_REG_CC5 = 54
    let UC_MIPS_REG_CC6 = 55
    let UC_MIPS_REG_CC7 = 56

    // FPU registers
    let UC_MIPS_REG_F0 = 57
    let UC_MIPS_REG_F1 = 58
    let UC_MIPS_REG_F2 = 59
    let UC_MIPS_REG_F3 = 60
    let UC_MIPS_REG_F4 = 61
    let UC_MIPS_REG_F5 = 62
    let UC_MIPS_REG_F6 = 63
    let UC_MIPS_REG_F7 = 64
    let UC_MIPS_REG_F8 = 65
    let UC_MIPS_REG_F9 = 66
    let UC_MIPS_REG_F10 = 67
    let UC_MIPS_REG_F11 = 68
    let UC_MIPS_REG_F12 = 69
    let UC_MIPS_REG_F13 = 70
    let UC_MIPS_REG_F14 = 71
    let UC_MIPS_REG_F15 = 72
    let UC_MIPS_REG_F16 = 73
    let UC_MIPS_REG_F17 = 74
    let UC_MIPS_REG_F18 = 75
    let UC_MIPS_REG_F19 = 76
    let UC_MIPS_REG_F20 = 77
    let UC_MIPS_REG_F21 = 78
    let UC_MIPS_REG_F22 = 79
    let UC_MIPS_REG_F23 = 80
    let UC_MIPS_REG_F24 = 81
    let UC_MIPS_REG_F25 = 82
    let UC_MIPS_REG_F26 = 83
    let UC_MIPS_REG_F27 = 84
    let UC_MIPS_REG_F28 = 85
    let UC_MIPS_REG_F29 = 86
    let UC_MIPS_REG_F30 = 87
    let UC_MIPS_REG_F31 = 88
    let UC_MIPS_REG_FCC0 = 89
    let UC_MIPS_REG_FCC1 = 90
    let UC_MIPS_REG_FCC2 = 91
    let UC_MIPS_REG_FCC3 = 92
    let UC_MIPS_REG_FCC4 = 93
    let UC_MIPS_REG_FCC5 = 94
    let UC_MIPS_REG_FCC6 = 95
    let UC_MIPS_REG_FCC7 = 96

    // AFPR128
    let UC_MIPS_REG_W0 = 97
    let UC_MIPS_REG_W1 = 98
    let UC_MIPS_REG_W2 = 99
    let UC_MIPS_REG_W3 = 100
    let UC_MIPS_REG_W4 = 101
    let UC_MIPS_REG_W5 = 102
    let UC_MIPS_REG_W6 = 103
    let UC_MIPS_REG_W7 = 104
    let UC_MIPS_REG_W8 = 105
    let UC_MIPS_REG_W9 = 106
    let UC_MIPS_REG_W10 = 107
    let UC_MIPS_REG_W11 = 108
    let UC_MIPS_REG_W12 = 109
    let UC_MIPS_REG_W13 = 110
    let UC_MIPS_REG_W14 = 111
    let UC_MIPS_REG_W15 = 112
    let UC_MIPS_REG_W16 = 113
    let UC_MIPS_REG_W17 = 114
    let UC_MIPS_REG_W18 = 115
    let UC_MIPS_REG_W19 = 116
    let UC_MIPS_REG_W20 = 117
    let UC_MIPS_REG_W21 = 118
    let UC_MIPS_REG_W22 = 119
    let UC_MIPS_REG_W23 = 120
    let UC_MIPS_REG_W24 = 121
    let UC_MIPS_REG_W25 = 122
    let UC_MIPS_REG_W26 = 123
    let UC_MIPS_REG_W27 = 124
    let UC_MIPS_REG_W28 = 125
    let UC_MIPS_REG_W29 = 126
    let UC_MIPS_REG_W30 = 127
    let UC_MIPS_REG_W31 = 128
    let UC_MIPS_REG_HI = 129
    let UC_MIPS_REG_LO = 130
    let UC_MIPS_REG_P0 = 131
    let UC_MIPS_REG_P1 = 132
    let UC_MIPS_REG_P2 = 133
    let UC_MIPS_REG_MPL0 = 134
    let UC_MIPS_REG_MPL1 = 135
    let UC_MIPS_REG_MPL2 = 136
    let UC_MIPS_REG_ENDING = 137
    let UC_MIPS_REG_ZERO = 2
    let UC_MIPS_REG_AT = 3
    let UC_MIPS_REG_V0 = 4
    let UC_MIPS_REG_V1 = 5
    let UC_MIPS_REG_A0 = 6
    let UC_MIPS_REG_A1 = 7
    let UC_MIPS_REG_A2 = 8
    let UC_MIPS_REG_A3 = 9
    let UC_MIPS_REG_T0 = 10
    let UC_MIPS_REG_T1 = 11
    let UC_MIPS_REG_T2 = 12
    let UC_MIPS_REG_T3 = 13
    let UC_MIPS_REG_T4 = 14
    let UC_MIPS_REG_T5 = 15
    let UC_MIPS_REG_T6 = 16
    let UC_MIPS_REG_T7 = 17
    let UC_MIPS_REG_S0 = 18
    let UC_MIPS_REG_S1 = 19
    let UC_MIPS_REG_S2 = 20
    let UC_MIPS_REG_S3 = 21
    let UC_MIPS_REG_S4 = 22
    let UC_MIPS_REG_S5 = 23
    let UC_MIPS_REG_S6 = 24
    let UC_MIPS_REG_S7 = 25
    let UC_MIPS_REG_T8 = 26
    let UC_MIPS_REG_T9 = 27
    let UC_MIPS_REG_K0 = 28
    let UC_MIPS_REG_K1 = 29
    let UC_MIPS_REG_GP = 30
    let UC_MIPS_REG_SP = 31
    let UC_MIPS_REG_FP = 32
    let UC_MIPS_REG_S8 = 32
    let UC_MIPS_REG_RA = 33
    let UC_MIPS_REG_HI0 = 45
    let UC_MIPS_REG_HI1 = 46
    let UC_MIPS_REG_HI2 = 47
    let UC_MIPS_REG_HI3 = 48
    let UC_MIPS_REG_LO0 = 45
    let UC_MIPS_REG_LO1 = 46
    let UC_MIPS_REG_LO2 = 47
    let UC_MIPS_REG_LO3 = 48

