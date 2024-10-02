// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

namespace UnicornEngine.Const

open System

[<AutoOpen>]
module AVR =

    // AVR architectures
    let UC_AVR_ARCH_AVR1 = 10
    let UC_AVR_ARCH_AVR2 = 20
    let UC_AVR_ARCH_AVR25 = 25
    let UC_AVR_ARCH_AVR3 = 30
    let UC_AVR_ARCH_AVR4 = 40
    let UC_AVR_ARCH_AVR5 = 50
    let UC_AVR_ARCH_AVR51 = 51
    let UC_AVR_ARCH_AVR6 = 60
    let UC_AVR_ARCH_AVRXMEGA = 100
    let UC_AVR_ARCH_AVRXMEGAR2 = 101
    let UC_CPU_AVR_ARCH = 1000

    // AVR CPU
    let UC_CPU_AVR_ATMEGA16 = 50016
    let UC_CPU_AVR_ATMEGA32 = 50032
    let UC_CPU_AVR_ATMEGA64 = 50064
    let UC_CPU_AVR_ATMEGA128 = 51128
    let UC_CPU_AVR_ATMEGA128RFR2 = 51129
    let UC_CPU_AVR_ATMEGA1280 = 51130
    let UC_CPU_AVR_ATMEGA256 = 60256
    let UC_CPU_AVR_ATMEGA256RFR2 = 60257
    let UC_CPU_AVR_ATMEGA2560 = 60258
    let UC_CPU_AVR_ATXMEGA16A4 = 100016
    let UC_CPU_AVR_ATXMEGA32A4 = 100032
    let UC_CPU_AVR_ATXMEGA64A3 = 100064
    let UC_CPU_AVR_ATXMEGA64A1U = 101064
    let UC_CPU_AVR_ATXMEGA64A3U = 101065
    let UC_CPU_AVR_ATXMEGA64A4U = 101066
    let UC_CPU_AVR_ATXMEGA128A3 = 100128
    let UC_CPU_AVR_ATXMEGA128A1U = 101128
    let UC_CPU_AVR_ATXMEGA128A3U = 101129
    let UC_CPU_AVR_ATXMEGA128A4U = 101130
    let UC_CPU_AVR_ATXMEGA192A3 = 100192
    let UC_CPU_AVR_ATXMEGA192A3U = 101192
    let UC_CPU_AVR_ATXMEGA256A3 = 100256
    let UC_CPU_AVR_ATXMEGA256A3U = 101256

    // AVR memory
    let UC_AVR_MEM_FLASH = 134217728

    // AVR registers

    let UC_AVR_REG_INVALID = 0
    let UC_AVR_REG_R0 = 1
    let UC_AVR_REG_R1 = 2
    let UC_AVR_REG_R2 = 3
    let UC_AVR_REG_R3 = 4
    let UC_AVR_REG_R4 = 5
    let UC_AVR_REG_R5 = 6
    let UC_AVR_REG_R6 = 7
    let UC_AVR_REG_R7 = 8
    let UC_AVR_REG_R8 = 9
    let UC_AVR_REG_R9 = 10
    let UC_AVR_REG_R10 = 11
    let UC_AVR_REG_R11 = 12
    let UC_AVR_REG_R12 = 13
    let UC_AVR_REG_R13 = 14
    let UC_AVR_REG_R14 = 15
    let UC_AVR_REG_R15 = 16
    let UC_AVR_REG_R16 = 17
    let UC_AVR_REG_R17 = 18
    let UC_AVR_REG_R18 = 19
    let UC_AVR_REG_R19 = 20
    let UC_AVR_REG_R20 = 21
    let UC_AVR_REG_R21 = 22
    let UC_AVR_REG_R22 = 23
    let UC_AVR_REG_R23 = 24
    let UC_AVR_REG_R24 = 25
    let UC_AVR_REG_R25 = 26
    let UC_AVR_REG_R26 = 27
    let UC_AVR_REG_R27 = 28
    let UC_AVR_REG_R28 = 29
    let UC_AVR_REG_R29 = 30
    let UC_AVR_REG_R30 = 31
    let UC_AVR_REG_R31 = 32
    let UC_AVR_REG_PC = 33
    let UC_AVR_REG_SP = 34
    let UC_AVR_REG_RAMPD = 57
    let UC_AVR_REG_RAMPX = 58
    let UC_AVR_REG_RAMPY = 59
    let UC_AVR_REG_RAMPZ = 60
    let UC_AVR_REG_EIND = 61
    let UC_AVR_REG_SPL = 62
    let UC_AVR_REG_SPH = 63
    let UC_AVR_REG_SREG = 64

    // 16-bit coalesced registers
    let UC_AVR_REG_R0W = 65
    let UC_AVR_REG_R1W = 66
    let UC_AVR_REG_R2W = 67
    let UC_AVR_REG_R3W = 68
    let UC_AVR_REG_R4W = 69
    let UC_AVR_REG_R5W = 70
    let UC_AVR_REG_R6W = 71
    let UC_AVR_REG_R7W = 72
    let UC_AVR_REG_R8W = 73
    let UC_AVR_REG_R9W = 74
    let UC_AVR_REG_R10W = 75
    let UC_AVR_REG_R11W = 76
    let UC_AVR_REG_R12W = 77
    let UC_AVR_REG_R13W = 78
    let UC_AVR_REG_R14W = 79
    let UC_AVR_REG_R15W = 80
    let UC_AVR_REG_R16W = 81
    let UC_AVR_REG_R17W = 82
    let UC_AVR_REG_R18W = 83
    let UC_AVR_REG_R19W = 84
    let UC_AVR_REG_R20W = 85
    let UC_AVR_REG_R21W = 86
    let UC_AVR_REG_R22W = 87
    let UC_AVR_REG_R23W = 88
    let UC_AVR_REG_R24W = 89
    let UC_AVR_REG_R25W = 90
    let UC_AVR_REG_R26W = 91
    let UC_AVR_REG_R27W = 92
    let UC_AVR_REG_R28W = 93
    let UC_AVR_REG_R29W = 94
    let UC_AVR_REG_R30W = 95

    // 32-bit coalesced registers
    let UC_AVR_REG_R0D = 97
    let UC_AVR_REG_R1D = 98
    let UC_AVR_REG_R2D = 99
    let UC_AVR_REG_R3D = 100
    let UC_AVR_REG_R4D = 101
    let UC_AVR_REG_R5D = 102
    let UC_AVR_REG_R6D = 103
    let UC_AVR_REG_R7D = 104
    let UC_AVR_REG_R8D = 105
    let UC_AVR_REG_R9D = 106
    let UC_AVR_REG_R10D = 107
    let UC_AVR_REG_R11D = 108
    let UC_AVR_REG_R12D = 109
    let UC_AVR_REG_R13D = 110
    let UC_AVR_REG_R14D = 111
    let UC_AVR_REG_R15D = 112
    let UC_AVR_REG_R16D = 113
    let UC_AVR_REG_R17D = 114
    let UC_AVR_REG_R18D = 115
    let UC_AVR_REG_R19D = 116
    let UC_AVR_REG_R20D = 117
    let UC_AVR_REG_R21D = 118
    let UC_AVR_REG_R22D = 119
    let UC_AVR_REG_R23D = 120
    let UC_AVR_REG_R24D = 121
    let UC_AVR_REG_R25D = 122
    let UC_AVR_REG_R26D = 123
    let UC_AVR_REG_R27D = 124
    let UC_AVR_REG_R28D = 125

    // Alias registers
    let UC_AVR_REG_Xhi = 28
    let UC_AVR_REG_Xlo = 27
    let UC_AVR_REG_Yhi = 30
    let UC_AVR_REG_Ylo = 29
    let UC_AVR_REG_Zhi = 32
    let UC_AVR_REG_Zlo = 31
    let UC_AVR_REG_X = 91
    let UC_AVR_REG_Y = 93
    let UC_AVR_REG_Z = 95

