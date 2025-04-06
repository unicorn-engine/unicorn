/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

/*
   Created for Unicorn Engine by Glenn Baker <glenn.baker@gmx.com>, 2024
*/

#ifndef UNICORN_AVR_H
#define UNICORN_AVR_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

//> AVR architectures
typedef enum uc_avr_arch {
    UC_AVR_ARCH_AVR1 = 10,
    UC_AVR_ARCH_AVR2 = 20,
    UC_AVR_ARCH_AVR25 = 25,
    UC_AVR_ARCH_AVR3 = 30,
    UC_AVR_ARCH_AVR4 = 40,
    UC_AVR_ARCH_AVR5 = 50,
    UC_AVR_ARCH_AVR51 = 51,
    UC_AVR_ARCH_AVR6 = 60,
} uc_avr_arch;

#define UC_CPU_AVR_ARCH 1000

//> AVR CPU
typedef enum uc_cpu_avr {
    // Enhanced Core with 16K up to 64K of program memory ("AVR5")
    UC_CPU_AVR_ATMEGA16 = UC_AVR_ARCH_AVR5*UC_CPU_AVR_ARCH + 16,
    UC_CPU_AVR_ATMEGA32 = UC_AVR_ARCH_AVR5*UC_CPU_AVR_ARCH + 32,
    UC_CPU_AVR_ATMEGA64 = UC_AVR_ARCH_AVR5*UC_CPU_AVR_ARCH + 64,

    // Enhanced Core with 128K of program memory ("AVR5.1")
    UC_CPU_AVR_ATMEGA128 = UC_AVR_ARCH_AVR51*UC_CPU_AVR_ARCH + 128,
    UC_CPU_AVR_ATMEGA128RFR2,
    UC_CPU_AVR_ATMEGA1280,

    // Enhanced Core with 128K+ of program memory, i.e. 3-byte PC ("AVR6")
    UC_CPU_AVR_ATMEGA256 = UC_AVR_ARCH_AVR6*UC_CPU_AVR_ARCH + 256,
    UC_CPU_AVR_ATMEGA256RFR2,
    UC_CPU_AVR_ATMEGA2560,
} uc_cpu_avr;

//> AVR memory
typedef enum uc_avr_mem {
    // Flash program memory (code)
    UC_AVR_MEM_FLASH = 0x08000000,
} uc_avr_mem;

//> AVR registers
typedef enum uc_avr_reg {
    UC_AVR_REG_INVALID = 0,

    // General purpose registers (GPR)
    UC_AVR_REG_R0 = 1,
    UC_AVR_REG_R1,
    UC_AVR_REG_R2,
    UC_AVR_REG_R3,
    UC_AVR_REG_R4,
    UC_AVR_REG_R5,
    UC_AVR_REG_R6,
    UC_AVR_REG_R7,
    UC_AVR_REG_R8,
    UC_AVR_REG_R9,
    UC_AVR_REG_R10,
    UC_AVR_REG_R11,
    UC_AVR_REG_R12,
    UC_AVR_REG_R13,
    UC_AVR_REG_R14,
    UC_AVR_REG_R15,
    UC_AVR_REG_R16,
    UC_AVR_REG_R17,
    UC_AVR_REG_R18,
    UC_AVR_REG_R19,
    UC_AVR_REG_R20,
    UC_AVR_REG_R21,
    UC_AVR_REG_R22,
    UC_AVR_REG_R23,
    UC_AVR_REG_R24,
    UC_AVR_REG_R25,
    UC_AVR_REG_R26,
    UC_AVR_REG_R27,
    UC_AVR_REG_R28,
    UC_AVR_REG_R29,
    UC_AVR_REG_R30,
    UC_AVR_REG_R31,

    UC_AVR_REG_PC,
    UC_AVR_REG_SP,

    UC_AVR_REG_RAMPD = UC_AVR_REG_PC + 16 + 8,
    UC_AVR_REG_RAMPX,
    UC_AVR_REG_RAMPY,
    UC_AVR_REG_RAMPZ,
    UC_AVR_REG_EIND,
    UC_AVR_REG_SPL,
    UC_AVR_REG_SPH,
    UC_AVR_REG_SREG,

    //> 16-bit coalesced registers
    UC_AVR_REG_R0W = UC_AVR_REG_PC + 32,
    UC_AVR_REG_R1W,
    UC_AVR_REG_R2W,
    UC_AVR_REG_R3W,
    UC_AVR_REG_R4W,
    UC_AVR_REG_R5W,
    UC_AVR_REG_R6W,
    UC_AVR_REG_R7W,
    UC_AVR_REG_R8W,
    UC_AVR_REG_R9W,
    UC_AVR_REG_R10W,
    UC_AVR_REG_R11W,
    UC_AVR_REG_R12W,
    UC_AVR_REG_R13W,
    UC_AVR_REG_R14W,
    UC_AVR_REG_R15W,
    UC_AVR_REG_R16W,
    UC_AVR_REG_R17W,
    UC_AVR_REG_R18W,
    UC_AVR_REG_R19W,
    UC_AVR_REG_R20W,
    UC_AVR_REG_R21W,
    UC_AVR_REG_R22W,
    UC_AVR_REG_R23W,
    UC_AVR_REG_R24W,
    UC_AVR_REG_R25W,
    UC_AVR_REG_R26W,
    UC_AVR_REG_R27W,
    UC_AVR_REG_R28W,
    UC_AVR_REG_R29W,
    UC_AVR_REG_R30W,

    //> 32-bit coalesced registers
    UC_AVR_REG_R0D = UC_AVR_REG_PC + 64,
    UC_AVR_REG_R1D,
    UC_AVR_REG_R2D,
    UC_AVR_REG_R3D,
    UC_AVR_REG_R4D,
    UC_AVR_REG_R5D,
    UC_AVR_REG_R6D,
    UC_AVR_REG_R7D,
    UC_AVR_REG_R8D,
    UC_AVR_REG_R9D,
    UC_AVR_REG_R10D,
    UC_AVR_REG_R11D,
    UC_AVR_REG_R12D,
    UC_AVR_REG_R13D,
    UC_AVR_REG_R14D,
    UC_AVR_REG_R15D,
    UC_AVR_REG_R16D,
    UC_AVR_REG_R17D,
    UC_AVR_REG_R18D,
    UC_AVR_REG_R19D,
    UC_AVR_REG_R20D,
    UC_AVR_REG_R21D,
    UC_AVR_REG_R22D,
    UC_AVR_REG_R23D,
    UC_AVR_REG_R24D,
    UC_AVR_REG_R25D,
    UC_AVR_REG_R26D,
    UC_AVR_REG_R27D,
    UC_AVR_REG_R28D,

    //> Alias registers
    UC_AVR_REG_Xhi = UC_AVR_REG_R27,
    UC_AVR_REG_Xlo = UC_AVR_REG_R26,
    UC_AVR_REG_Yhi = UC_AVR_REG_R29,
    UC_AVR_REG_Ylo = UC_AVR_REG_R28,
    UC_AVR_REG_Zhi = UC_AVR_REG_R31,
    UC_AVR_REG_Zlo = UC_AVR_REG_R30,

    UC_AVR_REG_X = UC_AVR_REG_R26W,
    UC_AVR_REG_Y = UC_AVR_REG_R28W,
    UC_AVR_REG_Z = UC_AVR_REG_R30W,
} uc_avr_reg;

#ifdef __cplusplus
}
#endif

#endif /* UNICORN_AVR_H */
