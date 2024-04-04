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

//> AVR CPU
typedef enum uc_cpu_avr {
    UC_CPU_AVR_AVR5 = 5,
    UC_CPU_AVR_AVR51 = 51,
    UC_CPU_AVR_AVR6 = 6,
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

    //> Alias registers
    UC_AVR_REG_Xhi = UC_AVR_REG_R27,
    UC_AVR_REG_Xlo = UC_AVR_REG_R26,
    UC_AVR_REG_Yhi = UC_AVR_REG_R29,
    UC_AVR_REG_Ylo = UC_AVR_REG_R28,
    UC_AVR_REG_Zhi = UC_AVR_REG_R31,
    UC_AVR_REG_Zlo = UC_AVR_REG_R30,
} uc_avr_reg;

#ifdef __cplusplus
}
#endif

#endif /* UNICORN_AVR_H */
