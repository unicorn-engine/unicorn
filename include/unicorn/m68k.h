/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef UNICORN_M68K_H
#define UNICORN_M68K_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

//> M68K CPU
typedef enum uc_cpu_m68k {
    UC_CPU_M68K_M5206 = 0,
    UC_CPU_M68K_M68000,
    UC_CPU_M68K_M68020,
    UC_CPU_M68K_M68030,
    UC_CPU_M68K_M68040,
    UC_CPU_M68K_M68060,
    UC_CPU_M68K_M5208,
    UC_CPU_M68K_CFV4E,
    UC_CPU_M68K_ANY,

    UC_CPU_M68K_ENDING
} uc_cpu_m68k;

//> M68K registers
typedef enum uc_m68k_reg {
    UC_M68K_REG_INVALID = 0,

    UC_M68K_REG_A0,
    UC_M68K_REG_A1,
    UC_M68K_REG_A2,
    UC_M68K_REG_A3,
    UC_M68K_REG_A4,
    UC_M68K_REG_A5,
    UC_M68K_REG_A6,
    UC_M68K_REG_A7,

    UC_M68K_REG_D0,
    UC_M68K_REG_D1,
    UC_M68K_REG_D2,
    UC_M68K_REG_D3,
    UC_M68K_REG_D4,
    UC_M68K_REG_D5,
    UC_M68K_REG_D6,
    UC_M68K_REG_D7,

    UC_M68K_REG_SR,
    UC_M68K_REG_PC,

    UC_M68K_REG_CR_SFC,
    UC_M68K_REG_CR_DFC,
    UC_M68K_REG_CR_VBR,
    UC_M68K_REG_CR_CACR,
    UC_M68K_REG_CR_TC,
    UC_M68K_REG_CR_MMUSR,
    UC_M68K_REG_CR_SRP,
    UC_M68K_REG_CR_USP,
    UC_M68K_REG_CR_MSP,
    UC_M68K_REG_CR_ISP,
    UC_M68K_REG_CR_URP,
    UC_M68K_REG_CR_ITT0,
    UC_M68K_REG_CR_ITT1,
    UC_M68K_REG_CR_DTT0,
    UC_M68K_REG_CR_DTT1,

    UC_M68K_REG_ENDING, // <-- mark the end of the list of registers
} uc_m68k_reg;

#ifdef __cplusplus
}
#endif

#endif
