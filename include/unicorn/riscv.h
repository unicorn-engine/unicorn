/* Unicorn Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2020 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
 */

#ifndef UNICORN_RISCV_H
#define UNICORN_RISCV_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> RISCV registers
typedef enum uc_riscv_reg {
    UC_RISCV_REG_INVALID = 0,
    //> General purpose registers
    UC_RISCV_REG_X0,
    UC_RISCV_REG_X1,
    UC_RISCV_REG_X2,
    UC_RISCV_REG_X3,
    UC_RISCV_REG_X4,
    UC_RISCV_REG_X5,
    UC_RISCV_REG_X6,
    UC_RISCV_REG_X7,
    UC_RISCV_REG_X8,
    UC_RISCV_REG_X9,
    UC_RISCV_REG_X10,
    UC_RISCV_REG_X11,
    UC_RISCV_REG_X12,
    UC_RISCV_REG_X13,
    UC_RISCV_REG_X14,
    UC_RISCV_REG_X15,
    UC_RISCV_REG_X16,
    UC_RISCV_REG_X17,
    UC_RISCV_REG_X18,
    UC_RISCV_REG_X19,
    UC_RISCV_REG_X20,
    UC_RISCV_REG_X21,
    UC_RISCV_REG_X22,
    UC_RISCV_REG_X23,
    UC_RISCV_REG_X24,
    UC_RISCV_REG_X25,
    UC_RISCV_REG_X26,
    UC_RISCV_REG_X27,
    UC_RISCV_REG_X28,
    UC_RISCV_REG_X29,
    UC_RISCV_REG_X30,
    UC_RISCV_REG_X31,

    //> Floating-point registers
    UC_RISCV_REG_F0,    // "ft0"
    UC_RISCV_REG_F1,    // "ft1"
    UC_RISCV_REG_F2,    // "ft2"
    UC_RISCV_REG_F3,    // "ft3"
    UC_RISCV_REG_F4,    // "ft4"
    UC_RISCV_REG_F5,    // "ft5"
    UC_RISCV_REG_F6,    // "ft6"
    UC_RISCV_REG_F7,    // "ft7"
    UC_RISCV_REG_F8,    // "fs0"
    UC_RISCV_REG_F9,    // "fs1"
    UC_RISCV_REG_F10,   // "fa0"
    UC_RISCV_REG_F11,   // "fa1"
    UC_RISCV_REG_F12,   // "fa2"
    UC_RISCV_REG_F13,   // "fa3"
    UC_RISCV_REG_F14,   // "fa4"
    UC_RISCV_REG_F15,   // "fa5"
    UC_RISCV_REG_F16,   // "fa6"
    UC_RISCV_REG_F17,   // "fa7"
    UC_RISCV_REG_F18,   // "fs2"
    UC_RISCV_REG_F19,   // "fs3"
    UC_RISCV_REG_F20,   // "fs4"
    UC_RISCV_REG_F21,   // "fs5"
    UC_RISCV_REG_F22,   // "fs6"
    UC_RISCV_REG_F23,   // "fs7"
    UC_RISCV_REG_F24,   // "fs8"
    UC_RISCV_REG_F25,   // "fs9"
    UC_RISCV_REG_F26,   // "fs10"
    UC_RISCV_REG_F27,   // "fs11"
    UC_RISCV_REG_F28,   // "ft8"
    UC_RISCV_REG_F29,   // "ft9"
    UC_RISCV_REG_F30,   // "ft10"
    UC_RISCV_REG_F31,   // "ft11"

    UC_RISCV_REG_PC,    // PC register

    UC_RISCV_REG_ENDING,	// <-- mark the end of the list or registers

    //> Alias registers
    UC_RISCV_REG_ZERO = UC_RISCV_REG_X0,    // "zero"
    UC_RISCV_REG_RA   = UC_RISCV_REG_X1,    // "ra"
    UC_RISCV_REG_SP   = UC_RISCV_REG_X2,    // "sp"
    UC_RISCV_REG_GP   = UC_RISCV_REG_X3,    // "gp"
    UC_RISCV_REG_TP   = UC_RISCV_REG_X4,    // "tp"
    UC_RISCV_REG_T0   = UC_RISCV_REG_X5,    // "t0"
    UC_RISCV_REG_T1   = UC_RISCV_REG_X6,    // "t1"
    UC_RISCV_REG_T2   = UC_RISCV_REG_X7,    // "t2"
    UC_RISCV_REG_S0   = UC_RISCV_REG_X8,    // "s0"
    UC_RISCV_REG_FP   = UC_RISCV_REG_X8,    // "fp"
    UC_RISCV_REG_S1   = UC_RISCV_REG_X9,    // "s1"
    UC_RISCV_REG_A0   = UC_RISCV_REG_X10,   // "a0"
    UC_RISCV_REG_A1   = UC_RISCV_REG_X11,   // "a1"
    UC_RISCV_REG_A2   = UC_RISCV_REG_X12,   // "a2"
    UC_RISCV_REG_A3   = UC_RISCV_REG_X13,   // "a3"
    UC_RISCV_REG_A4   = UC_RISCV_REG_X14,   // "a4"
    UC_RISCV_REG_A5   = UC_RISCV_REG_X15,   // "a5"
    UC_RISCV_REG_A6   = UC_RISCV_REG_X16,   // "a6"
    UC_RISCV_REG_A7   = UC_RISCV_REG_X17,   // "a7"
    UC_RISCV_REG_S2   = UC_RISCV_REG_X18,   // "s2"
    UC_RISCV_REG_S3   = UC_RISCV_REG_X19,   // "s3"
    UC_RISCV_REG_S4   = UC_RISCV_REG_X20,   // "s4"
    UC_RISCV_REG_S5   = UC_RISCV_REG_X21,   // "s5"
    UC_RISCV_REG_S6   = UC_RISCV_REG_X22,   // "s6"
    UC_RISCV_REG_S7   = UC_RISCV_REG_X23,   // "s7"
    UC_RISCV_REG_S8   = UC_RISCV_REG_X24,   // "s8"
    UC_RISCV_REG_S9   = UC_RISCV_REG_X25,   // "s9"
    UC_RISCV_REG_S10  = UC_RISCV_REG_X26,   // "s10"
    UC_RISCV_REG_S11  = UC_RISCV_REG_X27,   // "s11"
    UC_RISCV_REG_T3   = UC_RISCV_REG_X28,   // "t3"
    UC_RISCV_REG_T4   = UC_RISCV_REG_X29,   // "t4"
    UC_RISCV_REG_T5   = UC_RISCV_REG_X30,   // "t5"
    UC_RISCV_REG_T6   = UC_RISCV_REG_X31,   // "t6"

    UC_RISCV_REG_FT0 = UC_RISCV_REG_F0,	    // "ft0"
    UC_RISCV_REG_FT1 = UC_RISCV_REG_F1,	    // "ft1"
    UC_RISCV_REG_FT2 = UC_RISCV_REG_F2,	    // "ft2"
    UC_RISCV_REG_FT3 = UC_RISCV_REG_F3,	    // "ft3"
    UC_RISCV_REG_FT4 = UC_RISCV_REG_F4,	    // "ft4"
    UC_RISCV_REG_FT5 = UC_RISCV_REG_F5,	    // "ft5"
    UC_RISCV_REG_FT6 = UC_RISCV_REG_F6,	    // "ft6"
    UC_RISCV_REG_FT7 = UC_RISCV_REG_F7,	    // "ft7"
    UC_RISCV_REG_FS0 = UC_RISCV_REG_F8,	    // "fs0"
    UC_RISCV_REG_FS1 = UC_RISCV_REG_F9,	    // "fs1"

    UC_RISCV_REG_FA0 = UC_RISCV_REG_F10,    // "fa0"
    UC_RISCV_REG_FA1 = UC_RISCV_REG_F11,    // "fa1"
    UC_RISCV_REG_FA2 = UC_RISCV_REG_F12,    // "fa2"
    UC_RISCV_REG_FA3 = UC_RISCV_REG_F13,    // "fa3"
    UC_RISCV_REG_FA4 = UC_RISCV_REG_F14,    // "fa4"
    UC_RISCV_REG_FA5 = UC_RISCV_REG_F15,    // "fa5"
    UC_RISCV_REG_FA6 = UC_RISCV_REG_F16,    // "fa6"
    UC_RISCV_REG_FA7 = UC_RISCV_REG_F17,    // "fa7"
    UC_RISCV_REG_FS2 = UC_RISCV_REG_F18,    // "fs2"
    UC_RISCV_REG_FS3 = UC_RISCV_REG_F19,    // "fs3"
    UC_RISCV_REG_FS4 = UC_RISCV_REG_F20,    // "fs4"
    UC_RISCV_REG_FS5 = UC_RISCV_REG_F21,    // "fs5"
    UC_RISCV_REG_FS6 = UC_RISCV_REG_F22,    // "fs6"
    UC_RISCV_REG_FS7 = UC_RISCV_REG_F23,    // "fs7"
    UC_RISCV_REG_FS8 = UC_RISCV_REG_F24,    // "fs8"
    UC_RISCV_REG_FS9 = UC_RISCV_REG_F25,    // "fs9"
    UC_RISCV_REG_FS10 = UC_RISCV_REG_F26,   // "fs10"
    UC_RISCV_REG_FS11 = UC_RISCV_REG_F27,   // "fs11"
    UC_RISCV_REG_FT8 = UC_RISCV_REG_F28,    // "ft8"
    UC_RISCV_REG_FT9 = UC_RISCV_REG_F29,    // "ft9"
    UC_RISCV_REG_FT10 = UC_RISCV_REG_F30,   // "ft10"
    UC_RISCV_REG_FT11 = UC_RISCV_REG_F31,   // "ft11"
} uc_riscv_reg;

#ifdef __cplusplus
}
#endif

#endif
