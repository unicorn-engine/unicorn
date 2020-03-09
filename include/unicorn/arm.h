/* Unicorn Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef UNICORN_ARM_H
#define UNICORN_ARM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> ARM registers
typedef enum uc_arm_reg {
    UC_ARM_REG_INVALID = 0,
    UC_ARM_REG_APSR,
    UC_ARM_REG_APSR_NZCV,
    UC_ARM_REG_CPSR,
    UC_ARM_REG_FPEXC,
    UC_ARM_REG_FPINST,
    UC_ARM_REG_FPSCR,
    UC_ARM_REG_FPSCR_NZCV,
    UC_ARM_REG_FPSID,
    UC_ARM_REG_ITSTATE,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_SP,
    UC_ARM_REG_SPSR,
    UC_ARM_REG_D0,
    UC_ARM_REG_D1,
    UC_ARM_REG_D2,
    UC_ARM_REG_D3,
    UC_ARM_REG_D4,
    UC_ARM_REG_D5,
    UC_ARM_REG_D6,
    UC_ARM_REG_D7,
    UC_ARM_REG_D8,
    UC_ARM_REG_D9,
    UC_ARM_REG_D10,
    UC_ARM_REG_D11,
    UC_ARM_REG_D12,
    UC_ARM_REG_D13,
    UC_ARM_REG_D14,
    UC_ARM_REG_D15,
    UC_ARM_REG_D16,
    UC_ARM_REG_D17,
    UC_ARM_REG_D18,
    UC_ARM_REG_D19,
    UC_ARM_REG_D20,
    UC_ARM_REG_D21,
    UC_ARM_REG_D22,
    UC_ARM_REG_D23,
    UC_ARM_REG_D24,
    UC_ARM_REG_D25,
    UC_ARM_REG_D26,
    UC_ARM_REG_D27,
    UC_ARM_REG_D28,
    UC_ARM_REG_D29,
    UC_ARM_REG_D30,
    UC_ARM_REG_D31,
    UC_ARM_REG_FPINST2,
    UC_ARM_REG_MVFR0,
    UC_ARM_REG_MVFR1,
    UC_ARM_REG_MVFR2,
    UC_ARM_REG_Q0,
    UC_ARM_REG_Q1,
    UC_ARM_REG_Q2,
    UC_ARM_REG_Q3,
    UC_ARM_REG_Q4,
    UC_ARM_REG_Q5,
    UC_ARM_REG_Q6,
    UC_ARM_REG_Q7,
    UC_ARM_REG_Q8,
    UC_ARM_REG_Q9,
    UC_ARM_REG_Q10,
    UC_ARM_REG_Q11,
    UC_ARM_REG_Q12,
    UC_ARM_REG_Q13,
    UC_ARM_REG_Q14,
    UC_ARM_REG_Q15,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_S0,
    UC_ARM_REG_S1,
    UC_ARM_REG_S2,
    UC_ARM_REG_S3,
    UC_ARM_REG_S4,
    UC_ARM_REG_S5,
    UC_ARM_REG_S6,
    UC_ARM_REG_S7,
    UC_ARM_REG_S8,
    UC_ARM_REG_S9,
    UC_ARM_REG_S10,
    UC_ARM_REG_S11,
    UC_ARM_REG_S12,
    UC_ARM_REG_S13,
    UC_ARM_REG_S14,
    UC_ARM_REG_S15,
    UC_ARM_REG_S16,
    UC_ARM_REG_S17,
    UC_ARM_REG_S18,
    UC_ARM_REG_S19,
    UC_ARM_REG_S20,
    UC_ARM_REG_S21,
    UC_ARM_REG_S22,
    UC_ARM_REG_S23,
    UC_ARM_REG_S24,
    UC_ARM_REG_S25,
    UC_ARM_REG_S26,
    UC_ARM_REG_S27,
    UC_ARM_REG_S28,
    UC_ARM_REG_S29,
    UC_ARM_REG_S30,
    UC_ARM_REG_S31,

    UC_ARM_REG_C1_C0_2,
    UC_ARM_REG_C13_C0_2,
    UC_ARM_REG_C13_C0_3,

    UC_ARM_REG_IPSR,
    UC_ARM_REG_MSP,
    UC_ARM_REG_PSP,
    UC_ARM_REG_CONTROL,
    UC_ARM_REG_ENDING,		// <-- mark the end of the list or registers

    //> alias registers
    UC_ARM_REG_R13 = UC_ARM_REG_SP,
    UC_ARM_REG_R14 = UC_ARM_REG_LR,
    UC_ARM_REG_R15 = UC_ARM_REG_PC,

    UC_ARM_REG_SB = UC_ARM_REG_R9,
    UC_ARM_REG_SL = UC_ARM_REG_R10,
    UC_ARM_REG_FP = UC_ARM_REG_R11,
    UC_ARM_REG_IP = UC_ARM_REG_R12,
} uc_arm_reg;

#ifdef __cplusplus
}
#endif

#endif
