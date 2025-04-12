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
#pragma warning(disable : 4201)
#endif

//> ARM CPU
typedef enum uc_cpu_arm {
    UC_CPU_ARM_926 = 0,
    UC_CPU_ARM_946,
    UC_CPU_ARM_1026,
    UC_CPU_ARM_1136_R2,
    UC_CPU_ARM_1136,
    UC_CPU_ARM_1176,
    UC_CPU_ARM_11MPCORE,
    UC_CPU_ARM_CORTEX_M0,
    UC_CPU_ARM_CORTEX_M3,
    UC_CPU_ARM_CORTEX_M4,
    UC_CPU_ARM_CORTEX_M7,
    UC_CPU_ARM_CORTEX_M33,
    UC_CPU_ARM_CORTEX_R5,
    UC_CPU_ARM_CORTEX_R5F,
    UC_CPU_ARM_CORTEX_A7,
    UC_CPU_ARM_CORTEX_A8,
    UC_CPU_ARM_CORTEX_A9,
    UC_CPU_ARM_CORTEX_A15,
    UC_CPU_ARM_TI925T,
    UC_CPU_ARM_SA1100,
    UC_CPU_ARM_SA1110,
    UC_CPU_ARM_PXA250,
    UC_CPU_ARM_PXA255,
    UC_CPU_ARM_PXA260,
    UC_CPU_ARM_PXA261,
    UC_CPU_ARM_PXA262,
    UC_CPU_ARM_PXA270,
    UC_CPU_ARM_PXA270A0,
    UC_CPU_ARM_PXA270A1,
    UC_CPU_ARM_PXA270B0,
    UC_CPU_ARM_PXA270B1,
    UC_CPU_ARM_PXA270C0,
    UC_CPU_ARM_PXA270C5,
    UC_CPU_ARM_MAX,

    UC_CPU_ARM_ENDING
} uc_cpu_arm;

// ARM coprocessor registers, use this with UC_ARM_REG_CP_REG to
// in call to uc_reg_write/read() to access the registers.
typedef struct uc_arm_cp_reg {
    uint32_t cp;   // The coprocessor identifier
    uint32_t is64; // Is it a 64 bit control register
    uint32_t sec;  // Security state
    uint32_t crn;  // Coprocessor register number
    uint32_t crm;  // Coprocessor register number
    uint32_t opc1; // Opcode1
    uint32_t opc2; // Opcode2
    uint64_t val;  // The value to read/write
} uc_arm_cp_reg;

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

    UC_ARM_REG_C1_C0_2,  // Depreciated, use UC_ARM_REG_CP_REG instead
    UC_ARM_REG_C13_C0_2, // Depreciated, use UC_ARM_REG_CP_REG instead
    UC_ARM_REG_C13_C0_3, // Depreciated, use UC_ARM_REG_CP_REG instead

    UC_ARM_REG_IPSR,
    UC_ARM_REG_MSP,
    UC_ARM_REG_PSP,
    UC_ARM_REG_CONTROL,
    UC_ARM_REG_IAPSR,
    UC_ARM_REG_EAPSR,
    UC_ARM_REG_XPSR,
    UC_ARM_REG_EPSR,
    UC_ARM_REG_IEPSR,
    UC_ARM_REG_PRIMASK,
    UC_ARM_REG_BASEPRI,
    UC_ARM_REG_BASEPRI_MAX,
    UC_ARM_REG_FAULTMASK,
    UC_ARM_REG_APSR_NZCVQ,
    UC_ARM_REG_APSR_G,
    UC_ARM_REG_APSR_NZCVQG,
    UC_ARM_REG_IAPSR_NZCVQ,
    UC_ARM_REG_IAPSR_G,
    UC_ARM_REG_IAPSR_NZCVQG,
    UC_ARM_REG_EAPSR_NZCVQ,
    UC_ARM_REG_EAPSR_G,
    UC_ARM_REG_EAPSR_NZCVQG,
    UC_ARM_REG_XPSR_NZCVQ,
    UC_ARM_REG_XPSR_G,
    UC_ARM_REG_XPSR_NZCVQG,
    UC_ARM_REG_CP_REG,
	// A pseudo-register for fetching the exception syndrome
	// from the CPU state. This is not a real register.
    UC_ARM_REG_ESR,
    UC_ARM_REG_ENDING, // <-- mark the end of the list or registers

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
