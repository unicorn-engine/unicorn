/* Unicorn Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2021 */

#ifndef UNICORN_S390X_H
#define UNICORN_S390X_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> S390X registers
typedef enum uc_s390x_reg {
    UC_S390X_REG_INVALID = 0,
    //> General purpose registers
    UC_S390X_REG_R0,
    UC_S390X_REG_R1,
    UC_S390X_REG_R2,
    UC_S390X_REG_R3,
    UC_S390X_REG_R4,
    UC_S390X_REG_R5,
    UC_S390X_REG_R6,
    UC_S390X_REG_R7,
    UC_S390X_REG_R8,
    UC_S390X_REG_R9,
    UC_S390X_REG_R10,
    UC_S390X_REG_R11,
    UC_S390X_REG_R12,
    UC_S390X_REG_R13,
    UC_S390X_REG_R14,
    UC_S390X_REG_R15,

    //> Floating point registers
    UC_S390X_REG_F0,
    UC_S390X_REG_F1,
    UC_S390X_REG_F2,
    UC_S390X_REG_F3,
    UC_S390X_REG_F4,
    UC_S390X_REG_F5,
    UC_S390X_REG_F6,
    UC_S390X_REG_F7,
    UC_S390X_REG_F8,
    UC_S390X_REG_F9,
    UC_S390X_REG_F10,
    UC_S390X_REG_F11,
    UC_S390X_REG_F12,
    UC_S390X_REG_F13,
    UC_S390X_REG_F14,
    UC_S390X_REG_F15,
    UC_S390X_REG_F16,
    UC_S390X_REG_F17,
    UC_S390X_REG_F18,
    UC_S390X_REG_F19,
    UC_S390X_REG_F20,
    UC_S390X_REG_F21,
    UC_S390X_REG_F22,
    UC_S390X_REG_F23,
    UC_S390X_REG_F24,
    UC_S390X_REG_F25,
    UC_S390X_REG_F26,
    UC_S390X_REG_F27,
    UC_S390X_REG_F28,
    UC_S390X_REG_F29,
    UC_S390X_REG_F30,
    UC_S390X_REG_F31,

    //> Access registers
    UC_S390X_REG_A0,
    UC_S390X_REG_A1,
    UC_S390X_REG_A2,
    UC_S390X_REG_A3,
    UC_S390X_REG_A4,
    UC_S390X_REG_A5,
    UC_S390X_REG_A6,
    UC_S390X_REG_A7,
    UC_S390X_REG_A8,
    UC_S390X_REG_A9,
    UC_S390X_REG_A10,
    UC_S390X_REG_A11,
    UC_S390X_REG_A12,
    UC_S390X_REG_A13,
    UC_S390X_REG_A14,
    UC_S390X_REG_A15,

    UC_S390X_REG_PC,    // PC register

    UC_S390X_REG_ENDING,	// <-- mark the end of the list or registers

    //> Alias registers
} uc_s390x_reg;

#ifdef __cplusplus
}
#endif

#endif
