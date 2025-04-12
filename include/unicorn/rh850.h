/* Unicorn Engine */
/* By Damien Cauquil <dcauquil@quarkslab.com>, 2023 */

#ifndef UNICORN_RH850_H
#define UNICORN_RH850_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

//> RH850 global purpose registers
typedef enum uc_rh850_reg {
    UC_RH850_REG_R0 = 0,
    UC_RH850_REG_R1,
    UC_RH850_REG_R2,
    UC_RH850_REG_R3,
    UC_RH850_REG_R4,
    UC_RH850_REG_R5,
    UC_RH850_REG_R6,
    UC_RH850_REG_R7,
    UC_RH850_REG_R8,
    UC_RH850_REG_R9,
    UC_RH850_REG_R10,
    UC_RH850_REG_R11,
    UC_RH850_REG_R12,
    UC_RH850_REG_R13,
    UC_RH850_REG_R14,
    UC_RH850_REG_R15,
    UC_RH850_REG_R16,
    UC_RH850_REG_R17,
    UC_RH850_REG_R18,
    UC_RH850_REG_R19,
    UC_RH850_REG_R20,
    UC_RH850_REG_R21,
    UC_RH850_REG_R22,
    UC_RH850_REG_R23,
    UC_RH850_REG_R24,
    UC_RH850_REG_R25,
    UC_RH850_REG_R26,
    UC_RH850_REG_R27,
    UC_RH850_REG_R28,
    UC_RH850_REG_R29,
    UC_RH850_REG_R30,
    UC_RH850_REG_R31,

    //> RH850 system registers, selection ID 0
    UC_RH850_REG_EIPC,
    UC_RH850_REG_EIPSW,
    UC_RH850_REG_FEPC,
    UC_RH850_REG_FEPSW,
    UC_RH850_REG_ECR,
    UC_RH850_REG_PSW,
    UC_RH850_REG_FPSR,
    UC_RH850_REG_FPEPC,
    UC_RH850_REG_FPST,
    UC_RH850_REG_FPCC,
    UC_RH850_REG_FPCFG,
    UC_RH850_REG_FPEC,
    UC_RH850_REG_EIIC,
    UC_RH850_REG_FEIC,
    UC_RH850_REG_CTPC,
    UC_RH850_REG_CTPSW,
    UC_RH850_REG_CTBP,
    UC_RH850_REG_EIWR,
    UC_RH850_REG_FEWR,
    UC_RH850_REG_BSEL,

    //> RH850 system registers, selection ID 1
    UC_RH850_REG_MCFG0,
    UC_RH850_REG_RBASE,
    UC_RH850_REG_EBASE,
    UC_RH850_REG_INTBP,
    UC_RH850_REG_MCTL,
    UC_RH850_REG_PID,
    UC_RH850_REG_SCCFG,
    UC_RH850_REG_SCBP,

    //> RH850 system registers, selection ID 2
    UC_RH850_REG_HTCFG0,
    UC_RH850_REG_MEA,
    UC_RH850_REG_ASID,
    UC_RH850_REG_MEI,

    UC_RH850_REG_PC,
    UC_RH850_REG_ENDING,

    //> Alias registers
    UC_RH850_REG_ZERO = UC_RH850_REG_R0,
    UC_RH850_REG_SP = UC_RH850_REG_R3,
    UC_RH850_REG_EP = UC_RH850_REG_R30,
    UC_RH850_REG_LP = UC_RH850_REG_R31,
} uc_rh850_reg;

#ifdef __cplusplus
}
#endif

#endif
