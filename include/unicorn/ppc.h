/* Unicorn Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef UNICORN_PPC_H
#define UNICORN_PPC_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> PPC registers
typedef enum uc_ppc_reg {
    UC_PPC_REG_INVALID = 0,
    //> General purpose registers
    UC_PPC_REG_PC,

    UC_PPC_REG_0,
    UC_PPC_REG_1,
    UC_PPC_REG_2,
    UC_PPC_REG_3,
    UC_PPC_REG_4,
    UC_PPC_REG_5,
    UC_PPC_REG_6,
    UC_PPC_REG_7,
    UC_PPC_REG_8,
    UC_PPC_REG_9,
    UC_PPC_REG_10,
    UC_PPC_REG_11,
    UC_PPC_REG_12,
    UC_PPC_REG_13,
    UC_PPC_REG_14,
    UC_PPC_REG_15,
    UC_PPC_REG_16,
    UC_PPC_REG_17,
    UC_PPC_REG_18,
    UC_PPC_REG_19,
    UC_PPC_REG_20,
    UC_PPC_REG_21,
    UC_PPC_REG_22,
    UC_PPC_REG_23,
    UC_PPC_REG_24,
    UC_PPC_REG_25,
    UC_PPC_REG_26,
    UC_PPC_REG_27,
    UC_PPC_REG_28,
    UC_PPC_REG_29,
    UC_PPC_REG_30,
    UC_PPC_REG_31,
} uc_ppc_reg;

#ifdef __cplusplus
}
#endif

#endif
