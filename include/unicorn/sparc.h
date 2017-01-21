#ifndef UNICORN_SPARC_H
#define UNICORN_SPARC_H

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include "unicorn/platform.h"

// GCC SPARC toolchain has a default macro called "sparc" which breaks
// compilation
#undef sparc

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> SPARC registers
typedef enum uc_sparc_reg {
    UC_SPARC_REG_INVALID = 0,

    UC_SPARC_REG_F0,
    UC_SPARC_REG_F1,
    UC_SPARC_REG_F2,
    UC_SPARC_REG_F3,
    UC_SPARC_REG_F4,
    UC_SPARC_REG_F5,
    UC_SPARC_REG_F6,
    UC_SPARC_REG_F7,
    UC_SPARC_REG_F8,
    UC_SPARC_REG_F9,
    UC_SPARC_REG_F10,
    UC_SPARC_REG_F11,
    UC_SPARC_REG_F12,
    UC_SPARC_REG_F13,
    UC_SPARC_REG_F14,
    UC_SPARC_REG_F15,
    UC_SPARC_REG_F16,
    UC_SPARC_REG_F17,
    UC_SPARC_REG_F18,
    UC_SPARC_REG_F19,
    UC_SPARC_REG_F20,
    UC_SPARC_REG_F21,
    UC_SPARC_REG_F22,
    UC_SPARC_REG_F23,
    UC_SPARC_REG_F24,
    UC_SPARC_REG_F25,
    UC_SPARC_REG_F26,
    UC_SPARC_REG_F27,
    UC_SPARC_REG_F28,
    UC_SPARC_REG_F29,
    UC_SPARC_REG_F30,
    UC_SPARC_REG_F31,
    UC_SPARC_REG_F32,
    UC_SPARC_REG_F34,
    UC_SPARC_REG_F36,
    UC_SPARC_REG_F38,
    UC_SPARC_REG_F40,
    UC_SPARC_REG_F42,
    UC_SPARC_REG_F44,
    UC_SPARC_REG_F46,
    UC_SPARC_REG_F48,
    UC_SPARC_REG_F50,
    UC_SPARC_REG_F52,
    UC_SPARC_REG_F54,
    UC_SPARC_REG_F56,
    UC_SPARC_REG_F58,
    UC_SPARC_REG_F60,
    UC_SPARC_REG_F62,
    UC_SPARC_REG_FCC0,	// Floating condition codes
    UC_SPARC_REG_FCC1,
    UC_SPARC_REG_FCC2,
    UC_SPARC_REG_FCC3,
    UC_SPARC_REG_G0,
    UC_SPARC_REG_G1,
    UC_SPARC_REG_G2,
    UC_SPARC_REG_G3,
    UC_SPARC_REG_G4,
    UC_SPARC_REG_G5,
    UC_SPARC_REG_G6,
    UC_SPARC_REG_G7,
    UC_SPARC_REG_I0,
    UC_SPARC_REG_I1,
    UC_SPARC_REG_I2,
    UC_SPARC_REG_I3,
    UC_SPARC_REG_I4,
    UC_SPARC_REG_I5,
    UC_SPARC_REG_FP,
    UC_SPARC_REG_I7,
    UC_SPARC_REG_ICC,	// Integer condition codes
    UC_SPARC_REG_L0,
    UC_SPARC_REG_L1,
    UC_SPARC_REG_L2,
    UC_SPARC_REG_L3,
    UC_SPARC_REG_L4,
    UC_SPARC_REG_L5,
    UC_SPARC_REG_L6,
    UC_SPARC_REG_L7,
    UC_SPARC_REG_O0,
    UC_SPARC_REG_O1,
    UC_SPARC_REG_O2,
    UC_SPARC_REG_O3,
    UC_SPARC_REG_O4,
    UC_SPARC_REG_O5,
    UC_SPARC_REG_SP,
    UC_SPARC_REG_O7,
    UC_SPARC_REG_Y,

    // special register
    UC_SPARC_REG_XCC,

    // pseudo register
    UC_SPARC_REG_PC,   // program counter register

    UC_SPARC_REG_ENDING,   // <-- mark the end of the list of registers

    // extras
    UC_SPARC_REG_O6 = UC_SPARC_REG_SP,
    UC_SPARC_REG_I6 = UC_SPARC_REG_FP,
} uc_sparc_reg;

#ifdef __cplusplus
}
#endif

#endif
