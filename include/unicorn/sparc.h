#ifndef UNICORN_SPARC_H
#define UNICORN_SPARC_H

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "platform.h"

// GCC SPARC toolchain has a default macro called "sparc" which breaks
// compilation
#undef sparc

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> SPARC registers
typedef enum sparc_reg {
	SPARC_REG_INVALID = 0,

	SPARC_REG_F0,
	SPARC_REG_F1,
	SPARC_REG_F2,
	SPARC_REG_F3,
	SPARC_REG_F4,
	SPARC_REG_F5,
	SPARC_REG_F6,
	SPARC_REG_F7,
	SPARC_REG_F8,
	SPARC_REG_F9,
	SPARC_REG_F10,
	SPARC_REG_F11,
	SPARC_REG_F12,
	SPARC_REG_F13,
	SPARC_REG_F14,
	SPARC_REG_F15,
	SPARC_REG_F16,
	SPARC_REG_F17,
	SPARC_REG_F18,
	SPARC_REG_F19,
	SPARC_REG_F20,
	SPARC_REG_F21,
	SPARC_REG_F22,
	SPARC_REG_F23,
	SPARC_REG_F24,
	SPARC_REG_F25,
	SPARC_REG_F26,
	SPARC_REG_F27,
	SPARC_REG_F28,
	SPARC_REG_F29,
	SPARC_REG_F30,
	SPARC_REG_F31,
	SPARC_REG_F32,
	SPARC_REG_F34,
	SPARC_REG_F36,
	SPARC_REG_F38,
	SPARC_REG_F40,
	SPARC_REG_F42,
	SPARC_REG_F44,
	SPARC_REG_F46,
	SPARC_REG_F48,
	SPARC_REG_F50,
	SPARC_REG_F52,
	SPARC_REG_F54,
	SPARC_REG_F56,
	SPARC_REG_F58,
	SPARC_REG_F60,
	SPARC_REG_F62,
	SPARC_REG_FCC0,	// Floating condition codes
	SPARC_REG_FCC1,
	SPARC_REG_FCC2,
	SPARC_REG_FCC3,
	SPARC_REG_FP,
	SPARC_REG_G0,
	SPARC_REG_G1,
	SPARC_REG_G2,
	SPARC_REG_G3,
	SPARC_REG_G4,
	SPARC_REG_G5,
	SPARC_REG_G6,
	SPARC_REG_G7,
	SPARC_REG_I0,
	SPARC_REG_I1,
	SPARC_REG_I2,
	SPARC_REG_I3,
	SPARC_REG_I4,
	SPARC_REG_I5,
	SPARC_REG_I7,
	SPARC_REG_ICC,	// Integer condition codes
	SPARC_REG_L0,
	SPARC_REG_L1,
	SPARC_REG_L2,
	SPARC_REG_L3,
	SPARC_REG_L4,
	SPARC_REG_L5,
	SPARC_REG_L6,
	SPARC_REG_L7,
	SPARC_REG_O0,
	SPARC_REG_O1,
	SPARC_REG_O2,
	SPARC_REG_O3,
	SPARC_REG_O4,
	SPARC_REG_O5,
	SPARC_REG_O7,
	SPARC_REG_SP,
	SPARC_REG_Y,

	// special register
	SPARC_REG_XCC,

    // pseudo register
	SPARC_REG_PC,   // program counter register

	SPARC_REG_ENDING,   // <-- mark the end of the list of registers

	// extras
	SPARC_REG_O6 = SPARC_REG_SP,
	SPARC_REG_I6 = SPARC_REG_FP,
} sparc_reg;

#ifdef __cplusplus
}
#endif

#endif
