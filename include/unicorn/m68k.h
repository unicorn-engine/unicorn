#ifndef UNICORN_M68K_H
#define UNICORN_M68K_H

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> M68K registers
typedef enum m68k_reg {
	M68K_REG_INVALID = 0,

	M68K_REG_A0,
	M68K_REG_A1,
	M68K_REG_A2,
	M68K_REG_A3,
	M68K_REG_A4,
	M68K_REG_A5,
	M68K_REG_A6,
	M68K_REG_A7,

	M68K_REG_D0,
	M68K_REG_D1,
	M68K_REG_D2,
	M68K_REG_D3,
	M68K_REG_D4,
	M68K_REG_D5,
	M68K_REG_D6,
	M68K_REG_D7,

	M68K_REG_SR,
	M68K_REG_PC,

	M68K_REG_ENDING,   // <-- mark the end of the list of registers
} m68k_reg;

#ifdef __cplusplus
}
#endif

#endif
