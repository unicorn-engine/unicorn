/*
 * MIPS cpu parameters for qemu.
 *
 * SPDX-License-Identifier: LGPL-2.0+
 */

#ifndef MIPS_CPU_PARAM_H
#define MIPS_CPU_PARAM_H 1

#ifdef TARGET_MIPS64
# define TARGET_LONG_BITS 64
#else
# define TARGET_LONG_BITS 32
#endif
#ifdef TARGET_MIPS64
#define TARGET_PHYS_ADDR_SPACE_BITS 48
#define TARGET_VIRT_ADDR_SPACE_BITS 48
#else
#define TARGET_PHYS_ADDR_SPACE_BITS 40
#define TARGET_VIRT_ADDR_SPACE_BITS 32
#endif
#define TARGET_PAGE_BITS 12
#define NB_MMU_MODES 4

#endif
