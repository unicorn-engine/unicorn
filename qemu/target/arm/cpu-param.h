/*
 * ARM cpu parameters for qemu.
 *
 * Copyright (c) 2003 Fabrice Bellard
 * SPDX-License-Identifier: LGPL-2.0+
 */

#ifndef ARM_CPU_PARAM_H
#define ARM_CPU_PARAM_H 1

#ifdef TARGET_AARCH64
# define TARGET_LONG_BITS             64
# define TARGET_PHYS_ADDR_SPACE_BITS  48
# define TARGET_VIRT_ADDR_SPACE_BITS  48
#else
# define TARGET_LONG_BITS             32
# define TARGET_PHYS_ADDR_SPACE_BITS  40
# define TARGET_VIRT_ADDR_SPACE_BITS  32
#endif

/*
 * ARMv7 and later CPUs have 4K pages minimum, but ARMv5 and v6
 * have to support 1K tiny pages.
 */
# define TARGET_PAGE_BITS_VARY
# define TARGET_PAGE_BITS_MIN  10

/*
 * Cache the original page-table attributes required after translation.
 * For stage 2, pte_attrs contains descriptor bits [5:2]; otherwise it
 * uses the MAIR_EL1 byte format.
 */
# define TARGET_PAGE_ENTRY_EXTRA \
    uint8_t pte_attrs;            \
    uint8_t shareability;         \
    bool guarded;

#define NB_MMU_MODES 12

#endif
