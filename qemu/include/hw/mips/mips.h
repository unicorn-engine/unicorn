#ifndef HW_MIPS_H
#define HW_MIPS_H
/* Definitions for mips board emulation.  */

/* Kernels can be configured with 64KB pages */
#define INITRD_PAGE_MASK (~((1 << 16) - 1))

#include "exec/memory.h"

void mips_machine_init(struct uc_struct *uc);

void mips_cpu_register_types(void *opaque);

#endif
