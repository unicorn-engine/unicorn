/*
 * Misc ARM declarations
 *
 * Copyright (c) 2006 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the LGPL.
 *
 */

#ifndef ARM_MISC_H
#define ARM_MISC_H

#include "exec/memory.h"

void tosa_machine_init(struct uc_struct *uc);
void machvirt_machine_init(struct uc_struct *uc);   // ARM64

void arm_cpu_register_types(void *opaque);
void aarch64_cpu_register_types(void *opaque);

#endif /* !ARM_MISC_H */
