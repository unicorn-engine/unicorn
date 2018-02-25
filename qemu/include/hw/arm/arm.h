/*
 * Misc ARM declarations
 *
 * Copyright (c) 2006 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the LGPL.
 *
 */

#ifndef HW_ARM_H
#define HW_ARM_H

#include "exec/memory.h"
#include "target-arm/cpu-qom.h"

void tosa_machine_init(struct uc_struct *uc);
void machvirt_machine_init(struct uc_struct *uc);   // ARM64

void arm_cpu_register_types(void *opaque);
void aarch64_cpu_register_types(void *opaque);

#endif /* HW_ARM_H */
