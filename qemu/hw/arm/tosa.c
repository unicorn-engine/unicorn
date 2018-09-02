/* vim:set shiftwidth=4 ts=4 et: */
/*
 * PXA255 Sharp Zaurus SL-6000 PDA platform
 *
 * Copyright (c) 2008 Dmitry Baryshkov
 *
 * Code based on spitz platform by Andrzej Zaborowski <balrog@zabor.org>
 * This code is licensed under the GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/arm/arm.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"

static int tosa_init(struct uc_struct *uc, MachineState *machine)
{
    uc->cpu = cpu_create(uc, machine->cpu_type);
    return 0;
}

static void tosa_machine_init(struct uc_struct *uc, MachineClass *mc)
{
    mc->init = tosa_init;
    mc->is_default = 1;
    mc->arch = UC_ARCH_ARM;

    if (uc->mode & UC_MODE_MCLASS) {
        mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m3");
    } else {
        mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a15");
    }
}

DEFINE_MACHINE("tosa", tosa_machine_init)
