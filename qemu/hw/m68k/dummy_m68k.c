/*
 * Dummy board with just RAM and CPU for use as an ISS.
 *
 * Copyright (c) 2007 CodeSourcery.
 *
 * This code is licensed under the GPL
 */

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/m68k/m68k.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"

/* Board init.  */
static int dummy_m68k_init(struct uc_struct *uc, MachineState *machine)
{
    CPUM68KState *env;
    const char *cpu_type = parse_cpu_model(uc, "cf4ve");

    uc->cpu = cpu_create(uc, cpu_type);
    if (!uc->cpu) {
        fprintf(stderr, "Unable to find m68k CPU definition\n");
        return -1;
    }

    /* Initialize CPU registers.  */
    env = uc->cpu->env_ptr;
    env->vbr = 0;
    env->pc = 0;

    return 0;
}

static void dummy_m68k_machine_init(struct uc_struct *uc, MachineClass *mc)
{
    mc->init = dummy_m68k_init;
    mc->is_default = 1;
    mc->arch = UC_ARCH_M68K;
    mc->default_cpu_type = M68K_CPU_TYPE_NAME("cfv4e");
}

DEFINE_MACHINE("dummy", dummy_m68k_machine_init)
