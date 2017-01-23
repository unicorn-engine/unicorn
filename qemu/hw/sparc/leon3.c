/*
 * QEMU Leon3 System Emulator
 *
 * Copyright (c) 2010-2011 AdaCore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

#include "hw/hw.h"
#include "hw/sparc/sparc.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"


static int leon3_generic_hw_init(struct uc_struct *uc, MachineState *machine)
{
    const char *cpu_model = machine->cpu_model;
    SPARCCPU *cpu;

    /* Init CPU */
    if (!cpu_model) {
        cpu_model = "LEON3";
    }

    cpu = cpu_sparc_init(uc, cpu_model);
    uc->cpu = CPU(cpu);
    if (cpu == NULL) {
        fprintf(stderr, "qemu: Unable to find Sparc CPU definition\n");
        return -1;
    }

    cpu_sparc_set_id(&cpu->env, 0);

    return 0;
}

void leon3_machine_init(struct uc_struct *uc)
{
    static QEMUMachine leon3_generic_machine = {
        NULL,
        "leon3_generic",
        leon3_generic_hw_init,
        NULL,
        0,
        1,
        UC_ARCH_SPARC,
    };

    //printf(">>> leon3_machine_init\n");
    qemu_register_machine(uc, &leon3_generic_machine, TYPE_MACHINE, NULL);
}
