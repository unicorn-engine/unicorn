/*
 * QEMU Sun4u/Sun4v System Emulator
 *
 * Copyright (c) 2005 Fabrice Bellard
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
#include "hw/hw.h"
#include "hw/sparc/sparc.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"


/* Sun4u hardware initialisation */
static int sun4u_init(struct uc_struct *uc, MachineState *machine)
{
    const char *cpu_model = machine->cpu_model;
    SPARCCPU *cpu;

    if (cpu_model == NULL)
        cpu_model = "Sun UltraSparc IV";

    cpu = cpu_sparc_init(uc, cpu_model);
    if (cpu == NULL) {
        fprintf(stderr, "Unable to find Sparc CPU definition\n");
        return -1;
    }

    return 0;
}

void sun4u_machine_init(struct uc_struct *uc)
{
    static QEMUMachine sun4u_machine = {
        NULL,
        "sun4u",
        sun4u_init,
        NULL,
        1, // XXX for now
        1,
        UC_ARCH_SPARC,
    };

    qemu_register_machine(uc, &sun4u_machine, TYPE_MACHINE, NULL);
}
