/*
 * QEMU PC System Emulator
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
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
/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "hw/i386/pc.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"
#include "uc_priv.h"


/* Make sure that guest addresses aligned at 1Gbyte boundaries get mapped to
 * host addresses aligned at 1Gbyte boundaries.  This way we can use 1GByte
 * pages in the host.
 */
#define GIGABYTE_ALIGN true

/* PC hardware initialisation */
static int pc_init1(struct uc_struct *uc, MachineState *machine)
{
    return pc_cpus_init(uc, machine->cpu_model);
}

static int pc_init_pci(struct uc_struct *uc, MachineState *machine)
{
    return pc_init1(uc, machine);
}

static QEMUMachine pc_i440fx_machine_v2_2 = {
    "pc_piix",
    "pc-i440fx-2.2",
    pc_init_pci,
    NULL,
    255,
    1,
    UC_ARCH_X86,    // X86
};

static void pc_generic_machine_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(uc, oc);
    QEMUMachine *qm = data;

    mc->family = qm->family;
    mc->name = qm->name;
    mc->init = qm->init;
    mc->reset = qm->reset;
    mc->max_cpus = qm->max_cpus;
    mc->is_default = qm->is_default;
    mc->arch = qm->arch;
}

void pc_machine_init(struct uc_struct *uc);
void pc_machine_init(struct uc_struct *uc)
{
    qemu_register_machine(uc, &pc_i440fx_machine_v2_2,
            TYPE_PC_MACHINE, pc_generic_machine_class_init);
}
