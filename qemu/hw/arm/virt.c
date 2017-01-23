/*
 * ARM mach-virt emulation
 *
 * Copyright (c) 2013 Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Emulate a virtual board which works by passing Linux all the information
 * it needs about what devices are present via the device tree.
 * There are some restrictions about what we can do here:
 *  + we can only present devices whose Linux drivers will work based
 *    purely on the device tree with no platform data at all
 *  + we want to present a very stripped-down minimalist platform,
 *    both because this reduces the security attack surface from the guest
 *    and also because it reduces our exposure to being broken when
 *    the kernel updates its device tree bindings and requires further
 *    information in a device binding that we aren't providing.
 * This is essentially the same approach kvmtool uses.
 */

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

#include "hw/arm/arm.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"


static int machvirt_init(struct uc_struct *uc, MachineState *machine)
{
    const char *cpu_model = machine->cpu_model;
    int n;

    if (!cpu_model) {
        cpu_model = "cortex-a57";   // ARM64
    }

    for (n = 0; n < smp_cpus; n++) {
        Object *cpuobj;
        ObjectClass *oc = cpu_class_by_name(uc, TYPE_ARM_CPU, cpu_model);

        if (!oc) {
            fprintf(stderr, "Unable to find CPU definition\n");
            return -1;
        }

        cpuobj = object_new(uc, object_class_get_name(oc));
        uc->cpu = (CPUState *)cpuobj;
        object_property_set_bool(uc, cpuobj, true, "realized", NULL);
    }

    return 0;
}

void machvirt_machine_init(struct uc_struct *uc)
{
    static QEMUMachine machvirt_a15_machine = { 0 };
    machvirt_a15_machine.name = "virt",
    machvirt_a15_machine.init = machvirt_init,
    machvirt_a15_machine.is_default = 1,
    machvirt_a15_machine.arch = UC_ARCH_ARM64,

    qemu_register_machine(uc, &machvirt_a15_machine, TYPE_MACHINE, NULL);
}
