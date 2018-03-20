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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/arm/arm.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"

// Unicorn: Daughterboard member removed, as it's not necessary
//          for Unicorn's purposes.
typedef struct {
    MachineClass parent;
} VirtMachineClass;

typedef struct {
    MachineState parent;
    bool secure;
} VirtMachineState;

#define TYPE_VIRT_MACHINE   MACHINE_TYPE_NAME("virt")
#define VIRT_MACHINE(uc, obj) \
    OBJECT_CHECK((uc), VirtMachineState, (obj), TYPE_VIRT_MACHINE)
#define VIRT_MACHINE_GET_CLASS(uc, obj) \
    OBJECT_GET_CLASS(uc, VirtMachineClass, obj, TYPE_VIRT_MACHINE)
#define VIRT_MACHINE_CLASS(uc, klass) \
    OBJECT_CLASS_CHECK(uc, VirtMachineClass, klass, TYPE_VIRT_MACHINE)

static int machvirt_init(struct uc_struct *uc, MachineState *machine)
{
    const char *cpu_model = machine->cpu_model;
    char **cpustr;
    ObjectClass *oc;
    const char *typename;
    CPUClass *cc;
    Error *err = NULL;
    int n;

    if (!cpu_model) {
        // Unicorn: "max" used instead to allow use of ARMv8.1+ instructions.
        //cpu_model = "cortex-a57";   // ARM64
        cpu_model = "max";
    }

    /* Separate the actual CPU model name from any appended features */
    cpustr = g_strsplit(cpu_model, ",", 2);

    oc = cpu_class_by_name(uc, TYPE_ARM_CPU, cpustr[0]);
    if (!oc) {
        fprintf(stderr, "Unable to find CPU definition");
        return -1;
    }
    typename = object_class_get_name(oc);

    /* convert -smp CPU options specified by the user into global props */
    cc = CPU_CLASS(uc, oc);
    cc->parse_features(uc, typename, cpustr[1], &err);
    g_strfreev(cpustr);
    if (err) {
        fprintf(stderr, "Error parsing cpu features");
        return -1;
    }

    for (n = 0; n < smp_cpus; n++) {
        Object *cpuobj = object_new(uc, typename);

        uc->cpu = CPU(cpuobj);
        object_property_set_bool(uc, cpuobj, true, "realized", NULL);
    }
    return 0;
}

static QEMU_UNUSED_FUNC bool virt_get_secure(struct uc_struct *uc, Object *obj, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(uc, obj);

    return vms->secure;
}

static QEMU_UNUSED_FUNC int virt_set_secure(struct uc_struct *uc, Object *obj, bool value, Error **errp)
{
    VirtMachineState *vms = VIRT_MACHINE(uc, obj);

    vms->secure = value;
    return 0;
}

static void virt_instance_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    VirtMachineState *vms = VIRT_MACHINE(uc, obj);

    /* EL3 is enabled by default on virt */
    vms->secure = true;

    /* Unicorn: should be uncommented, but causes linkage errors :/
    object_property_add_bool(uc, obj, "secure", virt_get_secure,
                             virt_set_secure, NULL);
    object_property_set_description(uc, obj, "secure",
                                    "Set on/off to enable/disable the ARM "
                                    "Security Extensions (TrustZone)",
                                    NULL);
    */
}

static void virt_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(uc, oc);

    mc->init = machvirt_init;
    mc->max_cpus = 8;
    mc->is_default = 1;
    mc->arch = UC_ARCH_ARM64;
}

static const TypeInfo machvirt_info = {
    TYPE_VIRT_MACHINE,
    TYPE_MACHINE,

    sizeof(VirtMachineClass),
    sizeof(VirtMachineState),
    NULL,

    virt_instance_init,
    NULL,
    NULL,

    NULL,

    virt_class_init,
};

void machvirt_machine_init(struct uc_struct *uc)
{
    type_register_static(uc, &machvirt_info);
}
