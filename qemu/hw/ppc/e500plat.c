/*
 * Generic device-tree-driven paravirt PPC e500 platform
 *
 * Copyright 2012 Freescale Semiconductor, Inc.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of  the GNU General  Public License as published by
 * the Free Software Foundation;  either version 2 of the  License, or
 * (at your option) any later version.
 */

#include "config.h"
#include "qemu-common.h"
#include "e500.h"
#include "hw/boards.h"
#include "hw/ppc/ppc.h"
//#include "sysemu/device_tree.h"
//#include "hw/ppc/openpic.h"
//#include "kvm_ppc.h"

/*static void e500plat_fixup_devtree(PPCE500Params *params, void *fdt)
{
    const char model[] = "QEMU ppce500";
    const char compatible[] = "fsl,qemu-e500";

    qemu_fdt_setprop(fdt, "/", "model", model, sizeof(model));
    qemu_fdt_setprop(fdt, "/", "compatible", compatible,
                     sizeof(compatible));
}*/

static int e500plat_init(struct uc_struct *uc, MachineState *machine)
{
/*    PPCE500Params params = {
        .pci_first_slot = 0x1,
        .pci_nr_slots = PCI_SLOT_MAX - 1,
        .fixup_devtree = e500plat_fixup_devtree,
        .mpic_version = OPENPIC_MODEL_FSL_MPIC_42,
        .has_mpc8xxx_gpio = true,
        .has_platform_bus = true,
        .platform_bus_base = 0xf00000000ULL,
        .platform_bus_size = (128ULL * 1024 * 1024),
        .platform_bus_first_irq = 5,
        .platform_bus_num_irqs = 10,
    };*/

    /* Older KVM versions don't support EPR which breaks guests when we announce
       MPIC variants that support EPR. Revert to an older one for those */
/*    if (kvm_enabled() && !kvmppc_has_cap_epr()) {
        params.mpic_version = OPENPIC_MODEL_FSL_MPIC_20;
    }*/

//	cpu_ppc_init(uc, "e500v2_v30");
	cpu_ppc_init(uc, "e500v2_v10");
	return 0;
}

void ppc_machine_init(struct uc_struct *uc)
{
    static QEMUMachine ppc_machine = {
        NULL,
        "ppc",
        e500plat_init,
        NULL,
        0,
        1,
        UC_ARCH_PPC,
    };

    qemu_register_machine(uc, &ppc_machine, TYPE_MACHINE, NULL);
}
