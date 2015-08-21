/*
 * QEMU/MIPS pseudo-board
 *
 * emulates a simple machine with ISA-like bus.
 * ISA IO space mapped to the 0x14000000 (PHYS) and
 * ISA memory at the 0x10000000 (PHYS, 16Mb in size).
 * All peripherial devices are attached to this "bus" with
 * the standard PC ISA addresses.
*/

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

#include "hw/hw.h"
#include "hw/mips/mips.h"
#include "hw/mips/cpudevs.h"
#include "hw/mips/bios.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"


static void mips_r4k_init(struct uc_struct *uc, MachineState *machine)
{
    const char *cpu_model = machine->cpu_model;
    MIPSCPU *cpu;


    /* init CPUs */
    if (cpu_model == NULL) {
#ifdef TARGET_MIPS64
        cpu_model = "R4000";
#else
        cpu_model = "24Kf";
#endif
    }

    cpu = cpu_mips_init(uc, cpu_model);
    if (cpu == NULL) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
}

void mips_machine_init(struct uc_struct *uc)
{
    static QEMUMachine mips_machine = {
        .name = "mips",
        .init = mips_r4k_init,
        .is_default = 1,
        .arch = UC_ARCH_MIPS,
    };

    printf(">>> mips_machine_init\n");

    qemu_register_machine(uc, &mips_machine, TYPE_MACHINE, NULL);
}
