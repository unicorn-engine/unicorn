#include "qemu-common.h"
#include "hw/ppc/ppc.h"
#include "qemu/typedefs.h"
#include "uc_priv.h"
#include "exec/address-spaces.h"



/*
void generic_ppc_machine_init(struct uc_struct* uc)
{
    static QEMUMachine generic_machine = {
        .name = "powerpc",
        .init = generic_ppc_init,
        .is_default = 1,
        .arch = UC_ARCH_PPC,
    };

    qemu_register_machine(uc, &generic_machine, TYPE_MACHINE, NULL);
}
*/