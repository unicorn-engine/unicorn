#ifndef UC_MPC8572E_PPC_H
#define UC_MPC8572E_PPC_H

#include "sysemu/cpus.h"
#include "qom/object.h"

void ppc_mpc8572e_class_init(struct uc_struct *uc, ObjectClass *oc, void *data);

void ppc_mpc8572e_register_types(void* opaque);

#endif //UC_MPC8572E_PPC_H