#ifndef UC_CPU_604_PPC_H
#define UC_CPU_604_PPC_H

#include "sysemu/cpus.h"
#include "qom/object.h"

void ppc_604_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data);

void ppc_604_cpu_register_types(void* opaque);

#endif // UC_CPU_604_PPC_H