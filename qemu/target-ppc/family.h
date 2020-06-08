
#ifndef UC_FAMILY_PPC_H
#define UC_FAMILY_PPC_H

#include "cpu.h"

#if !defined(TARGET_PPC64)
void ppc_e500v2_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data);
void ppc_e500v2_cpu_family_register_types(struct uc_struct* uc);

void ppc_405_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data);
void ppc_405_cpu_family_register_types(struct uc_struct* uc);

void ppc_401_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data);
void ppc_401_cpu_family_register_types(struct uc_struct* uc);

void ppc_604_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data);
void ppc_604_cpu_family_register_types(struct uc_struct* uc);

#else
void ppc64_970_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data);
void ppc64_970_cpu_family_register_types(struct uc_struct* uc);
#endif

#endif //UC_FAMILY_PPC_H