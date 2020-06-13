#include "cpu_604.h"
#include "cpu.h"
#include "cpu-qom.h"

#define POWERPC_SVR_NONE 0x00000000
#define CPU_POWERPC_604 0x00040103

void ppc_604_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data){
    DeviceClass *dc = DEVICE_CLASS(uc, oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);

    pcc->pvr = CPU_POWERPC_604;
    pcc->svr = POWERPC_SVR_NONE;
    dc->desc = "PowerPC 604";
}

void ppc_604_cpu_register_types(void* opaque){
    const TypeInfo ppc_604_cpu_type_info = {
        "604-" TYPE_POWERPC_CPU,
        "604-family-" TYPE_POWERPC_CPU,
        0,
        0,
        opaque,
        NULL,
        NULL,
        NULL,
        NULL,
        ppc_604_cpu_class_init
    };

    type_register_static(opaque, &ppc_604_cpu_type_info);
}
