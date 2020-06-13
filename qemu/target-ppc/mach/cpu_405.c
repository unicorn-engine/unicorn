#include "cpu_405.h"
#include "cpu.h"
#include "cpu-qom.h"

#define POWERPC_SVR_NONE 0x00000000
#define CPU_POWERPC_405D2 0x20010000

void ppc_405_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data){
    DeviceClass *dc = DEVICE_CLASS(uc, oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);

    pcc->pvr = CPU_POWERPC_405D2;
    pcc->svr = POWERPC_SVR_NONE;
    dc->desc = "PowerPC 405 D2";
}

void ppc_405_cpu_register_types(void* opaque){
    const TypeInfo ppc_405_cpu_type_info = {
        "405-" TYPE_POWERPC_CPU,
        "405-family-" TYPE_POWERPC_CPU,
        0,
        0,
        opaque,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc_405_cpu_class_init,
    };

    type_register_static(opaque, &ppc_405_cpu_type_info);
}
