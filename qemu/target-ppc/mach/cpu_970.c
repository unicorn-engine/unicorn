#include "cpu_970.h"
#include "cpu.h"
#include "cpu-qom.h"



#define POWERPC_SVR_NONE 0x00000000
#define CPU_POWERPC_970 0x00390202

void ppc64_970_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data){
    DeviceClass *dc = DEVICE_CLASS(uc, oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);

    pcc->pvr = CPU_POWERPC_970;
    pcc->svr = POWERPC_SVR_NONE;
    dc->desc = "PowerPC 970";
}

void ppc64_970_cpu_register_types(void* opaque){
    const TypeInfo ppc64_970_cpu_type_info = {
        "970-" TYPE_POWERPC_CPU,
        "970-family-" TYPE_POWERPC_CPU,
        0,
        0,
        opaque,
        NULL,
        NULL,
        NULL,
        NULL,
        ppc64_970_cpu_class_init
    };

    type_register_static(opaque, &ppc64_970_cpu_type_info);
}
