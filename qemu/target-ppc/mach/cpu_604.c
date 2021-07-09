#include "cpu_604.h"
#include "cpu.h"
#include "cpu-qom.h"
/*
 *  #define TYPE_POWERPC_CPU "powerpc-cpu"
 *  #define CPU_POWERPC_401              CPU_POWERPC_401G2
 *  CPU_POWERPC_401G2              = 0x00270000,
 *  POWERPC_DEF("401", CPU_POWERPC_401,401,"Generic PowerPC 401")
 * . _name = "401"
 * . _pvr = CPU_POWERPC_401
 * . _svr = POWERPC_SVR_NONE
 * . _type = 401
 * . _desc = "Generic PowerPC 401"
*/

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
