#include "mpc8572e.h"
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

#define CPU_POWERPC_MPC8572 0x80210030

#define POWERPC_SVR_E500 0x40000000
#define POWERPC_SVR_8572E (0x80E80010 | POWERPC_SVR_E500)

void ppc_mpc8572e_class_init(struct uc_struct *uc, ObjectClass *oc, void *data){
    DeviceClass *dc = DEVICE_CLASS(uc, oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);

    pcc->pvr = CPU_POWERPC_MPC8572;
    pcc->svr = POWERPC_SVR_8572E;
    dc->desc = "MPC8572E";
}

void ppc_mpc8572e_register_types(void* opaque){
    const TypeInfo ppc_mpc8572e_type_info = {
        "MPC8572E-" TYPE_POWERPC_CPU,
        "e500v2-family-" TYPE_POWERPC_CPU,
        0,
        0,
        opaque,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc_mpc8572e_class_init,
    };

    type_register_static(opaque, &ppc_mpc8572e_type_info);
}
