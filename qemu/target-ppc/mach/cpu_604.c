#include "cpu_604.h"
#include "cpu.h"
#include "cpu-qom.h"

#define POWERPC_SVR_NONE 0x00000000
#define CPU_POWERPC_604 0x00040103

void ppc_604_cpu_class_init(struct uc_struct *uc, CPUClass *oc, void *data){
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc, oc);

    pcc->pvr = CPU_POWERPC_604;
    pcc->svr = POWERPC_SVR_NONE;
}