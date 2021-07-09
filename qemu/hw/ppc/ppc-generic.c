#include "hw/hw.h"
#include "hw/ppc/ppc.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"

#if defined(TARGET_PPC64)
 #if defined(TARGET_WORDS_BIGENDIAN)
  #define GENERIC_PPC_CPU "970"
 #else
  #define GENERIC_PPC_CPU "XXX" // TODO
 #endif
#else //32
 #if defined(TARGET_WORDS_BIGENDIAN)
  #define GENERIC_PPC_CPU "MPC8572E"
 #else
  #define GENERIC_PPC_CPU "401"
 #endif
#endif


static PowerPCCPU *cpu_ppc_init(struct uc_struct *uc, const char *cpu_model)
{
    return POWERPC_CPU(uc, cpu_generic_init(uc, TYPE_POWERPC_CPU, cpu_model));
}

static int generic_ppc_init(struct uc_struct *uc, MachineState *machine)
{
    uc->cpu = (CPUState *)cpu_ppc_init(uc,GENERIC_PPC_CPU); 
    
    if (uc->cpu == NULL) {
        fprintf(stderr, "Unable to find CPU definition\n");
        return -1;
    }

    return 0;
}

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