#include <string.h>

#include "uc_priv.h"
#include <unicorn/unicorn.h>
#include "./target/arm/cpu.h"
#include "ghash.h"

/*
This tools allows to list dynamically all coproc registers instanciated by the initialisation
of the CPU.
*/

static void cp_reg_test(gpointer key, gpointer value, gpointer opaque)
{

    ARMCPRegInfo *ri = value;
    uint8_t cp = ri->cp;

        int len = strlen(ri->name);

        // Ignore registers finishing by '_S' (to avoid duplication with Non-Secure versions)
        if (ri->name[len-2] == '_' && ri->name[len-1] == 'S')
            return;
    
        printf("%s;%d;%d;%d;%d;%d;%d;0x%x\n", ri->name,
                                         cp,
                                         ri->crn,
                                         ri->crm,
                                         ri->opc0,
                                         ri->opc1,
                                         ri->opc2,
                                         *(uint32_t *)key
                                        );
}

int main(int argc, char **argv, char **envp)
{  
    uc_engine * uc = NULL;
    // Initialize emulator in ARM mode
    uc_err err;
    #if defined(TARGET_AARCH64)
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    #elif defined(TARGET_ARM)
    err = uc_open(UC_ARCH_ARM,  UC_MODE_ARM, &uc);
    #else
       #error "INVALID TARGET, ONLY FOR TARGET_AARCH64/TARGET_ARM"
    #endif

    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return -1;
    }

    CPUState *s = uc->cpu;
    ARMCPU *cpu = ARM_CPU(s);

    // printf("Reg;cp;crn;crm;opc0;opc1;opc2;regid\n");
    g_hash_table_foreach(cpu->cp_regs, cp_reg_test, cpu);

    return 0;
}
