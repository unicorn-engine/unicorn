/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "hw/ppc/ppc.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"

#ifdef TARGET_PPC64
const int PPC64_REGS_STORAGE_SIZE = offsetof(CPUPPCState, tlb_table);
#else // PPC32
const int PPC_REGS_STORAGE_SIZE = offsetof(CPUPPCState, tlb_table);
#endif

#ifdef TARGET_PPC64
typedef uint64_t ppcreg_t;
#else
typedef uint32_t ppcreg_t;
#endif

static uint64_t ppc_mem_redirect(uint64_t address)
{
/*    // kseg0 range masks off high address bit
    if (address >= 0x80000000 && address <= 0x9fffffff)
        return address & 0x7fffffff;

    // kseg1 range masks off top 3 address bits
    if (address >= 0xa0000000 && address <= 0xbfffffff) {
        return address & 0x1fffffff;
    }*/

    // no redirect
    return address;
}

static void ppc_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUPPCState *)uc->cpu->env_ptr)->nip = address;
}


void ppc_cpu_unrealizefn(struct uc_struct *uc, CPUState *dev);

static void ppc_release(void *ctx)
{
//    PowerPCCPU* cpu;
    int i;
    TCGContext *tcg_ctx = (TCGContext *) ctx;
    release_common(ctx);
//    cpu = POWERPC_CPU(tcg_ctx->uc, tcg_ctx->uc->cpu);
//    g_free(cpu->env.tlb);
//    g_free(cpu->env.mvp);
    CPUState *cpu = tcg_ctx->uc->cpu;

    for (i = 0; i < 32; i++) {
        g_free(tcg_ctx->cpu_gpr[i]);
    }

    g_free(tcg_ctx->cpu_PC);
    g_free(tcg_ctx->btarget);
    g_free(tcg_ctx->bcond);
    g_free(tcg_ctx->cpu_dspctrl);

    g_free(tcg_ctx->tb_ctx.tbs);

    ppc_cpu_unrealizefn(tcg_ctx->uc, cpu);
}

void ppc_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    env = uc->cpu->env_ptr;
    memset(env->gpr, 0, sizeof(env->gpr));

    env->nip = 0;
}

int ppc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_PPC_REG_0 && regid <= UC_PPC_REG_31)
            *(ppcreg_t *)value = POWERPC_CPU(uc, mycpu)->env.gpr[regid - UC_PPC_REG_0];
        else {
            switch(regid) {
                default: break;
                case UC_PPC_REG_PC:
                         *(ppcreg_t *)value = POWERPC_CPU(uc, mycpu)->env.nip;
                         break;
/*                case UC_PPC_REG_CP0_CONFIG3:
                         *(mipsreg_t *)value = MIPS_CPU(uc, mycpu)->env.CP0_Config3;
                         break;
                case UC_MIPS_REG_CP0_USERLOCAL:
                         *(mipsreg_t *)value = MIPS_CPU(uc, mycpu)->env.active_tc.CP0_UserLocal;
                         break;                              */
            }
        }
    }

    return 0;
}

int ppc_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_PPC_REG_0 && regid <= UC_PPC_REG_31)
            POWERPC_CPU(uc, mycpu)->env.gpr[regid - UC_PPC_REG_0] = *(ppcreg_t *)value;
        else {
            switch(regid) {
                default: break;
                case UC_PPC_REG_PC:
                         POWERPC_CPU(uc, mycpu)->env.nip = *(ppcreg_t *)value;
                         // force to quit execution and flush TB
                         uc->quit_request = true;
                         uc_emu_stop(uc);
                         break;
/*                case UC_MIPS_REG_CP0_CONFIG3:
                         MIPS_CPU(uc, mycpu)->env.CP0_Config3 = *(mipsreg_t *)value;
                         break;
                case UC_MIPS_REG_CP0_USERLOCAL:
                         MIPS_CPU(uc, mycpu)->env.active_tc.CP0_UserLocal = *(mipsreg_t *)value;
                         break;                         */
            }
        }
    }

    return 0;
}

static int ppc_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    PowerPCCPU *cpu;

    cpu = cpu_ppc_init(uc, cpu_model);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_PPC64
  void ppc64_uc_init(struct uc_struct* uc)
#else // if TARGET_PPC
  void ppc_uc_init(struct uc_struct* uc)
#endif
{
    uc->reg_read = ppc_reg_read;
    uc->reg_write = ppc_reg_write;
    uc->reg_reset = ppc_reg_reset;
    uc->release = ppc_release;
    uc->set_pc = ppc_set_pc;
    uc->mem_redirect = ppc_mem_redirect;
    uc->cpus_init = ppc_cpus_init;
    uc_common_init(uc);
}
