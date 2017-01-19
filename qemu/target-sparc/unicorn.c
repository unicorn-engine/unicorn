/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/sparc/sparc.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


const int SPARC_REGS_STORAGE_SIZE = offsetof(CPUSPARCState, tlb_table);

static bool sparc_stop_interrupt(int intno)
{
    switch(intno) {
        default:
            return false;
        case TT_ILL_INSN:
            return true;
    }
}

static void sparc_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUSPARCState *)uc->current_cpu->env_ptr)->pc = address;
    ((CPUSPARCState *)uc->current_cpu->env_ptr)->npc = address + 4;
}

void sparc_release(void *ctx);
void sparc_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *) ctx;
    release_common(ctx);
    g_free(tcg_ctx->cpu_wim);
    g_free(tcg_ctx->cpu_cond);
    g_free(tcg_ctx->cpu_cc_src);
    g_free(tcg_ctx->cpu_cc_src2);
    g_free(tcg_ctx->cpu_cc_dst);
    g_free(tcg_ctx->cpu_fsr);
    g_free(tcg_ctx->sparc_cpu_pc);
    g_free(tcg_ctx->cpu_npc);
    g_free(tcg_ctx->cpu_y);
    g_free(tcg_ctx->cpu_tbr);

    for (i = 0; i < 8; i++) {
      g_free(tcg_ctx->cpu_gregs[i]);
    }
    for (i = 0; i < 32; i++) {
        g_free(tcg_ctx->cpu_gpr[i]);
    }

    g_free(tcg_ctx->cpu_PC);
    g_free(tcg_ctx->btarget);
    g_free(tcg_ctx->bcond);
    g_free(tcg_ctx->cpu_dspctrl);

    g_free(tcg_ctx->tb_ctx.tbs);
}

void sparc_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->gregs, 0, sizeof(env->gregs));
    memset(env->fpr, 0, sizeof(env->fpr));
    memset(env->regbase, 0, sizeof(env->regbase));

    env->pc = 0;
    env->npc = 0;
    env->regwptr = env->regbase;
}

int sparc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7)
            *(int32_t *)value = SPARC_CPU(uc, mycpu)->env.gregs[regid - UC_SPARC_REG_G0];
        else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7)
            *(int32_t *)value = SPARC_CPU(uc, mycpu)->env.regwptr[regid - UC_SPARC_REG_O0];
        else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7)
                *(int32_t *)value = SPARC_CPU(uc, mycpu)->env.regwptr[8 + regid - UC_SPARC_REG_L0];
        else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7)
                *(int32_t *)value = SPARC_CPU(uc, mycpu)->env.regwptr[16 + regid - UC_SPARC_REG_I0];
        else {
            switch(regid) {
                default: break;
                case UC_SPARC_REG_PC:
                    *(int32_t *)value = SPARC_CPU(uc, mycpu)->env.pc;
                    break;
            }
        }
    }

    return 0;
}

int sparc_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7)
            SPARC_CPU(uc, mycpu)->env.gregs[regid - UC_SPARC_REG_G0] = *(uint32_t *)value;
        else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7)
            SPARC_CPU(uc, mycpu)->env.regwptr[regid - UC_SPARC_REG_O0] = *(uint32_t *)value;
        else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7)
            SPARC_CPU(uc, mycpu)->env.regwptr[8 + regid - UC_SPARC_REG_L0] = *(uint32_t *)value;
        else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7)
                SPARC_CPU(uc, mycpu)->env.regwptr[16 + regid - UC_SPARC_REG_I0] = *(uint32_t *)value;
        else {
            switch(regid) {
                default: break;
                case UC_SPARC_REG_PC:
                    SPARC_CPU(uc, mycpu)->env.pc = *(uint32_t *)value;
                    SPARC_CPU(uc, mycpu)->env.npc = *(uint32_t *)value + 4;
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);
                    break;
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
void sparc_uc_init(struct uc_struct* uc)
{
    register_accel_types(uc);
    sparc_cpu_register_types(uc);
    leon3_machine_init(uc);
    uc->release = sparc_release;
    uc->reg_read = sparc_reg_read;
    uc->reg_write = sparc_reg_write;
    uc->reg_reset = sparc_reg_reset;
    uc->set_pc = sparc_set_pc;
    uc->stop_interrupt = sparc_stop_interrupt;
    uc_common_init(uc);
}
