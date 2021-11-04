/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

const int SPARC64_REGS_STORAGE_SIZE = offsetof(CPUSPARCState, irq_manager);

static bool sparc_stop_interrupt(struct uc_struct *uc, int intno)
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
    ((CPUSPARCState *)uc->cpu->env_ptr)->pc = address;
    ((CPUSPARCState *)uc->cpu->env_ptr)->npc = address + 4;
}

static void sparc_release(void *ctx)
{
    release_common(ctx);

#if 0
    int i;
    TCGContext *tcg_ctx = (TCGContext *) ctx;
    SPARCCPU *cpu = SPARC_CPU(tcg_ctx->uc->cpu);
    CPUSPARCState *env = &cpu->env;

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

    g_free(env->def);
#endif
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

static void reg_read(CPUSPARCState *env, unsigned int regid, void *value)
{
    if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7)
        *(int64_t *)value = env->gregs[regid - UC_SPARC_REG_G0];
    else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7)
        *(int64_t *)value = env->regwptr[regid - UC_SPARC_REG_O0];
    else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7)
        *(int64_t *)value = env->regwptr[8 + regid - UC_SPARC_REG_L0];
    else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7)
        *(int64_t *)value = env->regwptr[16 + regid - UC_SPARC_REG_I0];
    else {
        switch(regid) {
            default: break;
            case UC_SPARC_REG_PC:
                *(int64_t *)value = env->pc;
                break;
        }
    }
}

static void reg_write(CPUSPARCState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7)
        env->gregs[regid - UC_SPARC_REG_G0] = *(uint64_t *)value;
    else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7)
        env->regwptr[regid - UC_SPARC_REG_O0] = *(uint64_t *)value;
    else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7)
        env->regwptr[8 + regid - UC_SPARC_REG_L0] = *(uint64_t *)value;
    else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7)
        env->regwptr[16 + regid - UC_SPARC_REG_I0] = *(uint64_t *)value;
    else {
        switch(regid) {
            default: break;
            case UC_SPARC_REG_PC:
                    env->pc = *(uint64_t *)value;
                    env->npc = *(uint64_t *)value + 4;
                    break;
        }
    }
}

int sparc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUSPARCState *env = &(SPARC_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int sparc_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUSPARCState *env = &(SPARC_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
int sparc64_context_reg_read(struct uc_context *ctx, unsigned int *regs, void **vals, int count)
{
    CPUSPARCState *env = (CPUSPARCState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
int sparc64_context_reg_write(struct uc_context *ctx, unsigned int *regs, void *const *vals, int count)
{
    CPUSPARCState *env = (CPUSPARCState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static int sparc_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    SPARCCPU *cpu;

    cpu = cpu_sparc_init(uc);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void sparc64_uc_init(struct uc_struct* uc)
{
    uc->release = sparc_release;
    uc->reg_read = sparc_reg_read;
    uc->reg_write = sparc_reg_write;
    uc->reg_reset = sparc_reg_reset;
    uc->set_pc = sparc_set_pc;
    uc->stop_interrupt = sparc_stop_interrupt;
    uc->cpus_init = sparc_cpus_init;
    uc_common_init(uc);
}
