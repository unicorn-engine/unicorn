/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

static bool sparc_stop_interrupt(struct uc_struct *uc, int intno)
{
    switch (intno) {
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
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    SPARCCPU *cpu = (SPARCCPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }
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
        *(int32_t *)value = env->gregs[regid - UC_SPARC_REG_G0];
    else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7)
        *(int32_t *)value = env->regwptr[regid - UC_SPARC_REG_O0];
    else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7)
        *(int32_t *)value = env->regwptr[8 + regid - UC_SPARC_REG_L0];
    else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7)
        *(int32_t *)value = env->regwptr[16 + regid - UC_SPARC_REG_I0];
    else {
        switch (regid) {
        default:
            break;
        case UC_SPARC_REG_PC:
            *(int32_t *)value = env->pc;
            break;
        }
    }

    return;
}

static void reg_write(CPUSPARCState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7)
        env->gregs[regid - UC_SPARC_REG_G0] = *(uint32_t *)value;
    else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7)
        env->regwptr[regid - UC_SPARC_REG_O0] = *(uint32_t *)value;
    else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7)
        env->regwptr[8 + regid - UC_SPARC_REG_L0] = *(uint32_t *)value;
    else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7)
        env->regwptr[16 + regid - UC_SPARC_REG_I0] = *(uint32_t *)value;
    else {
        switch (regid) {
        default:
            break;
        case UC_SPARC_REG_PC:
            env->pc = *(uint32_t *)value;
            env->npc = *(uint32_t *)value + 4;
            break;
        }
    }

    return;
}

int sparc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count)
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

int sparc_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count)
{
    CPUSPARCState *env = &(SPARC_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_SPARC_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
            break;
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
int sparc_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count)
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
int sparc_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count)
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
void sparc_uc_init(struct uc_struct *uc)
{
    uc->release = sparc_release;
    uc->reg_read = sparc_reg_read;
    uc->reg_write = sparc_reg_write;
    uc->reg_reset = sparc_reg_reset;
    uc->set_pc = sparc_set_pc;
    uc->stop_interrupt = sparc_stop_interrupt;
    uc->cpus_init = sparc_cpus_init;
    uc->cpu_context_size = offsetof(CPUSPARCState, irq_manager);
    uc_common_init(uc);
}
