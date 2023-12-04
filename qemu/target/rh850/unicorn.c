/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2021 */
/* Modified for Unicorn Engine by Damien Cauquil<dcauquil@quarkslab.com>, 2020 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

RH850CPU *cpu_rh850_init(struct uc_struct *uc, const char *cpu_model);

static void rh850_set_pc(struct uc_struct *uc, uint64_t address)
{
    rh850_cpu_set_pc(uc->cpu, address);
}

static uint64_t rh850_get_pc(struct uc_struct *uc)
{
    return rh850_cpu_get_pc(uc->cpu);
}

static void rh850_release(void *ctx)
{

    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    RH850CPU *cpu = (RH850CPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;

    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }

    release_common(ctx);
}

void rh850_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->gpRegs, 0, sizeof(env->gpRegs));
    env->pc = 0;
}

static void reg_read(CPURH850State *env, unsigned int regid, void *value)
{
    int sel_id;

    /* PC */
    if (regid == UC_RH850_REG_PC)
    {
        *(uint64_t *)value = env->pc;
        return;
    }

    /* General purpose register. */
    if ((regid >= UC_RH850_REG_R0) && (regid <= UC_RH850_REG_R31))
    {
        *(uint64_t *)value = env->gpRegs[regid];
        return;
    }

    /* System registers. */
    if ((regid >= UC_RH850_SYSREG_SELID0) && (regid <= (UC_RH850_SYSREG_SELID7 + 32)))
    {
        sel_id = (regid - 32)/32;
        *(uint64_t *)value = env->systemRegs[sel_id][regid % 32];
        return;
    }
}

static void reg_write(CPURH850State *env, unsigned int regid, const void *value)
{
    /* TODO */

    int sel_id;

    /* PC */
    if (regid == UC_RH850_REG_PC)
    {
        env->pc = *(uint64_t *)value;
        return;
    }

    /* General purpose register. */
    if ((regid >= UC_RH850_REG_R0) && (regid <= UC_RH850_REG_R31))
    {
        env->gpRegs[regid] = *(uint64_t *)value;
        return;
    }

    /* System registers. */
    if ((regid >= UC_RH850_SYSREG_SELID0) && (regid <= (UC_RH850_SYSREG_SELID7 + 32)))
    {
        sel_id = (regid - 32)/32;
        env->systemRegs[sel_id][regid % 32] = *(uint64_t *)value;
        return;
    }
}

static int rh850_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                         int count)
{
    CPURH850State *env = &(RH850_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }
    return 0;
}

static int rh850_reg_write(struct uc_struct *uc, unsigned int *regs,
                          void *const *vals, int count)
{
    CPURH850State *env = &(RH850_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_RH850_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }
    return 0;
}

DEFAULT_VISIBILITY
int rh850_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count)
{
    CPURH850State *env = (CPURH850State *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
int rh850_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count)
{
    CPURH850State *env = (CPURH850State *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static int rh850_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    RH850CPU *cpu;

    cpu = cpu_rh850_init(uc, cpu_model);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void rh850_uc_init(struct uc_struct *uc)
{
    uc->release = rh850_release;
    uc->reg_read = rh850_reg_read;
    uc->reg_write = rh850_reg_write;
    uc->reg_reset = rh850_reg_reset;
    uc->set_pc = rh850_set_pc;
    uc->get_pc = rh850_get_pc;
    uc->cpus_init = rh850_cpus_init;
    uc->cpu_context_size = offsetof(CPURH850State, uc);
    uc_common_init(uc);
}
