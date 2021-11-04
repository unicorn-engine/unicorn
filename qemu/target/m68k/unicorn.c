/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

M68kCPU *cpu_m68k_init(struct uc_struct *uc);

static void m68k_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUM68KState *)uc->cpu->env_ptr)->pc = address;
}

static void m68k_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    M68kCPU *cpu = (M68kCPU *)tcg_ctx->uc->cpu;
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

void m68k_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->aregs, 0, sizeof(env->aregs));
    memset(env->dregs, 0, sizeof(env->dregs));

    env->pc = 0;
}

static void reg_read(CPUM68KState *env, unsigned int regid, void *value)
{
    if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
        *(int32_t *)value = env->aregs[regid - UC_M68K_REG_A0];
    else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
        *(int32_t *)value = env->dregs[regid - UC_M68K_REG_D0];
    else {
        switch (regid) {
        default:
            break;
        case UC_M68K_REG_PC:
            *(int32_t *)value = env->pc;
            break;
        }
    }

    return;
}

static void reg_write(CPUM68KState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
        env->aregs[regid - UC_M68K_REG_A0] = *(uint32_t *)value;
    else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
        env->dregs[regid - UC_M68K_REG_D0] = *(uint32_t *)value;
    else {
        switch (regid) {
        default:
            break;
        case UC_M68K_REG_PC:
            env->pc = *(uint32_t *)value;
            break;
        }
    }
}

int m68k_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                  int count)
{
    CPUM68KState *env = &(M68K_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int m68k_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                   int count)
{
    CPUM68KState *env = &(M68K_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_M68K_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
int m68k_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count)
{
    CPUM68KState *env = (CPUM68KState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
int m68k_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count)
{
    CPUM68KState *env = (CPUM68KState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static int m68k_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    M68kCPU *cpu;

    cpu = cpu_m68k_init(uc);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void m68k_uc_init(struct uc_struct *uc)
{
    uc->release = m68k_release;
    uc->reg_read = m68k_reg_read;
    uc->reg_write = m68k_reg_write;
    uc->reg_reset = m68k_reg_reset;
    uc->set_pc = m68k_set_pc;
    uc->cpus_init = m68k_cpus_init;
    uc->cpu_context_size = offsetof(CPUM68KState, end_reset_fields);
    uc_common_init(uc);
}
