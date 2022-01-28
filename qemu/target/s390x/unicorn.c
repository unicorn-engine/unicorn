/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2021 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"
#include "internal.h"

S390CPU *cpu_s390_init(struct uc_struct *uc, const char *cpu_model);

static void s390_set_pc(struct uc_struct *uc, uint64_t address)
{
    // ((CPUS390XState *)uc->cpu->env_ptr)->pc = address;
}

static void s390_release(void *ctx)
{

    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    S390CPU *cpu = (S390CPU *)tcg_ctx->uc->cpu;
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

    s390_cpu_model_finalize((CPUState *)cpu);
    // TODO: Anymore to free?
}

void s390_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->regs, 0, sizeof(env->regs));
    memset(env->aregs, 0, sizeof(env->aregs));

    env->psw.addr = 0;
}

static void reg_read(CPUS390XState *env, unsigned int regid, void *value)
{
    if (regid >= UC_S390X_REG_R0 && regid <= UC_S390X_REG_R15) {
        *(uint64_t *)value = env->regs[regid - UC_S390X_REG_R0];
        return;
    }

    if (regid >= UC_S390X_REG_A0 && regid <= UC_S390X_REG_A15) {
        *(uint32_t *)value = env->regs[regid - UC_S390X_REG_A0];
        return;
    }

    switch (regid) {
    default:
        break;
    case UC_S390X_REG_PC:
        *(uint64_t *)value = env->psw.addr;
        break;
    case UC_S390X_REG_PSWM:
        *(uint64_t *)value = get_psw_mask(env);
        break;
    }
}

static void reg_write(CPUS390XState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_S390X_REG_R0 && regid <= UC_S390X_REG_R15) {
        env->regs[regid - UC_S390X_REG_R0] = *(uint64_t *)value;
        return;
    }

    if (regid >= UC_S390X_REG_A0 && regid <= UC_S390X_REG_A15) {
        env->regs[regid - UC_S390X_REG_A0] = *(uint32_t *)value;
        return;
    }

    switch (regid) {
    default:
        break;
    case UC_S390X_REG_PC:
        env->psw.addr = *(uint64_t *)value;
        break;
    case UC_S390X_REG_PSWM:
        env->psw.mask = *(uint64_t *)value;
        env->cc_op = (env->psw.mask >> 44) & 3;
        break;
    }
}

static int s390_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                         int count)
{
    CPUS390XState *env = &(S390_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

static int s390_reg_write(struct uc_struct *uc, unsigned int *regs,
                          void *const *vals, int count)
{
    CPUS390XState *env = &(S390_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_S390X_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
int s390_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count)
{
    CPUS390XState *env = (CPUS390XState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
int s390_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count)
{
    CPUS390XState *env = (CPUS390XState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static int s390_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    S390CPU *cpu;

    cpu = cpu_s390_init(uc, cpu_model);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void s390_uc_init(struct uc_struct *uc)
{
    uc->release = s390_release;
    uc->reg_read = s390_reg_read;
    uc->reg_write = s390_reg_write;
    uc->reg_reset = s390_reg_reset;
    uc->set_pc = s390_set_pc;
    uc->cpus_init = s390_cpus_init;
    uc->cpu_context_size = offsetof(CPUS390XState, end_reset_fields);
    uc_common_init(uc);
}
