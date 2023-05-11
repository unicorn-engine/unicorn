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
    ((CPUS390XState *)uc->cpu->env_ptr)->psw.addr = address;
}

static uint64_t s390_get_pc(struct uc_struct *uc)
{
    return ((CPUS390XState *)uc->cpu->env_ptr)->psw.addr;
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

static uc_err reg_read(CPUS390XState *env, unsigned int regid, void *value,
                       size_t *size)
{
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_S390X_REG_R0 && regid <= UC_S390X_REG_R15) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->regs[regid - UC_S390X_REG_R0];
    } else if (regid >= UC_S390X_REG_A0 && regid <= UC_S390X_REG_A15) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->regs[regid - UC_S390X_REG_A0];
    } else {
        switch (regid) {
        default:
            break;
        case UC_S390X_REG_PC:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->psw.addr;
            break;
        case UC_S390X_REG_PSWM:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = get_psw_mask(env);
            break;
        }
    }

    return ret;
}

static uc_err reg_write(CPUS390XState *env, unsigned int regid,
                        const void *value, size_t *size)
{
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_S390X_REG_R0 && regid <= UC_S390X_REG_R15) {
        CHECK_REG_TYPE(uint64_t);
        env->regs[regid - UC_S390X_REG_R0] = *(uint64_t *)value;
    } else if (regid >= UC_S390X_REG_A0 && regid <= UC_S390X_REG_A15) {
        CHECK_REG_TYPE(uint32_t);
        env->regs[regid - UC_S390X_REG_A0] = *(uint32_t *)value;
    } else {
        switch (regid) {
        default:
            break;
        case UC_S390X_REG_PC:
            CHECK_REG_TYPE(uint64_t);
            env->psw.addr = *(uint64_t *)value;
            break;
        case UC_S390X_REG_PSWM:
            CHECK_REG_TYPE(uint64_t);
            env->psw.mask = *(uint64_t *)value;
            env->cc_op = (env->psw.mask >> 44) & 3;
            break;
        }
    }
    return ret;
}

DEFAULT_VISIBILITY
int s390_reg_read(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  size_t *sizes, int count)
{
    CPUS390XState *env = &(S390_CPU(uc->cpu)->env);
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        err = reg_read(env, regid, value, sizes ? sizes + i : NULL);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
int s390_reg_write(struct uc_struct *uc, unsigned int *regs,
                   const void *const *vals, size_t *sizes, int count)
{
    CPUS390XState *env = &(S390_CPU(uc->cpu)->env);
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        err = reg_write(env, regid, value, sizes ? sizes + i : NULL);
        if (err) {
            return err;
        }
        if (regid == UC_S390X_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            break_translation_loop(uc);
        }
    }

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
int s390_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void *const *vals, size_t *sizes, int count)
{
    CPUS390XState *env = (CPUS390XState *)ctx->data;
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        err = reg_read(env, regid, value, sizes ? sizes + i : NULL);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
int s390_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           const void *const *vals, size_t *sizes, int count)
{
    CPUS390XState *env = (CPUS390XState *)ctx->data;
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        err = reg_write(env, regid, value, sizes ? sizes + i : NULL);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
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
    uc->get_pc = s390_get_pc;
    uc->cpus_init = s390_cpus_init;
    uc->cpu_context_size = offsetof(CPUS390XState, end_reset_fields);
    uc_common_init(uc);
}
