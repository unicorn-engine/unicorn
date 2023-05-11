/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"
#include "internal.h"

#ifdef TARGET_MIPS64
typedef uint64_t mipsreg_t;
#else
typedef uint32_t mipsreg_t;
#endif

MIPSCPU *cpu_mips_init(struct uc_struct *uc);

static void mips_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUMIPSState *)uc->cpu->env_ptr)->active_tc.PC = address;
}

static uint64_t mips_get_pc(struct uc_struct *uc)
{
    return ((CPUMIPSState *)uc->cpu->env_ptr)->active_tc.PC;
}

static void mips_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    MIPSCPU *cpu = (MIPSCPU *)tcg_ctx->uc->cpu;
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

    g_free(cpu->env.mvp);
    g_free(cpu->env.tlb);
}

void mips_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    (void)uc;
    env = uc->cpu->env_ptr;
    memset(env->active_tc.gpr, 0, sizeof(env->active_tc.gpr));

    env->active_tc.PC = 0;
}

static uc_err reg_read(CPUMIPSState *env, unsigned int regid, void *value,
                       size_t *size)
{
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_MIPS_REG_0 && regid <= UC_MIPS_REG_31) {
        CHECK_REG_TYPE(mipsreg_t);
        *(mipsreg_t *)value = env->active_tc.gpr[regid - UC_MIPS_REG_0];
    } else {
        switch (regid) {
        default:
            break;
        case UC_MIPS_REG_HI:
            CHECK_REG_TYPE(mipsreg_t);
            *(mipsreg_t *)value = env->active_tc.HI[0];
            break;
        case UC_MIPS_REG_LO:
            CHECK_REG_TYPE(mipsreg_t);
            *(mipsreg_t *)value = env->active_tc.LO[0];
            break;
        case UC_MIPS_REG_PC:
            CHECK_REG_TYPE(mipsreg_t);
            *(mipsreg_t *)value = env->active_tc.PC;
            break;
        case UC_MIPS_REG_CP0_CONFIG3:
            CHECK_REG_TYPE(mipsreg_t);
            *(mipsreg_t *)value = env->CP0_Config3;
            break;
        case UC_MIPS_REG_CP0_STATUS:
            CHECK_REG_TYPE(mipsreg_t);
            *(mipsreg_t *)value = env->CP0_Status;
            break;
        case UC_MIPS_REG_CP0_USERLOCAL:
            CHECK_REG_TYPE(mipsreg_t);
            *(mipsreg_t *)value = env->active_tc.CP0_UserLocal;
            break;
        }
    }

    return ret;
}

static uc_err reg_write(CPUMIPSState *env, unsigned int regid,
                        const void *value, size_t *size)
{
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_MIPS_REG_0 && regid <= UC_MIPS_REG_31) {
        CHECK_REG_TYPE(mipsreg_t);
        env->active_tc.gpr[regid - UC_MIPS_REG_0] = *(mipsreg_t *)value;
    } else {
        switch (regid) {
        default:
            break;
        case UC_MIPS_REG_HI:
            CHECK_REG_TYPE(mipsreg_t);
            env->active_tc.HI[0] = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_LO:
            CHECK_REG_TYPE(mipsreg_t);
            env->active_tc.LO[0] = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_PC:
            CHECK_REG_TYPE(mipsreg_t);
            env->active_tc.PC = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_CP0_CONFIG3:
            CHECK_REG_TYPE(mipsreg_t);
            env->CP0_Config3 = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_CP0_STATUS:
            // TODO: ALL CP0 REGS
            // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
            // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00582-2B-microMIPS32-AFP-05.04.pdf
            CHECK_REG_TYPE(mipsreg_t);
            env->CP0_Status = *(mipsreg_t *)value;
            compute_hflags(env);
            break;
        case UC_MIPS_REG_CP0_USERLOCAL:
            CHECK_REG_TYPE(mipsreg_t);
            env->active_tc.CP0_UserLocal = *(mipsreg_t *)value;
            break;
        }
    }

    return ret;
}

int mips_reg_read(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  size_t *sizes, int count)
{
    CPUMIPSState *env = &(MIPS_CPU(uc->cpu)->env);
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

int mips_reg_write(struct uc_struct *uc, unsigned int *regs,
                   const void *const *vals, size_t *sizes, int count)
{
    CPUMIPSState *env = &(MIPS_CPU(uc->cpu)->env);
    int i;
    uc_err err;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        err = reg_write(env, regid, value, sizes ? sizes + i : NULL);
        if (err) {
            return err;
        }
        if (regid == UC_MIPS_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            break_translation_loop(uc);
        }
    }

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
#ifdef TARGET_MIPS64
#ifdef TARGET_WORDS_BIGENDIAN
int mips64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, size_t *sizes, int count)
#else
int mips64el_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, size_t *sizes, int count)
#endif
#else // if TARGET_MIPS
#ifdef TARGET_WORDS_BIGENDIAN
int mips_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void *const *vals, size_t *sizes, int count)
#else
int mipsel_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, size_t *sizes, int count)
#endif
#endif
{
    CPUMIPSState *env = (CPUMIPSState *)ctx->data;
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
#ifdef TARGET_MIPS64
#ifdef TARGET_WORDS_BIGENDIAN
int mips64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                             const void *const *vals, size_t *sizes, int count)
#else
int mips64el_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                               const void *const *vals, size_t *sizes,
                               int count)
#endif
#else // if TARGET_MIPS
#ifdef TARGET_WORDS_BIGENDIAN
int mips_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           const void *const *vals, size_t *sizes, int count)
#else
int mipsel_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                             const void *const *vals, size_t *sizes, int count)
#endif
#endif
{
    CPUMIPSState *env = (CPUMIPSState *)ctx->data;
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

static int mips_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    MIPSCPU *cpu;

    cpu = cpu_mips_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_MIPS64
#ifdef TARGET_WORDS_BIGENDIAN
void mips64_uc_init(struct uc_struct *uc)
#else
void mips64el_uc_init(struct uc_struct *uc)
#endif
#else // if TARGET_MIPS
#ifdef TARGET_WORDS_BIGENDIAN
void mips_uc_init(struct uc_struct *uc)
#else
void mipsel_uc_init(struct uc_struct *uc)
#endif
#endif
{
    uc->reg_read = mips_reg_read;
    uc->reg_write = mips_reg_write;
    uc->reg_reset = mips_reg_reset;
    uc->release = mips_release;
    uc->set_pc = mips_set_pc;
    uc->get_pc = mips_get_pc;
    uc->cpus_init = mips_cpus_init;
    uc->cpu_context_size = offsetof(CPUMIPSState, end_reset_fields);
    uc_common_init(uc);
}
