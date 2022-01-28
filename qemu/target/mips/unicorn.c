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

static uint64_t mips_mem_redirect(uint64_t address)
{
    // kseg0 range masks off high address bit
    if (address >= 0x80000000 && address <= 0x9fffffff)
        return address & 0x7fffffff;

    // kseg1 range masks off top 3 address bits
    if (address >= 0xa0000000 && address <= 0xbfffffff) {
        return address & 0x1fffffff;
    }

    // no redirect
    return address;
}

static void mips_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUMIPSState *)uc->cpu->env_ptr)->active_tc.PC = address;
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

static void reg_read(CPUMIPSState *env, unsigned int regid, void *value)
{
    if (regid >= UC_MIPS_REG_0 && regid <= UC_MIPS_REG_31)
        *(mipsreg_t *)value = env->active_tc.gpr[regid - UC_MIPS_REG_0];
    else {
        switch (regid) {
        default:
            break;
        case UC_MIPS_REG_HI:
            *(mipsreg_t *)value = env->active_tc.HI[0];
            break;
        case UC_MIPS_REG_LO:
            *(mipsreg_t *)value = env->active_tc.LO[0];
            break;
        case UC_MIPS_REG_PC:
            *(mipsreg_t *)value = env->active_tc.PC;
            break;
        case UC_MIPS_REG_CP0_CONFIG3:
            *(mipsreg_t *)value = env->CP0_Config3;
            break;
        case UC_MIPS_REG_CP0_STATUS:
            *(mipsreg_t *)value = env->CP0_Status;
            break;
        case UC_MIPS_REG_CP0_USERLOCAL:
            *(mipsreg_t *)value = env->active_tc.CP0_UserLocal;
            break;
        }
    }

    return;
}

static void reg_write(CPUMIPSState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_MIPS_REG_0 && regid <= UC_MIPS_REG_31)
        env->active_tc.gpr[regid - UC_MIPS_REG_0] = *(mipsreg_t *)value;
    else {
        switch (regid) {
        default:
            break;
        case UC_MIPS_REG_HI:
            env->active_tc.HI[0] = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_LO:
            env->active_tc.LO[0] = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_PC:
            env->active_tc.PC = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_CP0_CONFIG3:
            env->CP0_Config3 = *(mipsreg_t *)value;
            break;
        case UC_MIPS_REG_CP0_STATUS:
            // TODO: ALL CP0 REGS
            // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
            // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00582-2B-microMIPS32-AFP-05.04.pdf
            env->CP0_Status = *(mipsreg_t *)value;
            compute_hflags(env);
            break;
        case UC_MIPS_REG_CP0_USERLOCAL:
            env->active_tc.CP0_UserLocal = *(mipsreg_t *)value;
            break;
        }
    }

    return;
}

int mips_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                  int count)
{
    CPUMIPSState *env = &(MIPS_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int mips_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                   int count)
{
    CPUMIPSState *env = &(MIPS_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_MIPS_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_MIPS64
#ifdef TARGET_WORDS_BIGENDIAN
int mips64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                            void **vals, int count)
#else
int mips64el_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                              void **vals, int count)
#endif
#else // if TARGET_MIPS
#ifdef TARGET_WORDS_BIGENDIAN
int mips_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count)
#else
int mipsel_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                            void **vals, int count)
#endif
#endif
{
    CPUMIPSState *env = (CPUMIPSState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_MIPS64
#ifdef TARGET_WORDS_BIGENDIAN
int mips64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                             void *const *vals, int count)
#else
int mips64el_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                               void *const *vals, int count)
#endif
#else // if TARGET_MIPS
#ifdef TARGET_WORDS_BIGENDIAN
int mips_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count)
#else
int mipsel_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                             void *const *vals, int count)
#endif
#endif
{
    CPUMIPSState *env = (CPUMIPSState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
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
    uc->mem_redirect = mips_mem_redirect;
    uc->cpus_init = mips_cpus_init;
    uc->cpu_context_size = offsetof(CPUMIPSState, end_reset_fields);
    uc_common_init(uc);
}
