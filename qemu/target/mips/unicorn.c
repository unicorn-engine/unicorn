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

static void reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    (void)uc;
    env = uc->cpu->env_ptr;
    memset(env->active_tc.gpr, 0, sizeof(env->active_tc.gpr));

    env->active_tc.PC = 0;
}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUMIPSState *env = _env;
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

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUMIPSState *env = _env;
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
            *setpc = 1;
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
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->release = mips_release;
    uc->set_pc = mips_set_pc;
    uc->get_pc = mips_get_pc;
    uc->cpus_init = mips_cpus_init;
    uc->cpu_context_size = offsetof(CPUMIPSState, end_reset_fields);
    uc_common_init(uc);
}
