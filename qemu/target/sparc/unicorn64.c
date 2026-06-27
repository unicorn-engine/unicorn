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

static uint64_t sparc_get_pc(struct uc_struct *uc)
{
    return ((CPUSPARCState *)uc->cpu->env_ptr)->pc;
}

static uint32_t sparc_get_fpr_f(CPUSPARCState *env, unsigned int reg)
{
    CPU_DoubleU *fpr = &env->fpr[reg / 2];

    return (reg & 1) ? fpr->l.lower : fpr->l.upper;
}

static void sparc_set_fpr_f(CPUSPARCState *env, unsigned int reg,
                            uint32_t value)
{
    CPU_DoubleU *fpr = &env->fpr[reg / 2];

    if (reg & 1) {
        fpr->l.lower = value;
    } else {
        fpr->l.upper = value;
    }
}

static uint32_t sparc64_fpr_number(unsigned int regid)
{
    return 32 + (regid - UC_SPARC_REG_F32) * 2;
}

static uint32_t sparc_get_fcc(CPUSPARCState *env, unsigned int offset)
{
    return ((env->fsr >> (FSR_FCC0_SHIFT + offset)) & 1) |
           (((env->fsr >> (FSR_FCC1_SHIFT + offset)) & 1) << 1);
}

static void sparc_set_fcc(CPUSPARCState *env, unsigned int offset,
                          uint32_t value)
{
    target_ulong mask = (FSR_FCC0 | FSR_FCC1) << offset;

    env->fsr &= ~mask;
    if (value & 1) {
        env->fsr |= FSR_FCC0 << offset;
    }
    if (value & 2) {
        env->fsr |= FSR_FCC1 << offset;
    }
}

static unsigned int sparc_fcc_offset(unsigned int regid)
{
    static const unsigned int fcc_offsets[] = { 0, 22, 24, 26 };

    return fcc_offsets[regid - UC_SPARC_REG_FCC0];
}

static target_ulong sparc_get_ccr(CPUSPARCState *env)
{
    if (env->cc_op != CC_OP_FLAGS && env->cc_op != CC_OP_DYNAMIC) {
        return cpu_get_ccr(env);
    }
    return ((env->xcc >> PSR_CARRY_SHIFT) << 4) |
           ((env->psr & PSR_ICC) >> PSR_CARRY_SHIFT);
}

static void sparc_set_ccr(CPUSPARCState *env, target_ulong value)
{
    env->xcc = ((value >> 4) & 0xf) << PSR_CARRY_SHIFT;
    env->psr = (env->psr & ~PSR_ICC) |
               ((value & 0xf) << PSR_CARRY_SHIFT);
    env->cc_op = CC_OP_FLAGS;
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

static void reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->gregs, 0, sizeof(env->gregs));
    memset(env->fpr, 0, sizeof(env->fpr));
    memset(env->regbase, 0, sizeof(env->regbase));

    env->pc = 0;
    env->npc = 0;
    env->regwptr = env->regbase;
}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUSPARCState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->gregs[regid - UC_SPARC_REG_G0];
    } else if (regid >= UC_SPARC_REG_F0 && regid <= UC_SPARC_REG_F31) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = sparc_get_fpr_f(env,
                                             regid - UC_SPARC_REG_F0);
    } else if (regid >= UC_SPARC_REG_F32 && regid <= UC_SPARC_REG_F62) {
        uint32_t reg = sparc64_fpr_number(regid);

        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->fpr[reg / 2].ll;
    } else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->regwptr[regid - UC_SPARC_REG_O0];
    } else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->regwptr[8 + regid - UC_SPARC_REG_L0];
    } else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->regwptr[16 + regid - UC_SPARC_REG_I0];
    } else if (regid >= UC_SPARC_REG_FCC0 && regid <= UC_SPARC_REG_FCC3) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = sparc_get_fcc(env, sparc_fcc_offset(regid));
    } else if (regid == UC_SPARC_REG_ICC) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = sparc_get_ccr(env) & 0xf;
    } else if (regid == UC_SPARC_REG_Y) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->y;
    } else if (regid == UC_SPARC_REG_XCC) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = (sparc_get_ccr(env) >> 4) & 0xf;
    } else {
        switch (regid) {
        default:
            break;
        case UC_SPARC_REG_PC:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->pc;
            break;
        }
    }

    CHECK_RET_DEPRECATE(ret, regid);
    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUSPARCState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_SPARC_REG_G0 && regid <= UC_SPARC_REG_G7) {
        CHECK_REG_TYPE(uint64_t);
        env->gregs[regid - UC_SPARC_REG_G0] = *(uint64_t *)value;
    } else if (regid >= UC_SPARC_REG_F0 && regid <= UC_SPARC_REG_F31) {
        CHECK_REG_TYPE(uint32_t);
        sparc_set_fpr_f(env, regid - UC_SPARC_REG_F0, *(uint32_t *)value);
    } else if (regid >= UC_SPARC_REG_F32 && regid <= UC_SPARC_REG_F62) {
        uint32_t reg = sparc64_fpr_number(regid);

        CHECK_REG_TYPE(uint64_t);
        env->fpr[reg / 2].ll = *(uint64_t *)value;
    } else if (regid >= UC_SPARC_REG_O0 && regid <= UC_SPARC_REG_O7) {
        CHECK_REG_TYPE(uint64_t);
        env->regwptr[regid - UC_SPARC_REG_O0] = *(uint64_t *)value;
    } else if (regid >= UC_SPARC_REG_L0 && regid <= UC_SPARC_REG_L7) {
        CHECK_REG_TYPE(uint64_t);
        env->regwptr[8 + regid - UC_SPARC_REG_L0] = *(uint64_t *)value;
    } else if (regid >= UC_SPARC_REG_I0 && regid <= UC_SPARC_REG_I7) {
        CHECK_REG_TYPE(uint64_t);
        env->regwptr[16 + regid - UC_SPARC_REG_I0] = *(uint64_t *)value;
    } else if (regid >= UC_SPARC_REG_FCC0 && regid <= UC_SPARC_REG_FCC3) {
        CHECK_REG_TYPE(uint32_t);
        sparc_set_fcc(env, sparc_fcc_offset(regid), *(uint32_t *)value);
    } else if (regid == UC_SPARC_REG_ICC) {
        target_ulong ccr;

        CHECK_REG_TYPE(uint32_t);
        ccr = sparc_get_ccr(env) & ~0xf;
        ccr |= *(uint32_t *)value & 0xf;
        sparc_set_ccr(env, ccr);
    } else if (regid == UC_SPARC_REG_Y) {
        CHECK_REG_TYPE(uint64_t);
        env->y = *(uint64_t *)value;
    } else if (regid == UC_SPARC_REG_XCC) {
        target_ulong ccr;

        CHECK_REG_TYPE(uint32_t);
        ccr = sparc_get_ccr(env) & ~0xf0;
        ccr |= (*(uint32_t *)value & 0xf) << 4;
        sparc_set_ccr(env, ccr);
    } else {
        switch (regid) {
        default:
            break;
        case UC_SPARC_REG_PC:
            CHECK_REG_TYPE(uint64_t);
            env->pc = *(uint64_t *)value;
            env->npc = *(uint64_t *)value + 4;
            *setpc = 1;
            break;
        }
    }

    CHECK_RET_DEPRECATE(ret, regid);
    return ret;
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
void uc_init(struct uc_struct *uc)
{
    uc->release = sparc_release;
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->set_pc = sparc_set_pc;
    uc->get_pc = sparc_get_pc;
    uc->stop_interrupt = sparc_stop_interrupt;
    uc->cpus_init = sparc_cpus_init;
    uc_common_init(uc);
}
