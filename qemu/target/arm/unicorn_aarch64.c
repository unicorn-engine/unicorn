/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu/typedefs.h"
#include "unicorn/unicorn.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

ARMCPU *cpu_aarch64_init(struct uc_struct *uc);

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->cpu->env_ptr)->pc = address;
}

static void arm64_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    ARMCPU *cpu = (ARMCPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;
    ARMELChangeHook *entry, *next;
    CPUARMState *env = &cpu->env;
    uint32_t nr;

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }

    QLIST_FOREACH_SAFE(entry, &cpu->pre_el_change_hooks, node, next)
    {
        QLIST_SAFE_REMOVE(entry, node);
        g_free(entry);
    }
    QLIST_FOREACH_SAFE(entry, &cpu->el_change_hooks, node, next)
    {
        QLIST_SAFE_REMOVE(entry, node);
        g_free(entry);
    }

    if (arm_feature(env, ARM_FEATURE_PMSA) &&
        arm_feature(env, ARM_FEATURE_V7)) {
        nr = cpu->pmsav7_dregion;
        if (nr) {
            if (arm_feature(env, ARM_FEATURE_V8)) {
                g_free(env->pmsav8.rbar[M_REG_NS]);
                g_free(env->pmsav8.rlar[M_REG_NS]);
                if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
                    g_free(env->pmsav8.rbar[M_REG_S]);
                    g_free(env->pmsav8.rlar[M_REG_S]);
                }
            } else {
                g_free(env->pmsav7.drbar);
                g_free(env->pmsav7.drsr);
                g_free(env->pmsav7.dracr);
            }
        }
    }
    if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
        nr = cpu->sau_sregion;
        if (nr) {
            g_free(env->sau.rbar);
            g_free(env->sau.rlar);
        }
    }

    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);
    g_hash_table_destroy(cpu->cp_regs);
}

void arm64_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;
    memset(env->xregs, 0, sizeof(env->xregs));

    env->pc = 0;
}

static void reg_read(CPUARMState *env, unsigned int regid, void *value)
{
    if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
        regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
    }
    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        *(int64_t *)value = env->xregs[regid - UC_ARM64_REG_X0];
    } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
        *(int32_t *)value = READ_DWORD(env->xregs[regid - UC_ARM64_REG_W0]);
    } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) { // FIXME
        float64 *dst = (float64 *)value;
        uint32_t reg_index = regid - UC_ARM64_REG_Q0;
        dst[0] = env->vfp.zregs[reg_index].d[0];
        dst[1] = env->vfp.zregs[reg_index].d[1];
    } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
        *(float64 *)value = env->vfp.zregs[regid - UC_ARM64_REG_D0].d[0];
    } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
        *(int32_t *)value =
            READ_DWORD(env->vfp.zregs[regid - UC_ARM64_REG_S0].d[0]);
    } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
        *(int16_t *)value =
            READ_WORD(env->vfp.zregs[regid - UC_ARM64_REG_H0].d[0]);
    } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
        *(int8_t *)value =
            READ_BYTE_L(env->vfp.zregs[regid - UC_ARM64_REG_B0].d[0]);
    } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
        *(uint64_t *)value = env->elr_el[regid - UC_ARM64_REG_ELR_EL0];
    } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
        *(uint64_t *)value = env->sp_el[regid - UC_ARM64_REG_SP_EL0];
    } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
        *(uint64_t *)value = env->cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0];
    } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
        *(uint64_t *)value = env->cp15.far_el[regid - UC_ARM64_REG_FAR_EL0];
    } else if (regid >= UC_ARM64_REG_VBAR_EL0 &&
               regid <= UC_ARM64_REG_VBAR_EL3) {
        *(uint64_t *)value = env->cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0];
    } else {
        switch (regid) {
        default:
            break;
        case UC_ARM64_REG_CPACR_EL1:
            // *(uint32_t *)value = env->cp15.c1_coproc;
            break;
        case UC_ARM64_REG_TPIDR_EL0:
            // *(int64_t *)value = env->cp15.tpidr_el0;
            break;
        case UC_ARM64_REG_TPIDRRO_EL0:
            // *(int64_t *)value = env->cp15.tpidrro_el0;
            break;
        case UC_ARM64_REG_TPIDR_EL1:
            // *(int64_t *)value = env->cp15.tpidr_el1;
            break;
        case UC_ARM64_REG_X29:
            *(int64_t *)value = env->xregs[29];
            break;
        case UC_ARM64_REG_X30:
            *(int64_t *)value = env->xregs[30];
            break;
        case UC_ARM64_REG_PC:
            *(uint64_t *)value = env->pc;
            break;
        case UC_ARM64_REG_SP:
            *(int64_t *)value = env->xregs[31];
            break;
        case UC_ARM64_REG_NZCV:
            *(int32_t *)value = cpsr_read(env) & CPSR_NZCV;
            break;
        case UC_ARM64_REG_PSTATE:
            *(uint32_t *)value = pstate_read(env);
            break;
        case UC_ARM64_REG_TTBR0_EL1:
            // *(uint64_t *)value = env->cp15.ttbr0_el1;
            break;
        case UC_ARM64_REG_TTBR1_EL1:
            // *(uint64_t *)value = env->cp15.ttbr1_el1;
            break;
        case UC_ARM64_REG_PAR_EL1:
            // *(uint64_t *)value = env->cp15.par_el1;
            break;
        case UC_ARM64_REG_MAIR_EL1:
            // *(uint64_t *)value = env->cp15.mair_el1;
            break;
        }
    }

    return;
}

static void reg_write(CPUARMState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
        regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
    }
    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        env->xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
        WRITE_DWORD(env->xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
    } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
        float64 *src = (float64 *)value;
        uint32_t reg_index = regid - UC_ARM64_REG_Q0;
        env->vfp.zregs[reg_index].d[0] = src[0];
        env->vfp.zregs[reg_index].d[1] = src[1];
    } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
        env->vfp.zregs[regid - UC_ARM64_REG_D0].d[0] = *(float64 *)value;
    } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
        WRITE_DWORD(env->vfp.zregs[regid - UC_ARM64_REG_S0].d[0],
                    *(int32_t *)value);
    } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
        WRITE_WORD(env->vfp.zregs[regid - UC_ARM64_REG_H0].d[0],
                   *(int16_t *)value);
    } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
        WRITE_BYTE_L(env->vfp.zregs[regid - UC_ARM64_REG_B0].d[0],
                     *(int8_t *)value);
    } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
        env->elr_el[regid - UC_ARM64_REG_ELR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
        env->sp_el[regid - UC_ARM64_REG_SP_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
        env->cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
        env->cp15.far_el[regid - UC_ARM64_REG_FAR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_VBAR_EL0 &&
               regid <= UC_ARM64_REG_VBAR_EL3) {
        env->cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0] = *(uint64_t *)value;
    } else {
        switch (regid) {
        default:
            break;
        case UC_ARM64_REG_CPACR_EL1:
            // env->cp15.c1_coproc = *(uint32_t *)value;
            break;
        case UC_ARM64_REG_TPIDR_EL0:
            // env->cp15.tpidr_el0 = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TPIDRRO_EL0:
            // env->cp15.tpidrro_el0 = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TPIDR_EL1:
            // env->cp15.tpidr_el1 = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_X29:
            env->xregs[29] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_X30:
            env->xregs[30] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_PC:
            env->pc = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_SP:
            env->xregs[31] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_NZCV:
            // cpsr_write(env, *(uint32_t *)value, CPSR_NZCV);
            break;
        case UC_ARM64_REG_PSTATE:
            pstate_write(env, *(uint32_t *)value);
            break;
        case UC_ARM64_REG_TTBR0_EL1:
            // env->cp15.ttbr0_el1 = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TTBR1_EL1:
            // env->cp15.ttbr1_el1 = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_PAR_EL1:
            // env->cp15.par_el1 = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_MAIR_EL1:
            // env->cp15.mair_el1 = *(uint64_t *)value;
            break;
        }
    }

    return;
}

int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count)
{
    CPUARMState *env = &(ARM_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count)
{
    CPUARMState *env = &(ARM_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_ARM64_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
int arm64eb_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count)
#else
int arm64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count)
#endif
{
    CPUARMState *env = (CPUARMState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
int arm64eb_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count)
#else
int arm64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count)
#endif
{
    CPUARMState *env = (CPUARMState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static int arm64_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    ARMCPU *cpu;

    cpu = cpu_aarch64_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
void arm64eb_uc_init(struct uc_struct *uc)
#else
void arm64_uc_init(struct uc_struct *uc)
#endif
{
    uc->reg_read = arm64_reg_read;
    uc->reg_write = arm64_reg_write;
    uc->reg_reset = arm64_reg_reset;
    uc->set_pc = arm64_set_pc;
    uc->release = arm64_release;
    uc->cpus_init = arm64_cpus_init;
    uc->cpu_context_size = offsetof(CPUARMState, cpu_watchpoint);
    uc_common_init(uc);
}
