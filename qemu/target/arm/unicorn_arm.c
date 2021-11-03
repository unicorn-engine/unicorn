/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu/typedefs.h"
#include "unicorn/unicorn.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "cpu.h"
#include "uc_priv.h"
#include "unicorn_common.h"
#include "unicorn.h"

ARMCPU *cpu_arm_init(struct uc_struct *uc);

static void arm_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->cpu->env_ptr)->pc = address;
    ((CPUARMState *)uc->cpu->env_ptr)->regs[15] = address;
}

static void arm_release(void *ctx)
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

void arm_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    (void)uc;

    env = uc->cpu->env_ptr;
    memset(env->regs, 0, sizeof(env->regs));

    env->pc = 0;
}

/* these functions are implemented in helper.c. */
#include "exec/helper-head.h"
uint32_t HELPER(v7m_mrs)(CPUARMState *env, uint32_t reg);
void HELPER(v7m_msr)(CPUARMState *env, uint32_t reg, uint32_t val);

static uint32_t v7m_mrs_xpsr(CPUARMState *env, uint32_t reg)
{
    uint32_t mask = 0;

    if (reg & 1) {
        mask |= XPSR_EXCP; /* IPSR (unpriv. reads as zero) */
    }

    if (!(reg & 4)) {
        mask |= XPSR_NZCV | XPSR_Q; /* APSR */
        if (arm_feature(env, ARM_FEATURE_THUMB_DSP)) {
            mask |= XPSR_GE;
        }
    }

    if (reg & 2) {
        mask |= (XPSR_IT_0_1 | XPSR_IT_2_7 | XPSR_T); /* EPSR */
    }

    return xpsr_read(env) & mask;
}

static void v7m_msr_xpsr(CPUARMState *env, uint32_t mask, uint32_t reg,
                         uint32_t val)
{
    uint32_t xpsrmask = 0;

    if (reg & 1) {
        xpsrmask |= XPSR_EXCP;
    }

    if (!(reg & 4)) {
        if (mask & 8) {
            xpsrmask |= XPSR_NZCV | XPSR_Q;
        }
        if ((mask & 4) && arm_feature(env, ARM_FEATURE_THUMB_DSP)) {
            xpsrmask |= XPSR_GE;
        }
    }

    if (reg & 2) {
        xpsrmask |= (XPSR_IT_0_1 | XPSR_IT_2_7 | XPSR_T);
    }

    xpsr_write(env, val, xpsrmask);
}

static void reg_read(CPUARMState *env, unsigned int regid, void *value)
{
    if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12) {
        *(int32_t *)value = env->regs[regid - UC_ARM_REG_R0];
    } else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31) {
        uint32_t reg_index = regid - UC_ARM_REG_D0;
        *(float64 *)value = env->vfp.zregs[reg_index / 2].d[reg_index & 1];
    } else {
        switch (regid) {
        case UC_ARM_REG_APSR:
            if (arm_feature(env, ARM_FEATURE_M)) {
                *(int32_t *)value = v7m_mrs_xpsr(env, 0);
            } else {
                *(int32_t *)value =
                    cpsr_read(env) & (CPSR_NZCV | CPSR_Q | CPSR_GE);
            }
            break;
        case UC_ARM_REG_APSR_NZCV:
            *(int32_t *)value = cpsr_read(env) & CPSR_NZCV;
            break;
        case UC_ARM_REG_CPSR:
            *(int32_t *)value = cpsr_read(env);
            break;
        case UC_ARM_REG_SPSR:
            *(int32_t *)value = env->spsr;
            break;
        // case UC_ARM_REG_SP:
        case UC_ARM_REG_R13:
            *(int32_t *)value = env->regs[13];
            break;
        // case UC_ARM_REG_LR:
        case UC_ARM_REG_R14:
            *(int32_t *)value = env->regs[14];
            break;
        // case UC_ARM_REG_PC:
        case UC_ARM_REG_R15:
            *(int32_t *)value = env->regs[15];
            break;
        case UC_ARM_REG_C1_C0_2:
            *(int32_t *)value = env->cp15.cpacr_el1;
            break;
        case UC_ARM_REG_C13_C0_3:
            *(int32_t *)value = env->cp15.tpidrro_el[0];
            break;
        case UC_ARM_REG_FPEXC:
            *(int32_t *)value = env->vfp.xregs[ARM_VFP_FPEXC];
            break;
        case UC_ARM_REG_IPSR:
            *(int32_t *)value = v7m_mrs_xpsr(env, 5);
            break;
        case UC_ARM_REG_MSP:
            *(uint32_t *)value = helper_v7m_mrs(env, 8);
            break;
        case UC_ARM_REG_PSP:
            *(uint32_t *)value = helper_v7m_mrs(env, 9);
            break;
        case UC_ARM_REG_IAPSR:
            *(int32_t *)value = v7m_mrs_xpsr(env, 1);
            break;
        case UC_ARM_REG_EAPSR:
            *(int32_t *)value = v7m_mrs_xpsr(env, 2);
            break;
        case UC_ARM_REG_XPSR:
            *(int32_t *)value = v7m_mrs_xpsr(env, 3);
            break;
        case UC_ARM_REG_EPSR:
            *(int32_t *)value = v7m_mrs_xpsr(env, 6);
            break;
        case UC_ARM_REG_IEPSR:
            *(int32_t *)value = v7m_mrs_xpsr(env, 7);
            break;
        case UC_ARM_REG_PRIMASK:
            *(uint32_t *)value = helper_v7m_mrs(env, 16);
            break;
        case UC_ARM_REG_BASEPRI:
            *(uint32_t *)value = helper_v7m_mrs(env, 17);
            break;
        case UC_ARM_REG_BASEPRI_MAX:
            *(uint32_t *)value = helper_v7m_mrs(env, 18);
            break;
        case UC_ARM_REG_FAULTMASK:
            *(uint32_t *)value = helper_v7m_mrs(env, 19);
            break;
        case UC_ARM_REG_CONTROL:
            *(uint32_t *)value = helper_v7m_mrs(env, 20);
            break;
        }
    }

    return;
}

static void reg_write(CPUARMState *env, unsigned int regid, const void *value)
{
    if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12) {
        env->regs[regid - UC_ARM_REG_R0] = *(uint32_t *)value;
    } else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31) {
        uint32_t reg_index = regid - UC_ARM_REG_D0;
        env->vfp.zregs[reg_index / 2].d[reg_index & 1] = *(float64 *)value;
    } else {
        switch (regid) {
        case UC_ARM_REG_APSR:
            if (!arm_feature(env, ARM_FEATURE_M)) {
                cpsr_write(env, *(uint32_t *)value,
                           (CPSR_NZCV | CPSR_Q | CPSR_GE), CPSRWriteRaw);
            } else {
                // Same with UC_ARM_REG_APSR_NZCVQ
                v7m_msr_xpsr(env, 0b1000, 0, *(uint32_t *)value);
            }
            break;
        case UC_ARM_REG_APSR_NZCV:
            cpsr_write(env, *(uint32_t *)value, CPSR_NZCV, CPSRWriteRaw);
            break;
        case UC_ARM_REG_CPSR:
            cpsr_write(env, *(uint32_t *)value, ~0, CPSRWriteRaw);
            break;
        case UC_ARM_REG_SPSR:
            env->spsr = *(uint32_t *)value;
            break;
        // case UC_ARM_REG_SP:
        case UC_ARM_REG_R13:
            env->regs[13] = *(uint32_t *)value;
            break;
        // case UC_ARM_REG_LR:
        case UC_ARM_REG_R14:
            env->regs[14] = *(uint32_t *)value;
            break;
        // case UC_ARM_REG_PC:
        case UC_ARM_REG_R15:
            env->pc = (*(uint32_t *)value & ~1);
            env->thumb = (*(uint32_t *)value & 1);
            env->uc->thumb = (*(uint32_t *)value & 1);
            env->regs[15] = (*(uint32_t *)value & ~1);
            break;
            // case UC_ARM_REG_C1_C0_2:
            //     env->cp15.c1_coproc = *(int32_t *)value;
            //     break;

        case UC_ARM_REG_C13_C0_3:
            env->cp15.tpidrro_el[0] = *(int32_t *)value;
            break;
        case UC_ARM_REG_FPEXC:
            env->vfp.xregs[ARM_VFP_FPEXC] = *(int32_t *)value;
            break;
        case UC_ARM_REG_IPSR:
            v7m_msr_xpsr(env, 0b1000, 5, *(uint32_t *)value);
            break;
        case UC_ARM_REG_MSP:
            helper_v7m_msr(env, 8, *(uint32_t *)value);
            break;
        case UC_ARM_REG_PSP:
            helper_v7m_msr(env, 9, *(uint32_t *)value);
            break;
        case UC_ARM_REG_CONTROL:
            helper_v7m_msr(env, 20, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EPSR:
            v7m_msr_xpsr(env, 0b1000, 6, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IEPSR:
            v7m_msr_xpsr(env, 0b1000, 7, *(uint32_t *)value);
            break;
        case UC_ARM_REG_PRIMASK:
            helper_v7m_msr(env, 16, *(uint32_t *)value);
            break;
        case UC_ARM_REG_BASEPRI:
            helper_v7m_msr(env, 17, *(uint32_t *)value);
            break;
        case UC_ARM_REG_BASEPRI_MAX:
            helper_v7m_msr(env, 18, *(uint32_t *)value);
            break;
        case UC_ARM_REG_FAULTMASK:
            helper_v7m_msr(env, 19, *(uint32_t *)value);
            break;
        case UC_ARM_REG_APSR_NZCVQ:
            v7m_msr_xpsr(env, 0b1000, 0, *(uint32_t *)value);
            break;
        case UC_ARM_REG_APSR_G:
            v7m_msr_xpsr(env, 0b0100, 0, *(uint32_t *)value);
            break;
        case UC_ARM_REG_APSR_NZCVQG:
            v7m_msr_xpsr(env, 0b1100, 0, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IAPSR:
        case UC_ARM_REG_IAPSR_NZCVQ:
            v7m_msr_xpsr(env, 0b1000, 1, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IAPSR_G:
            v7m_msr_xpsr(env, 0b0100, 1, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IAPSR_NZCVQG:
            v7m_msr_xpsr(env, 0b1100, 1, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EAPSR:
        case UC_ARM_REG_EAPSR_NZCVQ:
            v7m_msr_xpsr(env, 0b1000, 2, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EAPSR_G:
            v7m_msr_xpsr(env, 0b0100, 2, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EAPSR_NZCVQG:
            v7m_msr_xpsr(env, 0b1100, 2, *(uint32_t *)value);
            break;
        case UC_ARM_REG_XPSR:
        case UC_ARM_REG_XPSR_NZCVQ:
            v7m_msr_xpsr(env, 0b1000, 3, *(uint32_t *)value);
            break;
        case UC_ARM_REG_XPSR_G:
            v7m_msr_xpsr(env, 0b0100, 3, *(uint32_t *)value);
            break;
        case UC_ARM_REG_XPSR_NZCVQG:
            v7m_msr_xpsr(env, 0b1100, 3, *(uint32_t *)value);
            break;
        }
    }

    return;
}

int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
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

int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  int count)
{
    CPUArchState *env = &(ARM_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_ARM_REG_R15) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
int armeb_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count)
#else
int arm_context_reg_read(struct uc_context *ctx, unsigned int *regs,
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
int armeb_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count)
#else
int arm_context_reg_write(struct uc_context *ctx, unsigned int *regs,
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

static bool arm_stop_interrupt(struct uc_struct *uc, int intno)
{
    switch (intno) {
    default:
        return false;
    case EXCP_UDEF:
    case EXCP_YIELD:
        return true;
    case EXCP_INVSTATE:
        uc->invalid_error = UC_ERR_EXCEPTION;
        return true;
    }
}

static uc_err arm_query(struct uc_struct *uc, uc_query_type type,
                        size_t *result)
{
    CPUState *mycpu = uc->cpu;
    uint32_t mode;

    switch (type) {
    case UC_QUERY_MODE:
        // zero out ARM/THUMB mode
        mode = uc->mode & ~(UC_MODE_ARM | UC_MODE_THUMB);
        // THUMB mode or ARM MOde
        mode |=
            ((ARM_CPU(mycpu)->env.thumb != 0) ? UC_MODE_THUMB : UC_MODE_ARM);
        *result = mode;
        return UC_ERR_OK;
    default:
        return UC_ERR_ARG;
    }
}

static bool arm_opcode_hook_invalidate(uint32_t op, uint32_t flags)
{
    if (op != UC_TCG_OP_SUB) {
        return false;
    }

    if (flags == UC_TCG_OP_FLAG_CMP && op != UC_TCG_OP_SUB) {
        return false;
    }

    return true;
}

static int arm_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    ARMCPU *cpu;

    cpu = cpu_arm_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

#ifdef TARGET_WORDS_BIGENDIAN
void armeb_uc_init(struct uc_struct *uc)
#else
void arm_uc_init(struct uc_struct *uc)
#endif
{
    uc->reg_read = arm_reg_read;
    uc->reg_write = arm_reg_write;
    uc->reg_reset = arm_reg_reset;
    uc->set_pc = arm_set_pc;
    uc->stop_interrupt = arm_stop_interrupt;
    uc->release = arm_release;
    uc->query = arm_query;
    uc->cpus_init = arm_cpus_init;
    uc->opcode_hook_invalidate = arm_opcode_hook_invalidate;
    uc->cpu_context_size = offsetof(CPUARMState, cpu_watchpoint);
    uc_common_init(uc);
}
