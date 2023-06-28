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
    ((CPUARMState *)uc->cpu->env_ptr)->regs[15] = address & ~1;
    ((CPUARMState *)uc->cpu->env_ptr)->thumb = address & 1;
}

static uint64_t arm_get_pc(struct uc_struct *uc)
{
    return ((CPUARMState *)uc->cpu->env_ptr)->regs[15] |
           ((CPUARMState *)uc->cpu->env_ptr)->thumb;
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

static void reg_reset(struct uc_struct *uc)
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

static uc_err read_cp_reg(CPUARMState *env, uc_arm_cp_reg *cp)
{
    ARMCPU *cpu = ARM_CPU(env->uc->cpu);
    int ns = cp->sec ? 0 : 1;
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(
        cpu->cp_regs, ENCODE_CP_REG(cp->cp, cp->is64, ns, cp->crn, cp->crm,
                                    cp->opc1, cp->opc2));

    if (!ri) {
        return UC_ERR_ARG;
    }

    cp->val = read_raw_cp_reg(env, ri);

    if (!cp->is64) {
        cp->val = cp->val & 0xFFFFFFFF;
    }

    return UC_ERR_OK;
}

static uc_err write_cp_reg(CPUARMState *env, uc_arm_cp_reg *cp)
{
    ARMCPU *cpu = ARM_CPU(env->uc->cpu);
    int ns = cp->sec ? 0 : 1;
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(
        cpu->cp_regs, ENCODE_CP_REG(cp->cp, cp->is64, ns, cp->crn, cp->crm,
                                    cp->opc1, cp->opc2));

    if (!ri) {
        return UC_ERR_ARG;
    }

    if (!cp->is64) {
        cp->val = cp->val & 0xFFFFFFFF;
    }

    if (ri->raw_writefn) {
        ri->raw_writefn(env, ri, cp->val);
    } else if (ri->writefn) {
        ri->writefn(env, ri, cp->val);
    } else {
        if (cpreg_field_is_64bit(ri)) {
            CPREG_FIELD64(env, ri) = cp->val;
        } else {
            CPREG_FIELD32(env, ri) = cp->val;
        }
    }

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUARMState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->regs[regid - UC_ARM_REG_R0];
    } else if (regid >= UC_ARM_REG_Q0 && regid <= UC_ARM_REG_Q15) {
        CHECK_REG_TYPE(uint64_t[2]);
        uint32_t reg_index = regid - UC_ARM_REG_Q0;
        *(uint64_t *)value = env->vfp.zregs[reg_index].d[0];
        *(((uint64_t *)value) + 1) = env->vfp.zregs[reg_index].d[1];
    } else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31) {
        CHECK_REG_TYPE(uint64_t);
        uint32_t reg_index = regid - UC_ARM_REG_D0;
        *(uint64_t *)value = env->vfp.zregs[reg_index / 2].d[reg_index & 1];
    } else if (regid >= UC_ARM_REG_S0 && regid <= UC_ARM_REG_S31) {
        CHECK_REG_TYPE(uint32_t);
        uint32_t reg_index = regid - UC_ARM_REG_S0;
        uint64_t reg_value = env->vfp.zregs[reg_index / 4].d[reg_index % 4 / 2];

        if (reg_index % 2 == 0) {
            *(uint32_t *)value = (uint32_t)(reg_value & 0xffffffff);
        } else {
            *(uint32_t *)value = (uint32_t)(reg_value >> 32);
        }
    } else {
        switch (regid) {
        case UC_ARM_REG_APSR:
            if (arm_feature(env, ARM_FEATURE_M)) {
                CHECK_REG_TYPE(int32_t);
                *(int32_t *)value = v7m_mrs_xpsr(env, 0);
            } else {
                CHECK_REG_TYPE(int32_t);
                *(int32_t *)value =
                    cpsr_read(env) & (CPSR_NZCV | CPSR_Q | CPSR_GE);
            }
            break;
        case UC_ARM_REG_APSR_NZCV:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = cpsr_read(env) & CPSR_NZCV;
            break;
        case UC_ARM_REG_CPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = cpsr_read(env);
            break;
        case UC_ARM_REG_SPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->spsr;
            break;
        // case UC_ARM_REG_SP:
        case UC_ARM_REG_R13:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->regs[13];
            break;
        // case UC_ARM_REG_LR:
        case UC_ARM_REG_R14:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->regs[14];
            break;
        // case UC_ARM_REG_PC:
        case UC_ARM_REG_R15:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->regs[15];
            break;
        case UC_ARM_REG_C1_C0_2:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->cp15.cpacr_el1;
            break;
        case UC_ARM_REG_C13_C0_3:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->cp15.tpidrro_el[0];
            break;
        case UC_ARM_REG_FPEXC:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->vfp.xregs[ARM_VFP_FPEXC];
            break;
        case UC_ARM_REG_FPSCR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = vfp_get_fpscr(env);
            break;
        case UC_ARM_REG_FPSID:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = env->vfp.xregs[ARM_VFP_FPSID];
            break;
        case UC_ARM_REG_IPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = v7m_mrs_xpsr(env, 5);
            break;
        case UC_ARM_REG_MSP:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 8);
            break;
        case UC_ARM_REG_PSP:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 9);
            break;
        case UC_ARM_REG_IAPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = v7m_mrs_xpsr(env, 1);
            break;
        case UC_ARM_REG_EAPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = v7m_mrs_xpsr(env, 2);
            break;
        case UC_ARM_REG_XPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = v7m_mrs_xpsr(env, 3);
            break;
        case UC_ARM_REG_EPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = v7m_mrs_xpsr(env, 6);
            break;
        case UC_ARM_REG_IEPSR:
            CHECK_REG_TYPE(int32_t);
            *(int32_t *)value = v7m_mrs_xpsr(env, 7);
            break;
        case UC_ARM_REG_PRIMASK:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 16);
            break;
        case UC_ARM_REG_BASEPRI:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 17);
            break;
        case UC_ARM_REG_BASEPRI_MAX:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 18);
            break;
        case UC_ARM_REG_FAULTMASK:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 19);
            break;
        case UC_ARM_REG_CONTROL:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = helper_v7m_mrs(env, 20);
            break;
        case UC_ARM_REG_CP_REG:
            CHECK_REG_TYPE(uc_arm_cp_reg);
            ret = read_cp_reg(env, (uc_arm_cp_reg *)value);
            break;
        }
    }

    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUARMState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12) {
        CHECK_REG_TYPE(uint32_t);
        env->regs[regid - UC_ARM_REG_R0] = *(uint32_t *)value;
    } else if (regid >= UC_ARM_REG_Q0 && regid <= UC_ARM_REG_Q15) {
        CHECK_REG_TYPE(uint64_t[2]);
        uint32_t reg_index = regid - UC_ARM_REG_Q0;
        env->vfp.zregs[reg_index].d[0] = *(uint64_t *)value;
        env->vfp.zregs[reg_index].d[1] = *(((uint64_t *)value) + 1);
    } else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31) {
        CHECK_REG_TYPE(uint64_t);
        uint32_t reg_index = regid - UC_ARM_REG_D0;
        env->vfp.zregs[reg_index / 2].d[reg_index & 1] = *(uint64_t *)value;
    } else if (regid >= UC_ARM_REG_S0 && regid <= UC_ARM_REG_S31) {
        CHECK_REG_TYPE(uint32_t);
        uint32_t reg_index = regid - UC_ARM_REG_S0;
        uint64_t *p_reg_value =
            &env->vfp.zregs[reg_index / 4].d[reg_index % 4 / 2];
        uint64_t in_value = *((uint32_t *)value);
        if (reg_index % 2 == 0) {
            in_value |= *p_reg_value & 0xffffffff00000000ul;
        } else {
            in_value = (in_value << 32) | (*p_reg_value & 0xfffffffful);
        }

        *p_reg_value = in_value;
    } else {
        switch (regid) {
        case UC_ARM_REG_APSR:
            CHECK_REG_TYPE(uint32_t);
            if (!arm_feature(env, ARM_FEATURE_M)) {
                cpsr_write(env, *(uint32_t *)value,
                           (CPSR_NZCV | CPSR_Q | CPSR_GE), CPSRWriteByUnicorn);
                arm_rebuild_hflags(env);
            } else {
                // Same with UC_ARM_REG_APSR_NZCVQ
                v7m_msr_xpsr(env, 0b1000, 0, *(uint32_t *)value);
            }
            break;
        case UC_ARM_REG_APSR_NZCV:
            CHECK_REG_TYPE(uint32_t);
            cpsr_write(env, *(uint32_t *)value, CPSR_NZCV, CPSRWriteByUnicorn);
            arm_rebuild_hflags(env);
            break;
        case UC_ARM_REG_CPSR:
            CHECK_REG_TYPE(uint32_t);
            cpsr_write(env, *(uint32_t *)value, ~0, CPSRWriteByUnicorn);
            arm_rebuild_hflags(env);
            break;
        case UC_ARM_REG_SPSR:
            CHECK_REG_TYPE(uint32_t);
            env->spsr = *(uint32_t *)value;
            break;
        // case UC_ARM_REG_SP:
        case UC_ARM_REG_R13:
            CHECK_REG_TYPE(uint32_t);
            env->regs[13] = *(uint32_t *)value;
            break;
        // case UC_ARM_REG_LR:
        case UC_ARM_REG_R14:
            CHECK_REG_TYPE(uint32_t);
            env->regs[14] = *(uint32_t *)value;
            break;
        // case UC_ARM_REG_PC:
        case UC_ARM_REG_R15:
            CHECK_REG_TYPE(uint32_t);
            env->pc = (*(uint32_t *)value & ~1);
            env->thumb = (*(uint32_t *)value & 1);
            env->uc->thumb = (*(uint32_t *)value & 1);
            env->regs[15] = (*(uint32_t *)value & ~1);
            *setpc = 1;
            break;
            // case UC_ARM_REG_C1_C0_2:
            //     env->cp15.c1_coproc = *(int32_t *)value;
            //     break;

        case UC_ARM_REG_C13_C0_3:
            CHECK_REG_TYPE(int32_t);
            env->cp15.tpidrro_el[0] = *(int32_t *)value;
            break;
        case UC_ARM_REG_FPEXC:
            CHECK_REG_TYPE(int32_t);
            env->vfp.xregs[ARM_VFP_FPEXC] = *(int32_t *)value;
            break;
        case UC_ARM_REG_FPSCR:
            CHECK_REG_TYPE(int32_t);
            vfp_set_fpscr(env, *(int32_t *)value);
            break;
        case UC_ARM_REG_FPSID:
            CHECK_REG_TYPE(int32_t);
            env->vfp.xregs[ARM_VFP_FPSID] = *(int32_t *)value;
            break;
        case UC_ARM_REG_IPSR:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 5, *(uint32_t *)value);
            break;
        case UC_ARM_REG_MSP:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 8, *(uint32_t *)value);
            break;
        case UC_ARM_REG_PSP:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 9, *(uint32_t *)value);
            break;
        case UC_ARM_REG_CONTROL:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 20, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EPSR:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 6, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IEPSR:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 7, *(uint32_t *)value);
            break;
        case UC_ARM_REG_PRIMASK:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 16, *(uint32_t *)value);
            break;
        case UC_ARM_REG_BASEPRI:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 17, *(uint32_t *)value);
            break;
        case UC_ARM_REG_BASEPRI_MAX:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 18, *(uint32_t *)value);
            break;
        case UC_ARM_REG_FAULTMASK:
            CHECK_REG_TYPE(uint32_t);
            helper_v7m_msr(env, 19, *(uint32_t *)value);
            break;
        case UC_ARM_REG_APSR_NZCVQ:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 0, *(uint32_t *)value);
            break;
        case UC_ARM_REG_APSR_G:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b0100, 0, *(uint32_t *)value);
            break;
        case UC_ARM_REG_APSR_NZCVQG:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1100, 0, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IAPSR:
        case UC_ARM_REG_IAPSR_NZCVQ:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 1, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IAPSR_G:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b0100, 1, *(uint32_t *)value);
            break;
        case UC_ARM_REG_IAPSR_NZCVQG:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1100, 1, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EAPSR:
        case UC_ARM_REG_EAPSR_NZCVQ:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 2, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EAPSR_G:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b0100, 2, *(uint32_t *)value);
            break;
        case UC_ARM_REG_EAPSR_NZCVQG:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1100, 2, *(uint32_t *)value);
            break;
        case UC_ARM_REG_XPSR:
        case UC_ARM_REG_XPSR_NZCVQ:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1000, 3, *(uint32_t *)value);
            break;
        case UC_ARM_REG_XPSR_G:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b0100, 3, *(uint32_t *)value);
            break;
        case UC_ARM_REG_XPSR_NZCVQG:
            CHECK_REG_TYPE(uint32_t);
            v7m_msr_xpsr(env, 0b1100, 3, *(uint32_t *)value);
            break;
        case UC_ARM_REG_CP_REG:
            CHECK_REG_TYPE(uc_arm_cp_reg);
            ret = write_cp_reg(env, (uc_arm_cp_reg *)value);
            arm_rebuild_hflags_arm(env);
            break;
        }
    }

    return ret;
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

static size_t uc_arm_context_size(struct uc_struct *uc)
{
    size_t ret = offsetof(CPUARMState, cpu_watchpoint);
    ARMCPU *cpu = (ARMCPU *)uc->cpu;
    CPUARMState *env = (CPUARMState *)&cpu->env;
    uint32_t nr;

#define ARM_ENV_CHECK(field)                                                   \
    if (field) {                                                               \
        ret += sizeof(uint32_t) * (nr + 1);                                    \
    } else {                                                                   \
        ret += sizeof(uint32_t);                                               \
    }

    // /* PMSAv7 MPU */
    // struct {
    //     uint32_t *drbar;
    //     uint32_t *drsr;
    //     uint32_t *dracr;
    //     uint32_t rnr[M_REG_NUM_BANKS];
    // } pmsav7;
    // /* PMSAv8 MPU */
    // struct {
    //     /* The PMSAv8 implementation also shares some PMSAv7 config
    //      * and state:
    //      *  pmsav7.rnr (region number register)
    //      *  pmsav7_dregion (number of configured regions)
    //      */
    //     uint32_t *rbar[M_REG_NUM_BANKS];
    //     uint32_t *rlar[M_REG_NUM_BANKS];
    //     uint32_t mair0[M_REG_NUM_BANKS];
    //     uint32_t mair1[M_REG_NUM_BANKS];
    // } pmsav8;
    nr = cpu->pmsav7_dregion;
    ARM_ENV_CHECK(env->pmsav7.drbar)
    ARM_ENV_CHECK(env->pmsav7.drsr)
    ARM_ENV_CHECK(env->pmsav7.dracr)
    ARM_ENV_CHECK(env->pmsav8.rbar[M_REG_NS])
    ARM_ENV_CHECK(env->pmsav8.rbar[M_REG_S])
    ARM_ENV_CHECK(env->pmsav8.rlar[M_REG_NS])
    ARM_ENV_CHECK(env->pmsav8.rlar[M_REG_S])

    // /* v8M SAU */
    // struct {
    //     uint32_t *rbar;
    //     uint32_t *rlar;
    //     uint32_t rnr;
    //     uint32_t ctrl;
    // } sau;
    nr = cpu->sau_sregion;
    ARM_ENV_CHECK(env->sau.rbar)
    ARM_ENV_CHECK(env->sau.rlar)
#undef ARM_ENV_CHECK
    // These fields are never used:
    // void *nvic;
    // const struct arm_boot_info *boot_info;
    // void *gicv3state;
    return ret;
}

static uc_err uc_arm_context_save(struct uc_struct *uc, uc_context *context)
{
    char *p = NULL;
    ARMCPU *cpu = (ARMCPU *)uc->cpu;
    CPUARMState *env = (CPUARMState *)&cpu->env;
    uint32_t nr = 0;

#define ARM_ENV_SAVE(field)                                                    \
    if (!field) {                                                              \
        *(uint32_t *)p = 0;                                                    \
        p += sizeof(uint32_t);                                                 \
    } else {                                                                   \
        *(uint32_t *)p = nr;                                                   \
        p += sizeof(uint32_t);                                                 \
        memcpy(p, (void *)field, sizeof(uint32_t) * nr);                       \
        p += sizeof(uint32_t) * nr;                                            \
    }
    p = context->data;
    memcpy(p, uc->cpu->env_ptr, uc->cpu_context_size);
    p += uc->cpu_context_size;

    nr = cpu->pmsav7_dregion;
    ARM_ENV_SAVE(env->pmsav7.drbar)
    ARM_ENV_SAVE(env->pmsav7.drsr)
    ARM_ENV_SAVE(env->pmsav7.dracr)
    ARM_ENV_SAVE(env->pmsav8.rbar[M_REG_NS])
    ARM_ENV_SAVE(env->pmsav8.rbar[M_REG_S])
    ARM_ENV_SAVE(env->pmsav8.rlar[M_REG_NS])
    ARM_ENV_SAVE(env->pmsav8.rlar[M_REG_S])

    nr = cpu->sau_sregion;
    ARM_ENV_SAVE(env->sau.rbar)
    ARM_ENV_SAVE(env->sau.rlar)

#undef ARM_ENV_SAVE
    return UC_ERR_OK;
}

static uc_err uc_arm_context_restore(struct uc_struct *uc, uc_context *context)
{
    char *p = NULL;
    ARMCPU *cpu = (ARMCPU *)uc->cpu;
    CPUARMState *env = (CPUARMState *)&cpu->env;
    uint32_t nr, ctx_nr;

#define ARM_ENV_RESTORE(field)                                                 \
    ctx_nr = *(uint32_t *)p;                                                   \
    if (ctx_nr != 0) {                                                         \
        p += sizeof(uint32_t);                                                 \
        if (field && ctx_nr == nr) {                                           \
            memcpy(field, p, sizeof(uint32_t) * ctx_nr);                       \
        }                                                                      \
        p += sizeof(uint32_t) * ctx_nr;                                        \
    } else {                                                                   \
        p += sizeof(uint32_t);                                                 \
    }

    p = context->data;
    memcpy(uc->cpu->env_ptr, p, uc->cpu_context_size);
    p += uc->cpu_context_size;

    nr = cpu->pmsav7_dregion;
    ARM_ENV_RESTORE(env->pmsav7.drbar)
    ARM_ENV_RESTORE(env->pmsav7.drsr)
    ARM_ENV_RESTORE(env->pmsav7.dracr)
    ARM_ENV_RESTORE(env->pmsav8.rbar[M_REG_NS])
    ARM_ENV_RESTORE(env->pmsav8.rbar[M_REG_S])
    ARM_ENV_RESTORE(env->pmsav8.rlar[M_REG_NS])
    ARM_ENV_RESTORE(env->pmsav8.rlar[M_REG_S])

    nr = cpu->sau_sregion;
    ARM_ENV_RESTORE(env->sau.rbar)
    ARM_ENV_RESTORE(env->sau.rlar)

#undef ARM_ENV_RESTORE

    return UC_ERR_OK;
}

DEFAULT_VISIBILITY
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->set_pc = arm_set_pc;
    uc->get_pc = arm_get_pc;
    uc->stop_interrupt = arm_stop_interrupt;
    uc->release = arm_release;
    uc->query = arm_query;
    uc->cpus_init = arm_cpus_init;
    uc->opcode_hook_invalidate = arm_opcode_hook_invalidate;
    uc->cpu_context_size = offsetof(CPUARMState, cpu_watchpoint);
    uc->context_size = uc_arm_context_size;
    uc->context_save = uc_arm_context_save;
    uc->context_restore = uc_arm_context_restore;
    uc_common_init(uc);
}
