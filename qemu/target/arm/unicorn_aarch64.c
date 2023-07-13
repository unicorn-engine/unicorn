/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu/typedefs.h"
#include "unicorn/unicorn.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "kvm-consts.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

ARMCPU *cpu_aarch64_init(struct uc_struct *uc);

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->cpu->env_ptr)->pc = address;
}

static uint64_t arm64_get_pc(struct uc_struct *uc)
{
    return ((CPUARMState *)uc->cpu->env_ptr)->pc;
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

static void reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;
    memset(env->xregs, 0, sizeof(env->xregs));

    env->pc = 0;
}

static uc_err read_cp_reg(CPUARMState *env, uc_arm64_cp_reg *cp)
{
    ARMCPU *cpu = ARM_CPU(env->uc->cpu);
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(
        cpu->cp_regs, ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, cp->crn,
                                         cp->crm, cp->op0, cp->op1, cp->op2));

    if (!ri) {
        return UC_ERR_ARG;
    }

    cp->val = read_raw_cp_reg(env, ri);

    return UC_ERR_OK;
}

static uc_err write_cp_reg(CPUARMState *env, uc_arm64_cp_reg *cp)
{
    ARMCPU *cpu = ARM_CPU(env->uc->cpu);
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(
        cpu->cp_regs, ENCODE_AA64_CP_REG(CP_REG_ARM64_SYSREG_CP, cp->crn,
                                         cp->crm, cp->op0, cp->op1, cp->op2));

    if (!ri) {
        return UC_ERR_ARG;
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

    if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
        regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
    }
    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->xregs[regid - UC_ARM64_REG_X0];
    } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = READ_DWORD(env->xregs[regid - UC_ARM64_REG_W0]);
    } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) { // FIXME
        CHECK_REG_TYPE(float64[2]);
        float64 *dst = (float64 *)value;
        uint32_t reg_index = regid - UC_ARM64_REG_Q0;
        dst[0] = env->vfp.zregs[reg_index].d[0];
        dst[1] = env->vfp.zregs[reg_index].d[1];
    } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
        CHECK_REG_TYPE(float64);
        *(float64 *)value = env->vfp.zregs[regid - UC_ARM64_REG_D0].d[0];
    } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
        CHECK_REG_TYPE(int32_t);
        *(int32_t *)value =
            READ_DWORD(env->vfp.zregs[regid - UC_ARM64_REG_S0].d[0]);
    } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
        CHECK_REG_TYPE(int16_t);
        *(int16_t *)value =
            READ_WORD(env->vfp.zregs[regid - UC_ARM64_REG_H0].d[0]);
    } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
        CHECK_REG_TYPE(int8_t);
        *(int8_t *)value =
            READ_BYTE_L(env->vfp.zregs[regid - UC_ARM64_REG_B0].d[0]);
    } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->elr_el[regid - UC_ARM64_REG_ELR_EL0];
    } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->sp_el[regid - UC_ARM64_REG_SP_EL0];
    } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0];
    } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->cp15.far_el[regid - UC_ARM64_REG_FAR_EL0];
    } else if (regid >= UC_ARM64_REG_VBAR_EL0 &&
               regid <= UC_ARM64_REG_VBAR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0];
    } else {
        switch (regid) {
        default:
            break;
        case UC_ARM64_REG_CPACR_EL1:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->cp15.cpacr_el1;
            break;
        case UC_ARM64_REG_TPIDR_EL0:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.tpidr_el[0];
            break;
        case UC_ARM64_REG_TPIDRRO_EL0:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.tpidrro_el[0];
            break;
        case UC_ARM64_REG_TPIDR_EL1:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.tpidr_el[1];
            break;
        case UC_ARM64_REG_X29:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->xregs[29];
            break;
        case UC_ARM64_REG_X30:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->xregs[30];
            break;
        case UC_ARM64_REG_PC:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->pc;
            break;
        case UC_ARM64_REG_SP:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->xregs[31];
            break;
        case UC_ARM64_REG_NZCV:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = cpsr_read(env) & CPSR_NZCV;
            break;
        case UC_ARM64_REG_PSTATE:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = pstate_read(env);
            break;
        case UC_ARM64_REG_TTBR0_EL1:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.ttbr0_el[1];
            break;
        case UC_ARM64_REG_TTBR1_EL1:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.ttbr1_el[1];
            break;
        case UC_ARM64_REG_PAR_EL1:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.par_el[1];
            break;
        case UC_ARM64_REG_MAIR_EL1:
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->cp15.mair_el[1];
            break;
        case UC_ARM64_REG_CP_REG:
            CHECK_REG_TYPE(uc_arm64_cp_reg);
            ret = read_cp_reg(env, (uc_arm64_cp_reg *)value);
            break;
        case UC_ARM64_REG_FPCR:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = vfp_get_fpcr(env);
            break;
        case UC_ARM64_REG_FPSR:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = vfp_get_fpsr(env);
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

    if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
        regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
    }
    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        CHECK_REG_TYPE(uint64_t);
        env->xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
        CHECK_REG_TYPE(uint32_t);
        WRITE_DWORD(env->xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
    } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
        CHECK_REG_TYPE(float64[2]);
        float64 *src = (float64 *)value;
        uint32_t reg_index = regid - UC_ARM64_REG_Q0;
        env->vfp.zregs[reg_index].d[0] = src[0];
        env->vfp.zregs[reg_index].d[1] = src[1];
    } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
        CHECK_REG_TYPE(float64);
        env->vfp.zregs[regid - UC_ARM64_REG_D0].d[0] = *(float64 *)value;
    } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
        CHECK_REG_TYPE(int32_t);
        WRITE_DWORD(env->vfp.zregs[regid - UC_ARM64_REG_S0].d[0],
                    *(int32_t *)value);
    } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
        CHECK_REG_TYPE(int16_t);
        WRITE_WORD(env->vfp.zregs[regid - UC_ARM64_REG_H0].d[0],
                   *(int16_t *)value);
    } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
        CHECK_REG_TYPE(int8_t);
        WRITE_BYTE_L(env->vfp.zregs[regid - UC_ARM64_REG_B0].d[0],
                     *(int8_t *)value);
    } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        env->elr_el[regid - UC_ARM64_REG_ELR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
        CHECK_REG_TYPE(uint64_t);
        env->sp_el[regid - UC_ARM64_REG_SP_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        env->cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        env->cp15.far_el[regid - UC_ARM64_REG_FAR_EL0] = *(uint64_t *)value;
    } else if (regid >= UC_ARM64_REG_VBAR_EL0 &&
               regid <= UC_ARM64_REG_VBAR_EL3) {
        CHECK_REG_TYPE(uint64_t);
        env->cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0] = *(uint64_t *)value;
    } else {
        switch (regid) {
        default:
            break;
        case UC_ARM64_REG_CPACR_EL1:
            CHECK_REG_TYPE(uint32_t);
            env->cp15.cpacr_el1 = *(uint32_t *)value;
            break;
        case UC_ARM64_REG_TPIDR_EL0:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.tpidr_el[0] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TPIDRRO_EL0:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.tpidrro_el[0] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TPIDR_EL1:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.tpidr_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_X29:
            CHECK_REG_TYPE(uint64_t);
            env->xregs[29] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_X30:
            CHECK_REG_TYPE(uint64_t);
            env->xregs[30] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_PC:
            CHECK_REG_TYPE(uint64_t);
            env->pc = *(uint64_t *)value;
            *setpc = 1;
            break;
        case UC_ARM64_REG_SP:
            CHECK_REG_TYPE(uint64_t);
            env->xregs[31] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_NZCV:
            CHECK_REG_TYPE(uint32_t);
            cpsr_write(env, *(uint32_t *)value, CPSR_NZCV, CPSRWriteRaw);
            break;
        case UC_ARM64_REG_PSTATE:
            CHECK_REG_TYPE(uint32_t);
            pstate_write(env, *(uint32_t *)value);
            break;
        case UC_ARM64_REG_TTBR0_EL1:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.ttbr0_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_TTBR1_EL1:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.ttbr1_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_PAR_EL1:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.par_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_MAIR_EL1:
            CHECK_REG_TYPE(uint64_t);
            env->cp15.mair_el[1] = *(uint64_t *)value;
            break;
        case UC_ARM64_REG_CP_REG:
            CHECK_REG_TYPE(uc_arm64_cp_reg);
            ret = write_cp_reg(env, (uc_arm64_cp_reg *)value);
            arm_rebuild_hflags(env);
            break;
        case UC_ARM64_REG_FPCR:
            CHECK_REG_TYPE(uint32_t);
            vfp_set_fpcr(env, *(uint32_t *)value);
            break;
        case UC_ARM64_REG_FPSR:
            CHECK_REG_TYPE(uint32_t);
            vfp_set_fpsr(env, *(uint32_t *)value);
            break;
        }
    }

    return ret;
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
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->set_pc = arm64_set_pc;
    uc->get_pc = arm64_get_pc;
    uc->release = arm64_release;
    uc->cpus_init = arm64_cpus_init;
    uc->cpu_context_size = offsetof(CPUARMState, cpu_watchpoint);
    uc_common_init(uc);
}
