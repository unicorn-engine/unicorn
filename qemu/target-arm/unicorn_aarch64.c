/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


const int ARM64_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
}

void arm64_release(void* ctx);

void arm64_release(void* ctx)
{
    struct uc_struct* uc;
    ARMCPU* cpu;
    TCGContext *s = (TCGContext *) ctx;

    g_free(s->tb_ctx.tbs);
    uc = s->uc;
    cpu = (ARMCPU*) uc->cpu;
    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);

    release_common(ctx);
}

void arm64_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;
    memset(env->xregs, 0, sizeof(env->xregs));

    env->pc = 0;
}

int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        // V & Q registers are the same
        if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0];
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            *(int32_t *)value = READ_DWORD(ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_W0]);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *dst = (float64*) value;
            uint32_t reg_index = 2*(regid - UC_ARM64_REG_Q0);
            dst[0] = ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index];
            dst[1] = ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index+1];
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            *(float64*)value = ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_D0)];
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            *(int32_t*)value = READ_DWORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_S0)]);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            *(int16_t*)value = READ_WORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_H0)]);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            *(int8_t*)value = READ_BYTE_L(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_B0)]);
        } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
            *(uint64_t*)value = ARM_CPU(uc, mycpu)->env.elr_el[regid - UC_ARM64_REG_ELR_EL0];
        } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
            *(uint64_t*)value = ARM_CPU(uc, mycpu)->env.sp_el[regid - UC_ARM64_REG_SP_EL0];
        } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
            *(uint64_t*)value = ARM_CPU(uc, mycpu)->env.cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0];
        } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
            *(uint64_t*)value = ARM_CPU(uc, mycpu)->env.cp15.far_el[regid - UC_ARM64_REG_FAR_EL0];
        } else if (regid >= UC_ARM64_REG_VBAR_EL0 && regid <= UC_ARM64_REG_VBAR_EL3) {
            *(uint64_t*)value = ARM_CPU(uc, mycpu)->env.cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0];
        } else {
            switch(regid) {
                default: break;
                case UC_ARM64_REG_CPACR_EL1:
                    *(uint32_t *)value = ARM_CPU(uc, mycpu)->env.cp15.c1_coproc;
                    break;
                case UC_ARM64_REG_TPIDR_EL0:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.tpidr_el0;
                    break;
                case UC_ARM64_REG_TPIDRRO_EL0:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.tpidrro_el0;
                    break;
                case UC_ARM64_REG_TPIDR_EL1:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.tpidr_el1;
                    break;
                case UC_ARM64_REG_X29:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[29];
                    break;
                case UC_ARM64_REG_X30:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[30];
                    break;
                case UC_ARM64_REG_PC:
                    *(uint64_t *)value = ARM_CPU(uc, mycpu)->env.pc;
                    break;
                case UC_ARM64_REG_SP:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[31];
                    break;
                case UC_ARM64_REG_NZCV:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env) & CPSR_NZCV;
                    break;
                case UC_ARM64_REG_PSTATE:
                    *(uint32_t *)value = pstate_read(&ARM_CPU(uc, mycpu)->env);
                    break;
                case UC_ARM64_REG_TTBR0_EL1:
                    *(uint64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.ttbr0_el1;
                    break;
                case UC_ARM64_REG_TTBR1_EL1:
                    *(uint64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.ttbr1_el1;
                    break;
                case UC_ARM64_REG_PAR_EL1:
                    *(uint64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.par_el1;
                    break;
                case UC_ARM64_REG_MAIR_EL1:
                    *(uint64_t *)value = ARM_CPU(uc, mycpu)->env.cp15.mair_el1;
                    break;
            }
        }
    }

    return 0;
}

int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            WRITE_DWORD(ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *src = (float64*) value;
            uint32_t reg_index = 2*(regid - UC_ARM64_REG_Q0);
            ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index] = src[0];
            ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index+1] = src[1];
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_D0)] = * (float64*) value;
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            WRITE_DWORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_S0)], *(int32_t*) value);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            WRITE_WORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_H0)], *(int16_t*) value);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            WRITE_BYTE_L(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_B0)], *(int8_t*) value);
        } else if (regid >= UC_ARM64_REG_ELR_EL0 && regid <= UC_ARM64_REG_ELR_EL3) {
            ARM_CPU(uc, mycpu)->env.elr_el[regid - UC_ARM64_REG_ELR_EL0] = *(uint64_t*)value;
        } else if (regid >= UC_ARM64_REG_SP_EL0 && regid <= UC_ARM64_REG_SP_EL3) {
            ARM_CPU(uc, mycpu)->env.sp_el[regid - UC_ARM64_REG_SP_EL0] = *(uint64_t*)value;
        } else if (regid >= UC_ARM64_REG_ESR_EL0 && regid <= UC_ARM64_REG_ESR_EL3) {
            ARM_CPU(uc, mycpu)->env.cp15.esr_el[regid - UC_ARM64_REG_ESR_EL0] = *(uint64_t*)value;
        } else if (regid >= UC_ARM64_REG_FAR_EL0 && regid <= UC_ARM64_REG_FAR_EL3) {
            ARM_CPU(uc, mycpu)->env.cp15.far_el[regid - UC_ARM64_REG_FAR_EL0] = *(uint64_t*)value;
        } else if (regid >= UC_ARM64_REG_VBAR_EL0 && regid <= UC_ARM64_REG_VBAR_EL3) {
            ARM_CPU(uc, mycpu)->env.cp15.vbar_el[regid - UC_ARM64_REG_VBAR_EL0] = *(uint64_t*)value;
        } else {
            switch(regid) {
                default: break;
                case UC_ARM64_REG_CPACR_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.c1_coproc = *(uint32_t *)value;
                    break;
                case UC_ARM64_REG_TPIDR_EL0:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidr_el0 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TPIDRRO_EL0:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidrro_el0 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TPIDR_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidr_el1 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_X29:
                    ARM_CPU(uc, mycpu)->env.xregs[29] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_X30:
                    ARM_CPU(uc, mycpu)->env.xregs[30] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_PC:
                    ARM_CPU(uc, mycpu)->env.pc = *(uint64_t *)value;
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);
                    break;
                case UC_ARM64_REG_SP:
                    ARM_CPU(uc, mycpu)->env.xregs[31] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_NZCV:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, CPSR_NZCV);
                    break;
                case UC_ARM64_REG_PSTATE:
                    pstate_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value);
                    break;
                case UC_ARM64_REG_TTBR0_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.ttbr0_el1 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TTBR1_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.ttbr1_el1 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_PAR_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.par_el1 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_MAIR_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.mair_el1 = *(uint64_t *)value;
                    break;
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
void arm64eb_uc_init(struct uc_struct* uc)
#else
void arm64_uc_init(struct uc_struct* uc)
#endif
{
    register_accel_types(uc);
    arm_cpu_register_types(uc);
    aarch64_cpu_register_types(uc);
    machvirt_machine_init(uc);
    uc->reg_read = arm64_reg_read;
    uc->reg_write = arm64_reg_write;
    uc->reg_reset = arm64_reg_reset;
    uc->set_pc = arm64_set_pc;
    uc->release = arm64_release;
    uc_common_init(uc);
}
