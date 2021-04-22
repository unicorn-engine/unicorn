/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"

const int ARM_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

static void arm_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
    ((CPUARMState *)uc->current_cpu->env_ptr)->regs[15] = address;
}

void arm_release(void* ctx);

void arm_release(void* ctx)
{
    ARMCPU* cpu;
    struct uc_struct* uc;
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

int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu;
    int i;

    mycpu = uc->cpu;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
            *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0];
        else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31)
            *(float64 *)value = ARM_CPU(uc, mycpu)->env.vfp.regs[regid - UC_ARM_REG_D0];
        else {
            switch(regid) {
                case UC_ARM_REG_APSR:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env) & (CPSR_NZCV | CPSR_Q | CPSR_GE);
                    break;
                case UC_ARM_REG_APSR_NZCV:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env) & CPSR_NZCV;
                    break;
                case UC_ARM_REG_CPSR:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env);
                    break;
                case UC_ARM_REG_SPSR:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.spsr;
                    break;
                //case UC_ARM_REG_SP:
                case UC_ARM_REG_R13:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[13];
                    break;
                //case UC_ARM_REG_LR:
                case UC_ARM_REG_R14:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[14];
                    break;
                //case UC_ARM_REG_PC:
                case UC_ARM_REG_R15:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[15];
                    break;
                case UC_ARM_REG_C1_C0_2:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.cp15.c1_coproc;
                    break;
                case UC_ARM_REG_C13_C0_3:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.cp15.tpidrro_el0;
                    break;
                case UC_ARM_REG_FPEXC:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.vfp.xregs[ARM_VFP_FPEXC];
                    break;
                case UC_ARM_REG_IPSR:
                    *(uint32_t *)value = xpsr_read(&ARM_CPU(uc, mycpu)->env) & 0x1ff;
                    break;
                case UC_ARM_REG_MSP:
                    *(uint32_t *)value = helper_v7m_mrs(&ARM_CPU(uc, mycpu)->env, 8);
                    break;
                case UC_ARM_REG_PSP:
                    *(uint32_t *)value = helper_v7m_mrs(&ARM_CPU(uc, mycpu)->env, 9);
                    break;
                 case UC_ARM_REG_CONTROL:
                    *(uint32_t *)value = helper_v7m_mrs(&ARM_CPU(uc, mycpu)->env, 20);
                    break; 
            }
        }
    }

    return 0;
}

int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
            ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0] = *(uint32_t *)value;
        else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31)
            ARM_CPU(uc, mycpu)->env.vfp.regs[regid - UC_ARM_REG_D0] = *(float64 *)value;
        else {
            switch(regid) {
                case UC_ARM_REG_APSR:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, (CPSR_NZCV | CPSR_Q | CPSR_GE));
                    break;
                case UC_ARM_REG_APSR_NZCV:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, CPSR_NZCV);
                    break;
                case UC_ARM_REG_CPSR:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, ~0);
                    break;
                case UC_ARM_REG_SPSR:
                    ARM_CPU(uc, mycpu)->env.spsr = *(uint32_t *)value;
                    break;
                //case UC_ARM_REG_SP:
                case UC_ARM_REG_R13:
                    ARM_CPU(uc, mycpu)->env.regs[13] = *(uint32_t *)value;
                    break;
                //case UC_ARM_REG_LR:
                case UC_ARM_REG_R14:
                    ARM_CPU(uc, mycpu)->env.regs[14] = *(uint32_t *)value;
                    break;
                //case UC_ARM_REG_PC:
                case UC_ARM_REG_R15:
                    ARM_CPU(uc, mycpu)->env.pc = (*(uint32_t *)value & ~1);
                    ARM_CPU(uc, mycpu)->env.thumb = (*(uint32_t *)value & 1);
                    ARM_CPU(uc, mycpu)->env.uc->thumb = (*(uint32_t *)value & 1);
                    ARM_CPU(uc, mycpu)->env.regs[15] = (*(uint32_t *)value & ~1);
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);

                    break;
                case UC_ARM_REG_C1_C0_2:
                    ARM_CPU(uc, mycpu)->env.cp15.c1_coproc = *(int32_t *)value;
                    break;

                case UC_ARM_REG_C13_C0_3:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidrro_el0 = *(int32_t *)value;
                    break;
                case UC_ARM_REG_FPEXC:
                    ARM_CPU(uc, mycpu)->env.vfp.xregs[ARM_VFP_FPEXC] = *(int32_t *)value;
                    break;
                case UC_ARM_REG_IPSR:
                    xpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, 0x1ff);
                    break;
                case UC_ARM_REG_MSP:
                    helper_v7m_msr(&ARM_CPU(uc, mycpu)->env, 8, *(uint32_t *)value);
                    break;
                case UC_ARM_REG_PSP:
                    helper_v7m_msr(&ARM_CPU(uc, mycpu)->env, 9, *(uint32_t *)value);
                    break;
                 case UC_ARM_REG_CONTROL:
                    helper_v7m_msr(&ARM_CPU(uc, mycpu)->env, 20, *(uint32_t *)value);
                    break;
            }
        }
    }

    return 0;
}

static bool arm_stop_interrupt(int intno)
{
    switch(intno) {
        default:
            return false;
        case EXCP_UDEF:
        case EXCP_YIELD:
            return true;
    }
}

static uc_err arm_query(struct uc_struct *uc, uc_query_type type, size_t *result)
{
    CPUState *mycpu = uc->cpu;
    uint32_t mode;

    switch(type) {
        case UC_QUERY_MODE:
            // zero out ARM/THUMB mode
            mode = uc->mode & ~(UC_MODE_ARM | UC_MODE_THUMB);
            // THUMB mode or ARM MOde
            mode |= ((ARM_CPU(uc, mycpu)->env.thumb != 0)? UC_MODE_THUMB : UC_MODE_ARM);
            *result = mode;
            return UC_ERR_OK;
        default:
            return UC_ERR_ARG;
    }
}

#ifdef TARGET_WORDS_BIGENDIAN
void armeb_uc_init(struct uc_struct* uc)
#else
void arm_uc_init(struct uc_struct* uc)
#endif
{
    register_accel_types(uc);
    arm_cpu_register_types(uc);
    tosa_machine_init(uc);
    uc->reg_read = arm_reg_read;
    uc->reg_write = arm_reg_write;
    uc->reg_reset = arm_reg_reset;
    uc->set_pc = arm_set_pc;
    uc->stop_interrupt = arm_stop_interrupt;
    uc->release = arm_release;
    uc->query = arm_query;
    uc_common_init(uc);
}
