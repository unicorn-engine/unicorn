/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


static void arm_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
    ((CPUARMState *)uc->current_cpu->env_ptr)->regs[15] = address;
}

void arm_release(void* ctx);

void arm_release(void* ctx)
{
    TCGContext *s = (TCGContext *) ctx;

    g_free(s->tb_ctx.tbs);
    struct uc_struct* uc = s->uc;
    ARMCPU* cpu = (ARMCPU*) uc->cpu;
    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);

    release_common(ctx);
}

void arm_reg_reset(struct uc_struct *uc)
{
    (void)uc;
    CPUArchState *env;

    env = first_cpu->env_ptr;
    memset(env->regs, 0, sizeof(env->regs));

    env->pc = 0;
}

int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu;
    int i;

    mycpu = first_cpu;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
            *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0];
        else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31)
            *(float64 *)value = ARM_CPU(uc, mycpu)->env.vfp.regs[regid - UC_ARM_REG_D0];
        else {
            switch(regid) {
                case UC_ARM_REG_CPSR:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env);
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
            }
        }
    }

    return 0;
}

int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = first_cpu;
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
                    ARM_CPU(uc, mycpu)->env.pc = *(uint32_t *)value;
                    ARM_CPU(uc, mycpu)->env.regs[15] = *(uint32_t *)value;
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);

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
    CPUState *mycpu = first_cpu;
    uint32_t mode;

    switch(type) {
        case UC_QUERY_MODE:
            // zero out ARM/THUMB mode
            mode = uc->mode & ~(UC_MODE_ARM | UC_MODE_THUMB);
            // THUMB mode or ARM MOde
            mode += ((ARM_CPU(uc, mycpu)->env.thumb != 0)? UC_MODE_THUMB : UC_MODE_ARM);
            *result = mode;
            return UC_ERR_OK;
        default:
            return UC_ERR_ARG;
    }
}

void arm_uc_init(struct uc_struct* uc)
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
