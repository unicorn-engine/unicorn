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
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0];
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            *(int32_t *)value = READ_DWORD(ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_W0]);
        } else {
            switch(regid) {
                default: break;
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
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            WRITE_DWORD(ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
        } else {
            switch(regid) {
                default: break;
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
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
void arm64_uc_init(struct uc_struct* uc)
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
