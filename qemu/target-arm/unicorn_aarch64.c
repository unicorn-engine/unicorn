/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/arm/arm.h"

#include "sysemu/cpus.h"

#include "unicorn.h"

#include "cpu.h"

#include "unicorn_common.h"


#define READ_QWORD(x) ((uint64)x)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_WORD(x) (x & 0xffff)
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)


static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
}

void arm64_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = first_cpu->env_ptr;
    memset(env->xregs, 0, sizeof(env->xregs));

    env->pc = 0;
}

int arm64_reg_read(struct uc_struct *uc, unsigned int regid, void *value)
{
    CPUState *mycpu = first_cpu;

    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28)
        *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0];
    else {
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

    return 0;
}

#define WRITE_DWORD(x, w) (x = (x & ~0xffffffff) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | ((b & 0xff) << 8))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))

int arm64_reg_write(struct uc_struct *uc, unsigned int regid, const void *value)
{
    CPUState *mycpu = first_cpu;

    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28)
        ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
    else {
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

    return 0;
}

__attribute__ ((visibility ("default")))
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
    uc_common_init(uc);
}
