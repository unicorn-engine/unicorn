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


static void arm_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
    ((CPUARMState *)uc->current_cpu->env_ptr)->regs[15] = address;
}

void arm_reg_reset(uch handle)
{
    struct uc_struct *uc = (struct uc_struct *) handle;
    CPUArchState *env;

    env = first_cpu->env_ptr;
    memset(env->regs, 0, sizeof(env->regs));

    env->pc = 0;
}

int arm_reg_read(uch handle, unsigned int regid, void *value)
{
    CPUState *mycpu;
    struct uc_struct *uc = (struct uc_struct *) handle;

    mycpu = first_cpu;

    switch(uc->mode) {
        default:
            break;
        case UC_MODE_ARM:
        case UC_MODE_THUMB:
            if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
                *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0];
            else {
                switch(regid) {
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
            break;
    }


    return 0;
}

#define WRITE_DWORD(x, w) (x = (x & ~0xffffffff) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | (b & 0xff))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))

int arm_reg_write(uch handle, unsigned int regid, const void *value)
{
    CPUState *mycpu;
    struct uc_struct *uc = (struct uc_struct *) handle;

    mycpu = first_cpu;

    switch(uc->mode) {
        default:
            break;

        case UC_MODE_ARM:
        case UC_MODE_THUMB:
            if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
                ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0] = *(int32_t *)value;
            else {
                switch(regid) {
                    //case UC_ARM_REG_SP:
                    case UC_ARM_REG_R13:
                        ARM_CPU(uc, mycpu)->env.regs[13] = *(int32_t *)value;
                        break;
                    //case UC_ARM_REG_LR:
                    case UC_ARM_REG_R14:
                        ARM_CPU(uc, mycpu)->env.regs[14] = *(int32_t *)value;
                        break;
                    //case UC_ARM_REG_PC:
                    case UC_ARM_REG_R15:
                        ARM_CPU(uc, mycpu)->env.regs[15] = *(int32_t *)value;
                        break;
                }
            }
            break;
    }

    return 0;
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
    uc_common_init(uc);
}
