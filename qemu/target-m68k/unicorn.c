/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/m68k/m68k.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


static void m68k_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUM68KState *)uc->current_cpu->env_ptr)->pc = address;
}

void m68k_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = first_cpu->env_ptr;

    memset(env->aregs, 0, sizeof(env->aregs));
    memset(env->dregs, 0, sizeof(env->dregs));

    env->pc = 0;
}

int m68k_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = first_cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
            *(int32_t *)value = M68K_CPU(uc, mycpu)->env.aregs[regid - UC_M68K_REG_A0];
        else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
            *(int32_t *)value = M68K_CPU(uc, mycpu)->env.dregs[regid - UC_M68K_REG_D0];
        else {
            switch(regid) {
                default: break;
                case UC_M68K_REG_PC:
                         *(int32_t *)value = M68K_CPU(uc, mycpu)->env.pc;
                         break;
            }
        }
    }

    return 0;
}

int m68k_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = first_cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
            M68K_CPU(uc, mycpu)->env.aregs[regid - UC_M68K_REG_A0] = *(uint32_t *)value;
        else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
            M68K_CPU(uc, mycpu)->env.dregs[regid - UC_M68K_REG_D0] = *(uint32_t *)value;
        else {
            switch(regid) {
                default: break;
                case UC_M68K_REG_PC:
                         M68K_CPU(uc, mycpu)->env.pc = *(uint32_t *)value;
                         // force to quit execution and flush TB
                         uc->quit_request = true;
                         uc_emu_stop(uc);
                         break;
            }
        }
    }

    return 0;
}

__attribute__ ((visibility ("default")))
void m68k_uc_init(struct uc_struct* uc)
{
    register_accel_types(uc);
    m68k_cpu_register_types(uc);
    dummy_m68k_machine_init(uc);
    uc->reg_read = m68k_reg_read;
    uc->reg_write = m68k_reg_write;
    uc->reg_reset = m68k_reg_reset;
    uc->set_pc = m68k_set_pc;
    uc_common_init(uc);
}
