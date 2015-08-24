/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/m68k/m68k.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"

#include "unicorn_common.h"

#define READ_QWORD(x) ((uint64)x)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_WORD(x) (x & 0xffff)
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)


static void m68k_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUM68KState *)uc->current_cpu->env_ptr)->pc = address;
}

void m68k_reg_reset(uch handle)
{
    struct uc_struct *uc = (struct uc_struct *) handle;
    CPUArchState *env;

    env = first_cpu->env_ptr;
    memset(env->aregs, 0, sizeof(env->aregs));
    memset(env->dregs, 0, sizeof(env->dregs));

    env->pc = 0;
}

int m68k_reg_read(uch handle, unsigned int regid, void *value)
{
    struct uc_struct *uc = (struct uc_struct *)handle;
    CPUState *mycpu = first_cpu;

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

    return 0;
}


#define WRITE_DWORD(x, w) (x = (x & ~0xffffffff) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | (b & 0xff))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))

int m68k_reg_write(uch handle, unsigned int regid, void *value)
{
    struct uc_struct *uc = (struct uc_struct *) handle;
    CPUState *mycpu = first_cpu;

    if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
        M68K_CPU(uc, mycpu)->env.aregs[regid - UC_M68K_REG_A0] = *(int32_t *)value;
    else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
        M68K_CPU(uc, mycpu)->env.dregs[regid - UC_M68K_REG_D0] = *(int32_t *)value;
    else {
        switch(regid) {
            default: break;
            case UC_M68K_REG_PC:
                     M68K_CPU(uc, mycpu)->env.pc = *(uint32_t *)value;
                     break;
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
