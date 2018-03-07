/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "hw/boards.h"
#include "hw/m68k/m68k.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "unicorn_common.h"
#include "uc_priv.h"

const int M68K_REGS_STORAGE_SIZE = offsetof(CPUM68KState, tlb_table);

static void m68k_set_pc(struct uc_struct *uc, uint64_t address)
{
    CPUM68KState *state = uc->cpu->env_ptr;

    state->pc = address;
}

void m68k_release(void* ctx);
void m68k_release(void* ctx)
{
    TCGContext *tcg_ctx = ctx;;

    release_common(ctx);
    g_free(tcg_ctx->tb_ctx.tbs);
}

void m68k_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->aregs, 0, sizeof(env->aregs));
    memset(env->dregs, 0, sizeof(env->dregs));

    env->pc = 0;
}

int m68k_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    CPUM68KState *state = &M68K_CPU(uc, mycpu)->env;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
            *(int32_t *)value = state->aregs[regid - UC_M68K_REG_A0];
        else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
            *(int32_t *)value = state->dregs[regid - UC_M68K_REG_D0];
        else {
            switch(regid) {
                default: break;
                case UC_M68K_REG_PC:
                         *(int32_t *)value = state->pc;
                         break;
            }
        }
    }

    return 0;
}

int m68k_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = uc->cpu;
    CPUM68KState *state = &M68K_CPU(uc, mycpu)->env;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7)
            state->aregs[regid - UC_M68K_REG_A0] = *(uint32_t *)value;
        else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7)
            state->dregs[regid - UC_M68K_REG_D0] = *(uint32_t *)value;
        else {
            switch(regid) {
                default: break;
                case UC_M68K_REG_PC:
                         state->pc = *(uint32_t *)value;
                         // force to quit execution and flush TB
                         uc->quit_request = true;
                         uc_emu_stop(uc);
                         break;
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
void m68k_uc_init(struct uc_struct* uc)
{
    register_accel_types(uc);
    m68k_cpu_register_types(uc);
    dummy_m68k_machine_init(uc);
    uc->release = m68k_release;
    uc->reg_read = m68k_reg_read;
    uc->reg_write = m68k_reg_write;
    uc->reg_reset = m68k_reg_reset;
    uc->set_pc = m68k_set_pc;
    uc_common_init(uc);
}
