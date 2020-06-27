/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


const int M68K_REGS_STORAGE_SIZE = offsetof(CPUM68KState, tlb_table);

static void m68k_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUM68KState *)uc->cpu->env_ptr)->pc = address;
}

static void m68k_release(void* ctx)
{
    TCGContext *tcg_ctx;
    int i;
    
    release_common(ctx);
    tcg_ctx = (TCGContext *) ctx;
    g_free(tcg_ctx->tb_ctx.tbs);
    g_free(tcg_ctx->QREG_PC);
    g_free(tcg_ctx->QREG_SR);
    g_free(tcg_ctx->QREG_CC_OP);
    g_free(tcg_ctx->QREG_CC_DEST);
    g_free(tcg_ctx->QREG_CC_SRC);
    g_free(tcg_ctx->QREG_CC_X);
    g_free(tcg_ctx->QREG_DIV1);
    g_free(tcg_ctx->QREG_DIV2);
    g_free(tcg_ctx->QREG_MACSR);
    g_free(tcg_ctx->QREG_MAC_MASK);
    for (i = 0; i < 8; i++) {
        g_free(tcg_ctx->cpu_dregs[i]);
        g_free(tcg_ctx->cpu_aregs[i]);
    }
    g_free(tcg_ctx->NULL_QREG);
    g_free(tcg_ctx->store_dummy); 
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
    CPUState *mycpu = uc->cpu;
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

static int m68k_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    M68kCPU *cpu;

    cpu = cpu_m68k_init(uc, cpu_model);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void m68k_uc_init(struct uc_struct* uc)
{
    uc->release = m68k_release;
    uc->reg_read = m68k_reg_read;
    uc->reg_write = m68k_reg_write;
    uc->reg_reset = m68k_reg_reset;
    uc->set_pc = m68k_set_pc;
    uc->cpus_init = m68k_cpus_init;
    uc_common_init(uc);
}
