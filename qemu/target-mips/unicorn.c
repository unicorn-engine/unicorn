/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/mips/mips.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"

#ifdef TARGET_MIPS64
const int MIPS64_REGS_STORAGE_SIZE = offsetof(CPUMIPSState, tlb_table);
#else // MIPS32
const int MIPS_REGS_STORAGE_SIZE = offsetof(CPUMIPSState, tlb_table);
#endif

#ifdef TARGET_MIPS64
typedef uint64_t mipsreg_t;
#else
typedef uint32_t mipsreg_t;
#endif

static uint64_t mips_mem_redirect(uint64_t address)
{
    // kseg0 range masks off high address bit
    if (address >= 0x80000000 && address <= 0x9fffffff)
        return address & 0x7fffffff;

    // kseg1 range masks off top 3 address bits
    if (address >= 0xa0000000 && address <= 0xbfffffff) {
        return address & 0x1fffffff;
    }

    // no redirect
    return address;
}

static void mips_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUMIPSState *)uc->current_cpu->env_ptr)->active_tc.PC = address;
}


void mips_release(void *ctx);
void mips_release(void *ctx)
{
    MIPSCPU* cpu;
    int i;
    TCGContext *tcg_ctx = (TCGContext *) ctx;
    release_common(ctx);
    cpu = MIPS_CPU(tcg_ctx->uc, tcg_ctx->uc->cpu);
    g_free(cpu->env.tlb);
    g_free(cpu->env.mvp);

    for (i = 0; i < MIPS_DSP_ACC; i++) {
        g_free(tcg_ctx->cpu_HI[i]);
        g_free(tcg_ctx->cpu_LO[i]);
    }

    for (i = 0; i < 32; i++) {
        g_free(tcg_ctx->cpu_gpr[i]);
    }

    g_free(tcg_ctx->cpu_PC);
    g_free(tcg_ctx->btarget);
    g_free(tcg_ctx->bcond);
    g_free(tcg_ctx->cpu_dspctrl);

    g_free(tcg_ctx->tb_ctx.tbs);
}

void mips_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    (void)uc;
    env = uc->cpu->env_ptr;
    memset(env->active_tc.gpr, 0, sizeof(env->active_tc.gpr));

    env->active_tc.PC = 0;
}

int mips_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_MIPS_REG_0 && regid <= UC_MIPS_REG_31)
            *(mipsreg_t *)value = MIPS_CPU(uc, mycpu)->env.active_tc.gpr[regid - UC_MIPS_REG_0];
        else {
            switch(regid) {
                default: break;
                case UC_MIPS_REG_PC:
                         *(mipsreg_t *)value = MIPS_CPU(uc, mycpu)->env.active_tc.PC;
                         break;
                case UC_MIPS_REG_CP0_CONFIG3:
                         *(mipsreg_t *)value = MIPS_CPU(uc, mycpu)->env.CP0_Config3;
                         break;
                case UC_MIPS_REG_CP0_USERLOCAL:
                         *(mipsreg_t *)value = MIPS_CPU(uc, mycpu)->env.active_tc.CP0_UserLocal;
                         break;                              
            }
        }
    }

    return 0;
}

int mips_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_MIPS_REG_0 && regid <= UC_MIPS_REG_31)
            MIPS_CPU(uc, mycpu)->env.active_tc.gpr[regid - UC_MIPS_REG_0] = *(mipsreg_t *)value;
        else {
            switch(regid) {
                default: break;
                case UC_MIPS_REG_PC:
                         MIPS_CPU(uc, mycpu)->env.active_tc.PC = *(mipsreg_t *)value;
                         // force to quit execution and flush TB
                         uc->quit_request = true;
                         uc_emu_stop(uc);
                         break;
                case UC_MIPS_REG_CP0_CONFIG3:
                         MIPS_CPU(uc, mycpu)->env.CP0_Config3 = *(mipsreg_t *)value;
                         break;
                case UC_MIPS_REG_CP0_USERLOCAL:
                         MIPS_CPU(uc, mycpu)->env.active_tc.CP0_UserLocal = *(mipsreg_t *)value;
                         break;                         
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_MIPS64
#ifdef TARGET_WORDS_BIGENDIAN
  void mips64_uc_init(struct uc_struct* uc)
#else
  void mips64el_uc_init(struct uc_struct* uc)
#endif
#else // if TARGET_MIPS
#ifdef TARGET_WORDS_BIGENDIAN
  void mips_uc_init(struct uc_struct* uc)
#else
  void mipsel_uc_init(struct uc_struct* uc)
#endif
#endif
{
    register_accel_types(uc);
    mips_cpu_register_types(uc);
    mips_machine_init(uc);
    uc->reg_read = mips_reg_read;
    uc->reg_write = mips_reg_write;
    uc->reg_reset = mips_reg_reset;
    uc->release = mips_release;
    uc->set_pc = mips_set_pc;
    uc->mem_redirect = mips_mem_redirect;
    uc_common_init(uc);
}
