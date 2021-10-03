/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "uc_priv.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "cpu_bits.h"
#include <unicorn/riscv.h>
#include "unicorn.h"

RISCVCPU *cpu_riscv_init(struct uc_struct *uc, const char *cpu_model);

static void riscv_set_pc(struct uc_struct *uc, uint64_t address)
{
    RISCV_CPU(uc->cpu)->env.pc = address;
}

static void riscv_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    RISCVCPU *cpu = (RISCVCPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }
}

void riscv_reg_reset(struct uc_struct *uc)
{
}

static void reg_read(CPURISCVState *env, unsigned int regid, void *value)
{
    switch(regid) {
        case UC_RISCV_REG_X0:
        case UC_RISCV_REG_X1:
        case UC_RISCV_REG_X2:
        case UC_RISCV_REG_X3:
        case UC_RISCV_REG_X4:
        case UC_RISCV_REG_X5:
        case UC_RISCV_REG_X6:
        case UC_RISCV_REG_X7:
        case UC_RISCV_REG_X8:
        case UC_RISCV_REG_X9:
        case UC_RISCV_REG_X10:
        case UC_RISCV_REG_X11:
        case UC_RISCV_REG_X12:
        case UC_RISCV_REG_X13:
        case UC_RISCV_REG_X14:
        case UC_RISCV_REG_X15:
        case UC_RISCV_REG_X16:
        case UC_RISCV_REG_X17:
        case UC_RISCV_REG_X18:
        case UC_RISCV_REG_X19:
        case UC_RISCV_REG_X20:
        case UC_RISCV_REG_X21:
        case UC_RISCV_REG_X22:
        case UC_RISCV_REG_X23:
        case UC_RISCV_REG_X24:
        case UC_RISCV_REG_X25:
        case UC_RISCV_REG_X26:
        case UC_RISCV_REG_X27:
        case UC_RISCV_REG_X28:
        case UC_RISCV_REG_X29:
        case UC_RISCV_REG_X30:
        case UC_RISCV_REG_X31:
#ifdef TARGET_RISCV64
            *(int64_t *)value = env->gpr[regid - UC_RISCV_REG_X0];
#else
            *(int32_t *)value = env->gpr[regid - UC_RISCV_REG_X0];
#endif
            break;
        case UC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
            *(int64_t *)value = env->pc;
#else
            *(int32_t *)value = env->pc;
#endif
            break;

        case UC_RISCV_REG_F0:	// "ft0"
        case UC_RISCV_REG_F1:	// "ft1"
        case UC_RISCV_REG_F2:	// "ft2"
        case UC_RISCV_REG_F3:	// "ft3"
        case UC_RISCV_REG_F4:	// "ft4"
        case UC_RISCV_REG_F5:	// "ft5"
        case UC_RISCV_REG_F6:	// "ft6"
        case UC_RISCV_REG_F7:	// "ft7"
        case UC_RISCV_REG_F8:	// "fs0"
        case UC_RISCV_REG_F9:	// "fs1"
        case UC_RISCV_REG_F10:	// "fa0"
        case UC_RISCV_REG_F11:	// "fa1"
        case UC_RISCV_REG_F12:	// "fa2"
        case UC_RISCV_REG_F13:	// "fa3"
        case UC_RISCV_REG_F14:	// "fa4"
        case UC_RISCV_REG_F15:	// "fa5"
        case UC_RISCV_REG_F16:	// "fa6"
        case UC_RISCV_REG_F17:	// "fa7"
        case UC_RISCV_REG_F18:	// "fs2"
        case UC_RISCV_REG_F19:	// "fs3"
        case UC_RISCV_REG_F20:	// "fs4"
        case UC_RISCV_REG_F21:	// "fs5"
        case UC_RISCV_REG_F22:	// "fs6"
        case UC_RISCV_REG_F23:	// "fs7"
        case UC_RISCV_REG_F24:	// "fs8"
        case UC_RISCV_REG_F25:	// "fs9"
        case UC_RISCV_REG_F26:	// "fs10"
        case UC_RISCV_REG_F27:	// "fs11"
        case UC_RISCV_REG_F28:	// "ft8"
        case UC_RISCV_REG_F29:	// "ft9"
        case UC_RISCV_REG_F30:	// "ft10"
        case UC_RISCV_REG_F31:	// "ft11"
#ifdef TARGET_RISCV64
            *(int64_t *)value = env->fpr[regid - UC_RISCV_REG_F0];
#else
            *(int32_t *)value = env->fpr[regid - UC_RISCV_REG_F0];
#endif
            break;
        default:
            break;
    }

    return;
}

static void reg_write(CPURISCVState *env, unsigned int regid, const void *value)
{
    switch(regid) {
        case UC_RISCV_REG_X0:
        case UC_RISCV_REG_X1:
        case UC_RISCV_REG_X2:
        case UC_RISCV_REG_X3:
        case UC_RISCV_REG_X4:
        case UC_RISCV_REG_X5:
        case UC_RISCV_REG_X6:
        case UC_RISCV_REG_X7:
        case UC_RISCV_REG_X8:
        case UC_RISCV_REG_X9:
        case UC_RISCV_REG_X10:
        case UC_RISCV_REG_X11:
        case UC_RISCV_REG_X12:
        case UC_RISCV_REG_X13:
        case UC_RISCV_REG_X14:
        case UC_RISCV_REG_X15:
        case UC_RISCV_REG_X16:
        case UC_RISCV_REG_X17:
        case UC_RISCV_REG_X18:
        case UC_RISCV_REG_X19:
        case UC_RISCV_REG_X20:
        case UC_RISCV_REG_X21:
        case UC_RISCV_REG_X22:
        case UC_RISCV_REG_X23:
        case UC_RISCV_REG_X24:
        case UC_RISCV_REG_X25:
        case UC_RISCV_REG_X26:
        case UC_RISCV_REG_X27:
        case UC_RISCV_REG_X28:
        case UC_RISCV_REG_X29:
        case UC_RISCV_REG_X30:
        case UC_RISCV_REG_X31:
#ifdef TARGET_RISCV64
            env->gpr[regid - UC_RISCV_REG_X0] = *(uint64_t *)value;
#else
            env->gpr[regid - UC_RISCV_REG_X0] = *(uint32_t *)value;
#endif
            break;
        case UC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
            env->pc = *(uint64_t *)value;
#else
            env->pc = *(uint32_t *)value;
#endif
            break;
        case UC_RISCV_REG_F0:	// "ft0"
        case UC_RISCV_REG_F1:	// "ft1"
        case UC_RISCV_REG_F2:	// "ft2"
        case UC_RISCV_REG_F3:	// "ft3"
        case UC_RISCV_REG_F4:	// "ft4"
        case UC_RISCV_REG_F5:	// "ft5"
        case UC_RISCV_REG_F6:	// "ft6"
        case UC_RISCV_REG_F7:	// "ft7"
        case UC_RISCV_REG_F8:	// "fs0"
        case UC_RISCV_REG_F9:	// "fs1"
        case UC_RISCV_REG_F10:	// "fa0"
        case UC_RISCV_REG_F11:	// "fa1"
        case UC_RISCV_REG_F12:	// "fa2"
        case UC_RISCV_REG_F13:	// "fa3"
        case UC_RISCV_REG_F14:	// "fa4"
        case UC_RISCV_REG_F15:	// "fa5"
        case UC_RISCV_REG_F16:	// "fa6"
        case UC_RISCV_REG_F17:	// "fa7"
        case UC_RISCV_REG_F18:	// "fs2"
        case UC_RISCV_REG_F19:	// "fs3"
        case UC_RISCV_REG_F20:	// "fs4"
        case UC_RISCV_REG_F21:	// "fs5"
        case UC_RISCV_REG_F22:	// "fs6"
        case UC_RISCV_REG_F23:	// "fs7"
        case UC_RISCV_REG_F24:	// "fs8"
        case UC_RISCV_REG_F25:	// "fs9"
        case UC_RISCV_REG_F26:	// "fs10"
        case UC_RISCV_REG_F27:	// "fs11"
        case UC_RISCV_REG_F28:	// "ft8"
        case UC_RISCV_REG_F29:	// "ft9"
        case UC_RISCV_REG_F30:	// "ft10"
        case UC_RISCV_REG_F31:	// "ft11"
#ifdef TARGET_RISCV64
            env->fpr[regid - UC_RISCV_REG_F0] = *(uint64_t *)value;
#else
            env->fpr[regid - UC_RISCV_REG_F0] = *(uint32_t *)value;
#endif
            break;
        default:
            break;
    }
}

int riscv_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int riscv_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if(regid == UC_RISCV_REG_PC){
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        } 
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
int riscv32_context_reg_read(struct uc_context *ctx, unsigned int *regs, void **vals, int count)
#else
    /* TARGET_RISCV64 */
int riscv64_context_reg_read(struct uc_context *ctx, unsigned int *regs, void **vals, int count)
#endif
{
    CPURISCVState *env = (CPURISCVState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
int riscv32_context_reg_write(struct uc_context *ctx, unsigned int *regs, void *const *vals, int count)
#else
    /* TARGET_RISCV64 */
int riscv64_context_reg_write(struct uc_context *ctx, unsigned int *regs, void *const *vals, int count)
#endif
{
    CPURISCVState *env = (CPURISCVState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static bool riscv_stop_interrupt(struct uc_struct *uc, int intno)
{
    // detect stop exception
    switch(intno){
        default:
            return false;
        case RISCV_EXCP_UNICORN_END:
            return true;
        case RISCV_EXCP_BREAKPOINT:
            uc->invalid_error = UC_ERR_EXCEPTION;
            return true;
    }
}

static bool riscv_insn_hook_validate(uint32_t insn_enum)
{
    return false;
}

static int riscv_cpus_init(struct uc_struct *uc, const char *cpu_model)
{

    RISCVCPU *cpu;

    cpu = cpu_riscv_init(uc, cpu_model);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
void riscv32_uc_init(struct uc_struct* uc)
#else
    /* TARGET_RISCV64 */
void riscv64_uc_init(struct uc_struct* uc)
#endif
{
    uc->reg_read = riscv_reg_read;
    uc->reg_write = riscv_reg_write;
    uc->reg_reset = riscv_reg_reset;
    uc->release = riscv_release;
    uc->set_pc = riscv_set_pc;
    uc->stop_interrupt = riscv_stop_interrupt;
    uc->insn_hook_validate = riscv_insn_hook_validate;
    uc->cpus_init = riscv_cpus_init;
    uc->cpu_context_size = offsetof(CPURISCVState, rdtime_fn);
    uc_common_init(uc);
}
