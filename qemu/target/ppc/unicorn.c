/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu/osdep.h"
#include "hw/ppc/ppc.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"
#include "helper_regs.h"
#include "cpu.h"

#ifdef TARGET_PPC64
typedef uint64_t ppcreg_t;
#else
typedef uint32_t ppcreg_t;
#endif

// Unicorn version to ensure writing MSR without exception
static inline int uc_ppc_store_msr(CPUPPCState *env, target_ulong value,
                                   int alter_hv)
{
    // int excp;
    // CPUState *cs = env_cpu(env);

    // excp = 0;
    value &= env->msr_mask;

    /* Neither mtmsr nor guest state can alter HV */
    if (!alter_hv || !(env->msr & MSR_HVB)) {
        value &= ~MSR_HVB;
        value |= env->msr & MSR_HVB;
    }
    if (((value >> MSR_IR) & 1) != msr_ir ||
        ((value >> MSR_DR) & 1) != msr_dr) {
        // cpu_interrupt_exittb(cs);
    }
    if ((env->mmu_model & POWERPC_MMU_BOOKE) &&
        ((value >> MSR_GS) & 1) != msr_gs) {
        // cpu_interrupt_exittb(cs);
    }
    if (unlikely((env->flags & POWERPC_FLAG_TGPR) &&
                 ((value ^ env->msr) & (1 << MSR_TGPR)))) {
        /* Swap temporary saved registers with GPRs */
        hreg_swap_gpr_tgpr(env);
    }
    if (unlikely((value >> MSR_EP) & 1) != msr_ep) {
        /* Change the exception prefix on PowerPC 601 */
        env->excp_prefix = ((value >> MSR_EP) & 1) * 0xFFF00000;
    }
    /*
     * If PR=1 then EE, IR and DR must be 1
     *
     * Note: We only enforce this on 64-bit server processors.
     * It appears that:
     * - 32-bit implementations supports PR=1 and EE/DR/IR=0 and MacOS
     *   exploits it.
     * - 64-bit embedded implementations do not need any operation to be
     *   performed when PR is set.
     */
    if (is_book3s_arch2x(env) && ((value >> MSR_PR) & 1)) {
        value |= (1 << MSR_EE) | (1 << MSR_DR) | (1 << MSR_IR);
    }

    env->msr = value;
    hreg_compute_hflags(env);

    // if (unlikely(msr_pow == 1)) {
    //     if (!env->pending_interrupts && (*env->check_pow)(env)) {
    //         cs->halted = 1;
    //         excp = EXCP_HALTED;
    //     }
    // }

    return 0;
}

static uint64_t ppc_mem_redirect(uint64_t address)
{
    /*    // kseg0 range masks off high address bit
        if (address >= 0x80000000 && address <= 0x9fffffff)
            return address & 0x7fffffff;

        // kseg1 range masks off top 3 address bits
        if (address >= 0xa0000000 && address <= 0xbfffffff) {
            return address & 0x1fffffff;
        }*/

    // no redirect
    return address;
}

static void ppc_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUPPCState *)uc->cpu->env_ptr)->nip = address;
}

void ppc_cpu_instance_finalize(CPUState *obj);
void ppc_cpu_unrealize(CPUState *dev);
static void ppc_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    PowerPCCPU *cpu = (PowerPCCPU *)tcg_ctx->uc->cpu;
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

    for (i = 0; i < 32; i++) {
        g_free(tcg_ctx->cpu_gpr[i]);
    }
    //    g_free(tcg_ctx->cpu_PC);
    g_free(tcg_ctx->btarget);
    g_free(tcg_ctx->bcond);
    g_free(tcg_ctx->cpu_dspctrl);

    //    g_free(tcg_ctx->tb_ctx.tbs);

    ppc_cpu_instance_finalize(tcg_ctx->uc->cpu);
    ppc_cpu_unrealize(tcg_ctx->uc->cpu);
}

void ppc_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    env = uc->cpu->env_ptr;
    memset(env->gpr, 0, sizeof(env->gpr));

    env->nip = 0;
}

// http://www.csit-sun.pub.ro/~cpop/Documentatie_SMP/Motorola_PowerPC/PowerPc/GenInfo/pemch2.pdf
static void reg_read(CPUPPCState *env, unsigned int regid, void *value)
{
    uint32_t val;

    if (regid >= UC_PPC_REG_0 && regid <= UC_PPC_REG_31)
        *(ppcreg_t *)value = env->gpr[regid - UC_PPC_REG_0];
    else {
        switch (regid) {
        default:
            break;
        case UC_PPC_REG_PC:
            *(ppcreg_t *)value = env->nip;
            break;
        case UC_PPC_REG_FPR0:
        case UC_PPC_REG_FPR1:
        case UC_PPC_REG_FPR2:
        case UC_PPC_REG_FPR3:
        case UC_PPC_REG_FPR4:
        case UC_PPC_REG_FPR5:
        case UC_PPC_REG_FPR6:
        case UC_PPC_REG_FPR7:
        case UC_PPC_REG_FPR8:
        case UC_PPC_REG_FPR9:
        case UC_PPC_REG_FPR10:
        case UC_PPC_REG_FPR11:
        case UC_PPC_REG_FPR12:
        case UC_PPC_REG_FPR13:
        case UC_PPC_REG_FPR14:
        case UC_PPC_REG_FPR15:
        case UC_PPC_REG_FPR16:
        case UC_PPC_REG_FPR17:
        case UC_PPC_REG_FPR18:
        case UC_PPC_REG_FPR19:
        case UC_PPC_REG_FPR20:
        case UC_PPC_REG_FPR21:
        case UC_PPC_REG_FPR22:
        case UC_PPC_REG_FPR23:
        case UC_PPC_REG_FPR24:
        case UC_PPC_REG_FPR25:
        case UC_PPC_REG_FPR26:
        case UC_PPC_REG_FPR27:
        case UC_PPC_REG_FPR28:
        case UC_PPC_REG_FPR29:
        case UC_PPC_REG_FPR30:
        case UC_PPC_REG_FPR31:
            *(uint64_t *)value = env->vsr[regid - UC_PPC_REG_FPR0].VsrD(0);
            break;
        case UC_PPC_REG_CR0:
        case UC_PPC_REG_CR1:
        case UC_PPC_REG_CR2:
        case UC_PPC_REG_CR3:
        case UC_PPC_REG_CR4:
        case UC_PPC_REG_CR5:
        case UC_PPC_REG_CR6:
        case UC_PPC_REG_CR7:
            *(uint32_t *)value = env->crf[regid - UC_PPC_REG_CR0];
            break;
        case UC_PPC_REG_CR:
            val = 0;
            for (int i = 0; i < 8; i++) {
                val <<= 4;
                val |= env->crf[i];
            }
            *(uint32_t *)value = val;
            break;
        case UC_PPC_REG_LR:
            *(ppcreg_t *)value = env->lr;
            break;
        case UC_PPC_REG_CTR:
            *(ppcreg_t *)value = env->ctr;
            break;
        case UC_PPC_REG_MSR:
            *(ppcreg_t *)value = env->msr;
            break;
        case UC_PPC_REG_XER:
            *(uint32_t *)value = env->xer;
            break;
        case UC_PPC_REG_FPSCR:
            *(uint32_t *)value = env->fpscr;
            break;
        }
    }

    return;
}

static void reg_write(CPUPPCState *env, unsigned int regid, const void *value)
{
    uint32_t val;
    int i;

    if (regid >= UC_PPC_REG_0 && regid <= UC_PPC_REG_31)
        env->gpr[regid - UC_PPC_REG_0] = *(ppcreg_t *)value;
    else {
        switch (regid) {
        default:
            break;
        case UC_PPC_REG_PC:
            env->nip = *(ppcreg_t *)value;
            break;
        case UC_PPC_REG_FPR0:
        case UC_PPC_REG_FPR1:
        case UC_PPC_REG_FPR2:
        case UC_PPC_REG_FPR3:
        case UC_PPC_REG_FPR4:
        case UC_PPC_REG_FPR5:
        case UC_PPC_REG_FPR6:
        case UC_PPC_REG_FPR7:
        case UC_PPC_REG_FPR8:
        case UC_PPC_REG_FPR9:
        case UC_PPC_REG_FPR10:
        case UC_PPC_REG_FPR11:
        case UC_PPC_REG_FPR12:
        case UC_PPC_REG_FPR13:
        case UC_PPC_REG_FPR14:
        case UC_PPC_REG_FPR15:
        case UC_PPC_REG_FPR16:
        case UC_PPC_REG_FPR17:
        case UC_PPC_REG_FPR18:
        case UC_PPC_REG_FPR19:
        case UC_PPC_REG_FPR20:
        case UC_PPC_REG_FPR21:
        case UC_PPC_REG_FPR22:
        case UC_PPC_REG_FPR23:
        case UC_PPC_REG_FPR24:
        case UC_PPC_REG_FPR25:
        case UC_PPC_REG_FPR26:
        case UC_PPC_REG_FPR27:
        case UC_PPC_REG_FPR28:
        case UC_PPC_REG_FPR29:
        case UC_PPC_REG_FPR30:
        case UC_PPC_REG_FPR31:
            env->vsr[regid - UC_PPC_REG_FPR0].VsrD(0) = *(uint64_t *)value;
            break;
        case UC_PPC_REG_CR0:
        case UC_PPC_REG_CR1:
        case UC_PPC_REG_CR2:
        case UC_PPC_REG_CR3:
        case UC_PPC_REG_CR4:
        case UC_PPC_REG_CR5:
        case UC_PPC_REG_CR6:
        case UC_PPC_REG_CR7:
            env->crf[regid - UC_PPC_REG_CR0] = (*(uint32_t *)value) & 0b1111;
            break;
        case UC_PPC_REG_CR:
            val = *(uint32_t *)value;
            for (i = 0; i < 8; i++) {
                env->crf[i] = val & 0b1111;
                val >>= 4;
            }
            break;
        case UC_PPC_REG_LR:
            env->lr = *(ppcreg_t *)value;
            break;
        case UC_PPC_REG_CTR:
            env->ctr = *(ppcreg_t *)value;
            break;
        case UC_PPC_REG_MSR:
            uc_ppc_store_msr(env, *(ppcreg_t *)value, 0);
            break;
        case UC_PPC_REG_XER:
            env->xer = *(uint32_t *)value;
            break;
        case UC_PPC_REG_FPSCR:
            store_fpscr(env, *(uint32_t *)value, 0xffffffff);
            break;
        }
    }

    return;
}

int ppc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                 int count)
{
    CPUPPCState *env = &(POWERPC_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int ppc_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  int count)
{
    CPUPPCState *env = &(POWERPC_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_PPC_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_PPC64
int ppc64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count)
#else
int ppc_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                         void **vals, int count)
#endif
{
    CPUPPCState *env = (CPUPPCState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_PPC64
int ppc64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count)
#else
int ppc_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                          void *const *vals, int count)
#endif
{
    CPUPPCState *env = (CPUPPCState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

PowerPCCPU *cpu_ppc_init(struct uc_struct *uc);
static int ppc_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    PowerPCCPU *cpu;

    cpu = cpu_ppc_init(uc);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_PPC64
void ppc64_uc_init(struct uc_struct *uc)
#else
void ppc_uc_init(struct uc_struct *uc)
#endif
{
    uc->reg_read = ppc_reg_read;
    uc->reg_write = ppc_reg_write;
    uc->reg_reset = ppc_reg_reset;
    uc->release = ppc_release;
    uc->set_pc = ppc_set_pc;
    uc->mem_redirect = ppc_mem_redirect;
    uc->cpus_init = ppc_cpus_init;
    uc->cpu_context_size = offsetof(CPUPPCState, uc);
    uc_common_init(uc);
}
