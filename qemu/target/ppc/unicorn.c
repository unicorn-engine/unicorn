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

static void ppc_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUPPCState *)uc->cpu->env_ptr)->nip = address;
}

static uint64_t ppc_get_pc(struct uc_struct *uc)
{
    return ((CPUPPCState *)uc->cpu->env_ptr)->nip;
}

void ppc_cpu_instance_finalize(CPUState *obj);
void ppc_cpu_unrealize(CPUState *dev);
static void ppc_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    PowerPCCPU *cpu = (PowerPCCPU *)tcg_ctx->uc->cpu;
    CPUPPCState *env = &cpu->env;
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

    if (env->nb_tlb != 0) {
        switch (env->tlb_type) {
        case TLB_6XX:
            g_free(env->tlb.tlb6);
            break;
        case TLB_EMB:
            g_free(env->tlb.tlbe);
            break;
        case TLB_MAS:
            g_free(env->tlb.tlbm);
            break;
        }
    }

    ppc_cpu_instance_finalize(tcg_ctx->uc->cpu);
    ppc_cpu_unrealize(tcg_ctx->uc->cpu);
}

static void reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    env = uc->cpu->env_ptr;
    memset(env->gpr, 0, sizeof(env->gpr));

    env->nip = 0;
}

// http://www.csit-sun.pub.ro/~cpop/Documentatie_SMP/Motorola_PowerPC/PowerPc/GenInfo/pemch2.pdf
DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUPPCState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_PPC_REG_0 && regid <= UC_PPC_REG_31) {
        CHECK_REG_TYPE(ppcreg_t);
        *(ppcreg_t *)value = env->gpr[regid - UC_PPC_REG_0];
    } else if (regid >= UC_PPC_REG_FPR0 && regid <= UC_PPC_REG_FPR31) {
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->vsr[regid - UC_PPC_REG_FPR0].VsrD(0);
    } else if (regid >= UC_PPC_REG_CR0 && regid <= UC_PPC_REG_CR7) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->crf[regid - UC_PPC_REG_CR0];
    } else {
        switch (regid) {
        default:
            break;
        case UC_PPC_REG_PC:
            CHECK_REG_TYPE(ppcreg_t);
            *(ppcreg_t *)value = env->nip;
            break;
        case UC_PPC_REG_CR: {
            CHECK_REG_TYPE(uint32_t);
            int i;
            uint32_t val = 0;
            for (i = 0; i < 8; i++) {
                val <<= 4;
                val |= env->crf[i];
            }
            *(uint32_t *)value = val;
            break;
        }
        case UC_PPC_REG_LR:
            CHECK_REG_TYPE(ppcreg_t);
            *(ppcreg_t *)value = env->lr;
            break;
        case UC_PPC_REG_CTR:
            CHECK_REG_TYPE(ppcreg_t);
            *(ppcreg_t *)value = env->ctr;
            break;
        case UC_PPC_REG_MSR:
            CHECK_REG_TYPE(ppcreg_t);
            *(ppcreg_t *)value = env->msr;
            break;
        case UC_PPC_REG_XER:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->xer;
            break;
        case UC_PPC_REG_FPSCR:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->fpscr;
            break;
        }
    }

    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUPPCState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_PPC_REG_0 && regid <= UC_PPC_REG_31) {
        CHECK_REG_TYPE(ppcreg_t);
        env->gpr[regid - UC_PPC_REG_0] = *(ppcreg_t *)value;
    } else if (regid >= UC_PPC_REG_FPR0 && regid <= UC_PPC_REG_FPR31) {
        CHECK_REG_TYPE(uint64_t);
        env->vsr[regid - UC_PPC_REG_FPR0].VsrD(0) = *(uint64_t *)value;
    } else if (regid >= UC_PPC_REG_CR0 && regid <= UC_PPC_REG_CR7) {
        CHECK_REG_TYPE(uint32_t);
        env->crf[regid - UC_PPC_REG_CR0] = (*(uint32_t *)value) & 0b1111;
    } else {
        switch (regid) {
        default:
            break;
        case UC_PPC_REG_PC:
            CHECK_REG_TYPE(ppcreg_t);
            env->nip = *(ppcreg_t *)value;
            *setpc = 1;
            break;
        case UC_PPC_REG_CR: {
            CHECK_REG_TYPE(uint32_t);
            int i;
            uint32_t val = *(uint32_t *)value;
            for (i = 7; i >= 0; i--) {
                env->crf[i] = val & 0b1111;
                val >>= 4;
            }
            break;
        }
        case UC_PPC_REG_LR:
            CHECK_REG_TYPE(ppcreg_t);
            env->lr = *(ppcreg_t *)value;
            break;
        case UC_PPC_REG_CTR:
            CHECK_REG_TYPE(ppcreg_t);
            env->ctr = *(ppcreg_t *)value;
            break;
        case UC_PPC_REG_MSR:
            CHECK_REG_TYPE(ppcreg_t);
            uc_ppc_store_msr(env, *(ppcreg_t *)value, 0);
            break;
        case UC_PPC_REG_XER:
            CHECK_REG_TYPE(uint32_t);
            env->xer = *(uint32_t *)value;
            break;
        case UC_PPC_REG_FPSCR:
            CHECK_REG_TYPE(uint32_t);
            store_fpscr(env, *(uint32_t *)value, 0xffffffff);
            break;
        }
    }

    return ret;
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
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->release = ppc_release;
    uc->set_pc = ppc_set_pc;
    uc->get_pc = ppc_get_pc;
    uc->cpus_init = ppc_cpus_init;
    uc->cpu_context_size = offsetof(CPUPPCState, uc);
    uc_common_init(uc);
}
