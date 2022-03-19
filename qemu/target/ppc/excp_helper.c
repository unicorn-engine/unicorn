/*
 *  PowerPC exception emulation helpers for QEMU.
 *
 *  Copyright (c) 2003-2007 Jocelyn Mayer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "internal.h"
#include "helper_regs.h"

/* #define DEBUG_OP */
/* #define DEBUG_SOFTWARE_TLB */
/* #define DEBUG_EXCEPTIONS */

#ifdef DEBUG_EXCEPTIONS
#  define LOG_EXCP(...) qemu_log(__VA_ARGS__)
#else
#  define LOG_EXCP(...) do { } while (0)
#endif

/*****************************************************************************/
/* Exception processing */
static inline void dump_syscall(CPUPPCState *env)
{
    qemu_log_mask(CPU_LOG_INT, "syscall r0=%016" PRIx64 " r3=%016" PRIx64
                  " r4=%016" PRIx64 " r5=%016" PRIx64 " r6=%016" PRIx64
                  " nip=" TARGET_FMT_lx "\n",
                  ppc_dump_gpr(env, 0), ppc_dump_gpr(env, 3),
                  ppc_dump_gpr(env, 4), ppc_dump_gpr(env, 5),
                  ppc_dump_gpr(env, 6), env->nip);
}

static int powerpc_reset_wakeup(CPUState *cs, CPUPPCState *env, int excp,
                                target_ulong *msr)
{
    /* We no longer are in a PM state */
    env->resume_as_sreset = false;

    /* Pretend to be returning from doze always as we don't lose state */
    *msr |= (0x1ull << (63 - 47));

    /* Machine checks are sent normally */
    if (excp == POWERPC_EXCP_MCHECK) {
        return excp;
    }
    switch (excp) {
    case POWERPC_EXCP_RESET:
        *msr |= 0x4ull << (63 - 45);
        break;
    case POWERPC_EXCP_EXTERNAL:
        *msr |= 0x8ull << (63 - 45);
        break;
    case POWERPC_EXCP_DECR:
        *msr |= 0x6ull << (63 - 45);
        break;
    case POWERPC_EXCP_SDOOR:
        *msr |= 0x5ull << (63 - 45);
        break;
    case POWERPC_EXCP_SDOOR_HV:
        *msr |= 0x3ull << (63 - 45);
        break;
    case POWERPC_EXCP_HV_MAINT:
        *msr |= 0xaull << (63 - 45);
        break;
    case POWERPC_EXCP_HVIRT:
        *msr |= 0x9ull << (63 - 45);
        break;
    default:
        cpu_abort(cs, "Unsupported exception %d in Power Save mode\n",
                  excp);
    }
    return POWERPC_EXCP_RESET;
}

static uint64_t ppc_excp_vector_offset(CPUState *cs, int ail)
{
    uint64_t offset = 0;

    switch (ail) {
    case AIL_NONE:
        break;
    case AIL_0001_8000:
        offset = 0x18000;
        break;
    case AIL_C000_0000_0000_4000:
        offset = 0xc000000000004000ull;
        break;
    default:
        cpu_abort(cs, "Invalid AIL combination %d\n", ail);
        break;
    }

    return offset;
}

static inline void powerpc_set_excp_state(PowerPCCPU *cpu,
                                          target_ulong vector, target_ulong msr)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;

    /*
     * We don't use hreg_store_msr here as already have treated any
     * special case that could occur. Just store MSR and update hflags
     *
     * Note: We *MUST* not use hreg_store_msr() as-is anyway because it
     * will prevent setting of the HV bit which some exceptions might need
     * to do.
     */
    env->msr = msr & env->msr_mask;
    hreg_compute_hflags(env);
    env->nip = vector;
    /* Reset exception state */
    cs->exception_index = POWERPC_EXCP_NONE;
    env->error_code = 0;

    /* Reset the reservation */
    env->reserve_addr = -1;

    /*
     * Any interrupt is context synchronizing, check if TCG TLB needs
     * a delayed flush on ppc64
     */
    check_tlb_flush(env, false);
}

/*
 * Note that this function should be greatly optimized when called
 * with a constant excp, from ppc_hw_interrupt
 */
static inline void powerpc_excp(PowerPCCPU *cpu, int excp_model, int excp)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    target_ulong msr, new_msr, vector;
    int srr0, srr1, asrr0, asrr1, lev, ail;
    bool lpes0;

    qemu_log_mask(CPU_LOG_INT, "Raise exception at " TARGET_FMT_lx
                  " => %08x (%02x)\n", env->nip, excp, env->error_code);

    /* new srr1 value excluding must-be-zero bits */
    if (excp_model == POWERPC_EXCP_BOOKE) {
        msr = env->msr;
    } else {
        msr = env->msr & ~0x783f0000ULL;
    }

    /*
     * new interrupt handler msr preserves existing HV and ME unless
     * explicitly overriden
     */
    new_msr = env->msr & (((target_ulong)1 << MSR_ME) | MSR_HVB);

    /* target registers */
    srr0 = SPR_SRR0;
    srr1 = SPR_SRR1;
    asrr0 = -1;
    asrr1 = -1;

    /*
     * check for special resume at 0x100 from doze/nap/sleep/winkle on
     * P7/P8/P9
     */
    if (env->resume_as_sreset) {
        excp = powerpc_reset_wakeup(cs, env, excp, &msr);
    }

    /*
     * Exception targetting modifiers
     *
     * LPES0 is supported on POWER7/8/9
     * LPES1 is not supported (old iSeries mode)
     *
     * On anything else, we behave as if LPES0 is 1
     * (externals don't alter MSR:HV)
     *
     * AIL is initialized here but can be cleared by
     * selected exceptions
     */
#if defined(TARGET_PPC64)
    if (excp_model == POWERPC_EXCP_POWER7 ||
        excp_model == POWERPC_EXCP_POWER8 ||
        excp_model == POWERPC_EXCP_POWER9) {
        lpes0 = !!(env->spr[SPR_LPCR] & LPCR_LPES0);
        if (excp_model != POWERPC_EXCP_POWER7) {
            ail = (env->spr[SPR_LPCR] & LPCR_AIL) >> LPCR_AIL_SHIFT;
        } else {
            ail = 0;
        }
    } else
#endif /* defined(TARGET_PPC64) */
    {
        lpes0 = true;
        ail = 0;
    }

    /*
     * Hypervisor emulation assistance interrupt only exists on server
     * arch 2.05 server or later. We also don't want to generate it if
     * we don't have HVB in msr_mask (PAPR mode).
     */
    if (excp == POWERPC_EXCP_HV_EMU
#if defined(TARGET_PPC64)
        && !((env->mmu_model & POWERPC_MMU_64) && (env->msr_mask & MSR_HVB))
#endif /* defined(TARGET_PPC64) */

    ) {
        excp = POWERPC_EXCP_PROGRAM;
    }

    switch (excp) {
    case POWERPC_EXCP_NONE:
        /* Should never happen */
        return;
    case POWERPC_EXCP_CRITICAL:    /* Critical input                         */
        switch (excp_model) {
        case POWERPC_EXCP_40x:
            srr0 = SPR_40x_SRR2;
            srr1 = SPR_40x_SRR3;
            break;
        case POWERPC_EXCP_BOOKE:
            srr0 = SPR_BOOKE_CSRR0;
            srr1 = SPR_BOOKE_CSRR1;
            break;
        case POWERPC_EXCP_G2:
            break;
        default:
            goto excp_invalid;
        }
        break;
    case POWERPC_EXCP_MCHECK:    /* Machine check exception                  */
        if (msr_me == 0) {
            /*
             * Machine check exception is not enabled.  Enter
             * checkstop state.
             */
            fprintf(stderr, "Machine check while not allowed. "
                    "Entering checkstop state\n");
#if 0
            if (qemu_log_separate()) {
                qemu_log("Machine check while not allowed. "
                        "Entering checkstop state\n");
            }
#endif
            cs->halted = 1;
            cpu_interrupt_exittb(cs);
        }
        if (env->msr_mask & MSR_HVB) {
            /*
             * ISA specifies HV, but can be delivered to guest with HV
             * clear (e.g., see FWNMI in PAPR).
             */
            new_msr |= (target_ulong)MSR_HVB;
        }
        ail = 0;

        /* machine check exceptions don't have ME set */
        new_msr &= ~((target_ulong)1 << MSR_ME);

        /* XXX: should also have something loaded in DAR / DSISR */
        switch (excp_model) {
        case POWERPC_EXCP_40x:
            srr0 = SPR_40x_SRR2;
            srr1 = SPR_40x_SRR3;
            break;
        case POWERPC_EXCP_BOOKE:
            /* FIXME: choose one or the other based on CPU type */
            srr0 = SPR_BOOKE_MCSRR0;
            srr1 = SPR_BOOKE_MCSRR1;
            asrr0 = SPR_BOOKE_CSRR0;
            asrr1 = SPR_BOOKE_CSRR1;
            break;
        default:
            break;
        }
        break;
    case POWERPC_EXCP_DSI:       /* Data storage exception                   */
        LOG_EXCP("DSI exception: DSISR=" TARGET_FMT_lx" DAR=" TARGET_FMT_lx
                 "\n", env->spr[SPR_DSISR], env->spr[SPR_DAR]);
        break;
    case POWERPC_EXCP_ISI:       /* Instruction storage exception            */
        LOG_EXCP("ISI exception: msr=" TARGET_FMT_lx ", nip=" TARGET_FMT_lx
                 "\n", msr, env->nip);
        msr |= env->error_code;
        break;
    case POWERPC_EXCP_EXTERNAL:  /* External input                           */
        cs = CPU(cpu);

        if (!lpes0) {
            new_msr |= (target_ulong)MSR_HVB;
            new_msr |= env->msr & ((target_ulong)1 << MSR_RI);
            srr0 = SPR_HSRR0;
            srr1 = SPR_HSRR1;
        }
        if (env->mpic_proxy) {
            /* IACK the IRQ on delivery */
#ifdef UNICORN_ARCH_POSTFIX
            env->spr[SPR_BOOKE_EPR] = glue(ldl_phys, UNICORN_ARCH_POSTFIX)(cs->uc, cs->as, env->mpic_iack);
#else
            env->spr[SPR_BOOKE_EPR] = ldl_phys(cs->uc, cs->as, env->mpic_iack);
#endif
        }
        break;
    case POWERPC_EXCP_ALIGN:     /* Alignment exception                      */
        /* Get rS/rD and rA from faulting opcode */
        /*
         * Note: the opcode fields will not be set properly for a
         * direct store load/store, but nobody cares as nobody
         * actually uses direct store segments.
         */
        env->spr[SPR_DSISR] |= (env->error_code & 0x03FF0000) >> 16;
        break;
    case POWERPC_EXCP_PROGRAM:   /* Program exception                        */
        switch (env->error_code & ~0xF) {
        case POWERPC_EXCP_FP:
            if ((msr_fe0 == 0 && msr_fe1 == 0) || msr_fp == 0) {
                LOG_EXCP("Ignore floating point exception\n");
                cs->exception_index = POWERPC_EXCP_NONE;
                env->error_code = 0;
                return;
            }

            /*
             * FP exceptions always have NIP pointing to the faulting
             * instruction, so always use store_next and claim we are
             * precise in the MSR.
             */
            msr |= 0x00100000;
            env->spr[SPR_BOOKE_ESR] = ESR_FP;
            break;
        case POWERPC_EXCP_INVAL:
            LOG_EXCP("Invalid instruction at " TARGET_FMT_lx "\n", env->nip);
            msr |= 0x00080000;
            env->spr[SPR_BOOKE_ESR] = ESR_PIL;
            break;
        case POWERPC_EXCP_PRIV:
            msr |= 0x00040000;
            env->spr[SPR_BOOKE_ESR] = ESR_PPR;
            break;
        case POWERPC_EXCP_TRAP:
            msr |= 0x00020000;
            env->spr[SPR_BOOKE_ESR] = ESR_PTR;
            break;
        default:
            /* Should never occur */
            cpu_abort(cs, "Invalid program exception %d. Aborting\n",
                      env->error_code);
            break;
        }
        break;
    case POWERPC_EXCP_SYSCALL:   /* System call exception                    */
        dump_syscall(env);
        lev = env->error_code;

        /*
         * We need to correct the NIP which in this case is supposed
         * to point to the next instruction
         */
        env->nip += 4;

#if 0
        /* "PAPR mode" built-in hypercall emulation */
        if ((lev == 1) && cpu->vhyp) {
            PPCVirtualHypervisorClass *vhc =
                PPC_VIRTUAL_HYPERVISOR_GET_CLASS(cpu->vhyp);
            vhc->hypercall(cpu->vhyp, cpu);
            return;
        }
#endif
        if (lev == 1) {
            new_msr |= (target_ulong)MSR_HVB;
        }
        break;
    case POWERPC_EXCP_FPU:       /* Floating-point unavailable exception     */
    case POWERPC_EXCP_APU:       /* Auxiliary processor unavailable          */
    case POWERPC_EXCP_DECR:      /* Decrementer exception                    */
        break;
    case POWERPC_EXCP_FIT:       /* Fixed-interval timer interrupt           */
        /* FIT on 4xx */
        LOG_EXCP("FIT exception\n");
        break;
    case POWERPC_EXCP_WDT:       /* Watchdog timer interrupt                 */
        LOG_EXCP("WDT exception\n");
        switch (excp_model) {
        case POWERPC_EXCP_BOOKE:
            srr0 = SPR_BOOKE_CSRR0;
            srr1 = SPR_BOOKE_CSRR1;
            break;
        default:
            break;
        }
        break;
    case POWERPC_EXCP_DTLB:      /* Data TLB error                           */
    case POWERPC_EXCP_ITLB:      /* Instruction TLB error                    */
        break;
    case POWERPC_EXCP_DEBUG:     /* Debug interrupt                          */
        if (env->flags & POWERPC_FLAG_DE) {
            /* FIXME: choose one or the other based on CPU type */
            srr0 = SPR_BOOKE_DSRR0;
            srr1 = SPR_BOOKE_DSRR1;
            asrr0 = SPR_BOOKE_CSRR0;
            asrr1 = SPR_BOOKE_CSRR1;
            /* DBSR already modified by caller */
        } else {
            cpu_abort(cs, "Debug exception triggered on unsupported model\n");
        }
        break;
    case POWERPC_EXCP_SPEU:      /* SPE/embedded floating-point unavailable  */
        env->spr[SPR_BOOKE_ESR] = ESR_SPV;
        break;
    case POWERPC_EXCP_EFPDI:     /* Embedded floating-point data interrupt   */
        /* XXX: TODO */
        cpu_abort(cs, "Embedded floating point data exception "
                  "is not implemented yet !\n");
        env->spr[SPR_BOOKE_ESR] = ESR_SPV;
        break;
    case POWERPC_EXCP_EFPRI:     /* Embedded floating-point round interrupt  */
        /* XXX: TODO */
        cpu_abort(cs, "Embedded floating point round exception "
                  "is not implemented yet !\n");
        env->spr[SPR_BOOKE_ESR] = ESR_SPV;
        break;
    case POWERPC_EXCP_EPERFM:    /* Embedded performance monitor interrupt   */
        /* XXX: TODO */
        cpu_abort(cs,
                  "Performance counter exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_DOORI:     /* Embedded doorbell interrupt              */
        break;
    case POWERPC_EXCP_DOORCI:    /* Embedded doorbell critical interrupt     */
        srr0 = SPR_BOOKE_CSRR0;
        srr1 = SPR_BOOKE_CSRR1;
        break;
    case POWERPC_EXCP_RESET:     /* System reset exception                   */
        /* A power-saving exception sets ME, otherwise it is unchanged */
        if (msr_pow) {
            /* indicate that we resumed from power save mode */
            msr |= 0x10000;
            new_msr |= ((target_ulong)1 << MSR_ME);
        }
        if (env->msr_mask & MSR_HVB) {
            /*
             * ISA specifies HV, but can be delivered to guest with HV
             * clear (e.g., see FWNMI in PAPR, NMI injection in QEMU).
             */
            new_msr |= (target_ulong)MSR_HVB;
        } else {
            if (msr_pow) {
                cpu_abort(cs, "Trying to deliver power-saving system reset "
                          "exception %d with no HV support\n", excp);
            }
        }
        ail = 0;
        break;
    case POWERPC_EXCP_DSEG:      /* Data segment exception                   */
    case POWERPC_EXCP_ISEG:      /* Instruction segment exception            */
    case POWERPC_EXCP_TRACE:     /* Trace exception                          */
        break;
    case POWERPC_EXCP_HDECR:     /* Hypervisor decrementer exception         */
    case POWERPC_EXCP_HDSI:      /* Hypervisor data storage exception        */
    case POWERPC_EXCP_HISI:      /* Hypervisor instruction storage exception */
    case POWERPC_EXCP_HDSEG:     /* Hypervisor data segment exception        */
    case POWERPC_EXCP_HISEG:     /* Hypervisor instruction segment exception */
    case POWERPC_EXCP_SDOOR_HV:  /* Hypervisor Doorbell interrupt            */
    case POWERPC_EXCP_HV_EMU:
    case POWERPC_EXCP_HVIRT:     /* Hypervisor virtualization                */
        srr0 = SPR_HSRR0;
        srr1 = SPR_HSRR1;
        new_msr |= (target_ulong)MSR_HVB;
        new_msr |= env->msr & ((target_ulong)1 << MSR_RI);
        break;
    case POWERPC_EXCP_VPU:       /* Vector unavailable exception             */
    case POWERPC_EXCP_VSXU:       /* VSX unavailable exception               */
    case POWERPC_EXCP_FU:         /* Facility unavailable exception          */
#ifdef TARGET_PPC64
        env->spr[SPR_FSCR] |= ((target_ulong)env->error_code << 56);
#endif
        break;
    case POWERPC_EXCP_HV_FU:     /* Hypervisor Facility Unavailable Exception */
#ifdef TARGET_PPC64
        env->spr[SPR_HFSCR] |= ((target_ulong)env->error_code << FSCR_IC_POS);
        srr0 = SPR_HSRR0;
        srr1 = SPR_HSRR1;
        new_msr |= (target_ulong)MSR_HVB;
        new_msr |= env->msr & ((target_ulong)1 << MSR_RI);
#endif
        break;
    case POWERPC_EXCP_PIT:       /* Programmable interval timer interrupt    */
        LOG_EXCP("PIT exception\n");
        break;
    case POWERPC_EXCP_IO:        /* IO error exception                       */
        /* XXX: TODO */
        cpu_abort(cs, "601 IO error exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_RUNM:      /* Run mode exception                       */
        /* XXX: TODO */
        cpu_abort(cs, "601 run mode exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_EMUL:      /* Emulation trap exception                 */
        /* XXX: TODO */
        cpu_abort(cs, "602 emulation trap exception "
                  "is not implemented yet !\n");
        break;
    case POWERPC_EXCP_IFTLB:     /* Instruction fetch TLB error              */
        switch (excp_model) {
        case POWERPC_EXCP_602:
        case POWERPC_EXCP_603:
        case POWERPC_EXCP_603E:
        case POWERPC_EXCP_G2:
            goto tlb_miss_tgpr;
        case POWERPC_EXCP_7x5:
            goto tlb_miss;
        case POWERPC_EXCP_74xx:
            goto tlb_miss_74xx;
        default:
            cpu_abort(cs, "Invalid instruction TLB miss exception\n");
            break;
        }
        break;
    case POWERPC_EXCP_DLTLB:     /* Data load TLB miss                       */
        switch (excp_model) {
        case POWERPC_EXCP_602:
        case POWERPC_EXCP_603:
        case POWERPC_EXCP_603E:
        case POWERPC_EXCP_G2:
            goto tlb_miss_tgpr;
        case POWERPC_EXCP_7x5:
            goto tlb_miss;
        case POWERPC_EXCP_74xx:
            goto tlb_miss_74xx;
        default:
            cpu_abort(cs, "Invalid data load TLB miss exception\n");
            break;
        }
        break;
    case POWERPC_EXCP_DSTLB:     /* Data store TLB miss                      */
        switch (excp_model) {
        case POWERPC_EXCP_602:
        case POWERPC_EXCP_603:
        case POWERPC_EXCP_603E:
        case POWERPC_EXCP_G2:
        tlb_miss_tgpr:
            /* Swap temporary saved registers with GPRs */
            if (!(new_msr & ((target_ulong)1 << MSR_TGPR))) {
                new_msr |= (target_ulong)1 << MSR_TGPR;
                hreg_swap_gpr_tgpr(env);
            }
            goto tlb_miss;
        case POWERPC_EXCP_7x5:
        tlb_miss:
#if defined(DEBUG_SOFTWARE_TLB)
            if (qemu_log_enabled()) {
                const char *es;
                target_ulong *miss, *cmp;
                int en;

                if (excp == POWERPC_EXCP_IFTLB) {
                    es = "I";
                    en = 'I';
                    miss = &env->spr[SPR_IMISS];
                    cmp = &env->spr[SPR_ICMP];
                } else {
                    if (excp == POWERPC_EXCP_DLTLB) {
                        es = "DL";
                    } else {
                        es = "DS";
                    }
                    en = 'D';
                    miss = &env->spr[SPR_DMISS];
                    cmp = &env->spr[SPR_DCMP];
                }
                qemu_log("6xx %sTLB miss: %cM " TARGET_FMT_lx " %cC "
                         TARGET_FMT_lx " H1 " TARGET_FMT_lx " H2 "
                         TARGET_FMT_lx " %08x\n", es, en, *miss, en, *cmp,
                         env->spr[SPR_HASH1], env->spr[SPR_HASH2],
                         env->error_code);
            }
#endif
            msr |= env->crf[0] << 28;
            msr |= env->error_code; /* key, D/I, S/L bits */
            /* Set way using a LRU mechanism */
            msr |= ((env->last_way + 1) & (env->nb_ways - 1)) << 17;
            break;
        case POWERPC_EXCP_74xx:
        tlb_miss_74xx:
#if defined(DEBUG_SOFTWARE_TLB)
            if (qemu_log_enabled()) {
                const char *es;
                target_ulong *miss, *cmp;
                int en;

                if (excp == POWERPC_EXCP_IFTLB) {
                    es = "I";
                    en = 'I';
                    miss = &env->spr[SPR_TLBMISS];
                    cmp = &env->spr[SPR_PTEHI];
                } else {
                    if (excp == POWERPC_EXCP_DLTLB) {
                        es = "DL";
                    } else {
                        es = "DS";
                    }
                    en = 'D';
                    miss = &env->spr[SPR_TLBMISS];
                    cmp = &env->spr[SPR_PTEHI];
                }
                qemu_log("74xx %sTLB miss: %cM " TARGET_FMT_lx " %cC "
                         TARGET_FMT_lx " %08x\n", es, en, *miss, en, *cmp,
                         env->error_code);
            }
#endif
            msr |= env->error_code; /* key bit */
            break;
        default:
            cpu_abort(cs, "Invalid data store TLB miss exception\n");
            break;
        }
        break;
    case POWERPC_EXCP_FPA:       /* Floating-point assist exception          */
        /* XXX: TODO */
        cpu_abort(cs, "Floating point assist exception "
                  "is not implemented yet !\n");
        break;
    case POWERPC_EXCP_DABR:      /* Data address breakpoint                  */
        /* XXX: TODO */
        cpu_abort(cs, "DABR exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_IABR:      /* Instruction address breakpoint           */
        /* XXX: TODO */
        cpu_abort(cs, "IABR exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_SMI:       /* System management interrupt              */
        /* XXX: TODO */
        cpu_abort(cs, "SMI exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_THERM:     /* Thermal interrupt                        */
        /* XXX: TODO */
        cpu_abort(cs, "Thermal management exception "
                  "is not implemented yet !\n");
        break;
    case POWERPC_EXCP_PERFM:     /* Embedded performance monitor interrupt   */
        /* XXX: TODO */
        cpu_abort(cs,
                  "Performance counter exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_VPUA:      /* Vector assist exception                  */
        /* XXX: TODO */
        cpu_abort(cs, "VPU assist exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_SOFTP:     /* Soft patch exception                     */
        /* XXX: TODO */
        cpu_abort(cs,
                  "970 soft-patch exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_MAINT:     /* Maintenance exception                    */
        /* XXX: TODO */
        cpu_abort(cs,
                  "970 maintenance exception is not implemented yet !\n");
        break;
    case POWERPC_EXCP_MEXTBR:    /* Maskable external breakpoint             */
        /* XXX: TODO */
        cpu_abort(cs, "Maskable external exception "
                  "is not implemented yet !\n");
        break;
    case POWERPC_EXCP_NMEXTBR:   /* Non maskable external breakpoint         */
        /* XXX: TODO */
        cpu_abort(cs, "Non maskable external exception "
                  "is not implemented yet !\n");
        break;
    default:
    excp_invalid:
        cpu_abort(cs, "Invalid PowerPC exception %d. Aborting\n", excp);
        break;
    }

    /* Save PC */
    env->spr[srr0] = env->nip;

    /* Save MSR */
    env->spr[srr1] = msr;

    /* Sanity check */
    if (!(env->msr_mask & MSR_HVB)) {
        if (new_msr & MSR_HVB) {
            cpu_abort(cs, "Trying to deliver HV exception (MSR) %d with "
                      "no HV support\n", excp);
        }
        if (srr0 == SPR_HSRR0) {
            cpu_abort(cs, "Trying to deliver HV exception (HSRR) %d with "
                      "no HV support\n", excp);
        }
    }

    /* If any alternate SRR register are defined, duplicate saved values */
    if (asrr0 != -1) {
        env->spr[asrr0] = env->spr[srr0];
    }
    if (asrr1 != -1) {
        env->spr[asrr1] = env->spr[srr1];
    }

    /*
     * Sort out endianness of interrupt, this differs depending on the
     * CPU, the HV mode, etc...
     */
#ifdef TARGET_PPC64
    if (excp_model == POWERPC_EXCP_POWER7) {
        if (!(new_msr & MSR_HVB) && (env->spr[SPR_LPCR] & LPCR_ILE)) {
            new_msr |= (target_ulong)1 << MSR_LE;
        }
    } else if (excp_model == POWERPC_EXCP_POWER8) {
        if (new_msr & MSR_HVB) {
            if (env->spr[SPR_HID0] & HID0_HILE) {
                new_msr |= (target_ulong)1 << MSR_LE;
            }
        } else if (env->spr[SPR_LPCR] & LPCR_ILE) {
            new_msr |= (target_ulong)1 << MSR_LE;
        }
    } else if (excp_model == POWERPC_EXCP_POWER9) {
        if (new_msr & MSR_HVB) {
            if (env->spr[SPR_HID0] & HID0_POWER9_HILE) {
                new_msr |= (target_ulong)1 << MSR_LE;
            }
        } else if (env->spr[SPR_LPCR] & LPCR_ILE) {
            new_msr |= (target_ulong)1 << MSR_LE;
        }
    } else if (msr_ile) {
        new_msr |= (target_ulong)1 << MSR_LE;
    }
#else
    if (msr_ile) {
        new_msr |= (target_ulong)1 << MSR_LE;
    }
#endif

    /* Jump to handler */
    vector = env->excp_vectors[excp];
#ifdef _MSC_VER
    if (vector == (target_ulong)(0ULL - 1ULL)) {
#else
    if (vector == (target_ulong)-1ULL) {
#endif
        cpu_abort(cs, "Raised an exception without defined vector %d\n",
                  excp);
    }
    vector |= env->excp_prefix;

    /*
     * AIL only works if there is no HV transition and we are running
     * with translations enabled
     */
    if (!((msr >> MSR_IR) & 1) || !((msr >> MSR_DR) & 1) ||
        ((new_msr & MSR_HVB) && !(msr & MSR_HVB))) {
        ail = 0;
    }
    /* Handle AIL */
    if (ail) {
        new_msr |= (1 << MSR_IR) | (1 << MSR_DR);
        vector |= ppc_excp_vector_offset(cs, ail);
    }

#if defined(TARGET_PPC64)
    if (excp_model == POWERPC_EXCP_BOOKE) {
        if (env->spr[SPR_BOOKE_EPCR] & EPCR_ICM) {
            /* Cat.64-bit: EPCR.ICM is copied to MSR.CM */
            new_msr |= (target_ulong)1 << MSR_CM;
        } else {
            vector = (uint32_t)vector;
        }
    } else {
        if (!msr_isf && !(env->mmu_model & POWERPC_MMU_64)) {
            vector = (uint32_t)vector;
        } else {
            new_msr |= (target_ulong)1 << MSR_SF;
        }
    }
#endif

    powerpc_set_excp_state(cpu, vector, new_msr);
}

void ppc_cpu_do_interrupt(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    powerpc_excp(cpu, env->excp_model, cs->exception_index);
}

static void ppc_hw_interrupt(CPUPPCState *env)
{
    PowerPCCPU *cpu = env_archcpu(env);
    bool async_deliver;

    /* External reset */
    if (env->pending_interrupts & (1 << PPC_INTERRUPT_RESET)) {
        env->pending_interrupts &= ~(1 << PPC_INTERRUPT_RESET);
        powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_RESET);
        return;
    }
    /* Machine check exception */
    if (env->pending_interrupts & (1 << PPC_INTERRUPT_MCK)) {
        env->pending_interrupts &= ~(1 << PPC_INTERRUPT_MCK);
        powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_MCHECK);
        return;
    }
#if 0 /* TODO */
    /* External debug exception */
    if (env->pending_interrupts & (1 << PPC_INTERRUPT_DEBUG)) {
        env->pending_interrupts &= ~(1 << PPC_INTERRUPT_DEBUG);
        powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_DEBUG);
        return;
    }
#endif

    /*
     * For interrupts that gate on MSR:EE, we need to do something a
     * bit more subtle, as we need to let them through even when EE is
     * clear when coming out of some power management states (in order
     * for them to become a 0x100).
     */
    async_deliver = (msr_ee != 0) || env->resume_as_sreset;

    /* Hypervisor decrementer exception */
    if (env->pending_interrupts & (1 << PPC_INTERRUPT_HDECR)) {
        /* LPCR will be clear when not supported so this will work */
        bool hdice = !!(env->spr[SPR_LPCR] & LPCR_HDICE);
        if ((async_deliver || msr_hv == 0) && hdice) {
            /* HDEC clears on delivery */
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_HDECR);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_HDECR);
            return;
        }
    }

    /* Hypervisor virtualization interrupt */
    if (env->pending_interrupts & (1 << PPC_INTERRUPT_HVIRT)) {
        /* LPCR will be clear when not supported so this will work */
        bool hvice = !!(env->spr[SPR_LPCR] & LPCR_HVICE);
        if ((async_deliver || msr_hv == 0) && hvice) {
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_HVIRT);
            return;
        }
    }

    /* External interrupt can ignore MSR:EE under some circumstances */
    if (env->pending_interrupts & (1 << PPC_INTERRUPT_EXT)) {
        bool lpes0 = !!(env->spr[SPR_LPCR] & LPCR_LPES0);
        bool heic = !!(env->spr[SPR_LPCR] & LPCR_HEIC);
        /* HEIC blocks delivery to the hypervisor */
        if ((async_deliver && !(heic && msr_hv && !msr_pr)) ||
            (env->has_hv_mode && msr_hv == 0 && !lpes0)) {
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_EXTERNAL);
            return;
        }
    }
    if (msr_ce != 0) {
        /* External critical interrupt */
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_CEXT)) {
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_CRITICAL);
            return;
        }
    }
    if (async_deliver != 0) {
        /* Watchdog timer on embedded PowerPC */
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_WDT)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_WDT);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_WDT);
            return;
        }
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_CDOORBELL)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_CDOORBELL);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_DOORCI);
            return;
        }
        /* Fixed interval timer on embedded PowerPC */
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_FIT)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_FIT);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_FIT);
            return;
        }
        /* Programmable interval timer on embedded PowerPC */
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_PIT)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_PIT);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_PIT);
            return;
        }
        /* Decrementer exception */
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_DECR)) {
            if (ppc_decr_clear_on_delivery(env)) {
                env->pending_interrupts &= ~(1 << PPC_INTERRUPT_DECR);
            }
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_DECR);
            return;
        }
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_DOORBELL)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_DOORBELL);
            if (is_book3s_arch2x(env)) {
                powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_SDOOR);
            } else {
                powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_DOORI);
            }
            return;
        }
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_HDOORBELL)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_HDOORBELL);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_SDOOR_HV);
            return;
        }
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_PERFM)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_PERFM);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_PERFM);
            return;
        }
        /* Thermal interrupt */
        if (env->pending_interrupts & (1 << PPC_INTERRUPT_THERM)) {
            env->pending_interrupts &= ~(1 << PPC_INTERRUPT_THERM);
            powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_THERM);
            return;
        }
    }

    if (env->resume_as_sreset) {
        /*
         * This is a bug ! It means that has_work took us out of halt without
         * anything to deliver while in a PM state that requires getting
         * out via a 0x100
         *
         * This means we will incorrectly execute past the power management
         * instruction instead of triggering a reset.
         *
         * It generally means a discrepancy between the wakup conditions in the
         * processor has_work implementation and the logic in this function.
         */
        cpu_abort(env_cpu(env),
                  "Wakeup from PM state but interrupt Undelivered");
    }
}

void ppc_cpu_do_system_reset(CPUState *cs, target_ulong vector)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    powerpc_excp(cpu, env->excp_model, POWERPC_EXCP_RESET);
    if (vector != -1) {
        env->nip = vector;
    }
}

void ppc_cpu_do_fwnmi_machine_check(CPUState *cs, target_ulong vector)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);
    target_ulong msr = 0;

    /*
     * Set MSR and NIP for the handler, SRR0/1, DAR and DSISR have already
     * been set by KVM.
     */
    msr = (1ULL << MSR_ME);
    msr |= env->msr & (1ULL << MSR_SF);
    if (!(*pcc->interrupts_big_endian)(cpu)) {
        msr |= (1ULL << MSR_LE);
    }

    powerpc_set_excp_state(cpu, vector, msr);
}

bool ppc_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    if (interrupt_request & CPU_INTERRUPT_HARD) {
        ppc_hw_interrupt(env);
        if (env->pending_interrupts == 0) {
            cs->interrupt_request &= ~CPU_INTERRUPT_HARD;
        }
        return true;
    }
    return false;
}

#if defined(DEBUG_OP)
static void cpu_dump_rfi(target_ulong RA, target_ulong msr)
{
    qemu_log("Return from exception at " TARGET_FMT_lx " with flags "
             TARGET_FMT_lx "\n", RA, msr);
}
#endif

/*****************************************************************************/
/* Exceptions processing helpers */

void raise_exception_err_ra(CPUPPCState *env, uint32_t exception,
                            uint32_t error_code, uintptr_t raddr)
{
    CPUState *cs = env_cpu(env);

    cs->exception_index = exception;
    env->error_code = error_code;
    cpu_loop_exit_restore(cs, raddr);
}

void raise_exception_err(CPUPPCState *env, uint32_t exception,
                         uint32_t error_code)
{
    raise_exception_err_ra(env, exception, error_code, 0);
}

void raise_exception(CPUPPCState *env, uint32_t exception)
{
    raise_exception_err_ra(env, exception, 0, 0);
}

void raise_exception_ra(CPUPPCState *env, uint32_t exception,
                        uintptr_t raddr)
{
    raise_exception_err_ra(env, exception, 0, raddr);
}

void helper_raise_exception_err(CPUPPCState *env, uint32_t exception,
                                uint32_t error_code)
{
    raise_exception_err_ra(env, exception, error_code, 0);
}

void helper_raise_exception(CPUPPCState *env, uint32_t exception)
{
    raise_exception_err_ra(env, exception, 0, 0);
}

void helper_store_msr(CPUPPCState *env, target_ulong val)
{
    uint32_t excp = hreg_store_msr(env, val, 0);

    if (excp != 0) {
        CPUState *cs = env_cpu(env);
        cpu_interrupt_exittb(cs);
        raise_exception(env, excp);
    }
}

#if defined(TARGET_PPC64)
void helper_pminsn(CPUPPCState *env, powerpc_pm_insn_t insn)
{
    CPUState *cs;

    cs = env_cpu(env);
    cs->halted = 1;

    /*
     * The architecture specifies that HDEC interrupts are discarded
     * in PM states
     */
    env->pending_interrupts &= ~(1 << PPC_INTERRUPT_HDECR);

    /* Condition for waking up at 0x100 */
    env->resume_as_sreset = (insn != PPC_PM_STOP) ||
        (env->spr[SPR_PSSCR] & PSSCR_EC);
}
#endif /* defined(TARGET_PPC64) */

static inline void do_rfi(CPUPPCState *env, target_ulong nip, target_ulong msr)
{
    CPUState *cs = env_cpu(env);

    /* MSR:POW cannot be set by any form of rfi */
    msr &= ~(1ULL << MSR_POW);

#if defined(TARGET_PPC64)
    /* Switching to 32-bit ? Crop the nip */
    if (!msr_is_64bit(env, msr)) {
        nip = (uint32_t)nip;
    }
#else
    nip = (uint32_t)nip;
#endif
    /* XXX: beware: this is false if VLE is supported */
    env->nip = nip & ~((target_ulong)0x00000003);
    hreg_store_msr(env, msr, 1);
#if defined(DEBUG_OP)
    cpu_dump_rfi(env->nip, env->msr);
#endif
    /*
     * No need to raise an exception here, as rfi is always the last
     * insn of a TB
     */
    cpu_interrupt_exittb(cs);
    /* Reset the reservation */
    env->reserve_addr = -1;

    /* Context synchronizing: check if TCG TLB needs flush */
    check_tlb_flush(env, false);
}

void helper_rfi(CPUPPCState *env)
{
    do_rfi(env, env->spr[SPR_SRR0], env->spr[SPR_SRR1] & 0xfffffffful);
}

#define MSR_BOOK3S_MASK
#if defined(TARGET_PPC64)
void helper_rfid(CPUPPCState *env)
{
    /*
     * The architeture defines a number of rules for which bits can
     * change but in practice, we handle this in hreg_store_msr()
     * which will be called by do_rfi(), so there is no need to filter
     * here
     */
    do_rfi(env, env->spr[SPR_SRR0], env->spr[SPR_SRR1]);
}

void helper_hrfid(CPUPPCState *env)
{
    do_rfi(env, env->spr[SPR_HSRR0], env->spr[SPR_HSRR1]);
}
#endif

/*****************************************************************************/
/* Embedded PowerPC specific helpers */
void helper_40x_rfci(CPUPPCState *env)
{
    do_rfi(env, env->spr[SPR_40x_SRR2], env->spr[SPR_40x_SRR3]);
}

void helper_rfci(CPUPPCState *env)
{
    do_rfi(env, env->spr[SPR_BOOKE_CSRR0], env->spr[SPR_BOOKE_CSRR1]);
}

void helper_rfdi(CPUPPCState *env)
{
    /* FIXME: choose CSRR1 or DSRR1 based on cpu type */
    do_rfi(env, env->spr[SPR_BOOKE_DSRR0], env->spr[SPR_BOOKE_DSRR1]);
}

void helper_rfmci(CPUPPCState *env)
{
    /* FIXME: choose CSRR1 or MCSRR1 based on cpu type */
    do_rfi(env, env->spr[SPR_BOOKE_MCSRR0], env->spr[SPR_BOOKE_MCSRR1]);
}

void helper_tw(CPUPPCState *env, target_ulong arg1, target_ulong arg2,
               uint32_t flags)
{
    if (!likely(!(((int32_t)arg1 < (int32_t)arg2 && (flags & 0x10)) ||
                  ((int32_t)arg1 > (int32_t)arg2 && (flags & 0x08)) ||
                  ((int32_t)arg1 == (int32_t)arg2 && (flags & 0x04)) ||
                  ((uint32_t)arg1 < (uint32_t)arg2 && (flags & 0x02)) ||
                  ((uint32_t)arg1 > (uint32_t)arg2 && (flags & 0x01))))) {
        raise_exception_err_ra(env, POWERPC_EXCP_PROGRAM,
                               POWERPC_EXCP_TRAP, GETPC());
    }
}

#if defined(TARGET_PPC64)
void helper_td(CPUPPCState *env, target_ulong arg1, target_ulong arg2,
               uint32_t flags)
{
    if (!likely(!(((int64_t)arg1 < (int64_t)arg2 && (flags & 0x10)) ||
                  ((int64_t)arg1 > (int64_t)arg2 && (flags & 0x08)) ||
                  ((int64_t)arg1 == (int64_t)arg2 && (flags & 0x04)) ||
                  ((uint64_t)arg1 < (uint64_t)arg2 && (flags & 0x02)) ||
                  ((uint64_t)arg1 > (uint64_t)arg2 && (flags & 0x01))))) {
        raise_exception_err_ra(env, POWERPC_EXCP_PROGRAM,
                               POWERPC_EXCP_TRAP, GETPC());
    }
}
#endif

/*****************************************************************************/
/* PowerPC 601 specific instructions (POWER bridge) */

void helper_rfsvc(CPUPPCState *env)
{
    do_rfi(env, env->lr, env->ctr & 0x0000FFFF);
}

/* Embedded.Processor Control */
static int dbell2irq(target_ulong rb)
{
    int msg = rb & DBELL_TYPE_MASK;
    int irq = -1;

    switch (msg) {
    case DBELL_TYPE_DBELL:
        irq = PPC_INTERRUPT_DOORBELL;
        break;
    case DBELL_TYPE_DBELL_CRIT:
        irq = PPC_INTERRUPT_CDOORBELL;
        break;
    case DBELL_TYPE_G_DBELL:
    case DBELL_TYPE_G_DBELL_CRIT:
    case DBELL_TYPE_G_DBELL_MC:
        /* XXX implement */
    default:
        break;
    }

    return irq;
}

void helper_msgclr(CPUPPCState *env, target_ulong rb)
{
    int irq = dbell2irq(rb);

    if (irq < 0) {
        return;
    }

    env->pending_interrupts &= ~(1 << irq);
}

void helper_msgsnd(CPUPPCState *env, target_ulong rb)
{
    int irq = dbell2irq(rb);
    int pir = rb & DBELL_PIRTAG_MASK;
    CPUState *cs = (CPUState *)env;
    PowerPCCPU *cpu = POWERPC_CPU(env->uc->cpu);
    CPUPPCState *cenv = &cpu->env;

    if (irq < 0) {
        return;
    }

    if ((rb & DBELL_BRDCAST) || (cenv->spr[SPR_BOOKE_PIR] == pir)) {
        cenv->pending_interrupts |= 1 << irq;
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

/* Server Processor Control */

static bool dbell_type_server(target_ulong rb)
{
    /*
     * A Directed Hypervisor Doorbell message is sent only if the
     * message type is 5. All other types are reserved and the
     * instruction is a no-op
     */
    return (rb & DBELL_TYPE_MASK) == DBELL_TYPE_DBELL_SERVER;
}

void helper_book3s_msgclr(CPUPPCState *env, target_ulong rb)
{
    if (!dbell_type_server(rb)) {
        return;
    }

    env->pending_interrupts &= ~(1 << PPC_INTERRUPT_HDOORBELL);
}

static void book3s_msgsnd_common(CPUPPCState *env, int pir, int irq)
{
    CPUState *cs = (CPUState *)env;
    PowerPCCPU *cpu = POWERPC_CPU(env->uc->cpu);
    CPUPPCState *cenv = &cpu->env;

    /* TODO: broadcast message to all threads of the same  processor */
    if (cenv->spr_cb[SPR_PIR].default_value == pir) {
        cenv->pending_interrupts |= 1 << irq;
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

void helper_book3s_msgsnd(CPUPPCState *env, target_ulong rb)
{
    int pir = rb & DBELL_PROCIDTAG_MASK;

    if (!dbell_type_server(rb)) {
        return;
    }

    book3s_msgsnd_common(env, pir, PPC_INTERRUPT_HDOORBELL);
}

#if defined(TARGET_PPC64)
void helper_book3s_msgclrp(CPUPPCState *env, target_ulong rb)
{
    helper_hfscr_facility_check(env, HFSCR_MSGP, "msgclrp", HFSCR_IC_MSGP);

    if (!dbell_type_server(rb)) {
        return;
    }

    env->pending_interrupts &= ~(1 << PPC_INTERRUPT_DOORBELL);
}

/*
 * sends a message to other threads that are on the same
 * multi-threaded processor
 */
void helper_book3s_msgsndp(CPUPPCState *env, target_ulong rb)
{
    int pir = env->spr_cb[SPR_PIR].default_value;

    helper_hfscr_facility_check(env, HFSCR_MSGP, "msgsndp", HFSCR_IC_MSGP);

    if (!dbell_type_server(rb)) {
        return;
    }

    /* TODO: TCG supports only one thread */

    book3s_msgsnd_common(env, pir, PPC_INTERRUPT_DOORBELL);
}
#endif

void ppc_cpu_do_unaligned_access(CPUState *cs, vaddr vaddr,
                                 MMUAccessType access_type,
                                 int mmu_idx, uintptr_t retaddr)
{
    CPUPPCState *env = cs->env_ptr;
    uint32_t insn;

    /* Restore state and reload the insn we executed, for filling in DSISR.  */
    cpu_restore_state(cs, retaddr, true);
    insn = cpu_ldl_code(env, env->nip);

    cs->exception_index = POWERPC_EXCP_ALIGN;
    env->error_code = insn & 0x03FF0000;
    cpu_loop_exit(cs);
}
