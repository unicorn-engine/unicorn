/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "sysemu/sysemu.h"
#include "exec/address-spaces.h"
#include "exec/tb-hash.h"

#include "uc_priv.h"

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc_ptr;

    // Unicorn: commented out
    //qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
    //                       "Trace %p [" TARGET_FMT_lx "] %s\n",
    //                       itb->tc_ptr, itb->pc, lookup_symbol(itb->pc));
    ret = tcg_qemu_tb_exec(env, tb_ptr);
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    //trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(env->uc, cpu);
        // Unicorn: commented out
        //qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
        //                       "Stopped execution of TB chain before %p ["
        //                       TARGET_FMT_lx "] %s\n",
        //                       last_tb->tc_ptr, last_tb->pc,
        //                       lookup_symbol(last_tb->pc));
        if (cc->synchronize_from_tb) {
            // avoid sync twice when helper_uc_tracecode() already did this.
            if (env->uc->emu_counter <= env->uc->emu_count &&
                    !env->uc->stop_request && !env->uc->quit_request) {
                cc->synchronize_from_tb(cpu, last_tb);
            }
        } else {
            assert(cc->set_pc);
            // avoid sync twice when helper_uc_tracecode() already did this.
            if (env->uc->emu_counter <= env->uc->emu_count && !env->uc->quit_request) {
                cc->set_pc(cpu, last_tb->pc);
            }
        }
    }
    if (tb_exit == TB_EXIT_REQUESTED) {
        /* We were asked to stop executing TBs (probably a pending
         * interrupt. We've now stopped, so clear the flag.
         */
        cpu->tcg_exit_req = 0;
    }
    return ret;
}

static TranslationBlock *tb_find_slow(CPUState *cpu,
                                      target_ulong pc,
                                      target_ulong cs_base,
                                      uint64_t flags)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    target_ulong virt_page2;

    /* find translated block using physical mappings */
    phys_pc = get_page_addr_code(env, pc);  // qq
    if (phys_pc == -1) { // invalid code?
        return NULL;
    }
    phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = &tcg_ctx->tb_ctx.tb_phys_hash[h];
    for(;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;
        if (tb->pc == pc &&
                tb->page_addr[0] == phys_page1 &&
                tb->cs_base == cs_base &&
                tb->flags == flags) {
            /* check next page if needed */
            if (tb->page_addr[1] != -1) {
                tb_page_addr_t phys_page2;

                virt_page2 = (pc & TARGET_PAGE_MASK) +
                    TARGET_PAGE_SIZE;
                phys_page2 = get_page_addr_code(env, virt_page2);
                if (tb->page_addr[1] == phys_page2)
                    goto found;
            } else {
                goto found;
            }
        }
        ptb1 = &tb->phys_hash_next;
    }
not_found:
    /* if no translated code available, then translate it now */
    tb = tb_gen_code(cpu, pc, cs_base, (int)flags, 0);   // qq

found:
    /* Move the last found TB to the head of the list */
    if (likely(*ptb1)) {
        *ptb1 = tb->phys_hash_next;
        tb->phys_hash_next = tcg_ctx->tb_ctx.tb_phys_hash[h];
        tcg_ctx->tb_ctx.tb_phys_hash[h] = tb;
    }
    /* we add the TB in the virtual pc hash table */
    cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

static inline TranslationBlock *tb_find_fast(CPUState *cpu,
                                             TranslationBlock **last_tb,
                                             int tb_exit)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    // Unicorn: commented out
    //tb_lock();
    tb = cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                tb->flags != flags)) {
        tb = tb_find_slow(cpu, pc, cs_base, flags); // qq
    }
    if (cpu->tb_flushed) {
        /* Ensure that no TB jump will be modified as the
         * translation buffer has been flushed.
         */
        *last_tb = NULL;
        cpu->tb_flushed = false;
    }
#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        *last_tb = NULL;
    }
#endif
    /* See if we can patch the calling TB. */
    if (*last_tb && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        tb_add_jump(*last_tb, tb_exit, tb);
    }
    // Unicorn: commented out
    //tb_unlock();
    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
        if (!cpu_has_work(cpu)) {
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(struct uc_struct *uc, CPUState *cpu, int *ret)
{
    struct hook *hook;

    if (cpu->exception_index >= 0) {
        if (uc->stop_interrupt && uc->stop_interrupt(cpu->exception_index)) {
            cpu->halted = 1;
            uc->invalid_error = UC_ERR_INSN_INVALID;
            *ret = EXCP_HLT;
            return true;
        }

        if (cpu->exception_index >= EXCP_INTERRUPT) {
            /* exit request from the cpu execution loop */
            *ret = cpu->exception_index;
            if (*ret == EXCP_DEBUG) {
                cpu_handle_debug_exception(cpu);
            }
            cpu->exception_index = -1;
            return true;
        } else {
#if defined(CONFIG_USER_ONLY)
            /* if user mode only, we simulate a fake exception
               which will be handled outside the cpu execution
               loop */
#if defined(TARGET_I386)
            CPUClass *cc = CPU_GET_CLASS(cpu);
            cc->do_interrupt(cpu);
#endif
            *ret = cpu->exception_index;
            cpu->exception_index = -1;
            return true;
#else
            bool catched = false;
            // Unicorn: call registered interrupt callbacks
            HOOK_FOREACH_VAR_DECLARE;
            HOOK_FOREACH(uc, hook, UC_HOOK_INTR) {
                ((uc_cb_hookintr_t)hook->callback)(uc, cpu->exception_index, hook->user_data);
                catched = true;
            }
            // Unicorn: If un-catched interrupt, stop executions.
            if (!catched) {
                cpu->halted = 1;
                uc->invalid_error = UC_ERR_EXCEPTION;
                *ret = EXCP_HLT;
                return true;
            }
            cpu->exception_index = -1;
#endif
        }
    }

    return false;
}

static inline void cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);
    int interrupt_request = cpu->interrupt_request;

    if (unlikely(interrupt_request)) {
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            cpu_loop_exit(cpu);
        }
        if (interrupt_request & CPU_INTERRUPT_HALT) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            cpu_loop_exit(cpu);
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu->uc, cpu);
            CPUArchState *env = &x86_cpu->env;
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            cpu_loop_exit(cpu);
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            cpu_reset(cpu);
        }
#endif
        else {
            /* The target hook has 3 exit conditions:
               False when the interrupt isn't processed,
               True when it is, and we should restart on a new TB,
               and via longjmp via cpu_loop_exit.  */
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }

        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }
    }
    if (unlikely(cpu->exit_request)) {
        cpu->exit_request = 0;
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit)
{
    uintptr_t ret;

    if (unlikely(cpu->exit_request)) {
        return;
    }

    /* execute the generated code */
    ret = cpu_tb_exec(cpu, tb);
    *last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    switch (*tb_exit) {
    case TB_EXIT_REQUESTED:
        /* Something asked us to stop executing
         * chained TBs; just continue round the main
         * loop. Whatever requested the exit will also
         * have set something else (eg exit_request or
         * interrupt_request) which we will handle
         * next time around the loop.  But we need to
         * ensure the tcg_exit_req read in generated code
         * comes before the next read of cpu->exit_request
         * or cpu->interrupt_request.
         */
        smp_rmb();
        *last_tb = NULL;
        break;
    default:
        break;
    }
}

/* main execution loop */

int cpu_exec(struct uc_struct *uc, CPUState *cpu)
{
    CPUArchState *env = cpu->env_ptr;
    CPUClass *cc = CPU_GET_CLASS(uc, cpu);
    int ret;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    uc->current_cpu = cpu;
    atomic_mb_set(&uc->tcg_current_cpu, cpu);

    if (unlikely(atomic_mb_read(&uc->exit_request))) {
        cpu->exit_request = 1;
    }

    cc->cpu_exec_enter(cpu);
    cpu->exception_index = -1;
    env->invalid_error = UC_ERR_OK;

    for(;;) {
        TranslationBlock *tb, *last_tb;
        int tb_exit = 0;

        /* prepare setjmp context for exception handling */
        if (sigsetjmp(cpu->jmp_env, 0) == 0) {
            if (uc->stop_request || uc->invalid_error) {
                break;
            }

            /* if an exception is pending, we execute it here */
            if (cpu_handle_exception(uc, cpu, &ret)) {
                break;
            }

            last_tb = NULL; /* forget the last executed TB after exception */
            cpu->tb_flushed = false; /* reset before first TB lookup */
            for(;;) {
                cpu_handle_interrupt(cpu, &last_tb);
                tb = tb_find_fast(cpu, &last_tb, tb_exit);
                if (!tb) {   // invalid TB due to invalid code?
                    uc->invalid_error = UC_ERR_FETCH_UNMAPPED;
                    ret = EXCP_HLT;
                    break;
                }
                cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
            } /* for(;;) */
        } else {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
            /* Some compilers wrongly smash all local variables after
             * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
             * Reload essential local variables here for those compilers.
             * Newer versions of gcc would complain about this code (-Wclobbered). */
            cpu = uc->current_cpu;
            env = cpu->env_ptr;
            cc = CPU_GET_CLASS(uc, cpu);
#else /* buggy compiler */
            /* Assert that the compiler does not smash local variables. */
            g_assert(cpu == current_cpu);
            g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
            cpu->can_do_io = 1;
        }
    } /* for(;;) */

    cc->cpu_exec_exit(cpu);

    // Unicorn: flush JIT cache to because emulation might stop in
    // the middle of translation, thus generate incomplete code.
    // TODO: optimize this for better performance
    tb_flush(cpu);

    /* fail safe : never use current_cpu outside cpu_exec() */
    uc->current_cpu = NULL;
    /* Does not need atomic_mb_set because a spurious wakeup is okay.  */
    atomic_set(&uc->tcg_current_cpu, NULL);
    return ret;
}
