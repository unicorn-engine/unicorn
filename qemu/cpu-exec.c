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

#include "tcg.h"
#include "sysemu/sysemu.h"

#include "uc_priv.h"

static tcg_target_ulong cpu_tb_exec(CPUState *cpu, uint8_t *tb_ptr);
static TranslationBlock *tb_find_slow(CPUArchState *env, target_ulong pc,
        target_ulong cs_base, uint64_t flags);
static TranslationBlock *tb_find_fast(CPUArchState *env);
static void cpu_handle_debug_exception(CPUArchState *env);

void cpu_loop_exit(CPUState *cpu)
{
    cpu->current_tb = NULL;
    siglongjmp(cpu->jmp_env, 1);
}

/* exit the current TB from a signal handler. The host registers are
   restored in a state compatible with the CPU emulator
   */
void cpu_resume_from_signal(CPUState *cpu, void *puc)
{
    /* XXX: restore cpu registers saved in host registers */
    cpu->exception_index = -1;
    siglongjmp(cpu->jmp_env, 1);
}

/* main execution loop */

int cpu_exec(struct uc_struct *uc, CPUArchState *env)   // qq
{
    CPUState *cpu = ENV_GET_CPU(env);
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    CPUClass *cc = CPU_GET_CLASS(uc, cpu);
#ifdef TARGET_I386
    X86CPU *x86_cpu = X86_CPU(uc, cpu);
#endif
    int ret = 0, interrupt_request;
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    uintptr_t next_tb;
    struct hook *hook;

    if (cpu->halted) {
        if (!cpu_has_work(cpu)) {
            return EXCP_HALTED;
        }

        cpu->halted = 0;
    }

    uc->current_cpu = cpu;

    /* As long as current_cpu is null, up to the assignment just above,
     * requests by other threads to exit the execution loop are expected to
     * be issued using the exit_request global. We must make sure that our
     * evaluation of the global value is performed past the current_cpu
     * value transition point, which requires a memory barrier as well as
     * an instruction scheduling constraint on modern architectures.  */
    smp_mb();

    if (unlikely(uc->exit_request)) {
        cpu->exit_request = 1;
    }

    cc->cpu_exec_enter(cpu);
    cpu->exception_index = -1;
    env->invalid_error = UC_ERR_OK;

    /* prepare setjmp context for exception handling */
    for(;;) {
        if (sigsetjmp(cpu->jmp_env, 0) == 0) {
            if (uc->stop_request || uc->invalid_error) {
                break;
            }

            /* if an exception is pending, we execute it here */
            if (cpu->exception_index >= 0) {
                //printf(">>> GOT INTERRUPT. exception idx = %x\n", cpu->exception_index);	// qq
                if (cpu->exception_index >= EXCP_INTERRUPT) {
                    /* exit request from the cpu execution loop */
                    ret = cpu->exception_index;
                    if (ret == EXCP_DEBUG) {
                        cpu_handle_debug_exception(env);
                    }
                    break;
                } else {
                    bool catched = false;
#if defined(CONFIG_USER_ONLY)
                    /* if user mode only, we simulate a fake exception
                       which will be handled outside the cpu execution
                       loop */
#if defined(TARGET_I386)
                    cc->do_interrupt(cpu);
#endif
                    ret = cpu->exception_index;
                    break;
#else
#if defined(TARGET_X86_64)
                    if (env->exception_is_int) {
                        // point EIP to the next instruction after INT
                        env->eip = env->exception_next_eip;
                    }
#endif
#if defined(TARGET_MIPS) || defined(TARGET_MIPS64)
                    env->active_tc.PC = uc->next_pc;
#endif
                    if (uc->stop_interrupt && uc->stop_interrupt(cpu->exception_index)) {
                        // Unicorn: call registered invalid instruction callbacks
                        HOOK_FOREACH_VAR_DECLARE;
                        HOOK_FOREACH(uc, hook, UC_HOOK_INSN_INVALID) {
                            if (hook->to_delete)
                                continue;
                            catched = ((uc_cb_hookinsn_invalid_t)hook->callback)(uc, hook->user_data);
                            if (catched)
                                break;
                        }
                        if (!catched)
                            uc->invalid_error = UC_ERR_INSN_INVALID;
                    } else {
                        // Unicorn: call registered interrupt callbacks
                        HOOK_FOREACH_VAR_DECLARE;
                        HOOK_FOREACH(uc, hook, UC_HOOK_INTR) {
                            if (hook->to_delete)
                                continue;
                            ((uc_cb_hookintr_t)hook->callback)(uc, cpu->exception_index, hook->user_data);
                            catched = true;
                        }
                        if (!catched)
                            uc->invalid_error = UC_ERR_EXCEPTION;
                    }

                    // Unicorn: If un-catched interrupt, stop executions.
                    if (!catched) {
                        cpu->halted = 1;
                        ret = EXCP_HLT;
                        break;
                    }

                    cpu->exception_index = -1;
#endif
                }
            }

            next_tb = 0; /* force lookup of first TB */
            for(;;) {
                interrupt_request = cpu->interrupt_request;

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
                    if (interrupt_request & CPU_INTERRUPT_INIT) {
                        cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0);
                        do_cpu_init(x86_cpu);
                        cpu->exception_index = EXCP_HALTED;
                        cpu_loop_exit(cpu);
                    }
#else
                    if (interrupt_request & CPU_INTERRUPT_RESET) {
                        cpu_reset(cpu);
                    }
#endif
                    /* The target hook has 3 exit conditions:
                       False when the interrupt isn't processed,
                       True when it is, and we should restart on a new TB,
                       and via longjmp via cpu_loop_exit.  */
                    if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                        next_tb = 0;
                    }

                    /* Don't use the cached interrupt_request value,
                       do_interrupt may have updated the EXITTB flag. */
                    if (cpu->interrupt_request & CPU_INTERRUPT_EXITTB) {
                        cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
                        /* ensure that no TB jump will be modified as
                           the program flow was changed */
                        next_tb = 0;
                    }
                }

                if (unlikely(cpu->exit_request)) {
                    cpu->exit_request = 0;
                    cpu->exception_index = EXCP_INTERRUPT;
                    cpu_loop_exit(cpu);
                }

                tb = tb_find_fast(env);	// qq
                if (!tb) {   // invalid TB due to invalid code?
                    uc->invalid_error = UC_ERR_FETCH_UNMAPPED;
                    ret = EXCP_HLT;
                    break;
                }

                /* Note: we do it here to avoid a gcc bug on Mac OS X when
                   doing it in tb_find_slow */
                if (tcg_ctx->tb_ctx.tb_invalidated_flag) {
                    /* as some TB could have been invalidated because
                       of memory exceptions while generating the code, we
                       must recompute the hash index here */
                    next_tb = 0;
                    tcg_ctx->tb_ctx.tb_invalidated_flag = 0;
                }

                /* see if we can patch the calling TB. When the TB
                   spans two pages, we cannot safely do a direct
                   jump. */
                if (next_tb != 0 && tb->page_addr[1] == -1) {
                    tb_add_jump((TranslationBlock *)(next_tb & ~TB_EXIT_MASK),
                            next_tb & TB_EXIT_MASK, tb);
                }

                /* cpu_interrupt might be called while translating the
                   TB, but before it is linked into a potentially
                   infinite loop and becomes env->current_tb. Avoid
                   starting execution if there is a pending interrupt. */
                cpu->current_tb = tb;
                barrier();
                if (likely(!cpu->exit_request)) {
                    tc_ptr = tb->tc_ptr;
                    /* execute the generated code */
                    next_tb = cpu_tb_exec(cpu, tc_ptr);	// qq

                    switch (next_tb & TB_EXIT_MASK) {
                        case TB_EXIT_REQUESTED:
                            /* Something asked us to stop executing
                             * chained TBs; just continue round the main
                             * loop. Whatever requested the exit will also
                             * have set something else (eg exit_request or
                             * interrupt_request) which we will handle
                             * next time around the loop.
                             */
                            tb = (TranslationBlock *)(next_tb & ~TB_EXIT_MASK);
                            next_tb = 0;
                            break;
                        default:
                            break;
                    }
                }

                cpu->current_tb = NULL;
                /* reset soft MMU for next block (it can currently
                   only be set by a memory fault) */
            } /* for(;;) */
        } else {
            /* Reload env after longjmp - the compiler may have smashed all
             * local variables as longjmp is marked 'noreturn'. */
            cpu = uc->current_cpu;
            env = cpu->env_ptr;
            cc = CPU_GET_CLASS(uc, cpu);
#ifdef TARGET_I386
            x86_cpu = X86_CPU(uc, cpu);
#endif
        }
    } /* for(;;) */

    // Unicorn: Clear any TCG exit flag that might have been left set by exit requests
    uc->current_cpu->tcg_exit_req = 0;

    cc->cpu_exec_exit(cpu);

    // Unicorn: flush JIT cache to because emulation might stop in
    // the middle of translation, thus generate incomplete code.
    // TODO: optimize this for better performance
    tb_flush(env);

    /* fail safe : never use current_cpu outside cpu_exec() */
    // uc->current_cpu = NULL;

    return ret;
}

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static tcg_target_ulong cpu_tb_exec(CPUState *cpu, uint8_t *tb_ptr)
{
    CPUArchState *env = cpu->env_ptr;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    uintptr_t next_tb;

    next_tb = tcg_qemu_tb_exec(env, tb_ptr);

    if ((next_tb & TB_EXIT_MASK) > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(env->uc, cpu);
        TranslationBlock *tb = (TranslationBlock *)(next_tb & ~TB_EXIT_MASK);

        /* Both set_pc() & synchronize_fromtb() can be ignored when code tracing hook is installed,
         * or timer mode is in effect, since these already fix the PC.
         */
        if (!HOOK_EXISTS(env->uc, UC_HOOK_CODE) && !env->uc->timeout) {
            // We should sync pc for R/W error.
            switch (env->invalid_error) {
                case UC_ERR_WRITE_PROT:
                case UC_ERR_READ_PROT:
                case UC_ERR_FETCH_PROT:
                case UC_ERR_WRITE_UNMAPPED:
                case UC_ERR_READ_UNMAPPED:
                case UC_ERR_FETCH_UNMAPPED:
                case UC_ERR_WRITE_UNALIGNED:
                case UC_ERR_READ_UNALIGNED:
                case UC_ERR_FETCH_UNALIGNED:
                    break;
                default:
                    if (cc->synchronize_from_tb) {
                        // avoid sync twice when helper_uc_tracecode() already did this.
                        if (env->uc->emu_counter <= env->uc->emu_count &&
                                !env->uc->stop_request && !env->uc->quit_request)
                            cc->synchronize_from_tb(cpu, tb);
                    } else {
                        assert(cc->set_pc);
                        // avoid sync twice when helper_uc_tracecode() already did this.
                        if (env->uc->emu_counter <= env->uc->emu_count &&
                                !env->uc->stop_request && !env->uc->quit_request)
                            cc->set_pc(cpu, tb->pc);
                    }
            }
        }
    }

    if ((next_tb & TB_EXIT_MASK) == TB_EXIT_REQUESTED) {
        /* We were asked to stop executing TBs (probably a pending
         * interrupt. We've now stopped, so clear the flag.
         */
        cpu->tcg_exit_req = 0;
    }

    return next_tb;
}

static TranslationBlock *tb_find_slow(CPUArchState *env, target_ulong pc,
        target_ulong cs_base, uint64_t flags)   // qq
{
    CPUState *cpu = ENV_GET_CPU(env);
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    target_ulong virt_page2;

    tcg_ctx->tb_ctx.tb_invalidated_flag = 0;

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
    if (tb == NULL) {
        return NULL;
    }

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

static TranslationBlock *tb_find_fast(CPUArchState *env)    // qq
{
    CPUState *cpu = ENV_GET_CPU(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    int flags;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                tb->flags != flags)) {
        tb = tb_find_slow(env, pc, cs_base, flags); // qq
    }
    return tb;
}

static void cpu_handle_debug_exception(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    CPUClass *cc = CPU_GET_CLASS(env->uc, cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}
