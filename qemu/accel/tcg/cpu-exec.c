/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include "qemu-common.h"
#include "hw/core/cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "qemu/atomic.h"
#include "qemu/timer.h"
#include "exec/tb-hash.h"
#include "exec/tb-lookup.h"
#include "sysemu/cpus.h"
#include "uc_priv.h"

/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc.ptr;

    tb_exec_lock(cpu->uc->tcg_ctx);
    ret = tcg_qemu_tb_exec(env, tb_ptr);
    tb_exec_unlock(cpu->uc->tcg_ctx);
    cpu->can_do_io = 1;
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    // trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        if (!HOOK_EXISTS(env->uc, UC_HOOK_CODE) && !env->uc->timeout) {
            // We should sync pc for R/W error.
            switch (env->uc->invalid_error) {
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
                        cc->synchronize_from_tb(cpu, last_tb);
                    } else {
                        assert(cc->set_pc);
                        cc->set_pc(cpu, last_tb->pc);
                    }
            }
        }

        cpu->tcg_exit_req = 0;
    }
    return ret;
}

/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;
    uint32_t cflags = curr_cflags() | CF_NOCACHE;

    if (ignore_icount) {
        cflags &= ~CF_USE_ICOUNT;
    }

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    cflags |= MIN(max_cycles, CF_COUNT_MASK);

    mmap_lock();
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base,
                     orig_tb->flags, cflags);
    tb->orig_tb = orig_tb;
    mmap_unlock();

    /* execute the generated code */
    cpu_tb_exec(cpu, tb);

    mmap_lock();
    tb_phys_invalidate(cpu->uc->tcg_ctx, tb, -1);
    mmap_unlock();
    tcg_tb_remove(cpu->uc->tcg_ctx, tb);
}

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
    uint32_t cf_mask;
    uint32_t trace_vcpu_dstate;
};

static bool tb_lookup_cmp(struct uc_struct *uc, const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        tb->trace_vcpu_dstate == desc->trace_vcpu_dstate &&
        (tb_cflags(tb) & (CF_HASH_MASK | CF_INVALID)) == desc->cf_mask) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                   target_ulong cs_base, uint32_t flags,
                                   uint32_t cf_mask)
{
    struct uc_struct *uc = cpu->uc;
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.cf_mask = cf_mask;
    desc.trace_vcpu_dstate = *cpu->trace_dstate;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    if (phys_pc == -1) {
        return NULL;
    }
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags, cf_mask, *cpu->trace_dstate);
    return qht_lookup_custom(uc, &cpu->uc->tcg_ctx->tb_ctx.htable, &desc, h, tb_lookup_cmp);
}

void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr)
{
    if (TCG_TARGET_HAS_direct_jump) {
        uintptr_t offset = tb->jmp_target_arg[n];
        uintptr_t tc_ptr = (uintptr_t)tb->tc.ptr;
        tb_target_set_jmp_target(tc_ptr, tc_ptr + offset, addr);
    } else {
        tb->jmp_target_arg[n] = addr;
    }
}

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    uintptr_t old;

    assert(n < ARRAY_SIZE(tb->jmp_list_next));

    /* make sure the destination TB is valid */
    if (tb_next->cflags & CF_INVALID) {
        goto out_unlock_next;
    }
    /* Atomically claim the jump destination slot only if it was NULL */
#ifdef _MSC_VER
    old = atomic_cmpxchg((long *)&tb->jmp_dest[n], (uintptr_t)NULL, (uintptr_t)tb_next);
#else
    old = atomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL, (uintptr_t)tb_next);
#endif
    if (old) {
        goto out_unlock_next;
    }

    /* patch the native jump address */
    tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc.ptr);

    /* add in TB jmp list */
    tb->jmp_list_next[n] = tb_next->jmp_list_head;
    tb_next->jmp_list_head = (uintptr_t)tb | n;

    return;

 out_unlock_next:
    return;
}

static inline TranslationBlock *tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit, uint32_t cf_mask)
{
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;
    uc_tb cur_tb, prev_tb;
    uc_engine *uc = cpu->uc;
    struct list_item *cur;
    struct hook *hook;

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, cf_mask);
    if (tb == NULL) {
        mmap_lock();
        tb = tb_gen_code(cpu, pc, cs_base, flags, cf_mask);
        mmap_unlock();
        /* We add the TB in the virtual pc hash table for the fast lookup */
        cpu->tb_jmp_cache[tb_jmp_cache_hash_func(cpu->uc, pc)] = tb;
    }
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        last_tb = NULL;
    }
    /* See if we can patch the calling TB. */
    if (last_tb) {
        tb_add_jump(last_tb, tb_exit, tb);
    }

    UC_TB_COPY(&cur_tb, tb);

    if (last_tb) {
        UC_TB_COPY(&prev_tb, last_tb);
        for (cur = uc->hook[UC_HOOK_EDGE_GENERATED_IDX].head;
            cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
            if (hook->to_delete) {
                continue;
            }

            if (HOOK_BOUND_CHECK(hook, (uint64_t)tb->pc)) {
                ((uc_hook_edge_gen_t)hook->callback)(uc, &cur_tb, &prev_tb, hook->user_data);
            }
        }
    }

    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if 0
#if defined(TARGET_I386)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
        }
#endif
#endif
        if (!cpu_has_work(cpu)) {
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    bool catched = false;
    struct uc_struct *uc = cpu->uc;
    struct hook *hook;

    // printf(">> exception index = %u\n", cpu->exception_index); qq

    if (cpu->uc->stop_interrupt && cpu->uc->stop_interrupt(cpu->uc, cpu->exception_index)) {
        // Unicorn: call registered invalid instruction callbacks
        catched = false;
        HOOK_FOREACH_VAR_DECLARE;
        HOOK_FOREACH(uc, hook, UC_HOOK_INSN_INVALID) {
            if (hook->to_delete) {
                continue;
            }
            catched = ((uc_cb_hookinsn_invalid_t)hook->callback)(uc, hook->user_data);
            if (catched) {
                break;
            }
        }
        if (!catched) {
            uc->invalid_error = UC_ERR_INSN_INVALID;
        }

        // we want to stop emulation
        *ret = EXCP_HLT;
        return true;
    }

    if (cpu->exception_index < 0) {
        return false;
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
#if defined(TARGET_X86_64)
        CPUArchState *env = cpu->env_ptr;
        if (env->exception_is_int) {
            // point EIP to the next instruction after INT
            env->eip = env->exception_next_eip;
        }
#endif
#if defined(TARGET_MIPS) || defined(TARGET_MIPS64)
        // Unicorn: Imported from https://github.com/unicorn-engine/unicorn/pull/1098
        CPUMIPSState *env = &(MIPS_CPU(cpu)->env);
        env->active_tc.PC = uc->next_pc;
#endif
#if defined(TARGET_RISCV)
        CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
        env->pc += 4;
#endif
        // Unicorn: call registered interrupt callbacks
        catched = false;
        HOOK_FOREACH_VAR_DECLARE;
        HOOK_FOREACH(uc, hook, UC_HOOK_INTR) {
            if (hook->to_delete) {
                continue;
            }
            ((uc_cb_hookintr_t)hook->callback)(uc, cpu->exception_index, hook->user_data);
            catched = true;
        }
        // Unicorn: If un-catched interrupt, stop executions.
        if (!catched) {
            // printf("AAAAAAAAAAAA\n"); qq
            uc->invalid_error = UC_ERR_EXCEPTION;
            cpu->halted = 1;
            *ret = EXCP_HLT;
            return true;
        }

        cpu->exception_index = -1;
    }

    *ret = EXCP_INTERRUPT;
    return false;
}

static inline bool cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    /* Clear the interrupt flag now since we're processing
     * cpu->interrupt_request and cpu->exit_request.
     * Ensure zeroing happens before reading cpu->exit_request or
     * cpu->interrupt_request (see also smp_wmb in cpu_exit())
     */
    cpu_neg(cpu)->icount_decr.u16.high = 0;

    if (unlikely(cpu->interrupt_request)) {
        int interrupt_request;
        interrupt_request = cpu->interrupt_request;
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            return true;
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            //replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            return true;
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            //replay_interrupt();
            cpu_reset(cpu);
            return true;
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                //replay_interrupt();
                cpu->exception_index = -1;
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

    /* Finally, check if we need to exit to the main loop.  */
    if (unlikely(cpu->exit_request)) {
        cpu->exit_request = 0;
        if (cpu->exception_index == -1) {
            cpu->exception_index = EXCP_INTERRUPT;
        }
        return true;
    }

    return false;
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit)
{
    uintptr_t ret;
    int32_t insns_left;

    // trace_exec_tb(tb, tb->pc);
    ret = cpu_tb_exec(cpu, tb);
    tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    if (*tb_exit != TB_EXIT_REQUESTED) {
        *last_tb = tb;
        return;
    }

    *last_tb = NULL;
    insns_left = cpu_neg(cpu)->icount_decr.u32;
    if (insns_left < 0) {
        /* Something asked us to stop executing chained TBs; just
         * continue round the main loop. Whatever requested the exit
         * will also have set something else (eg exit_request or
         * interrupt_request) which will be handled by
         * cpu_handle_interrupt.  cpu_handle_interrupt will also
         * clear cpu->icount_decr.u16.high.
         */
        return;
    }

    /* Instruction counter expired.  */
    /* Refill decrementer and continue execution.  */
    insns_left = MIN(0xffff, cpu->icount_budget);
    cpu_neg(cpu)->icount_decr.u16.low = insns_left;
    cpu->icount_extra = cpu->icount_budget - insns_left;
    if (!cpu->icount_extra) {
        /* Execute any remaining instructions, then let the main loop
         * handle the next event.
         */
        if (insns_left > 0) {
            cpu_exec_nocache(cpu, insns_left, tb, false);
        }
    }
}

/* main execution loop */
int cpu_exec(struct uc_struct *uc, CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    // SyncClocks sc = { 0 };

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    // rcu_read_lock();

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    // init_delay_params(&sc, cpu);

    /* prepare setjmp context for exception handling */
    if (sigsetjmp(cpu->jmp_env, 0) != 0) {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
        /* Some compilers wrongly smash all local variables after
         * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
         * Reload essential local variables here for those compilers.
         * Newer versions of gcc would complain about this code (-Wclobbered). */
        cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
        /* Assert that the compiler does not smash local variables. */
        // g_assert(cpu == current_cpu);
        g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */

        assert_no_pages_locked();
    }

    /* if an exception is pending, we execute it here */
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            uint32_t cflags = cpu->cflags_next_tb;
            TranslationBlock *tb;

            /* When requested, use an exact setting for cflags for the next
               execution.  This is used for icount, precise smc, and stop-
               after-access watchpoints.  Since this request should never
               have CF_INVALID set, -1 is a convenient invalid value that
               does not require tcg headers for cpu_common_reset.  */
            if (cflags == -1) {
                cflags = curr_cflags();
            } else {
                cpu->cflags_next_tb = -1;
            }

            tb = tb_find(cpu, last_tb, tb_exit, cflags);
            cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
            /* Try to align the host and virtual clocks
               if the guest is in advance */
            // align_clocks(&sc, cpu);
        }
    }

    // Unicorn: Clear any TCG exit flag that might have been left set by exit requests
    uc->cpu->tcg_exit_req = 0;

    cc->cpu_exec_exit(cpu);
    // rcu_read_unlock();

    return ret;
}
