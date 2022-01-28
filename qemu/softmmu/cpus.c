/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "sysemu/tcg.h"
#include "sysemu/cpus.h"
#include "qemu/bitmap.h"
#include "tcg/tcg.h"
#include "exec/tb-hash.h"
#include "accel/tcg/translate-all.h"

#include "uc_priv.h"


int64_t cpu_icount_to_ns(int64_t icount)
{
    // return icount << atomic_read(&timers_state.icount_time_shift);
    // from configure_icount(QemuOpts *opts, Error **errp)
    /* 125MIPS seems a reasonable initial guess at the guest speed.
       It will be corrected fairly quickly anyway.  */
    // timers_state.icount_time_shift = 3;

    return icount << 3;
}

bool cpu_is_stopped(CPUState *cpu)
{
    return cpu->stopped;
}

/* return the time elapsed in VM between vm_start and vm_stop.  Unless
 * icount is active, cpu_get_ticks() uses units of the host CPU cycle
 * counter.
 */
int64_t cpu_get_ticks(void)
{
    return cpu_get_host_ticks();
}

/* Return the monotonic time elapsed in VM, i.e.,
 * the time between vm_start and vm_stop
 */
int64_t cpu_get_clock(void)
{
    return get_clock();
}

static bool cpu_can_run(CPUState *cpu)
{
    if (cpu->stop) {
        return false;
    }
    if (cpu_is_stopped(cpu)) {
        return false;
    }
    return true;
}

static void cpu_handle_guest_debug(CPUState *cpu)
{
    cpu->stopped = true;
}

static int tcg_cpu_exec(struct uc_struct *uc)
{
    int r;
    bool finish = false;

    while (!uc->exit_request) {
        CPUState *cpu = uc->cpu;

        //qemu_clock_enable(QEMU_CLOCK_VIRTUAL,
        //                  (cpu->singlestep_enabled & SSTEP_NOTIMER) == 0);
        if (cpu_can_run(cpu)) {
            uc->quit_request = false;
            r = cpu_exec(uc, cpu);

            // quit current TB but continue emulating?
            if (uc->quit_request) {
                // reset stop_request
                uc->stop_request = false;
            } else if (uc->stop_request) {
                //printf(">>> got STOP request!!!\n");
                finish = true;
                break;
            }

            // save invalid memory access error & quit
            if (uc->invalid_error) {
                // printf(">>> invalid memory accessed, STOP = %u!!!\n", env->invalid_error);
                finish = true;
                break;
            }

            // printf(">>> stop with r = %x, HLT=%x\n", r, EXCP_HLT);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
                break;
            }
            if (r == EXCP_HLT) {
                //printf(">>> got HLT!!!\n");
                finish = true;
                break;
            }
        } else if (cpu->stop || cpu->stopped) {
            // printf(">>> got stopped!!!\n");
            break;
        }
    }
    uc->exit_request = 0;

    return finish;
}

void cpu_resume(CPUState *cpu)
{
    cpu->stop = false;
    cpu->stopped = false;
}

static void qemu_tcg_init_vcpu(CPUState *cpu)
{
    /*
     * Initialize TCG regions--once. Now is a good time, because:
     * (1) TCG's init context, prologue and target globals have been set up.
     * (2) qemu_tcg_mttcg_enabled() works now (TCG init code runs before the
     *     -accel flag is processed, so the check doesn't work then).
     */
    tcg_region_init(cpu->uc->tcg_ctx);

    cpu->created = true;
}

void qemu_init_vcpu(CPUState *cpu)
{
    cpu->nr_cores = 1;
    cpu->nr_threads = 1;
    cpu->stopped = true;

    qemu_tcg_init_vcpu(cpu);

    return;
}

void cpu_stop_current(struct uc_struct *uc)
{
    if (uc->cpu) {
        uc->cpu->stop = false;
        uc->cpu->stopped = true;
        cpu_exit(uc->cpu);
    }
}



static inline gboolean uc_exit_invalidate_iter(gpointer key, gpointer val, gpointer data) 
{
    uint64_t exit = *((uint64_t*)key);
    uc_engine *uc = (uc_engine*)data;
    
    if (exit != 0) {
        // Unicorn: Why addr - 1?
        // 
        // 0: INC ecx
        // 1: DEC edx <--- We put exit here, then the range of TB is [0, 1)
        //
        // While tb_invalidate_phys_range invalides [start, end)
        //
        // This function is designed to used with g_tree_foreach
        uc->uc_invalidate_tb(uc, exit - 1, 1);
    }

    return false;
}

void resume_all_vcpus(struct uc_struct* uc)
{
    CPUState *cpu = uc->cpu;
    cpu->halted = 0;
    cpu->exit_request = 0;
    cpu->exception_index = -1;
    cpu_resume(cpu);
    /* static void qemu_tcg_cpu_loop(struct uc_struct *uc) */
    cpu->created = true;
    while (true) {
        if (tcg_cpu_exec(uc)) {
            break;
        }
    }

    // clear the cache of the exits address, since the generated code
    // at that address is to exit emulation, but not for the instruction there.
    // if we dont do this, next time we cannot emulate at that address

    g_tree_foreach(uc->exits, uc_exit_invalidate_iter, (void*)uc);

    cpu->created = false;
}

void vm_start(struct uc_struct* uc)
{
    resume_all_vcpus(uc);
}
