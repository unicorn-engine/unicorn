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

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

/* Needed early for CONFIG_BSD etc. */
#include "config-host.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "qemu/thread.h"

#include "exec/address-spaces.h"	// debug, can be removed later

#include "uc_priv.h"

static bool cpu_can_run(CPUState *cpu);
static void cpu_handle_guest_debug(CPUState *cpu);
static int tcg_cpu_exec(struct uc_struct *uc, CPUArchState *env);
static bool tcg_exec_all(struct uc_struct* uc);
static int qemu_tcg_init_vcpu(CPUState *cpu);
static void qemu_tcg_cpu_loop(struct uc_struct *uc);

int vm_start(struct uc_struct* uc)
{
    if (resume_all_vcpus(uc)) {
        return -1;
    }
    return 0;
}

bool cpu_is_stopped(CPUState *cpu)
{
    return cpu->stopped;
}

void run_on_cpu(CPUState *cpu, void (*func)(void *data), void *data)
{
    func(data);
}

int resume_all_vcpus(struct uc_struct *uc)
{
    CPUState *cpu = uc->cpu;
    // Fix call multiple time (vu).
    // We have to check whether this is the second time, then reset all CPU.
    if (!cpu->created) {
        cpu->created = true;
        cpu->halted = 0;
        if (qemu_init_vcpu(cpu))
            return -1;
    }

    cpu->exit_request = 0;

    //qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
    cpu_resume(cpu);
    qemu_tcg_cpu_loop(uc);

    return 0;
}

int qemu_init_vcpu(CPUState *cpu)
{
    cpu->nr_cores = smp_cores;
    cpu->nr_threads = smp_threads;
    cpu->stopped = true;

    if (tcg_enabled(cpu->uc))
        return qemu_tcg_init_vcpu(cpu);

    return 0;
}

static void qemu_tcg_cpu_loop(struct uc_struct *uc)
{
    CPUState *cpu = uc->cpu;

    //qemu_tcg_init_cpu_signals();

    cpu->created = true;

    while (1) {
        if (tcg_exec_all(uc))
            break;
    }

    cpu->created = false;
}

static int qemu_tcg_init_vcpu(CPUState *cpu)
{
    tcg_cpu_address_space_init(cpu, cpu->as);

    return 0;
}

static int tcg_cpu_exec(struct uc_struct *uc, CPUArchState *env)
{
    return cpu_exec(uc, env);
}

static bool tcg_exec_all(struct uc_struct* uc)
{
    int r;
    bool finish = false;
    while (!uc->exit_request) {
        CPUState *cpu = uc->cpu;
        CPUArchState *env = cpu->env_ptr;

        //qemu_clock_enable(QEMU_CLOCK_VIRTUAL,
        //                  (cpu->singlestep_enabled & SSTEP_NOTIMER) == 0);
        if (cpu_can_run(cpu)) {
            uc->quit_request = false;
            r = tcg_cpu_exec(uc, env);

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
            if (env->invalid_error) {
                // printf(">>> invalid memory accessed, STOP = %u!!!\n", env->invalid_error);
                uc->invalid_addr = env->invalid_addr;
                uc->invalid_error = env->invalid_error;
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

#if 0
#ifndef _WIN32
static void qemu_tcg_init_cpu_signals(void)
{
    sigset_t set;
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = cpu_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    sigemptyset(&set);
    sigaddset(&set, SIG_IPI);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}
#else /* _WIN32 */
static void qemu_tcg_init_cpu_signals(void)
{
}
#endif /* _WIN32 */
#endif

