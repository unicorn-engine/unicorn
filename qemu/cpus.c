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

#include "exec/address-spaces.h"	// debug, can be removed later

#include "uc_priv.h"

static bool cpu_can_run(CPUState *cpu);
static void cpu_handle_guest_debug(CPUState *cpu);
static int tcg_cpu_exec(struct uc_struct *uc, CPUArchState *env);
static bool tcg_exec_all(struct uc_struct* uc);
static int qemu_tcg_init_vcpu(CPUState *cpu);
static void *qemu_tcg_cpu_thread_fn(void *arg);

int vm_start(struct uc_struct* uc)
{
    if (uc->lock_at_vm_start) {
        uc->lock_at_vm_start = false;
        qemu_mutex_lock_iothread(uc);
    }
    
    if (resume_all_vcpus(uc)) {
        return -1;
    }

    // kick off TCG thread
    qemu_mutex_unlock_iothread(uc);

    return 0;
}

bool cpu_is_stopped(CPUState *cpu)
{
    return cpu->stopped;
}

void run_on_cpu(CPUState *cpu, void (*func)(void *data), void *data)
{
    if (qemu_cpu_is_self(cpu)) {
        func(data);
        return;
    }
}

// send halt_cond/tcg_halt_cond to @cpu
bool qemu_cpu_is_self(CPUState *cpu)
{
    return qemu_thread_is_self(cpu->thread);
}

void pause_all_vcpus(struct uc_struct *uc)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        qemu_thread_join(cpu->thread);	// qq: fix qemu_thread_join() to work for instance
    }
}


int resume_all_vcpus(struct uc_struct *uc)
{
    CPUState *cpu;

    {
        // Fix call multiple time (vu).
        // We have to check whether this is the second time, then reset all CPU.
        bool created = false;
        CPU_FOREACH(cpu) {
            created |= cpu->created;
        }
        if (!created) {
            CPU_FOREACH(cpu) {
                cpu->created = true;
                cpu->halted = 0;
                if (qemu_init_vcpu(cpu))
                    return -1;
            }
            qemu_mutex_lock_iothread(uc);
        }
    }

    //qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
    CPU_FOREACH(cpu) {
        cpu_resume(cpu);
    }

    return 0;
}

int qemu_init_vcpu(CPUState *cpu)
{
    cpu->nr_cores = smp_cores;
    cpu->nr_threads = smp_threads;
    cpu->stopped = true;
    cpu->uc->tcg_cpu_thread = NULL;

    if (tcg_enabled(cpu->uc))
        return qemu_tcg_init_vcpu(cpu);

    return 0;
}


static void *qemu_tcg_cpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    struct uc_struct *uc = cpu->uc;

    //qemu_tcg_init_cpu_signals();
    qemu_thread_get_self(uc, cpu->thread);

    qemu_mutex_lock(&uc->qemu_global_mutex);
    CPU_FOREACH(cpu) {
        cpu->thread_id = qemu_get_thread_id();
        cpu->created = true;
    }
    qemu_cond_signal(&uc->qemu_cpu_cond);

   /* wait for initial kick-off after machine start */
    while (QTAILQ_FIRST(&uc->cpus)->stopped) {
        qemu_cond_wait(uc->tcg_halt_cond, &uc->qemu_global_mutex);
    }

    while (1) {
#if 0
        int count = 0;
        if (count < 10) {
            count++;
            unsigned int eip = X86_CPU(mycpu)->env.eip;
            printf(">>> current EIP = %x\n", eip);
            printf(">>> ECX = %x\n", (unsigned int)X86_CPU(mycpu)->env.regs[R_ECX]);
            printf(">>> EDX = %x\n", (unsigned int)X86_CPU(mycpu)->env.regs[R_EDX]);
        }
#endif

        if (tcg_exec_all(uc))
            break;
    }

    CPU_FOREACH(cpu) {
        cpu->thread_id = 0;
        cpu->created = false;
    }

    qemu_mutex_unlock(&uc->qemu_global_mutex);

    return NULL;
}



/* For temporary buffers for forming a name */
#define VCPU_THREAD_NAME_SIZE 16

static int qemu_tcg_init_vcpu(CPUState *cpu)
{
    struct uc_struct *uc = cpu->uc;
    char thread_name[VCPU_THREAD_NAME_SIZE];

    tcg_cpu_address_space_init(cpu, cpu->as);

    /* share a single thread for all cpus with TCG */
    if (!uc->tcg_cpu_thread) {
        cpu->thread = g_malloc0(sizeof(QemuThread));
        cpu->halt_cond = g_malloc0(sizeof(QemuCond));
        qemu_cond_init(cpu->halt_cond);
        uc->tcg_halt_cond = cpu->halt_cond;
        snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/TCG",
                cpu->cpu_index);
        if (qemu_thread_create(uc, cpu->thread, thread_name, qemu_tcg_cpu_thread_fn,
                cpu, QEMU_THREAD_JOINABLE))
            return -1;
#ifdef _WIN32
        cpu->hThread = qemu_thread_get_handle(cpu->thread);
#endif
        while (!cpu->created) {
            qemu_cond_wait(&uc->qemu_cpu_cond, &uc->qemu_global_mutex);
        }
        uc->tcg_cpu_thread = cpu->thread;
    } else {
        cpu->thread = uc->tcg_cpu_thread;
        cpu->halt_cond = uc->tcg_halt_cond;
    }

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
    CPUState *next_cpu = uc->next_cpu;

    if (next_cpu == NULL) {
        next_cpu = first_cpu;
    }

    for (; next_cpu != NULL && !uc->exit_request; next_cpu = CPU_NEXT(next_cpu)) {
        CPUState *cpu = next_cpu;
        CPUArchState *env = cpu->env_ptr;

        //qemu_clock_enable(QEMU_CLOCK_VIRTUAL,
        //                  (cpu->singlestep_enabled & SSTEP_NOTIMER) == 0);
        if (cpu_can_run(cpu)) {
            r = tcg_cpu_exec(uc, env);
            if (uc->stop_request) {
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
                printf(">>> got stopped!!!\n");
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

