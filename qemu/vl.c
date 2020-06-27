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

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "vl.h"
#include "uc_priv.h"

#define DEFAULT_RAM_SIZE 128

int smp_cpus = 1;
int smp_cores = 1;
int smp_threads = 1;

// cpus.c
void cpu_resume(CPUState *cpu)
{
    cpu->stop = false;
    cpu->stopped = false;
}

void cpu_stop_current(struct uc_struct *uc)
{
    if (uc->cpu) {
        uc->cpu->stop = false;
        uc->cpu->stopped = true;
        cpu_exit(uc->cpu);
    }
}


DEFAULT_VISIBILITY
int machine_initialize(struct uc_struct *uc)
{
    // Initialize arch specific.
    uc->init_arch(uc);

    /* Init memory. */
    uc->cpu_exec_init_all(uc);

#define TCG_TB_SIZE 0
    uc->tcg_exec_init(uc, TCG_TB_SIZE * 1024 * 1024);

    /* Init cpu. */
    return uc->cpus_init(uc, NULL);
}

void qemu_system_reset_request(struct uc_struct* uc)
{
    cpu_stop_current(uc);
}

void qemu_system_shutdown_request(struct uc_struct *uc)
{
    cpu_stop_current(uc);
}
