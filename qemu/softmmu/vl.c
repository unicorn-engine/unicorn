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

#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "uc_priv.h"

void init_real_host_page_size(struct uc_struct *uc);
void init_cache_info(struct uc_struct *uc);


DEFAULT_VISIBILITY
int machine_initialize(struct uc_struct *uc)
{
    init_get_clock();

    /* Init uc->qemu_real_host_page_size. */
    init_real_host_page_size(uc);

    /* Init uc->qemu_icache_linesize. */
    init_cache_info(uc);

    // Initialize arch specific.
    uc->init_arch(uc);

    /* Init memory. */
    uc->cpu_exec_init_all(uc);

    uc->target_page(uc);

    /* Init tcg. use DEFAULT_CODE_GEN_BUFFER_SIZE. */
    uc->tcg_exec_init(uc, 0);

    /* Init cpu. use default cpu_model. */
    return uc->cpus_init(uc, NULL);
}

void qemu_system_reset_request(struct uc_struct* uc)
{
    cpu_stop(uc);
}

void qemu_system_shutdown_request(struct uc_struct *uc)
{
    /* TODO: shutdown(exit program) immediately? */
    cpu_stop(uc);
}
