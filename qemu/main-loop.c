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

#include "qemu-common.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "qom/cpu.h"

#include "uc_priv.h"

#ifndef _WIN32
#endif

static void qemu_cpu_kick_thread(CPUState *cpu);

void qemu_mutex_lock_iothread(struct uc_struct* uc)
{
    if (!uc->tcg_enabled(uc)) { // arch-dependent
        qemu_mutex_lock(&uc->qemu_global_mutex);
    } else {
        if (qemu_mutex_trylock(&uc->qemu_global_mutex)) {
            qemu_cpu_kick_thread(first_cpu);
            qemu_mutex_lock(&uc->qemu_global_mutex);
        }
    }
}

void qemu_mutex_unlock_iothread(struct uc_struct* uc)
{
    qemu_mutex_unlock(&uc->qemu_global_mutex);
}

static void qemu_cpu_kick_thread(CPUState *cpu)
{
#ifndef _WIN32
    int err;

    err = pthread_kill(cpu->thread->thread, SIG_IPI);
    if (err) {
        fprintf(stderr, "qemu:%s: %s", __func__, strerror(err));
        exit(1);
    }
#else /* _WIN32 */
    if (!qemu_thread_is_self(cpu->thread)) {
        CONTEXT tcgContext;

        if (SuspendThread(cpu->hThread) == (DWORD)-1) {
            fprintf(stderr, "qemu:%s: GetLastError:%lu\n", __func__,
                    GetLastError());
            exit(1);
        }

        /* On multi-core systems, we are not sure that the thread is actually
         * suspended until we can get the context.
         */
        tcgContext.ContextFlags = CONTEXT_CONTROL;
        while (GetThreadContext(cpu->hThread, &tcgContext) != 0) {
            continue;
        }

				// FIXME(danghvu): anysignal ?
        // cpu_signal(0);

        if (ResumeThread(cpu->hThread) == (DWORD)-1) {
            fprintf(stderr, "qemu:%s: GetLastError:%lu\n", __func__,
                    GetLastError());
            exit(1);
        }

        CloseHandle(cpu->hThread);
        cpu->hThread = 0;
    }
#endif
}


#if 0
static int qemu_signal_init(void)
{
    sigset_t set;

    /*
     * SIG_IPI must be blocked in the main thread and must not be caught
     * by sigwait() in the signal thread. Otherwise, the cpu thread will
     * not catch it reliably.
     */
    sigemptyset(&set);
    sigaddset(&set, SIG_IPI);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGBUS);
    /* SIGINT cannot be handled via signalfd, so that ^C can be used
     * to interrupt QEMU when it is being run under gdb.  SIGHUP and
     * SIGTERM are also handled asynchronously, even though it is not
     * strictly necessary, because they use the same handler as SIGINT.
     */
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    sigdelset(&set, SIG_IPI);
    return 0;
}
#endif

/*
static int qemu_signal_init(void)
{
    return 0;
}*/

/*
static int qemu_init_main_loop(void)
{
    init_clocks();

    return qemu_signal_init();
}*/


