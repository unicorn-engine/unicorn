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

#ifndef QEMU_MAIN_LOOP_H
#define QEMU_MAIN_LOOP_H 1

#define SIG_IPI SIGUSR1

struct uc_struct;

/**
 * qemu_init_main_loop: Set up the process so that it can run the main loop.
 *
 * This includes setting up signal handlers.  It should be called before
 * any other threads are created.  In addition, threads other than the
 * main one should block signals that are trapped by the main loop.
 * For simplicity, you can consider these signals to be safe: SIGUSR1,
 * SIGUSR2, thread signals (SIGFPE, SIGILL, SIGSEGV, SIGBUS) and real-time
 * signals if available.  Remember that Windows in practice does not have
 * signals, though.
 *
 * In the case of QEMU tools, this will also start/initialize timers.
 */
int qemu_init_main_loop(void);

/**
 * qemu_mutex_lock_iothread: Lock the main loop mutex.
 *
 * This function locks the main loop mutex.  The mutex is taken by
 * qemu_init_main_loop and always taken except while waiting on
 * external events (such as with select).  The mutex should be taken
 * by threads other than the main loop thread when calling
 * qemu_bh_new(), qemu_set_fd_handler() and basically all other
 * functions documented in this file.
 *
 * NOTE: tools currently are single-threaded and qemu_mutex_lock_iothread
 * is a no-op there.
 */
void qemu_mutex_lock_iothread(struct uc_struct* uc);

/**
 * qemu_mutex_unlock_iothread: Unlock the main loop mutex.
 *
 * This function unlocks the main loop mutex.  The mutex is taken by
 * qemu_init_main_loop and always taken except while waiting on
 * external events (such as with select).  The mutex should be unlocked
 * as soon as possible by threads other than the main loop thread,
 * because it prevents the main loop from processing callbacks,
 * including timers and bottom halves.
 *
 * NOTE: tools currently are single-threaded and qemu_mutex_unlock_iothread
 * is a no-op there.
 */
void qemu_mutex_unlock_iothread(struct uc_struct* uc);

#endif
