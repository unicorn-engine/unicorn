/*
 * Win32 implementation for mutex/cond/thread functions
 *
 * Copyright Red Hat, Inc. 2010
 *
 * Author:
 *  Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include "qemu-common.h"
#include "qemu/thread.h"
#include <process.h>
#include <assert.h>
#include <limits.h>

#include "uc_priv.h"


static void error_exit(int err, const char *msg)
{
    char *pstr;

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                  NULL, err, 0, (LPTSTR)&pstr, 2, NULL);
    fprintf(stderr, "qemu: %s: %s\n", msg, pstr);
    LocalFree(pstr);
    //abort();
}

struct QemuThreadData {
    /* Passed to win32_start_routine.  */
    void             *(*start_routine)(void *);
    void             *arg;
    short             mode;

    /* Only used for joinable threads. */
    bool              exited;
    void             *ret;
    CRITICAL_SECTION  cs;
    struct uc_struct *uc;
};

static unsigned __stdcall win32_start_routine(void *arg)
{
    QemuThreadData *data = (QemuThreadData *) arg;
    void *(*start_routine)(void *) = data->start_routine;
    void *thread_arg = data->arg;

    if (data->mode == QEMU_THREAD_DETACHED) {
        data->uc->qemu_thread_data = NULL;
        g_free(data);
        data = NULL;
    }
    qemu_thread_exit(data->uc, start_routine(thread_arg));
    abort();
}

void qemu_thread_exit(struct uc_struct *uc, void *arg)
{
    QemuThreadData *data = uc->qemu_thread_data;

    if (data) {
        assert(data->mode != QEMU_THREAD_DETACHED);
        data->ret = arg;
        EnterCriticalSection(&data->cs);
        data->exited = true;
        LeaveCriticalSection(&data->cs);
    }
    _endthreadex(0);
}

void *qemu_thread_join(QemuThread *thread)
{
    QemuThreadData *data;
    void *ret;
    HANDLE handle;

    data = thread->data;
    if (!data) {
        return NULL;
    }
    /*
     * Because multiple copies of the QemuThread can exist via
     * qemu_thread_get_self, we need to store a value that cannot
     * leak there.  The simplest, non racy way is to store the TID,
     * discard the handle that _beginthreadex gives back, and
     * get another copy of the handle here.
     */
    handle = qemu_thread_get_handle(thread);
    if (handle) {
        WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
    }
    ret = data->ret;
    assert(data->mode != QEMU_THREAD_DETACHED);
    DeleteCriticalSection(&data->cs);
    data->uc->qemu_thread_data = NULL;
    g_free(data);
    data = NULL;
    return ret;
}

int qemu_thread_create(struct uc_struct *uc, QemuThread *thread, const char *name,
                       void *(*start_routine)(void *),
                       void *arg, int mode)
{
    HANDLE hThread;
    struct QemuThreadData *data;

    data = g_malloc(sizeof *data);
    data->start_routine = start_routine;
    data->arg = arg;
    data->mode = mode;
    data->exited = false;
    data->uc = uc;

    uc->qemu_thread_data = data;

    if (data->mode != QEMU_THREAD_DETACHED) {
        InitializeCriticalSection(&data->cs);
    }

    hThread = (HANDLE) _beginthreadex(NULL, 0, win32_start_routine,
                                      data, 0, &thread->tid);
    if (!hThread) {
        error_exit(GetLastError(), __func__);
        return -1;
    }

    CloseHandle(hThread);
    thread->data = (mode == QEMU_THREAD_DETACHED) ? NULL : data;

    return 0;
}

HANDLE qemu_thread_get_handle(QemuThread *thread)
{
    QemuThreadData *data;
    HANDLE handle;

    data = thread->data;
    if (!data) {
        return NULL;
    }

    assert(data->mode != QEMU_THREAD_DETACHED);
    EnterCriticalSection(&data->cs);
    if (!data->exited) {
        handle = OpenThread(SYNCHRONIZE | THREAD_SUSPEND_RESUME, FALSE,
                            thread->tid);
    } else {
        handle = NULL;
    }
    LeaveCriticalSection(&data->cs);
    return handle;
}
