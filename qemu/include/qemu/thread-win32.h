#ifndef QEMU_THREAD_WIN32_H
#define QEMU_THREAD_WIN32_H

#include <windows.h>

typedef struct QemuThreadData QemuThreadData;
struct QemuThread {
    QemuThreadData *data;
    unsigned tid;
};

/* Only valid for joinable threads.  */
HANDLE qemu_thread_get_handle(struct QemuThread *thread);

#endif
