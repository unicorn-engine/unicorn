#ifndef __QEMU_THREAD_WIN32_H
#define __QEMU_THREAD_WIN32_H 1
#include "windows.h"

struct QemuMutex {
    CRITICAL_SECTION lock;
    LONG owner;
};

struct QemuCond {
    LONG waiters, target;
    HANDLE sema;
    HANDLE continue_event;
};

struct QemuSemaphore {
    HANDLE sema;
};

struct QemuEvent {
    HANDLE event;
};

#endif
