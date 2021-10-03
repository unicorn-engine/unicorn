#ifndef QEMU_THREAD_H
#define QEMU_THREAD_H

#include "unicorn/platform.h"
#include "qemu/processor.h"

struct uc_struct;
typedef struct QemuThread QemuThread;

#if defined(_WIN32) && !defined(__MINGW32__)
#include "qemu/thread-win32.h"
#else
#include "qemu/thread-posix.h"
#endif

#define QEMU_THREAD_JOINABLE 0
#define QEMU_THREAD_DETACHED 1

int qemu_thread_create(struct uc_struct *uc, QemuThread *thread, const char *name,
                        void *(*start_routine)(void *),
                        void *arg, int mode);
void *qemu_thread_join(QemuThread *thread);
void qemu_thread_exit(struct uc_struct *uc, void *retval);

#endif
