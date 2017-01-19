#ifndef __QEMU_THREAD_H
#define __QEMU_THREAD_H 1

#include "platform.h"

typedef struct QemuMutex QemuMutex;
typedef struct QemuThread QemuThread;

#ifdef _WIN32
#include "qemu/thread-win32.h"
#else
#include "qemu/thread-posix.h"
#endif

#define QEMU_THREAD_JOINABLE 0
#define QEMU_THREAD_DETACHED 1

void qemu_mutex_init(QemuMutex *mutex);
void qemu_mutex_destroy(QemuMutex *mutex);
void qemu_mutex_lock(QemuMutex *mutex);
void qemu_mutex_unlock(QemuMutex *mutex);

struct uc_struct;
// return -1 on error, 0 on success
int qemu_thread_create(struct uc_struct *uc, QemuThread *thread, const char *name,
                        void *(*start_routine)(void *),
                        void *arg, int mode);
void *qemu_thread_join(QemuThread *thread);
void qemu_thread_exit(struct uc_struct *uc, void *retval);

#endif
