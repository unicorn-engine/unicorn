/*
 * QEMU low level functions
 *
 * Copyright (c) 2003 Fabrice Bellard
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
#include "qemu/osdep.h"

/* Needed early for CONFIG_BSD etc. */

#ifdef CONFIG_SOLARIS
#include <sys/statvfs.h>
/* See MySQL bug #7156 (http://bugs.mysql.com/bug.php?id=7156) for
   discussion about Solaris header problems */
extern int madvise(char *, size_t, int);
#endif

#include "qemu-common.h"
#include "qemu/cutils.h"

int qemu_madvise(void *addr, size_t len, int advice)
{
    if (advice == QEMU_MADV_INVALID) {
        errno = EINVAL;
        return -1;
    }
#if defined(CONFIG_MADVISE)
    return madvise(addr, len, advice);
#elif defined(CONFIG_POSIX_MADVISE)
    return posix_madvise(addr, len, advice);
#else
    errno = EINVAL;
    return -1;
#endif
}

static int qemu_mprotect__osdep(void *addr, size_t size, int prot)
{
#ifdef _WIN32
    DWORD old_protect;

    if (!VirtualProtect(addr, size, prot, &old_protect)) {
        // g_autofree gchar *emsg = g_win32_error_message(GetLastError());
        // error_report("%s: VirtualProtect failed: %s", __func__, emsg);
        return -1;
    }
    return 0;
#else
    if (mprotect(addr, size, prot)) {
        // error_report("%s: mprotect failed: %s", __func__, strerror(errno));
        return -1;
    }
    return 0;
#endif
}

int qemu_mprotect_rwx(void *addr, size_t size)
{
#ifdef _WIN32
    return qemu_mprotect__osdep(addr, size, PAGE_EXECUTE_READWRITE);
#else
    return qemu_mprotect__osdep(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
}

int qemu_mprotect_none(void *addr, size_t size)
{
#ifdef _WIN32
    return qemu_mprotect__osdep(addr, size, PAGE_NOACCESS);
#else
    return qemu_mprotect__osdep(addr, size, PROT_NONE);
#endif
}
