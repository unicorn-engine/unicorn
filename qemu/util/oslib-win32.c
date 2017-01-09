/*
 * os-win32.c
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2010 Red Hat, Inc.
 *
 * QEMU library functions for win32 which are shared between QEMU and
 * the QEMU tools.
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
 *
 */
#include <windows.h>

#include <stdlib.h>
#include "config-host.h"
#include "sysemu/sysemu.h"
// #include "trace.h"
//#include "qemu/sockets.h"

/* this must come after including "trace.h" */
#include <shlobj.h>

void *qemu_oom_check(void *ptr)
{
    if (ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory: %lu\n", GetLastError());
        abort();
    }
    return ptr;
}

void *qemu_try_memalign(size_t alignment, size_t size)
{
    void *ptr;

    if (!size) {
        abort();
    }
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    // trace_qemu_memalign(alignment, size, ptr);
    return ptr;
}

void *qemu_memalign(size_t alignment, size_t size)
{
    return qemu_oom_check(qemu_try_memalign(alignment, size));
}

void *qemu_anon_ram_alloc(size_t size, uint64_t *align)
{
    void *ptr;

    /* FIXME: this is not exactly optimal solution since VirtualAlloc
       has 64Kb granularity, but at least it guarantees us that the
       memory is page aligned. */
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    // trace_qemu_anon_ram_alloc(size, ptr);
    return ptr;
}

void qemu_vfree(void *ptr)
{
    // trace_qemu_vfree(ptr);
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

void qemu_anon_ram_free(void *ptr, size_t size)
{
    // trace_qemu_anon_ram_free(ptr, size);
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

/* FIXME: add proper locking */
struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    struct tm *p = gmtime(timep);
    memset(result, 0, sizeof(*result));
    if (p) {
        *result = *p;
        p = result;
    }
    return p;
}

/* FIXME: add proper locking */
struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    struct tm *p = localtime(timep);
    memset(result, 0, sizeof(*result));
    if (p) {
        *result = *p;
        p = result;
    }
    return p;
}

/* Offset between 1/1/1601 and 1/1/1970 in 100 nanosec units */
#define _W32_FT_OFFSET (116444736000000000ULL)

int qemu_gettimeofday(qemu_timeval *tp)
{
  union {
    unsigned long long ns100; /*time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  }  _now;

  if(tp) {
      GetSystemTimeAsFileTime (&_now.ft);
      tp->tv_usec=(long)((_now.ns100 / 10ULL) % 1000000ULL );
      tp->tv_sec= (long)((_now.ns100 - _W32_FT_OFFSET) / 10000000ULL);
  }
  /* Always return 0 as per Open Group Base Specifications Issue 6.
     Do not set errno on error.  */
  return 0;
}

size_t getpagesize(void)
{
    SYSTEM_INFO system_info;

    GetSystemInfo(&system_info);
    return system_info.dwPageSize;
}
