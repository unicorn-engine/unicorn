/*
 * os-posix-lib.c
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2010 Red Hat, Inc.
 *
 * QEMU library functions on POSIX which are shared between QEMU and
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
 */

#include <uc_priv.h>
#include "qemu/osdep.h"

#ifdef CONFIG_LINUX
#include <linux/mman.h>
#else  /* !CONFIG_LINUX */
#define MAP_SYNC              0x0
#define MAP_SHARED_VALIDATE   0x0
#endif /* CONFIG_LINUX */

#ifndef __MINGW32__
static void *qemu_ram_mmap(struct uc_struct *uc,
                    size_t size,
                    size_t align,
                    bool shared);

static void qemu_ram_munmap(struct uc_struct *uc, void *ptr, size_t size);
#endif

void *qemu_oom_check(void *ptr)
{
    if (ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        abort();
    }
    return ptr;
}

void *qemu_try_memalign(size_t alignment, size_t size)
{
    void *ptr;

    if (alignment < sizeof(void*)) {
        alignment = sizeof(void*);
    }

#if defined(CONFIG_POSIX_MEMALIGN)
    int ret;
    ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0) {
        errno = ret;
        ptr = NULL;
    }
#elif defined(CONFIG_BSD)
    ptr = valloc(size);
#elif defined(__MINGW32__)
    ptr = __mingw_aligned_malloc(size, alignment);
#else
    ptr = memalign(alignment, size);
#endif
    //trace_qemu_memalign(alignment, size, ptr);
    return ptr;
}

void *qemu_memalign(size_t alignment, size_t size)
{
    return qemu_oom_check(qemu_try_memalign(alignment, size));
}

#ifdef __MINGW32__
static int get_allocation_granularity(void)
{
    SYSTEM_INFO system_info;

    GetSystemInfo(&system_info);
    return system_info.dwAllocationGranularity;
}
#endif

/* alloc shared memory pages */
void *qemu_anon_ram_alloc(struct uc_struct *uc, size_t size, uint64_t *alignment)
{
#ifdef __MINGW32__
    void *ptr;

    ptr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    // trace_qemu_anon_ram_alloc(size, ptr);

    if (ptr && alignment) {
        *alignment = MAX(get_allocation_granularity(), getpagesize());
    }
    return ptr;
#else
    size_t align = QEMU_VMALLOC_ALIGN;
    void *ptr = qemu_ram_mmap(uc, size, align, false);

    if (ptr == MAP_FAILED) {
        return NULL;
    }

    if (alignment) {
        *alignment = align;
    }

    //trace_qemu_anon_ram_alloc(size, ptr);
    return ptr;
#endif
}

void qemu_vfree(void *ptr)
{
#ifdef __MINGW32__
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
#else
    //trace_qemu_vfree(ptr);
    free(ptr);
#endif
}

void qemu_anon_ram_free(struct uc_struct *uc, void *ptr, size_t size)
{
#ifdef __MINGW32__
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
#else
    //trace_qemu_anon_ram_free(ptr, size);
    qemu_ram_munmap(uc, ptr, size);
#endif
}

#if defined(__powerpc64__) && defined(__linux__)
static size_t qemu_fd_getpagesize(struct uc_struct *uc)
{
#ifdef CONFIG_LINUX
#ifdef __sparc__
    /* SPARC Linux needs greater alignment than the pagesize */
    return QEMU_VMALLOC_ALIGN;
#endif
#endif

    return uc->qemu_real_host_page_size;
}
#endif

#ifndef __MINGW32__
static void *qemu_ram_mmap(struct uc_struct *uc,
                    size_t size,
                    size_t align,
                    bool shared)
{
    int flags;
    int map_sync_flags = 0;
    int guardfd;
    size_t offset;
    size_t pagesize;
    size_t total;
    void *guardptr;
    void *ptr;

    /*
     * Note: this always allocates at least one extra page of virtual address
     * space, even if size is already aligned.
     */
    total = size + align;

#if defined(__powerpc64__) && defined(__linux__)
    /* On ppc64 mappings in the same segment (aka slice) must share the same
     * page size. Since we will be re-allocating part of this segment
     * from the supplied fd, we should make sure to use the same page size, to
     * this end we mmap the supplied fd.  In this case, set MAP_NORESERVE to
     * avoid allocating backing store memory.
     * We do this unless we are using the system page size, in which case
     * anonymous memory is OK.
     */
    flags = MAP_PRIVATE;
    pagesize = qemu_fd_getpagesize(uc);
    if (pagesize == uc->qemu_real_host_page_size) {
        guardfd = -1;
        flags |= MAP_ANONYMOUS;
    } else {
        guardfd = -1;
        flags |= MAP_NORESERVE;
    }
#else
    guardfd = -1;
    pagesize = uc->qemu_real_host_page_size;
    flags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif

    guardptr = mmap(0, total, PROT_NONE, flags, guardfd, 0);

    if (guardptr == MAP_FAILED) {
        return MAP_FAILED;
    }

    assert(is_power_of_2(align));
    /* Always align to host page size */
    assert(align >= pagesize);

    flags = MAP_FIXED;
    flags |= MAP_ANONYMOUS;
    flags |= shared ? MAP_SHARED : MAP_PRIVATE;

    offset = QEMU_ALIGN_UP((uintptr_t)guardptr, align) - (uintptr_t)guardptr;

    ptr = mmap(guardptr + offset, size, PROT_READ | PROT_WRITE,
               flags | map_sync_flags, -1, 0);

    if (ptr == MAP_FAILED && map_sync_flags) {
        /*
         * if map failed with MAP_SHARED_VALIDATE | MAP_SYNC,
         * we will remove these flags to handle compatibility.
         */
        ptr = mmap(guardptr + offset, size, PROT_READ | PROT_WRITE,
                   flags, -1, 0);
    }

    if (ptr == MAP_FAILED) {
        munmap(guardptr, total);
        return MAP_FAILED;
    }

    if (offset > 0) {
        munmap(guardptr, offset);
    }

    /*
     * Leave a single PROT_NONE page allocated after the RAM block, to serve as
     * a guard page guarding against potential buffer overflows.
     */
    total -= offset;
    if (total > size + pagesize) {
        munmap(ptr + size + pagesize, total - size - pagesize);
    }

    return ptr;
}

static void qemu_ram_munmap(struct uc_struct *uc, void *ptr, size_t size)
{
    size_t pagesize;

    if (ptr) {
        /* Unmap both the RAM block and the guard page */
#if defined(__powerpc64__) && defined(__linux__)
        pagesize = qemu_fd_getpagesize(uc);
#else
        pagesize = uc->qemu_real_host_page_size;
#endif
        munmap(ptr, size + pagesize);
    }
}
#endif
