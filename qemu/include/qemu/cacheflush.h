/*
 * Flush host instruction and data caches for generated code.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_CACHEFLUSH_H
#define QEMU_CACHEFLUSH_H

#if defined(__APPLE__) && (defined(__aarch64__) || defined(__arm__))
#include <libkern/OSCacheControl.h>
#endif

#if defined(__aarch64__) && !defined(__APPLE__)
static inline uint64_t qemu_aarch64_read_ctr_el0(void)
{
    uint64_t ctr_el0;

    asm volatile("mrs\t%0, ctr_el0" : "=r"(ctr_el0));
    return ctr_el0;
}
#endif

static inline void flush_idcache_range(uintptr_t rx, uintptr_t rw, size_t len)
{
#if defined(__i386__) || defined(__x86_64__) || defined(__s390__)
    /* Instruction and data caches are coherent. */
    (void)rx;
    (void)rw;
    (void)len;
#elif defined(__aarch64__) && !defined(__APPLE__)
    const unsigned int ctr_idc = 1u << 28;
    const unsigned int ctr_dic = 1u << 29;
    const uint64_t ctr_el0 = qemu_aarch64_read_ctr_el0();
    const uintptr_t dcache_lsize = 4 << ((ctr_el0 >> 16) & 15);
    const uintptr_t icache_lsize = 4 << (ctr_el0 & 15);
    uintptr_t p;

    if (!(ctr_el0 & ctr_idc)) {
        for (p = rw & ~(dcache_lsize - 1);
             p < rw + len; p += dcache_lsize) {
            asm volatile("dc\tcvau, %0" : : "r"(p) : "memory");
        }
    }

    asm volatile("dsb\tish" : : : "memory");

    if (!(ctr_el0 & ctr_dic)) {
        for (p = rx & ~(icache_lsize - 1);
             p < rx + len; p += icache_lsize) {
            asm volatile("ic\tivau, %0" : : "r"(p) : "memory");
        }
        asm volatile("dsb\tish" : : : "memory");
    }

    asm volatile("isb" : : : "memory");
#elif defined(__APPLE__) && (defined(__aarch64__) || defined(__arm__))
    sys_dcache_flush((void *)rw, len);
    sys_icache_invalidate((void *)rx, len);
#else
    if (rw != rx) {
        __builtin___clear_cache((char *)rw, (char *)rw + len);
    }
    __builtin___clear_cache((char *)rx, (char *)rx + len);
#endif
}

#endif /* QEMU_CACHEFLUSH_H */
