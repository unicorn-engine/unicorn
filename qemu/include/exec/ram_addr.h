/*
 * Declarations for cpu physical memory functions
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Avi Kivity <avi@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

/*
 * This header is for use by exec.c and memory.c ONLY.  Do not include it.
 * The functions declared here will be removed soon.
 */

#ifndef RAM_ADDR_H
#define RAM_ADDR_H

#include "uc_priv.h"

#ifndef CONFIG_USER_ONLY

ram_addr_t qemu_ram_alloc_from_ptr(ram_addr_t size, void *host,
                                   MemoryRegion *mr, Error **errp);
ram_addr_t qemu_ram_alloc(ram_addr_t size, MemoryRegion *mr, Error **errp);
int qemu_get_ram_fd(struct uc_struct *uc, ram_addr_t addr);
void *qemu_get_ram_block_host_ptr(struct uc_struct *uc, ram_addr_t addr);
void *qemu_get_ram_ptr(struct uc_struct *uc, ram_addr_t addr);
void qemu_ram_free(struct uc_struct *c, ram_addr_t addr);
void qemu_ram_free_from_ptr(struct uc_struct *uc, ram_addr_t addr);

static inline bool cpu_physical_memory_get_dirty(struct uc_struct *uc, ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    unsigned long end, page, next;

    assert(client < DIRTY_MEMORY_NUM);

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;
    next = find_next_bit(uc->ram_list.dirty_memory[client], end, page);

    return next < end;
}

static inline bool cpu_physical_memory_get_clean(struct uc_struct *uc, ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    unsigned long end, page, next;

    assert(client < DIRTY_MEMORY_NUM);

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;
    next = find_next_zero_bit(uc->ram_list.dirty_memory[client], end, page);

    return next < end;
}

static inline bool cpu_physical_memory_get_dirty_flag(struct uc_struct *uc, ram_addr_t addr,
                                                      unsigned client)
{
    return cpu_physical_memory_get_dirty(uc, addr, 1, client);
}

static inline bool cpu_physical_memory_is_clean(struct uc_struct *uc, ram_addr_t addr)
{
    return !cpu_physical_memory_get_dirty_flag(uc, addr, DIRTY_MEMORY_CODE);
}

static inline bool cpu_physical_memory_range_includes_clean(struct uc_struct *uc, ram_addr_t start,
                                                            ram_addr_t length)
{
    return cpu_physical_memory_get_clean(uc, start, length, DIRTY_MEMORY_CODE);
}

static inline void cpu_physical_memory_set_dirty_flag(struct uc_struct *uc, ram_addr_t addr,
                                                      unsigned client)
{
    assert(client < DIRTY_MEMORY_NUM);
    set_bit(addr >> TARGET_PAGE_BITS, uc->ram_list.dirty_memory[client]);
}

static inline void cpu_physical_memory_set_dirty_range(struct uc_struct *uc, ram_addr_t start,
                                                       ram_addr_t length)
{
    unsigned long end, page;

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;
    qemu_bitmap_set(uc->ram_list.dirty_memory[DIRTY_MEMORY_CODE], page, end - page);
}

#if !defined(_WIN32)
static inline void cpu_physical_memory_set_dirty_lebitmap(struct uc_struct *uc, unsigned long *bitmap,
                                                          ram_addr_t start,
                                                          ram_addr_t pages)
{
    unsigned long i, j;
    unsigned long page_number, c;
    hwaddr addr;
    ram_addr_t ram_addr;
    unsigned long len = (pages + HOST_LONG_BITS - 1) / HOST_LONG_BITS;
    unsigned long hpratio = getpagesize() / TARGET_PAGE_SIZE;
    unsigned long page = BIT_WORD(start >> TARGET_PAGE_BITS);

    /* start address is aligned at the start of a word? */
    if ((((page * BITS_PER_LONG) << TARGET_PAGE_BITS) == start) &&
        (hpratio == 1)) {
        long k;
        long nr = BITS_TO_LONGS(pages);

        for (k = 0; k < nr; k++) {
            if (bitmap[k]) {
                unsigned long temp = leul_to_cpu(bitmap[k]);
                uc->ram_list.dirty_memory[DIRTY_MEMORY_CODE][page + k] |= temp;
            }
        }
    } else {
        /*
         * bitmap-traveling is faster than memory-traveling (for addr...)
         * especially when most of the memory is not dirty.
         */
        for (i = 0; i < len; i++) {
            if (bitmap[i] != 0) {
                c = leul_to_cpu(bitmap[i]);
                do {
                    j = ctzl(c);
                    c &= ~(1ul << j);
                    page_number = (i * HOST_LONG_BITS + j) * hpratio;
                    addr = page_number * TARGET_PAGE_SIZE;
                    ram_addr = start + addr;
                    cpu_physical_memory_set_dirty_range(uc, ram_addr,
                                       TARGET_PAGE_SIZE * hpratio);
                } while (c != 0);
            }
        }
    }
}
#endif /* not _WIN32 */

static inline void cpu_physical_memory_clear_dirty_range(struct uc_struct *uc, ram_addr_t start,
                                                         ram_addr_t length,
                                                         unsigned client)
{
    unsigned long end, page;

    assert(client < DIRTY_MEMORY_NUM);
    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;
    qemu_bitmap_clear(uc->ram_list.dirty_memory[client], page, end - page);
}

void cpu_physical_memory_reset_dirty(struct uc_struct *uc,
    ram_addr_t start, ram_addr_t length, unsigned client);

#endif
#endif
