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

#include "cpu.h"
#include "sysemu/tcg.h"
#include "exec/ramlist.h"
#include "exec/ramblock.h"

static inline bool offset_in_ramblock(RAMBlock *b, ram_addr_t offset)
{
    return (b && b->host && offset < b->used_length) ? true : false;
}

static inline void *ramblock_ptr(RAMBlock *block, ram_addr_t offset)
{
    assert(offset_in_ramblock(block, offset));
    return (char *)block->host + offset;
}

static inline unsigned long int ramblock_recv_bitmap_offset(struct uc_struct *uc, void *host_addr,
                                                            RAMBlock *rb)
{
    uint64_t host_addr_offset =
            (uint64_t)(uintptr_t)((char *)host_addr - (char *)rb->host);
    return host_addr_offset >> TARGET_PAGE_BITS;
}

RAMBlock *qemu_ram_alloc_from_ptr(struct uc_struct *uc, ram_addr_t size, void *host,
                                  MemoryRegion *mr);
RAMBlock *qemu_ram_alloc(struct uc_struct *uc, ram_addr_t size, MemoryRegion *mr);
void qemu_ram_free(struct uc_struct *uc, RAMBlock *block);

#define DIRTY_CLIENTS_ALL     ((1 << DIRTY_MEMORY_NUM) - 1)
#define DIRTY_CLIENTS_NOCODE  (DIRTY_CLIENTS_ALL & ~(1 << DIRTY_MEMORY_CODE))

void tb_invalidate_phys_range(struct uc_struct *uc, ram_addr_t start, ram_addr_t end);

static inline bool cpu_physical_memory_get_dirty(ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    return false;
}

static inline bool cpu_physical_memory_all_dirty(ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    return false;
}

static inline bool cpu_physical_memory_get_dirty_flag(ram_addr_t addr,
                                                      unsigned client)
{
    return cpu_physical_memory_get_dirty(addr, 1, client);
}

static inline bool cpu_physical_memory_is_clean(ram_addr_t addr)
{
    return true;
}

static inline void cpu_physical_memory_set_dirty_flag(ram_addr_t addr,
                                                      unsigned client)
{
}

static inline void cpu_physical_memory_set_dirty_range(ram_addr_t start,
                                                       ram_addr_t length,
                                                       uint8_t mask)
{
}

#if !defined(_WIN32)
static inline void cpu_physical_memory_set_dirty_lebitmap(unsigned long *bitmap,
                                                          ram_addr_t start,
                                                          ram_addr_t pages)
{
}
#endif /* not _WIN32 */

bool cpu_physical_memory_test_and_clear_dirty(ram_addr_t start,
                                              ram_addr_t length,
                                              unsigned client);

static inline void cpu_physical_memory_clear_dirty_range(ram_addr_t start,
                                                         ram_addr_t length)
{
}


/* Called with RCU critical section */
static inline
uint64_t cpu_physical_memory_sync_dirty_bitmap(RAMBlock *rb,
                                               ram_addr_t start,
                                               ram_addr_t length,
                                               uint64_t *real_dirty_pages)
{
    return 0;
}
#endif
