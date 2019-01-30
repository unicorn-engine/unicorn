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
#include "hw/xen/xen.h"
#include "exec/ramlist.h"

struct RAMBlock {
    struct MemoryRegion *mr;
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized)(const char*, uint64_t length, void *host);
    uint32_t flags;
    char idstr[256];
    /* Reads can take either the iothread or the ramlist lock.
     * Writes must take both locks.
     */
    QLIST_ENTRY(RAMBlock) next;
    int fd;
};

static inline bool offset_in_ramblock(RAMBlock *b, ram_addr_t offset)
{
    return (b && b->host && offset < b->used_length) ? true : false;
}

static inline void *ramblock_ptr(RAMBlock *block, ram_addr_t offset)
{
    assert(offset < block->used_length);
    assert(block->host);
    return (char *)block->host + offset;
}

RAMBlock *qemu_ram_alloc_from_ptr(ram_addr_t size, void *host,
                                  MemoryRegion *mr, Error **errp);
RAMBlock *qemu_ram_alloc(ram_addr_t size, MemoryRegion *mr, Error **errp);
RAMBlock *qemu_ram_alloc_resizeable(ram_addr_t size, ram_addr_t max_size,
                                    void (*resized)(const char*,
                                                    uint64_t length,
                                                    void *host),
                                    MemoryRegion *mr, Error **errp);
void qemu_ram_free(struct uc_struct *c, ram_addr_t addr);

int qemu_ram_resize(struct uc_struct *c, RAMBlock *block, ram_addr_t newsize, Error **errp);

#define DIRTY_CLIENTS_ALL     ((1 << DIRTY_MEMORY_NUM) - 1)
#define DIRTY_CLIENTS_NOCODE  (DIRTY_CLIENTS_ALL & ~(1 << DIRTY_MEMORY_CODE))

static inline bool cpu_physical_memory_get_dirty(struct uc_struct *uc, ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    DirtyMemoryBlocks *blocks;
    unsigned long end, page;
    unsigned long idx, offset, base;
    bool dirty = false;

    assert(client < DIRTY_MEMORY_NUM);

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;

    // Unicorn: commented out
    //rcu_read_lock();

    // Unicorn: atomic_read used instead of atomic_rcu_read
    blocks = atomic_read(&uc->ram_list.dirty_memory[client]);

    idx = page / DIRTY_MEMORY_BLOCK_SIZE;
    offset = page % DIRTY_MEMORY_BLOCK_SIZE;
    base = page - offset;
    while (page < end) {
        unsigned long next = MIN(end, base + DIRTY_MEMORY_BLOCK_SIZE);
        unsigned long num = next - base;
        unsigned long found = find_next_bit(blocks->blocks[idx], num, offset);
        if (found < num) {
            dirty = true;
            break;
        }

        page = next;
        idx++;
        offset = 0;
        base += DIRTY_MEMORY_BLOCK_SIZE;
    }

    // Unicorn: commented out
    //rcu_read_unlock();

    return dirty;

}

static inline bool cpu_physical_memory_all_dirty(struct uc_struct *uc, ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    DirtyMemoryBlocks *blocks;
    unsigned long end, page;
    unsigned long idx, offset, base;
    bool dirty = true;

    assert(client < DIRTY_MEMORY_NUM);

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;

    // Unicorn: commented out
    //rcu_read_lock();

    // Unicorn: atomic_read used instead of atomic_rcu_read
    blocks = atomic_read(&uc->ram_list.dirty_memory[client]);

    idx = page / DIRTY_MEMORY_BLOCK_SIZE;
    offset = page % DIRTY_MEMORY_BLOCK_SIZE;
    base = page - offset;
    while (page < end) {
        unsigned long next = MIN(end, base + DIRTY_MEMORY_BLOCK_SIZE);
        unsigned long num = next - base;
        unsigned long found = find_next_zero_bit(blocks->blocks[idx], num, offset);
        if (found < num) {
            dirty = false;
            break;
        }

        page = next;
        idx++;
        offset = 0;
        base += DIRTY_MEMORY_BLOCK_SIZE;
    }

    // Unicorn: commented out
    //rcu_read_unlock();

    return dirty;
}

static inline bool cpu_physical_memory_range_includes_clean(struct uc_struct *uc, ram_addr_t start,
                                                            ram_addr_t length, uint8_t mask)
{
    uint8_t ret = 0;

    if (mask & (1 << DIRTY_MEMORY_CODE) &&
        !cpu_physical_memory_all_dirty(uc, start, length, DIRTY_MEMORY_CODE)) {
        ret |= (1 << DIRTY_MEMORY_CODE);
    }
    return ret;
}

static inline void cpu_physical_memory_set_dirty_flag(struct uc_struct *uc, ram_addr_t addr,
                                                      unsigned client)
{
    unsigned long page, idx, offset;
    DirtyMemoryBlocks *blocks;

    assert(client < DIRTY_MEMORY_NUM);

    page = addr >> TARGET_PAGE_BITS;
    idx = page / DIRTY_MEMORY_BLOCK_SIZE;
    offset = page % DIRTY_MEMORY_BLOCK_SIZE;

    // Unicorn: commented out
    //rcu_read_lock();

    // Unicorn: atomic_read used instead of atomic_rcu_read
    blocks = atomic_read(&uc->ram_list.dirty_memory[client]);

    set_bit_atomic(offset, blocks->blocks[idx]);

    // Unicorn: commented out
    //rcu_read_unlock();
}

#endif
#endif
