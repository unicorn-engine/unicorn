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

static inline void cpu_physical_memory_set_dirty_range(struct uc_struct *uc, ram_addr_t start,
                                                       ram_addr_t length,
                                                       uint8_t mask)
{
    DirtyMemoryBlocks *blocks[DIRTY_MEMORY_NUM];
    unsigned long end, page;
    unsigned long idx, offset, base;
    int i;

    if (!mask && !xen_enabled()) {
        return;
    }

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;

    // Unicorn: commented out
    //rcu_read_lock();

    for (i = 0; i < DIRTY_MEMORY_NUM; i++) {
        // Unicorn: atomic_read used instead of atomic_rcu_read
        blocks[i] = atomic_read(&uc->ram_list.dirty_memory[i]);
    }

    idx = page / DIRTY_MEMORY_BLOCK_SIZE;
    offset = page % DIRTY_MEMORY_BLOCK_SIZE;
    base = page - offset;
    while (page < end) {
        unsigned long next = MIN(end, base + DIRTY_MEMORY_BLOCK_SIZE);

        if (unlikely(mask & (1 << DIRTY_MEMORY_CODE))) {
            bitmap_set_atomic(blocks[DIRTY_MEMORY_CODE]->blocks[idx],
                              offset, next - page);
        }

        page = next;
        idx++;
        offset = 0;
        base += DIRTY_MEMORY_BLOCK_SIZE;
    }

    // Unicorn: commented out
    //rcu_read_unlock();
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
        unsigned long **blocks[DIRTY_MEMORY_NUM];
        unsigned long idx;
        unsigned long offset;
        long k;
        long nr = BITS_TO_LONGS(pages);

        idx = (start >> TARGET_PAGE_BITS) / DIRTY_MEMORY_BLOCK_SIZE;
        offset = BIT_WORD((start >> TARGET_PAGE_BITS) %
                          DIRTY_MEMORY_BLOCK_SIZE);

        // Unicorn: commented out
        //rcu_read_lock();

        for (i = 0; i < DIRTY_MEMORY_NUM; i++) {
            // Unicorn: atomic_read used instead of atomic_rcu_read
            blocks[i] = atomic_read(&uc->ram_list.dirty_memory[i])->blocks;
        }

        for (k = 0; k < nr; k++) {
            if (bitmap[k]) {
                unsigned long temp = leul_to_cpu(bitmap[k]);

                if (tcg_enabled(uc)) {
                    atomic_or(&blocks[DIRTY_MEMORY_CODE][idx][offset], temp);
                }
            }

            if (++offset >= BITS_TO_LONGS(DIRTY_MEMORY_BLOCK_SIZE)) {
                offset = 0;
                idx++;
            }
        }

        // Unicorn: commented out
        //rcu_read_unlock();
    } else {
        uint8_t clients = tcg_enabled(uc) ? DIRTY_CLIENTS_ALL : DIRTY_CLIENTS_NOCODE;
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
                                       TARGET_PAGE_SIZE * hpratio, clients);
                } while (c != 0);
            }
        }
    }
}
#endif /* not _WIN32 */

bool cpu_physical_memory_test_and_clear_dirty(struct uc_struct *uc,
                                              ram_addr_t start,
                                              ram_addr_t length,
                                              unsigned client);

static inline void cpu_physical_memory_clear_dirty_range(struct uc_struct *uc, ram_addr_t start,
                                                         ram_addr_t length)
{
    cpu_physical_memory_test_and_clear_dirty(uc, start, length, DIRTY_MEMORY_CODE);
}

#endif
#endif
