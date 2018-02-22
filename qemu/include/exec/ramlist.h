#ifndef RAMLIST_H
#define RAMLIST_H

#include "qemu/queue.h"
#include "qemu/thread.h"

#define DIRTY_MEMORY_CODE      0
#define DIRTY_MEMORY_NUM       1        /* num of dirty bits */

/* The dirty memory bitmap is split into fixed-size blocks to allow growth
 * under RCU.  The bitmap for a block can be accessed as follows:
 *
 *   rcu_read_lock();
 *
 *   DirtyMemoryBlocks *blocks =
 *       atomic_rcu_read(&ram_list.dirty_memory[DIRTY_MEMORY_MIGRATION]);
 *
 *   ram_addr_t idx = (addr >> TARGET_PAGE_BITS) / DIRTY_MEMORY_BLOCK_SIZE;
 *   unsigned long *block = blocks.blocks[idx];
 *   ...access block bitmap...
 *
 *   rcu_read_unlock();
 *
 * Remember to check for the end of the block when accessing a range of
 * addresses.  Move on to the next block if you reach the end.
 *
 * Organization into blocks allows dirty memory to grow (but not shrink) under
 * RCU.  When adding new RAMBlocks requires the dirty memory to grow, a new
 * DirtyMemoryBlocks array is allocated with pointers to existing blocks kept
 * the same.  Other threads can safely access existing blocks while dirty
 * memory is being grown.  When no threads are using the old DirtyMemoryBlocks
 * anymore it is freed by RCU (but the underlying blocks stay because they are
 * pointed to from the new DirtyMemoryBlocks).
 */
#define DIRTY_MEMORY_BLOCK_SIZE ((ram_addr_t)256 * 1024 * 8)
typedef struct {
    //struct rcu_head rcu;
    // Unicorn: unicorn-specific variable to make memory handling less painful
    size_t num_blocks;
    unsigned long *blocks[];
} DirtyMemoryBlocks;

typedef struct RAMList {
    RAMBlock *mru_block;
    QLIST_HEAD(, RAMBlock) blocks;
    DirtyMemoryBlocks *dirty_memory[DIRTY_MEMORY_NUM];
    uint32_t version;
} RAMList;

#endif
