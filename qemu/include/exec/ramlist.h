#ifndef RAMLIST_H
#define RAMLIST_H

#include "qemu/queue.h"
#include "qemu/thread.h"

#define DIRTY_MEMORY_CODE      0
#define DIRTY_MEMORY_NUM       1        /* num of dirty bits */

typedef struct RAMList {
    /* Protected by the iothread lock.  */
    unsigned long *dirty_memory[DIRTY_MEMORY_NUM];
    RAMBlock *mru_block;
    QLIST_HEAD(, RAMBlock) blocks;
    uint32_t version;
} RAMList;

#endif
