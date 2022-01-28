#ifndef RAMLIST_H
#define RAMLIST_H

#include "qemu/queue.h"
#include "qemu/thread.h"
//#include "qemu/rcu.h"
//#include "qemu/rcu_queue.h"

#define DIRTY_MEMORY_VGA       0
#define DIRTY_MEMORY_CODE      1
#define DIRTY_MEMORY_MIGRATION 2
#define DIRTY_MEMORY_NUM       3        /* num of dirty bits */

#define  INTERNAL_RAMBLOCK_FOREACH(block)  \
    QLIST_FOREACH(block, &uc->ram_list.blocks, next)
/* Never use the INTERNAL_ version except for defining other macros */
#define RAMBLOCK_FOREACH(block) INTERNAL_RAMBLOCK_FOREACH(block)

#endif /* RAMLIST_H */
