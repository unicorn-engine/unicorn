/* By Dang Hoang Vu <dang.hvu -at- gmail.com>, 2015 */

#ifndef UC_QEMU_H
#define UC_QEMU_H

struct uc_struct;

#define OPC_BUF_SIZE 640

#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "exec/cpu-common.h"
#include "exec/memory.h"

#include "qemu/thread.h"
#include "include/qom/cpu.h"

#include "vl.h"

// These two structs are originally from qemu/include/exec/cpu-all.h
// Temporarily moved here since there is circular inclusion.

typedef struct {
    MemoryRegion *mr;
    void *buffer;
    hwaddr addr;
    hwaddr len;
    bool in_use;
} BounceBuffer;

typedef struct RAMList {
    /* Protected by the iothread lock.  */
    unsigned long *dirty_memory[DIRTY_MEMORY_NUM];
    RAMBlock *mru_block;
    QLIST_HEAD(, RAMBlock) blocks;
    uint32_t version;
} RAMList;

#endif
