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

// This two struct is originally from qemu/include/exec/cpu-all.h
// Temporarily moved here since there is circular inclusion.
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

static inline void *ramblock_ptr(RAMBlock *block, ram_addr_t offset)
{
    assert(offset < block->used_length);
    assert(block->host);
    return (char *)block->host + offset;
}

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
