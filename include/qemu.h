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
typedef struct RAMBlock {
    struct MemoryRegion *mr;
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t length;
    uint32_t flags;
    char idstr[256];
    /* Reads can take either the iothread or the ramlist lock.
     * Writes must take both locks.
     */
    QTAILQ_ENTRY(RAMBlock) next;
    int fd;
} RAMBlock;

typedef struct {
    MemoryRegion *mr;
    void *buffer;
    hwaddr addr;
    hwaddr len;
} BounceBuffer;

typedef struct RAMList {
    /* Protected by the iothread lock.  */
    unsigned long *dirty_memory[DIRTY_MEMORY_NUM];
    RAMBlock *mru_block;
    QTAILQ_HEAD(, RAMBlock) blocks;
    uint32_t version;
} RAMList;

#endif
