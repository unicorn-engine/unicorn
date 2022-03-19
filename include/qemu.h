/* By Dang Hoang Vu <dang.hvu -at- gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef UC_QEMU_H
#define UC_QEMU_H

struct uc_struct;

#define OPC_BUF_SIZE 640

#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "exec/cpu-common.h"
#include "exec/memory.h"

#include "qemu/thread.h"
#include "hw/core/cpu.h"

#include "vl.h"

// This struct is originally from qemu/include/exec/ramblock.h
// Temporarily moved here since there is circular inclusion.
struct RAMBlock {
    struct MemoryRegion *mr;
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    uint32_t flags;
    /* RCU-enabled, writes protected by the ramlist lock */
    QLIST_ENTRY(RAMBlock) next;
    size_t page_size;
};

typedef struct {
    MemoryRegion *mr;
    void *buffer;
    hwaddr addr;
    hwaddr len;
} BounceBuffer;

// This struct is originally from qemu/include/exec/ramlist.h
typedef struct RAMList {
    RAMBlock *mru_block;
    QLIST_HEAD(, RAMBlock) blocks;
} RAMList;

#endif
