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
#include "qom/cpu.h"

#include "vl.h"

// This two struct is originally from qemu/include/exec/cpu-all.h
// Temporarily moved here since there is circular inclusion.
typedef struct RAMBlock {
    struct MemoryRegion *mr;
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t length;
    uint32_t flags;
    /* Reads can take either the iothread or the ramlist lock.
     * Writes must take both locks.
     */
    QTAILQ_ENTRY(RAMBlock) next;
} RAMBlock;

typedef struct {
    MemoryRegion *mr;
    void *buffer;
    hwaddr addr;
    hwaddr len;
} BounceBuffer;

typedef struct RAMList {
    RAMBlock *mru_block;
    QTAILQ_HEAD(, RAMBlock) blocks;
} RAMList;

#endif
