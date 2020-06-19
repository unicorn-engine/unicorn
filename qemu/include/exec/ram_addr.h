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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef RAM_ADDR_H
#define RAM_ADDR_H

#include "uc_priv.h"

ram_addr_t qemu_ram_alloc_from_ptr(ram_addr_t size, void *host,
                                   MemoryRegion *mr);
ram_addr_t qemu_ram_alloc(ram_addr_t size, MemoryRegion *mr);
void *qemu_get_ram_block_host_ptr(struct uc_struct *uc, ram_addr_t addr);
void *qemu_get_ram_ptr(struct uc_struct *uc, ram_addr_t addr);
void qemu_ram_free(struct uc_struct *c, ram_addr_t addr);
void qemu_ram_free_from_ptr(struct uc_struct *uc, ram_addr_t addr);

static inline bool cpu_physical_memory_get_dirty(struct uc_struct *uc, ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    return false;
}

static inline bool cpu_physical_memory_get_clean(struct uc_struct *uc, ram_addr_t start,
                                                 ram_addr_t length,
                                                 unsigned client)
{
    return true;
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
                                                            ram_addr_t length)
{
    return cpu_physical_memory_get_clean(uc, start, length, DIRTY_MEMORY_CODE);
}

static inline void cpu_physical_memory_set_dirty_flag(struct uc_struct *uc, ram_addr_t addr,
                                                      unsigned client)
{
}

static inline void cpu_physical_memory_set_dirty_range(struct uc_struct *uc, ram_addr_t start,
                                                       ram_addr_t length)
{
}

#if !defined(_WIN32)
static inline void cpu_physical_memory_set_dirty_lebitmap(struct uc_struct *uc, unsigned long *bitmap,
                                                          ram_addr_t start,
                                                          ram_addr_t pages)
{
}
#endif /* not _WIN32 */

static inline void cpu_physical_memory_clear_dirty_range(struct uc_struct *uc, ram_addr_t start,
                                                         ram_addr_t length,
                                                         unsigned client)
{
}

void cpu_physical_memory_reset_dirty(struct uc_struct *uc,
    ram_addr_t start, ram_addr_t length, unsigned client);

#endif
