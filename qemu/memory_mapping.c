/*
 * QEMU memory mapping
 *
 * Copyright Fujitsu, Corp. 2011, 2012
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "glib_compat.h"

#include "cpu.h"
#include "exec/cpu-all.h"
#include "sysemu/memory_mapping.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"

#include "uc_priv.h"

//#define DEBUG_GUEST_PHYS_REGION_ADD

static void memory_mapping_list_add_mapping_sorted(MemoryMappingList *list,
                                                   MemoryMapping *mapping)
{
    MemoryMapping *p;

    QTAILQ_FOREACH(p, &list->head, next) {
        if (p->phys_addr >= mapping->phys_addr) {
            QTAILQ_INSERT_BEFORE(p, mapping, next);
            return;
        }
    }
    QTAILQ_INSERT_TAIL(&list->head, mapping, next);
}

static void create_new_memory_mapping(MemoryMappingList *list,
                                      hwaddr phys_addr,
                                      hwaddr virt_addr,
                                      ram_addr_t length)
{
    MemoryMapping *memory_mapping;

    memory_mapping = g_malloc(sizeof(MemoryMapping));
    memory_mapping->phys_addr = phys_addr;
    memory_mapping->virt_addr = virt_addr;
    memory_mapping->length = length;
    list->last_mapping = memory_mapping;
    list->num++;
    memory_mapping_list_add_mapping_sorted(list, memory_mapping);
}

static inline bool mapping_contiguous(MemoryMapping *map,
                                      hwaddr phys_addr,
                                      hwaddr virt_addr)
{
    return phys_addr == map->phys_addr + map->length &&
           virt_addr == map->virt_addr + map->length;
}

/*
 * [map->phys_addr, map->phys_addr + map->length) and
 * [phys_addr, phys_addr + length) have intersection?
 */
static inline bool mapping_have_same_region(MemoryMapping *map,
                                            hwaddr phys_addr,
                                            ram_addr_t length)
{
    return !(phys_addr + length < map->phys_addr ||
             phys_addr >= map->phys_addr + map->length);
}

/*
 * [map->phys_addr, map->phys_addr + map->length) and
 * [phys_addr, phys_addr + length) have intersection. The virtual address in the
 * intersection are the same?
 */
static inline bool mapping_conflict(MemoryMapping *map,
                                    hwaddr phys_addr,
                                    hwaddr virt_addr)
{
    return virt_addr - map->virt_addr != phys_addr - map->phys_addr;
}

/*
 * [map->virt_addr, map->virt_addr + map->length) and
 * [virt_addr, virt_addr + length) have intersection. And the physical address
 * in the intersection are the same.
 */
static inline void mapping_merge(MemoryMapping *map,
                                 hwaddr virt_addr,
                                 ram_addr_t length)
{
    if (virt_addr < map->virt_addr) {
        map->length += map->virt_addr - virt_addr;
        map->virt_addr = virt_addr;
    }

    if ((virt_addr + length) >
        (map->virt_addr + map->length)) {
        map->length = virt_addr + length - map->virt_addr;
    }
}

void memory_mapping_list_add_merge_sorted(MemoryMappingList *list,
                                          hwaddr phys_addr,
                                          hwaddr virt_addr,
                                          ram_addr_t length)
{
    MemoryMapping *memory_mapping, *last_mapping;

    if (QTAILQ_EMPTY(&list->head)) {
        create_new_memory_mapping(list, phys_addr, virt_addr, length);
        return;
    }

    last_mapping = list->last_mapping;
    if (last_mapping) {
        if (mapping_contiguous(last_mapping, phys_addr, virt_addr)) {
            last_mapping->length += length;
            return;
        }
    }

    QTAILQ_FOREACH(memory_mapping, &list->head, next) {
        if (mapping_contiguous(memory_mapping, phys_addr, virt_addr)) {
            memory_mapping->length += length;
            list->last_mapping = memory_mapping;
            return;
        }

        if (phys_addr + length < memory_mapping->phys_addr) {
            /* create a new region before memory_mapping */
            break;
        }

        if (mapping_have_same_region(memory_mapping, phys_addr, length)) {
            if (mapping_conflict(memory_mapping, phys_addr, virt_addr)) {
                continue;
            }

            /* merge this region into memory_mapping */
            mapping_merge(memory_mapping, virt_addr, length);
            list->last_mapping = memory_mapping;
            return;
        }
    }

    /* this region can not be merged into any existed memory mapping. */
    create_new_memory_mapping(list, phys_addr, virt_addr, length);
}

