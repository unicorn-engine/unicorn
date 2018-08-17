/*
 *  i386 CPUID helper functions
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/bitops.h"
#include "unicorn/platform.h"
#include "uc_priv.h"

#include "cpu.h"
#include "exec/exec-all.h"
#include "sysemu/cpus.h"

#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qerror.h"

#include "qapi/qapi-visit.h"
#include "qapi/visitor.h"

#include "hw/hw.h"

#include "sysemu/sysemu.h"
#include "topology.h"
#include "hw/cpu/icc_bus.h"
#ifndef CONFIG_USER_ONLY
#include "exec/address-spaces.h"
#include "hw/i386/apic_internal.h"
#endif

/* Helpers for building CPUID[2] descriptors: */

struct CPUID2CacheDescriptorInfo {
    enum CacheType type;
    int level;
    int size;
    int line_size;
    int associativity;
};

/*
 * Known CPUID 2 cache descriptors.
 * From Intel SDM Volume 2A, CPUID instruction
 */
struct CPUID2CacheDescriptorInfo cpuid2_cache_descriptors[] = {
    [0x06] = { .level = 1, .type = INSTRUCTION_CACHE,        .size =   8 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x08] = { .level = 1, .type = INSTRUCTION_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x09] = { .level = 1, .type = INSTRUCTION_CACHE,        .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0A] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 2,  .line_size = 32, },
    [0x0C] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x0D] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0E] = { .level = 1, .type = DATA_CACHE,        .size =  24 * KiB,
               .associativity = 6,  .line_size = 64, },
    [0x1D] = { .level = 2, .type = UNIFIED_CACHE, .size = 128 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x21] = { .level = 2, .type = UNIFIED_CACHE, .size = 256 * KiB,
               .associativity = 8,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x22, 0x23 are not included
    */
    [0x24] = { .level = 2, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 16, .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x25, 0x20 are not included
    */
    [0x2C] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x30] = { .level = 1, .type = INSTRUCTION_CACHE,        .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x41] = { .level = 2, .type = UNIFIED_CACHE, .size = 128 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x42] = { .level = 2, .type = UNIFIED_CACHE, .size = 256 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x43] = { .level = 2, .type = UNIFIED_CACHE, .size = 512 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x44] = { .level = 2, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x45] = { .level = 2, .type = UNIFIED_CACHE, .size =   2 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x46] = { .level = 3, .type = UNIFIED_CACHE, .size =   4 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0x47] = { .level = 3, .type = UNIFIED_CACHE, .size =   8 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x48] = { .level = 2, .type = UNIFIED_CACHE, .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    /* Descriptor 0x49 depends on CPU family/model, so it is not included */
    [0x4A] = { .level = 3, .type = UNIFIED_CACHE, .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4B] = { .level = 3, .type = UNIFIED_CACHE, .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4C] = { .level = 3, .type = UNIFIED_CACHE, .size =  12 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4D] = { .level = 3, .type = UNIFIED_CACHE, .size =  16 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4E] = { .level = 2, .type = UNIFIED_CACHE, .size =   6 * MiB,
               .associativity = 24, .line_size = 64, },
    [0x60] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x66] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x67] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x68] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x78] = { .level = 2, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x79, 0x7A, 0x7B, 0x7C are not included.
    */
    [0x7D] = { .level = 2, .type = UNIFIED_CACHE, .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x7F] = { .level = 2, .type = UNIFIED_CACHE, .size = 512 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x80] = { .level = 2, .type = UNIFIED_CACHE, .size = 512 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x82] = { .level = 2, .type = UNIFIED_CACHE, .size = 256 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x83] = { .level = 2, .type = UNIFIED_CACHE, .size = 512 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x84] = { .level = 2, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x85] = { .level = 2, .type = UNIFIED_CACHE, .size =   2 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x86] = { .level = 2, .type = UNIFIED_CACHE, .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x87] = { .level = 2, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD0] = { .level = 3, .type = UNIFIED_CACHE, .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0xD1] = { .level = 3, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD2] = { .level = 3, .type = UNIFIED_CACHE, .size =   2 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD6] = { .level = 3, .type = UNIFIED_CACHE, .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD7] = { .level = 3, .type = UNIFIED_CACHE, .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD8] = { .level = 3, .type = UNIFIED_CACHE, .size =   4 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xDC] = { .level = 3, .type = UNIFIED_CACHE, .size = 1.5 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDD] = { .level = 3, .type = UNIFIED_CACHE, .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDE] = { .level = 3, .type = UNIFIED_CACHE, .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xE2] = { .level = 3, .type = UNIFIED_CACHE, .size =   2 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE3] = { .level = 3, .type = UNIFIED_CACHE, .size =   4 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE4] = { .level = 3, .type = UNIFIED_CACHE, .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xEA] = { .level = 3, .type = UNIFIED_CACHE, .size =  12 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEB] = { .level = 3, .type = UNIFIED_CACHE, .size =  18 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEC] = { .level = 3, .type = UNIFIED_CACHE, .size =  24 * MiB,
               .associativity = 24, .line_size = 64, },
};

/*
 * "CPUID leaf 2 does not report cache descriptor information,
 * use CPUID leaf 4 to query cache parameters"
 */
#define CACHE_DESCRIPTOR_UNAVAILABLE 0xFF

/*
 * Return a CPUID 2 cache descriptor for a given cache.
 * If no known descriptor is found, return CACHE_DESCRIPTOR_UNAVAILABLE
 */
static uint8_t cpuid2_cache_descriptor(CPUCacheInfo *cache)
{
    int i;

    assert(cache->size > 0);
    assert(cache->level > 0);
    assert(cache->line_size > 0);
    assert(cache->associativity > 0);
    for (i = 0; i < ARRAY_SIZE(cpuid2_cache_descriptors); i++) {
        struct CPUID2CacheDescriptorInfo *d = &cpuid2_cache_descriptors[i];
        if (d->level == cache->level && d->type == cache->type &&
            d->size == cache->size && d->line_size == cache->line_size &&
            d->associativity == cache->associativity) {
                return i;
            }
    }

    return CACHE_DESCRIPTOR_UNAVAILABLE;
}

/* CPUID Leaf 4 constants: */

/* EAX: */
#define CACHE_TYPE_D    1
#define CACHE_TYPE_I    2
#define CACHE_TYPE_UNIFIED   3

#define CACHE_LEVEL(l)        (l << 5)

#define CACHE_SELF_INIT_LEVEL (1 << 8)

/* EDX: */
#define CACHE_NO_INVD_SHARING   (1 << 0)
#define CACHE_INCLUSIVE       (1 << 1)
#define CACHE_COMPLEX_IDX     (1 << 2)

/* Encode CacheType for CPUID[4].EAX */
#define CACHE_TYPE(t) (((t) == DATA_CACHE)  ? CACHE_TYPE_D  : \
                       ((t) == INSTRUCTION_CACHE)  ? CACHE_TYPE_I  : \
                       ((t) == UNIFIED_CACHE) ? CACHE_TYPE_UNIFIED : \
                       0 /* Invalid value */)


/* Encode cache info for CPUID[4] */
static void encode_cache_cpuid4(CPUCacheInfo *cache,
                                int num_apic_ids, int num_cores,
                                uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{
    assert(cache->size == cache->line_size * cache->associativity *
                          cache->partitions * cache->sets);

    assert(num_apic_ids > 0);
    *eax = CACHE_TYPE(cache->type) |
           CACHE_LEVEL(cache->level) |
           (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0) |
           ((num_cores - 1) << 26) |
           ((num_apic_ids - 1) << 14);

    assert(cache->line_size > 0);
    assert(cache->partitions > 0);
    assert(cache->associativity > 0);
    /* We don't implement fully-associative caches */
    assert(cache->associativity < cache->sets);
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    assert(cache->sets > 0);
    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

/* Encode cache info for CPUID[0x80000005].ECX or CPUID[0x80000005].EDX */
static uint32_t encode_cache_cpuid80000005(CPUCacheInfo *cache)
{
    assert(cache->size % 1024 == 0);
    assert(cache->lines_per_tag > 0);
    assert(cache->associativity > 0);
    assert(cache->line_size > 0);
    return ((cache->size / 1024) << 24) | (cache->associativity << 16) |
           (cache->lines_per_tag << 8) | (cache->line_size);
}

#define ASSOC_FULL 0xFF

/* AMD associativity encoding used on CPUID Leaf 0x80000006: */
#define AMD_ENC_ASSOC(a) (a <=   1 ? a   : \
                          a ==   2 ? 0x2 : \
                          a ==   4 ? 0x4 : \
                          a ==   8 ? 0x6 : \
                          a ==  16 ? 0x8 : \
                          a ==  32 ? 0xA : \
                          a ==  48 ? 0xB : \
                          a ==  64 ? 0xC : \
                          a ==  96 ? 0xD : \
                          a == 128 ? 0xE : \
                          a == ASSOC_FULL ? 0xF : \
                          0 /* invalid value */)

/*
 * Encode cache info for CPUID[0x80000006].ECX and CPUID[0x80000006].EDX
 * @l3 can be NULL.
 */
static void encode_cache_cpuid80000006(CPUCacheInfo *l2,
                                       CPUCacheInfo *l3,
                                       uint32_t *ecx, uint32_t *edx)
{
    assert(l2->size % 1024 == 0);
    assert(l2->associativity > 0);
    assert(l2->lines_per_tag > 0);
    assert(l2->line_size > 0);
    *ecx = ((l2->size / 1024) << 16) |
           (AMD_ENC_ASSOC(l2->associativity) << 12) |
           (l2->lines_per_tag << 8) | (l2->line_size);

    if (l3) {
        assert(l3->size % (512 * 1024) == 0);
        assert(l3->associativity > 0);
        assert(l3->lines_per_tag > 0);
        assert(l3->line_size > 0);
        *edx = ((l3->size / (512 * 1024)) << 18) |
               (AMD_ENC_ASSOC(l3->associativity) << 12) |
               (l3->lines_per_tag << 8) | (l3->line_size);
    } else {
        *edx = 0;
    }
}

/*
 * Definitions used for building CPUID Leaf 0x8000001D and 0x8000001E
 * Please refer to the AMD64 Architecture Programmer’s Manual Volume 3.
 * Define the constants to build the cpu topology. Right now, TOPOEXT
 * feature is enabled only on EPYC. So, these constants are based on
 * EPYC supported configurations. We may need to handle the cases if
 * these values change in future.
 */
/* Maximum core complexes in a node */
#define MAX_CCX 2
/* Maximum cores in a core complex */
#define MAX_CORES_IN_CCX 4
/* Maximum cores in a node */
#define MAX_CORES_IN_NODE 8
/* Maximum nodes in a socket */
#define MAX_NODES_PER_SOCKET 4

/*
 * Figure out the number of nodes required to build this config.
 * Max cores in a node is 8
 */
static int nodes_in_socket(int nr_cores)
{
    int nodes;

    nodes = DIV_ROUND_UP(nr_cores, MAX_CORES_IN_NODE);

   /* Hardware does not support config with 3 nodes, return 4 in that case */
    return (nodes == 3) ? 4 : nodes;
}

/*
 * Decide the number of cores in a core complex with the given nr_cores using
 * following set constants MAX_CCX, MAX_CORES_IN_CCX, MAX_CORES_IN_NODE and
 * MAX_NODES_PER_SOCKET. Maintain symmetry as much as possible
 * L3 cache is shared across all cores in a core complex. So, this will also
 * tell us how many cores are sharing the L3 cache.
 */
static int cores_in_core_complex(int nr_cores)
{
    int nodes;

    /* Check if we can fit all the cores in one core complex */
    if (nr_cores <= MAX_CORES_IN_CCX) {
        return nr_cores;
    }
    /* Get the number of nodes required to build this config */
    nodes = nodes_in_socket(nr_cores);

    /*
     * Divide the cores accros all the core complexes
     * Return rounded up value
     */
    return DIV_ROUND_UP(nr_cores, nodes * MAX_CCX);
}

/* Encode cache info for CPUID[8000001D] */
static void encode_cache_cpuid8000001d(CPUCacheInfo *cache, CPUState *cs,
                                uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{
    uint32_t l3_cores;
    assert(cache->size == cache->line_size * cache->associativity *
                          cache->partitions * cache->sets);

    *eax = CACHE_TYPE(cache->type) | CACHE_LEVEL(cache->level) |
               (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0);

    /* L3 is shared among multiple cores */
    if (cache->level == 3) {
        l3_cores = cores_in_core_complex(cs->nr_cores);
        *eax |= ((l3_cores * cs->nr_threads) - 1) << 14;
    } else {
        *eax |= ((cs->nr_threads - 1) << 14);
    }

    assert(cache->line_size > 0);
    assert(cache->partitions > 0);
    assert(cache->associativity > 0);
    /* We don't implement fully-associative caches */
    assert(cache->associativity < cache->sets);
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    assert(cache->sets > 0);
    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

/* Data structure to hold the configuration info for a given core index */
struct core_topology {
    /* core complex id of the current core index */
    int ccx_id;
    /*
     * Adjusted core index for this core in the topology
     * This can be 0,1,2,3 with max 4 cores in a core complex
     */
    int core_id;
    /* Node id for this core index */
    int node_id;
    /* Number of nodes in this config */
    int num_nodes;
};

/*
 * Build the configuration closely match the EPYC hardware. Using the EPYC
 * hardware configuration values (MAX_CCX, MAX_CORES_IN_CCX, MAX_CORES_IN_NODE)
 * right now. This could change in future.
 * nr_cores : Total number of cores in the config
 * core_id  : Core index of the current CPU
 * topo     : Data structure to hold all the config info for this core index
 */
static void build_core_topology(int nr_cores, int core_id,
                                struct core_topology *topo)
{
    int nodes, cores_in_ccx;

    /* First get the number of nodes required */
    nodes = nodes_in_socket(nr_cores);

    cores_in_ccx = cores_in_core_complex(nr_cores);

    topo->node_id = core_id / (cores_in_ccx * MAX_CCX);
    topo->ccx_id = (core_id % (cores_in_ccx * MAX_CCX)) / cores_in_ccx;
    topo->core_id = core_id % cores_in_ccx;
    topo->num_nodes = nodes;
}

/* Encode cache info for CPUID[8000001E] */
static void encode_topo_cpuid8000001e(CPUState *cs, X86CPU *cpu,
                                       uint32_t *eax, uint32_t *ebx,
                                       uint32_t *ecx, uint32_t *edx)
{
    struct core_topology topo = {0};
    unsigned long nodes;
    int shift;

    build_core_topology(cs->nr_cores, cpu->core_id, &topo);
    *eax = cpu->apic_id;
    /*
     * CPUID_Fn8000001E_EBX
     * 31:16 Reserved
     * 15:8  Threads per core (The number of threads per core is
     *       Threads per core + 1)
     *  7:0  Core id (see bit decoding below)
     *       SMT:
     *           4:3 node id
     *             2 Core complex id
     *           1:0 Core id
     *       Non SMT:
     *           5:4 node id
     *             3 Core complex id
     *           1:0 Core id
     */
    if (cs->nr_threads - 1) {
        *ebx = ((cs->nr_threads - 1) << 8) | (topo.node_id << 3) |
                (topo.ccx_id << 2) | topo.core_id;
    } else {
        *ebx = (topo.node_id << 4) | (topo.ccx_id << 3) | topo.core_id;
    }
    /*
     * CPUID_Fn8000001E_ECX
     * 31:11 Reserved
     * 10:8  Nodes per processor (Nodes per processor is number of nodes + 1)
     *  7:0  Node id (see bit decoding below)
     *         2  Socket id
     *       1:0  Node id
     */
    if (topo.num_nodes <= 4) {
        *ecx = ((topo.num_nodes - 1) << 8) | (cpu->socket_id << 2) |
                topo.node_id;
    } else {
        /*
         * Node id fix up. Actual hardware supports up to 4 nodes. But with
         * more than 32 cores, we may end up with more than 4 nodes.
         * Node id is a combination of socket id and node id. Only requirement
         * here is that this number should be unique accross the system.
         * Shift the socket id to accommodate more nodes. We dont expect both
         * socket id and node id to be big number at the same time. This is not
         * an ideal config but we need to to support it. Max nodes we can have
         * is 32 (255/8) with 8 cores per node and 255 max cores. We only need
         * 5 bits for nodes. Find the left most set bit to represent the total
         * number of nodes. find_last_bit returns last set bit(0 based). Left
         * shift(+1) the socket id to represent all the nodes.
         */
        nodes = topo.num_nodes - 1;
        shift = find_last_bit(&nodes, 8);
        *ecx = ((topo.num_nodes - 1) << 8) | (cpu->socket_id << (shift + 1)) |
                topo.node_id;
    }
    *edx = 0;
}

/*
 * Definitions of the hardcoded cache entries we expose:
 * These are legacy cache values. If there is a need to change any
 * of these values please use builtin_x86_defs
 */

/* L1 data cache: */
static CPUCacheInfo legacy_l1d_cache = {
    DATA_CACHE,
    1,
    32 * KiB,
    64,
    8,
    1,
    64,
    0,
    1,
    true,
};

/*FIXME: CPUID leaf 0x80000005 is inconsistent with leaves 2 & 4 */
static CPUCacheInfo legacy_l1d_cache_amd = {
    DATA_CACHE,
    1,
    64 * KiB,
    64,
    2,
    1,
    512,
    1,
    1,
    true,
};

/* L1 instruction cache: */
static CPUCacheInfo legacy_l1i_cache = {
    INSTRUCTION_CACHE,
    1,
    32 * KiB,
    64,
    8,
    1,
    64,
    true,
};

/*FIXME: CPUID leaf 0x80000005 is inconsistent with leaves 2 & 4 */
static CPUCacheInfo legacy_l1i_cache_amd = {
    INSTRUCTION_CACHE,
    1,
    64 * KiB,
    64,
    2,
    1,
    512,
    1,
    1,
    true,
};

/* Level 2 unified cache: */
static CPUCacheInfo legacy_l2_cache = {
    UNIFIED_CACHE,
    2,
    4 * MiB,
    64,
    16,
    1,
    4096,
    0,
    1,
    true,
};

/*FIXME: CPUID leaf 2 descriptor is inconsistent with CPUID leaf 4 */
static CPUCacheInfo legacy_l2_cache_cpuid2 = {
    UNIFIED_CACHE,
    2,
    2 * MiB,
    64,
    8,
};

/*FIXME: CPUID leaf 0x80000006 is inconsistent with leaves 2 & 4 */
static CPUCacheInfo legacy_l2_cache_amd = {
    UNIFIED_CACHE,
    2,
    512 * KiB,
    64,
    16,
    1,
    512,
    1,
};

/* Level 3 unified cache: */
static CPUCacheInfo legacy_l3_cache = {
    UNIFIED_CACHE,
    3,
    16 * MiB,
    64,
    16,
    1,
    16384,
    1,
    true,
    false,
    true,
    true,
};

/* TLB definitions: */

#define L1_DTLB_2M_ASSOC       1
#define L1_DTLB_2M_ENTRIES   255
#define L1_DTLB_4K_ASSOC       1
#define L1_DTLB_4K_ENTRIES   255

#define L1_ITLB_2M_ASSOC       1
#define L1_ITLB_2M_ENTRIES   255
#define L1_ITLB_4K_ASSOC       1
#define L1_ITLB_4K_ENTRIES   255

#define L2_DTLB_2M_ASSOC       0 /* disabled */
#define L2_DTLB_2M_ENTRIES     0 /* disabled */
#define L2_DTLB_4K_ASSOC       4
#define L2_DTLB_4K_ENTRIES   512

#define L2_ITLB_2M_ASSOC       0 /* disabled */
#define L2_ITLB_2M_ENTRIES     0 /* disabled */
#define L2_ITLB_4K_ASSOC       4
#define L2_ITLB_4K_ENTRIES   512

/* CPUID Leaf 0x14 constants: */
#define INTEL_PT_MAX_SUBLEAF     0x1
/*
 * bit[00]: IA32_RTIT_CTL.CR3 filter can be set to 1 and IA32_RTIT_CR3_MATCH
 *          MSR can be accessed;
 * bit[01]: Support Configurable PSB and Cycle-Accurate Mode;
 * bit[02]: Support IP Filtering, TraceStop filtering, and preservation
 *          of Intel PT MSRs across warm reset;
 * bit[03]: Support MTC timing packet and suppression of COFI-based packets;
 */
#define INTEL_PT_MINIMAL_EBX     0xf
/*
 * bit[00]: Tracing can be enabled with IA32_RTIT_CTL.ToPA = 1 and
 *          IA32_RTIT_OUTPUT_BASE and IA32_RTIT_OUTPUT_MASK_PTRS MSRs can be
 *          accessed;
 * bit[01]: ToPA tables can hold any number of output entries, up to the
 *          maximum allowed by the MaskOrTableOffset field of
 *          IA32_RTIT_OUTPUT_MASK_PTRS;
 * bit[02]: Support Single-Range Output scheme;
 */
#define INTEL_PT_MINIMAL_ECX     0x7
/* generated packets which contain IP payloads have LIP values */
#define INTEL_PT_IP_LIP          (1 << 31)
#define INTEL_PT_ADDR_RANGES_NUM 0x2 /* Number of configurable address ranges */
#define INTEL_PT_ADDR_RANGES_NUM_MASK 0x3
#define INTEL_PT_MTC_BITMAP      (0x0249 << 16) /* Support ART(0,3,6,9) */
#define INTEL_PT_CYCLE_BITMAP    0x1fff         /* Support 0,2^(0~11) */
#define INTEL_PT_PSB_BITMAP      (0x003f << 16) /* Support 2K,4K,8K,16K,32K,64K */

void x86_cpu_register_types(void *);

static void x86_cpu_vendor_words2str(char *dst, uint32_t vendor1,
                                     uint32_t vendor2, uint32_t vendor3)
{
    int i;
    for (i = 0; i < 4; i++) {
        dst[i] = vendor1 >> (8 * i);
        dst[i + 4] = vendor2 >> (8 * i);
        dst[i + 8] = vendor3 >> (8 * i);
    }
    dst[CPUID_VENDOR_SZ] = '\0';
}

#define I486_FEATURES (CPUID_FP87 | CPUID_VME | CPUID_PSE)
#define PENTIUM_FEATURES (I486_FEATURES | CPUID_DE | CPUID_TSC | \
          CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_MMX | CPUID_APIC)
#define PENTIUM2_FEATURES (PENTIUM_FEATURES | CPUID_PAE | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_FXSR)
#define PENTIUM3_FEATURES (PENTIUM2_FEATURES | CPUID_SSE)
#define PPRO_FEATURES (CPUID_FP87 | CPUID_DE | CPUID_PSE | CPUID_TSC | \
          CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_PGE | CPUID_CMOV | \
          CPUID_PAT | CPUID_FXSR | CPUID_MMX | CPUID_SSE | CPUID_SSE2 | \
          CPUID_PAE | CPUID_SEP | CPUID_APIC)

#define TCG_FEATURES (CPUID_FP87 | CPUID_PSE | CPUID_TSC | CPUID_MSR | \
          CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_CLFLUSH | CPUID_ACPI | CPUID_MMX | \
          CPUID_FXSR | CPUID_SSE | CPUID_SSE2 | CPUID_SS | CPUID_DE)
          /* partly implemented:
          CPUID_MTRR, CPUID_MCA, CPUID_CLFLUSH (needed for Win64) */
          /* missing:
          CPUID_VME, CPUID_DTS, CPUID_SS, CPUID_HT, CPUID_TM, CPUID_PBE */
#define TCG_EXT_FEATURES (CPUID_EXT_SSE3 | CPUID_EXT_PCLMULQDQ | \
          CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 | CPUID_EXT_CX16 | \
          CPUID_EXT_SSE41 | CPUID_EXT_SSE42 | CPUID_EXT_POPCNT | \
          CPUID_EXT_XSAVE | /* CPUID_EXT_OSXSAVE is dynamic */   \
          CPUID_EXT_MOVBE | CPUID_EXT_AES | CPUID_EXT_HYPERVISOR)
          /* missing:
          CPUID_EXT_DTES64, CPUID_EXT_DSCPL, CPUID_EXT_VMX, CPUID_EXT_SMX,
          CPUID_EXT_EST, CPUID_EXT_TM2, CPUID_EXT_CID, CPUID_EXT_FMA,
          CPUID_EXT_XTPR, CPUID_EXT_PDCM, CPUID_EXT_PCID, CPUID_EXT_DCA,
          CPUID_EXT_X2APIC, CPUID_EXT_TSC_DEADLINE_TIMER, CPUID_EXT_AVX,
          CPUID_EXT_F16C, CPUID_EXT_RDRAND */

#ifdef TARGET_X86_64
#define TCG_EXT2_X86_64_FEATURES (CPUID_EXT2_SYSCALL | CPUID_EXT2_LM)
#else
#define TCG_EXT2_X86_64_FEATURES 0
#endif

#define TCG_EXT2_FEATURES ((TCG_FEATURES & CPUID_EXT2_AMD_ALIASES) | \
          CPUID_EXT2_NX | CPUID_EXT2_MMXEXT | CPUID_EXT2_RDTSCP | \
          CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT | CPUID_EXT2_PDPE1GB | \
          TCG_EXT2_X86_64_FEATURES)
#define TCG_EXT3_FEATURES (CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM | \
          CPUID_EXT3_CR8LEG | CPUID_EXT3_ABM | CPUID_EXT3_SSE4A)
#define TCG_EXT4_FEATURES 0
#define TCG_SVM_FEATURES 0
#define TCG_KVM_FEATURES 0
#define TCG_7_0_EBX_FEATURES (CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_SMAP | \
          CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ADX | \
          CPUID_7_0_EBX_PCOMMIT | CPUID_7_0_EBX_CLFLUSHOPT |            \
          CPUID_7_0_EBX_CLWB | CPUID_7_0_EBX_MPX | CPUID_7_0_EBX_FSGSBASE | \
          CPUID_7_0_EBX_ERMS)
          /* missing:
          CPUID_7_0_EBX_HLE, CPUID_7_0_EBX_AVX2,
          CPUID_7_0_EBX_INVPCID, CPUID_7_0_EBX_RTM,
          CPUID_7_0_EBX_RDSEED */
#define TCG_7_0_ECX_FEATURES (CPUID_7_0_ECX_PKU | \
          /* CPUID_7_0_ECX_OSPKE is dynamic */ \
          CPUID_7_0_ECX_LA57)
#define TCG_7_0_EDX_FEATURES 0
#define TCG_APM_FEATURES 0
#define TCG_6_EAX_FEATURES CPUID_6_EAX_ARAT

#define TCG_XSAVE_FEATURES (CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XGETBV1)
          /* missing:
          CPUID_XSAVE_XSAVEC, CPUID_XSAVE_XSAVES */

typedef struct FeatureWordInfo {
    /* feature flags names are taken from "Intel Processor Identification and
     * the CPUID Instruction" and AMD's "CPUID Specification".
     * In cases of disagreement between feature naming conventions,
     * aliases may be added.
     */
    const char *feat_names[32];
    uint32_t cpuid_eax;   /* Input EAX for CPUID */
    bool cpuid_needs_ecx; /* CPUID instruction uses ECX as input */
    uint32_t cpuid_ecx;   /* Input ECX value for CPUID */
    int cpuid_reg;        /* output register (R_* constant) */
    uint32_t tcg_features; /* Feature flags supported by TCG */
    uint32_t unmigratable_flags; /* Feature flags known to be unmigratable */
    uint32_t migratable_flags; /* Feature flags known to be migratable */
} FeatureWordInfo;

static FeatureWordInfo feature_word_info[FEATURE_WORDS] = {
    // FEAT_1_EDX
    {
        {
            "fpu", "vme", "de", "pse",
            "tsc", "msr", "pae", "mce",
            "cx8", "apic", NULL, "sep",
            "mtrr", "pge", "mca", "cmov",
            "pat", "pse36", "pn" /* Intel psn */, "clflush" /* Intel clfsh */,
            NULL, "ds" /* Intel dts */, "acpi", "mmx",
            "fxsr", "sse", "sse2", "ss",
            "ht" /* Intel htt */, "tm", "ia64", "pbe",
        },
        1,
        false,0,
        R_EDX,
        TCG_FEATURES,
    },
    // FEAT_1_ECX
    {
        {
            "pni" /* Intel,AMD sse3 */, "pclmulqdq", "dtes64", "monitor",
            "ds-cpl", "vmx", "smx", "est",
            "tm2", "ssse3", "cid", NULL,
            "fma", "cx16", "xtpr", "pdcm",
            NULL, "pcid", "dca", "sse4.1",
            "sse4.2", "x2apic", "movbe", "popcnt",
            "tsc-deadline", "aes", "xsave", NULL /* osxsave */,
            "avx", "f16c", "rdrand", "hypervisor",
        },
        1,
        false,0,
        R_ECX,
        TCG_EXT_FEATURES,
    },
    // FEAT_7_0_EBX
    {
        {
            "fsgsbase", "tsc-adjust", NULL, "bmi1",
            "hle", "avx2", NULL, "smep",
            "bmi2", "erms", "invpcid", "rtm",
            NULL, NULL, "mpx", NULL,
            "avx512f", "avx512dq", "rdseed", "adx",
            "smap", "avx512ifma", "pcommit", "clflushopt",
            "clwb", "intel-pt", "avx512pf", "avx512er",
            "avx512cd", "sha-ni", "avx512bw", "avx512vl",
        },
        7,
        true, 0,
        R_EBX,
        TCG_7_0_EBX_FEATURES,
    },
    // FEAT_7_0_ECX
    {
        {
            NULL, "avx512vbmi", "umip", "pku",
            NULL /* ospke */, NULL, "avx512vbmi2", NULL,
            "gfni", "vaes", "vpclmulqdq", "avx512vnni",
            "avx512bitalg", NULL, "avx512-vpopcntdq", NULL,
            "la57", NULL, NULL, NULL,
            NULL, NULL, "rdpid", NULL,
            NULL, "cldemote", NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        7,
        true, 0,
        R_ECX,
        TCG_7_0_ECX_FEATURES,
    },
    // FEAT_7_0_EDX
    {
        {
            NULL, NULL, "avx512-4vnniw", "avx512-4fmaps",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, "pconfig", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, "spec-ctrl", NULL,
            NULL, "arch-capabilities", NULL, "ssbd",
        },
        7,
        true, 0,
        R_EDX,
        TCG_7_0_EDX_FEATURES,
        CPUID_7_0_EDX_ARCH_CAPABILITIES,
    },
    /* Feature names that are already defined on feature_name[] but
     * are set on CPUID[8000_0001].EDX on AMD CPUs don't have their
     * names on feat_names below. They are copied automatically
     * to features[FEAT_8000_0001_EDX] if and only if CPU vendor is AMD.
     */
    // FEAT_8000_0001_EDX
    {
        {
            NULL /* fpu */, NULL /* vme */, NULL /* de */, NULL /* pse */,
            NULL /* tsc */, NULL /* msr */, NULL /* pae */, NULL /* mce */,
            NULL /* cx8 */, NULL /* apic */, NULL, "syscall",
            NULL /* mtrr */, NULL /* pge */, NULL /* mca */, NULL /* cmov */,
            NULL /* pat */, NULL /* pse36 */, NULL, NULL /* Linux mp */,
            "nx", NULL, "mmxext", NULL /* mmx */,
            NULL /* fxsr */, "fxsr-opt", "pdpe1gb", "rdtscp",
            NULL, "lm", "3dnowext", "3dnow",
        },
        0x80000001,
        false,0,
        R_EDX,
        TCG_EXT2_FEATURES,
    },
    // FEAT_8000_0001_ECX
    {
        {
            "lahf-lm", "cmp_legacy", "svm", "extapic",
            "cr8legacy", "abm", "sse4a", "misalignsse",
            "3dnowprefetch", "osvw", "ibs", "xop",
            "skinit", "wdt", NULL, "lwp",
            "fma4", "tce", NULL, "nodeid-msr",
            NULL, "tbm", "topoext", "perfctr-core",
            "perfctr_nb", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0x80000001,
        false,0,
        R_ECX,
        TCG_EXT3_FEATURES,
    },
    // FEAT_8000_0007_EDX
    {
        {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "invtsc", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0x80000007,
        false,0,
        R_EDX,
        TCG_APM_FEATURES,
        CPUID_APM_INVTSC,
    },
    // FEAT_8000_0008_EBX
    {
        {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, "wbnoinvd", NULL, NULL,
            "ibpb", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "amd-ssbd", "virt-ssbd", "amd-no-ssb", NULL,
            NULL, NULL, NULL, NULL,
        },
        0x80000008,
        false,0,
        R_EBX,
        0,
        0,
    },
    // FEAT_C000_0001_EDX
    {
        {
            NULL, NULL, "xstore", "xstore-en",
            NULL, NULL, "xcrypt", "xcrypt-en",
            "ace2", "ace2-en", "phe", "phe-en",
            "pmm", "pmm-en", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0xC0000001,
        false,0,
        R_EDX,
        TCG_EXT4_FEATURES,
    },
    // FEAT_KVM
    {
      {NULL},
      /* Unicorn: commented out
        {
            "kvmclock", "kvm-nopiodelay", "kvm-mmu", "kvmclock",
            "kvm-asyncpf", "kvm-steal-time", "kvm-pv-eoi", "kvm-pv-unhalt",
            NULL, "kvm-pv-tlb-flush", NULL, "kvm-pv-ipi",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "kvmclock-stable-bit", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        KVM_CPUID_FEATURES,
        false, 0,
        R_EAX,
        TCG_KVM_FEATURES,*/
    },
    // FEAT_KVM_HINTS
    {
      {NULL},
      /* Unicorn: commented out
        {
            "kvm-hint-dedicated", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        KVM_CPUID_FEATURES,
        false, 0,
        R_EDX,
        TCG_KVM_FEATURES,*/
    },
    // FEAT_HYPERV_EAX
    {
        {
            NULL /* hv_msr_vp_runtime_access */, NULL /* hv_msr_time_refcount_access */,
            NULL /* hv_msr_synic_access */, NULL /* hv_msr_stimer_access */,
            NULL /* hv_msr_apic_access */, NULL /* hv_msr_hypercall_access */,
            NULL /* hv_vpindex_access */, NULL /* hv_msr_reset_access */,
            NULL /* hv_msr_stats_access */, NULL /* hv_reftsc_access */,
            NULL /* hv_msr_idle_access */, NULL /* hv_msr_frequency_access */,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0x40000003,
        false, 0,
        R_EAX,
    },
    // FEAT_HYPERV_EBX
    {
        {
            NULL /* hv_create_partitions */, NULL /* hv_access_partition_id */,
            NULL /* hv_access_memory_pool */, NULL /* hv_adjust_message_buffers */,
            NULL /* hv_post_messages */, NULL /* hv_signal_events */,
            NULL /* hv_create_port */, NULL /* hv_connect_port */,
            NULL /* hv_access_stats */, NULL, NULL, NULL /* hv_debugging */,
            NULL /* hv_cpu_power_management */, NULL /* hv_configure_profiler */,
            NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0x40000003,
        false, 0,
        R_EBX,
    },
    // FEAT_HYPERV_EDX
    {
        {
            NULL /* hv_mwait */, NULL /* hv_guest_debugging */,
            NULL /* hv_perf_monitor */, NULL /* hv_cpu_dynamic_part */,
            NULL /* hv_hypercall_params_xmm */, NULL /* hv_guest_idle_state */,
            NULL, NULL,
            NULL, NULL, NULL /* hv_guest_crash_msr */, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0x40000003,
        false, 0,
        R_EDX,
    },
    // FEAT_SVM
    {
        {
            "npt", "lbrv", "svm-lock", "nrip-save",
            "tsc-scale", "vmcb-clean",  "flushbyasid", "decodeassists",
            NULL, NULL, "pause-filter", NULL,
            "pfthreshold", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0x8000000A,
        false, 0,
        R_EDX,
        0,
        TCG_SVM_FEATURES,
    },
    // FEAT_XSAVE
    {
        {
            "xsaveopt", "xsavec", "xgetbv1", "xsaves",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        0xd,
        true,1,
        R_EAX,
        0,
        TCG_XSAVE_FEATURES,
    },
    // FEAT_ARAT
    {
        {
            NULL, NULL, "arat", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        6,
        false, 0,
        R_EAX,
        TCG_6_EAX_FEATURES,
    },
    // FEAT_XSAVE_COMP_LO
    {
        {NULL},
        0xD,
        true, 0,
        R_EAX,
        ~0U,
        0,
        XSTATE_FP_MASK | XSTATE_SSE_MASK |
            XSTATE_YMM_MASK | XSTATE_BNDREGS_MASK | XSTATE_BNDCSR_MASK |
            XSTATE_OPMASK_MASK | XSTATE_ZMM_Hi256_MASK | XSTATE_Hi16_ZMM_MASK |
            XSTATE_PKRU_MASK,

    },
    // FEAT_XSAVE_COMP_HI
    {
        {NULL},
        0xD,
        true, 0,
        R_EDX,
        ~0U,
    },
};

typedef struct X86RegisterInfo32 {
    /* Name of register */
    const char *name;
    /* QAPI enum value register */
    X86CPURegister32 qapi_enum;
} X86RegisterInfo32;

#define REGISTER(reg) \
    { #reg, X86_CPU_REGISTER32_##reg }
static const X86RegisterInfo32 x86_reg_info_32[CPU_NB_REGS32] = {
    REGISTER(EAX),
    REGISTER(ECX),
    REGISTER(EDX),
    REGISTER(EBX),
    REGISTER(ESP),
    REGISTER(EBP),
    REGISTER(ESI),
    REGISTER(EDI),
};
#undef REGISTER

typedef struct ExtSaveArea {
    uint32_t feature, bits;
    uint32_t offset, size;
} ExtSaveArea;

static const ExtSaveArea x86_ext_save_areas[] = {
    // XSTATE_FP_BIT
    {
        /* x87 FP state component is always enabled if XSAVE is supported */
        FEAT_1_ECX, CPUID_EXT_XSAVE,
        /* x87 state is in the legacy region of the XSAVE area */
        0,
        sizeof(X86LegacyXSaveArea) + sizeof(X86XSaveHeader),
    },
    // XSTATE_SSE_BIT
    {
        /* SSE state component is always enabled if XSAVE is supported */
        FEAT_1_ECX, CPUID_EXT_XSAVE,
        /* SSE state is in the legacy region of the XSAVE area */
        0,
        sizeof(X86LegacyXSaveArea) + sizeof(X86XSaveHeader),
    },
    // XSTATE_YMM_BIT
    {
        FEAT_1_ECX, CPUID_EXT_AVX,
        offsetof(X86XSaveArea, avx_state),
        sizeof(XSaveAVX),
    },
    // XSTATE_BNDREGS_BIT
    {
        FEAT_7_0_EBX, CPUID_7_0_EBX_MPX,
        offsetof(X86XSaveArea, bndreg_state),
        sizeof(XSaveBNDREG),
    },
    // XSTATE_BNDCSR_BIT
    {
        FEAT_7_0_EBX, CPUID_7_0_EBX_MPX,
        offsetof(X86XSaveArea, bndcsr_state),
        sizeof(XSaveBNDCSR),
    },
    // XSTATE_OPMASK_BIT
    {
        FEAT_7_0_EBX, CPUID_7_0_EBX_AVX512F,
        offsetof(X86XSaveArea, opmask_state),
        sizeof(XSaveOpmask),
    },
    // XSTATE_ZMM_Hi256_BIT
    {
        FEAT_7_0_EBX, CPUID_7_0_EBX_AVX512F,
        offsetof(X86XSaveArea, zmm_hi256_state),
        sizeof(XSaveZMM_Hi256),
    },
    // XSTATE_Hi16_ZMM_BIT
    {
        FEAT_7_0_EBX, CPUID_7_0_EBX_AVX512F,
        offsetof(X86XSaveArea, hi16_zmm_state),
        sizeof(XSaveHi16_ZMM),
    },
    // XSTATE_PKRU_BIT
    {
        FEAT_7_0_ECX, CPUID_7_0_ECX_PKU,
        offsetof(X86XSaveArea, pkru_state),
        sizeof(XSavePKRU),
    },
};

static uint32_t xsave_area_size(uint64_t mask)
{
    int i;
    uint64_t ret = 0;

    for (i = 0; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        const ExtSaveArea *esa = &x86_ext_save_areas[i];
        if ((mask >> i) & 1) {
            ret = MAX(ret, esa->offset + esa->size);
        }
    }
    return ret;
}

static inline uint64_t x86_cpu_xsave_components(X86CPU *cpu)
{
    return ((uint64_t)cpu->env.features[FEAT_XSAVE_COMP_HI]) << 32 |
           cpu->env.features[FEAT_XSAVE_COMP_LO];
}

const char *get_register_name_32(unsigned int reg)
{
    if (reg >= CPU_NB_REGS32) {
        return NULL;
    }
    return x86_reg_info_32[reg].name;
}

#ifdef _MSC_VER
#include <intrin.h>
#endif

/*
 * Returns the set of feature flags that are supported and migratable by
 * QEMU, for a given FeatureWord.
 */
static uint32_t x86_cpu_get_migratable_flags(FeatureWord w)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint32_t r = 0;
    int i;

    for (i = 0; i < 32; i++) {
        uint32_t f = 1U << i;
        /* If the feature name is known, it is implicitly considered migratable,
         * unless it is explicitly set in unmigratable_flags */
        if ((wi->migratable_flags & f) ||
            (wi->feat_names[i] && !(wi->unmigratable_flags & f))) {
            r |= f;
        }
    }
    return r;
}

void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef _MSC_VER
    __cpuidex((int*)vec, function, count);
#else
#ifdef __x86_64__
    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
#elif defined(__i386__)
    asm volatile("pusha \n\t"
                 "cpuid \n\t"
                 "mov %%eax, 0(%2) \n\t"
                 "mov %%ebx, 4(%2) \n\t"
                 "mov %%ecx, 8(%2) \n\t"
                 "mov %%edx, 12(%2) \n\t"
                 "popa"
                 : : "a"(function), "c"(count), "S"(vec)
                 : "memory", "cc");
#else
    abort();
#endif
#endif // _MSC_VER

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

#define iswhite(c) ((c) && ((c) <= ' ' || '~' < (c)))

/* general substring compare of *[s1..e1) and *[s2..e2).  sx is start of
 * a substring.  ex if !NULL points to the first char after a substring,
 * otherwise the string is assumed to sized by a terminating nul.
 * Return lexical ordering of *s1:*s2.
 */
static int sstrcmp(const char *s1, const char *e1,
                   const char *s2, const char *e2)
{
    for (;;) {
        if (!*s1 || !*s2 || *s1 != *s2)
            return (*s1 - *s2);
        ++s1, ++s2;
        if (s1 == e1 && s2 == e2)
            return (0);
        else if (s1 == e1)
            return (*s2);
        else if (s2 == e2)
            return (*s1);
    }
}

/* compare *[s..e) to *altstr.  *altstr may be a simple string or multiple
 * '|' delimited (possibly empty) strings in which case search for a match
 * within the alternatives proceeds left to right.  Return 0 for success,
 * non-zero otherwise.
 */
static int altcmp(const char *s, const char *e, const char *altstr)
{
    const char *p, *q;

    for (q = p = altstr; ; ) {
        while (*p && *p != '|')
            ++p;
        if ((q == p && !*s) || (q != p && !sstrcmp(s, e, q, p)))
            return (0);
        if (!*p)
            return (1);
        else
            q = ++p;
    }
}

/* search featureset for flag *[s..e), if found set corresponding bit in
 * *pval and return true, otherwise return false
 */
static bool lookup_feature(uint32_t *pval, const char *s, const char *e,
                           const char **featureset)
{
    uint32_t mask;
    const char **ppc;
    bool found = false;

    for (mask = 1, ppc = featureset; mask; mask <<= 1, ++ppc) {
        if (*ppc && !altcmp(s, e, *ppc)) {
            *pval |= mask;
            found = true;
        }
    }
    return found;
}

static void add_flagname_to_bitmaps(const char *flagname,
                                    FeatureWordArray words,
                                    Error **errp)
{
    FeatureWord w;
    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *wi = &feature_word_info[w];
        if (lookup_feature(&words[w], flagname, NULL, wi->feat_names)) {
            break;
        }
    }
    if (w == FEATURE_WORDS) {
        error_setg(errp, "CPU feature %s not found", flagname);
    }
}

void host_vendor_fms(char *vendor, int *family, int *model, int *stepping)
{
    uint32_t eax, ebx, ecx, edx;

    host_cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);
    x86_cpu_vendor_words2str(vendor, ebx, edx, ecx);

    host_cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);
    if (family) {
        *family = ((eax >> 8) & 0x0F) + ((eax >> 20) & 0xFF);
    }
    if (model) {
        *model = ((eax >> 4) & 0x0F) | ((eax & 0xF0000) >> 12);
    }
    if (stepping) {
        *stepping = eax & 0x0F;
    }
}

/* Return type name for a given CPU model name
 * Caller is responsible for freeing the returned string.
 */
static char *x86_cpu_type_name(const char *model_name)
{
    return g_strdup_printf(X86_CPU_TYPE_NAME("%s"), model_name);
}

static ObjectClass *x86_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    if (cpu_model == NULL) {
        return NULL;
    }

    typename = x86_cpu_type_name(cpu_model);
    oc = object_class_by_name(uc, typename);
    g_free(typename);
    return oc;
}

struct X86CPUDefinition {
    const char *name;
    uint32_t level;
    uint32_t xlevel;
    /* vendor is zero-terminated, 12 character ASCII string */
    char vendor[CPUID_VENDOR_SZ + 1];
    int family;
    int model;
    int stepping;
    FeatureWordArray features;
    const char *model_id;
    bool cache_info_passthrough;
    CPUCaches *cache_info;
};

static CPUCacheInfo epyc_l1d_cache = {
    DATA_CACHE,
    1,
    32 * KiB,
    64,
    8,
    1,
    64,
    1,
    1,
    true,
};

static CPUCacheInfo epyc_l1i_cache = {
    INSTRUCTION_CACHE,
    1,
    64 * KiB,
    64,
    4,
    1,
    256,
    1,
    1,
    true,
};

static CPUCacheInfo epyc_l2_cache = {
    UNIFIED_CACHE,
    2,
    512 * KiB,
    64,
    8,
    1,
    1024,
    1,
};

static CPUCacheInfo epyc_l3_cache = {
    UNIFIED_CACHE,
    3,
    8 * MiB,
    64,
    16,
    1,
    8192,
    1,
    true,
    false,
    true,
    true,
};

static CPUCaches epyc_cache_info = {
    &epyc_l1d_cache,
    &epyc_l1i_cache,
    &epyc_l2_cache,
    &epyc_l3_cache,
};

static X86CPUDefinition builtin_x86_defs[] = {
    {
        "qemu64",
        0xd, 0x8000000A,
        CPUID_VENDOR_AMD,
        6, 6, 3,
        {
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36,
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_CX16,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM,
        },
        "QEMU Virtual CPU version " QEMU_HW_VERSION
    },
    {
        "phenom",
        5, 0x8000001A,
        CPUID_VENDOR_AMD,
        16, 2, 3,
        {
        /* Missing: CPUID_HT */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36 | CPUID_VME,
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_CX16 |
            CPUID_EXT_POPCNT,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX |
            CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT | CPUID_EXT2_MMXEXT |
            CPUID_EXT2_FFXSR | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP,
        /* Missing: CPUID_EXT3_CMP_LEG, CPUID_EXT3_EXTAPIC,
                  CPUID_EXT3_CR8LEG,
                  CPUID_EXT3_MISALIGNSSE, CPUID_EXT3_3DNOWPREFETCH,
                  CPUID_EXT3_OSVW, CPUID_EXT3_IBS */
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM |
            CPUID_EXT3_ABM | CPUID_EXT3_SSE4A,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        /* Missing: CPUID_SVM_LBRV */
        // FEAT_SVM
            CPUID_SVM_NPT,
        },
        "AMD Phenom(tm) 9550 Quad-Core Processor",
    },
    {
        "core2duo",
        10, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 15, 11,
        {
        /* Missing: CPUID_DTS, CPUID_HT, CPUID_TM, CPUID_PBE */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36 | CPUID_VME | CPUID_ACPI | CPUID_SS,
        /* Missing: CPUID_EXT_DTES64, CPUID_EXT_DSCPL, CPUID_EXT_EST,
         * CPUID_EXT_TM2, CPUID_EXT_XTPR, CPUID_EXT_PDCM, CPUID_EXT_VMX */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 |
            CPUID_EXT_CX16,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel(R) Core(TM)2 Duo CPU     T7700  @ 2.40GHz",
    },
    {
        "kvm64",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        15, 6, 1,
        {
        /* Missing: CPUID_HT */
        // FEAT_1_EDX
            PPRO_FEATURES | CPUID_VME |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36,
        /* Missing: CPUID_EXT_POPCNT, CPUID_EXT_MONITOR */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_CX16,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        /* Missing: CPUID_EXT2_PDPE1GB, CPUID_EXT2_RDTSCP */
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        /* Missing: CPUID_EXT3_LAHF_LM, CPUID_EXT3_CMP_LEG, CPUID_EXT3_EXTAPIC,
                    CPUID_EXT3_CR8LEG, CPUID_EXT3_ABM, CPUID_EXT3_SSE4A,
                    CPUID_EXT3_MISALIGNSSE, CPUID_EXT3_3DNOWPREFETCH,
                    CPUID_EXT3_OSVW, CPUID_EXT3_IBS, CPUID_EXT3_SVM */
        // FEAT_8000_0001_ECX
            0,
        },
        "Common KVM processor",
    },
    {
        "qemu32",
        4, 0x80000004,
        CPUID_VENDOR_INTEL,
        6, 6, 3,
        {
        // FEAT_1_EDX
            PPRO_FEATURES,
        // FEAT_1_ECX
            CPUID_EXT_SSSE3,
        },
        "QEMU Virtual CPU version " QEMU_HW_VERSION
    },
    {
        "kvm32",
        5, 0x80000008,
        CPUID_VENDOR_INTEL,
        15, 6, 1,
        {
        // FEAT_1_EDX
            PPRO_FEATURES | CPUID_VME |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_PSE36,
        // FEAT_1_ECX
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
        // FEAT_8000_0001_ECX
            0,
        },
        "Common 32-bit KVM processor",
    },
    {
        "coreduo",
        10, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 14, 8,
        {
        /* Missing: CPUID_DTS, CPUID_HT, CPUID_TM, CPUID_PBE */
        // FEAT_1_EDX
            PPRO_FEATURES | CPUID_VME |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_ACPI |
            CPUID_SS,
        /* Missing: CPUID_EXT_EST, CPUID_EXT_TM2 , CPUID_EXT_XTPR,
         * CPUID_EXT_PDCM, CPUID_EXT_VMX */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_NX,
        },
        "Genuine Intel(R) CPU           T2600  @ 2.16GHz",
    },
    {
        "486",
        1, 0,
        CPUID_VENDOR_INTEL,
        4, 8, 0,
        {
        // FEAT_1_EDX
            I486_FEATURES,
        },
        "",
    },
    {
        "pentium",
        1, 0,
        CPUID_VENDOR_INTEL,
        5, 4, 3,
        {
        // FEAT_1_EDX
            PENTIUM_FEATURES,
        },
        "",
    },
    {
        "pentium2",
        2, 0,
        CPUID_VENDOR_INTEL,
        6, 5, 2,
        {
        // FEAT_1_EDX
            PENTIUM2_FEATURES,
        },
        "",
    },
    {
        "pentium3",
        3, 0,
        CPUID_VENDOR_INTEL,
        6, 7, 3,
        {
        // FEAT_1_EDX
            PENTIUM3_FEATURES,
        },
        "",
    },
    {
        "athlon",
        2, 0x80000008,
        CPUID_VENDOR_AMD,
        6, 2, 3,
        {
        // FEAT_1_EDX
            PPRO_FEATURES | CPUID_PSE36 | CPUID_VME | CPUID_MTRR |
            CPUID_MCA,
        // FEAT_1_ECX
            0,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_MMXEXT | CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT,
        },
        "QEMU Virtual CPU version " QEMU_HW_VERSION
    },
    {
        "n270",
        10, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 28, 2,
        {
        /* Missing: CPUID_DTS, CPUID_HT, CPUID_TM, CPUID_PBE */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_VME |
            CPUID_ACPI | CPUID_SS,
            /* Some CPUs got no CPUID_SEP */
        /* Missing: CPUID_EXT_DSCPL, CPUID_EXT_EST, CPUID_EXT_TM2,
         * CPUID_EXT_XTPR */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 |
            CPUID_EXT_MOVBE,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel(R) Atom(TM) CPU N270   @ 1.60GHz",
    },
    {
        "Conroe",
        10, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 15, 3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_SSSE3 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Celeron_4x0 (Conroe/Merom Class Core 2)",
    },
    {
        "Penryn",
        10, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 23, 3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Core 2 Duo P9xxx (Penryn Class Core 2)",
    },
    {
        "Nehalem",
        11, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 26, 3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_POPCNT | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Core i7 9xx (Nehalem Class Core i7)",
    },
    {
        "Nehalem-IBRS",
        11, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,26,3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_POPCNT | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Core i7 9xx (Nehalem Core i7, IBRS update)",
    },
    {
        "Westmere",
        11, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 44, 1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AES | CPUID_EXT_POPCNT | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            0,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Westmere E56xx/L56xx/X56xx (Nehalem-C)",
    },
    {
        "Westmere-IBRS",
        11, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,44,1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AES | CPUID_EXT_POPCNT | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            0,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Westmere E56xx/L56xx/X56xx (IBRS update)",
    },
    {
        "SandyBridge",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 42, 1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_POPCNT |
            CPUID_EXT_X2APIC | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon E312xx (Sandy Bridge)",
    },
    {
        "SandyBridge-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,42,1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_POPCNT |
            CPUID_EXT_X2APIC | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon E312xx (Sandy Bridge, IBRS update)",
    },
    {
        "IvyBridge",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 58, 9,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_POPCNT |
            CPUID_EXT_X2APIC | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3 | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_ERMS,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon E3-12xx v2 (Ivy Bridge)",
    },
    {
        "IvyBridge-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,58,9,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_POPCNT |
            CPUID_EXT_X2APIC | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3 | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_ERMS,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon E3-12xx v2 (Ivy Bridge, IBRS)",
    },
    {
        "Haswell-noTSX",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 60, 1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Haswell, no TSX)",
    },
    {
        "Haswell-noTSX-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,60,1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Haswell, no TSX, IBRS)",
    },
    {
        "Haswell",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 60, 4,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Haswell)",
    },
    {
        "Haswell-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,60,4,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Haswell, IBRS)",
    },
    {
        "Broadwell-noTSX",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 61, 2,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Broadwell, no TSX)",
    },
    {
        "Broadwell-noTSX-IBRS",
        0xd,0x80000008,
        CPUID_VENDOR_INTEL,
        6,61,2,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Broadwell, no TSX, IBRS)",
    },
    {
        "Broadwell",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 61, 2,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_ARAT
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Broadwell)",
    },
    {
        "Broadwell-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,61,2,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP,
        // // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Broadwell, IBRS)",
    },
    {
        "Skylake-Client",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 94, 3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_MPX,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        /* Missing: XSAVES (not supported by some Linux versions,
         * including v4.1 to v4.12).
         * KVM doesn't yet expose any XSAVES state save component,
         * and the only one defined in Skylake (processor tracing)
         * probably will block migration anyway.
         */
        // FEAT_XSAVE]
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Skylake)",
    },
    {
        "Skylake-Client-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6, 94, 3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_MPX,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        /* Missing: XSAVES (not supported by some Linux versions,
         * including v4.1 to v4.12).
         * KVM doesn't yet expose any XSAVES state save component,
         * and the only one defined in Skylake (processor tracing)
         * probably will block migration anyway.
         */
        // FEAT_XSAVE]
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Core Processor (Skylake, IBRS)",
    },
    {
        "Skylake-Server",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,
        85,
        4,
        {
        // FEAT_1_EDX]
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_MPX | CPUID_7_0_EBX_CLWB |
            CPUID_7_0_EBX_AVX512F | CPUID_7_0_EBX_AVX512DQ |
            CPUID_7_0_EBX_AVX512BW | CPUID_7_0_EBX_AVX512CD |
            CPUID_7_0_EBX_AVX512VL,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        /* Missing: XSAVES (not supported by some Linux versions,
         * including v4.1 to v4.12).
         * KVM doesn't yet expose any XSAVES state save component,
         * and the only one defined in Skylake (processor tracing)
         * probably will block migration anyway.
         */
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon Processor (Skylake)",
    },
    {
        "Skylake-Server-IBRS",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,85,4,
        {
        // FEAT_1_EDX]
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_MPX | CPUID_7_0_EBX_CLWB |
            CPUID_7_0_EBX_AVX512F | CPUID_7_0_EBX_AVX512DQ |
            CPUID_7_0_EBX_AVX512BW | CPUID_7_0_EBX_AVX512CD |
            CPUID_7_0_EBX_AVX512VL,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_SPEC_CTRL,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        /* Missing: XSAVES (not supported by some Linux versions,
         * including v4.1 to v4.12).
         * KVM doesn't yet expose any XSAVES state save component,
         * and the only one defined in Skylake (processor tracing)
         * probably will block migration anyway.
         */
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon Processor (Skylake, IBRS)",
    },
    {
        .name = "Icelake-Client",
        .level = 0xd,
        .vendor = CPUID_VENDOR_INTEL,
        .family = 6,
        .model = 126,
        .stepping = 0,
        .features[FEAT_1_EDX] =
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        .features[FEAT_1_ECX] =
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        .features[FEAT_8000_0001_EDX] =
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        .features[FEAT_8000_0001_ECX] =
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        .features[FEAT_8000_0008_EBX] =
            CPUID_8000_0008_EBX_WBNOINVD,
        .features[FEAT_7_0_EBX] =
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_MPX | CPUID_7_0_EBX_INTEL_PT,
        .features[FEAT_7_0_ECX] =
            CPUID_7_0_ECX_VBMI | CPUID_7_0_ECX_UMIP | CPUID_7_0_ECX_PKU |
            CPUID_7_0_ECX_OSPKE | CPUID_7_0_ECX_VBMI2 | CPUID_7_0_ECX_GFNI |
            CPUID_7_0_ECX_VAES | CPUID_7_0_ECX_VPCLMULQDQ |
            CPUID_7_0_ECX_AVX512VNNI | CPUID_7_0_ECX_AVX512BITALG |
            CPUID_7_0_ECX_AVX512_VPOPCNTDQ,
        .features[FEAT_7_0_EDX] =
            CPUID_7_0_EDX_SPEC_CTRL | CPUID_7_0_EDX_SPEC_CTRL_SSBD,
        /* Missing: XSAVES (not supported by some Linux versions,
                * including v4.1 to v4.12).
                * KVM doesn't yet expose any XSAVES state save component,
                * and the only one defined in Skylake (processor tracing)
                * probably will block migration anyway.
                */
        .features[FEAT_XSAVE] =
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        .features[FEAT_6_EAX] =
            CPUID_6_EAX_ARAT,
        .xlevel = 0x80000008,
        .model_id = "Intel Core Processor (Icelake)",
    },
    {
        .name = "Icelake-Server",
        .level = 0xd,
        .vendor = CPUID_VENDOR_INTEL,
        .family = 6,
        .model = 134,
        .stepping = 0,
        .features[FEAT_1_EDX] =
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        .features[FEAT_1_ECX] =
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID | CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        .features[FEAT_8000_0001_EDX] =
            CPUID_EXT2_LM | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        .features[FEAT_8000_0001_ECX] =
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        .features[FEAT_8000_0008_EBX] =
            CPUID_8000_0008_EBX_WBNOINVD,
        .features[FEAT_7_0_EBX] =
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_MPX | CPUID_7_0_EBX_CLWB |
            CPUID_7_0_EBX_AVX512F | CPUID_7_0_EBX_AVX512DQ |
            CPUID_7_0_EBX_AVX512BW | CPUID_7_0_EBX_AVX512CD |
            CPUID_7_0_EBX_AVX512VL | CPUID_7_0_EBX_CLFLUSHOPT |
            CPUID_7_0_EBX_INTEL_PT,
        .features[FEAT_7_0_ECX] =
            CPUID_7_0_ECX_VBMI | CPUID_7_0_ECX_UMIP | CPUID_7_0_ECX_PKU |
            CPUID_7_0_ECX_OSPKE | CPUID_7_0_ECX_VBMI2 | CPUID_7_0_ECX_GFNI |
            CPUID_7_0_ECX_VAES | CPUID_7_0_ECX_VPCLMULQDQ |
            CPUID_7_0_ECX_AVX512VNNI | CPUID_7_0_ECX_AVX512BITALG |
            CPUID_7_0_ECX_AVX512_VPOPCNTDQ | CPUID_7_0_ECX_LA57,
        .features[FEAT_7_0_EDX] =
            CPUID_7_0_EDX_PCONFIG | CPUID_7_0_EDX_SPEC_CTRL |
            CPUID_7_0_EDX_SPEC_CTRL_SSBD,
        /* Missing: XSAVES (not supported by some Linux versions,
                * including v4.1 to v4.12).
                * KVM doesn't yet expose any XSAVES state save component,
                * and the only one defined in Skylake (processor tracing)
                * probably will block migration anyway.
                */
        .features[FEAT_XSAVE] =
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        .features[FEAT_6_EAX] =
            CPUID_6_EAX_ARAT,
        .xlevel = 0x80000008,
        .model_id = "Intel Xeon Processor (Icelake)",
    },
    {
        "KnightsMill",
        0xd, 0x80000008,
        CPUID_VENDOR_INTEL,
        6,
        133,
        0,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SS | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR |
            CPUID_MMX | CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV |
            CPUID_MCA | CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC |
            CPUID_CX8 | CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC |
            CPUID_PSE | CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_F16C | CPUID_EXT_RDRAND,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_AVX2 |
            CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS |
            CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX | CPUID_7_0_EBX_AVX512F |
            CPUID_7_0_EBX_AVX512CD | CPUID_7_0_EBX_AVX512PF |
            CPUID_7_0_EBX_AVX512ER,
        // FEAT_7_0_ECX
            CPUID_7_0_ECX_AVX512_VPOPCNTDQ,
        // FEAT_7_0_EDX
            CPUID_7_0_EDX_AVX512_4VNNIW | CPUID_7_0_EDX_AVX512_4FMAPS,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_ABM | CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "Intel Xeon Phi Processor (Knights Mill)",
    },
    {
        "Opteron_G1",
        5, 0x80000008,
        CPUID_VENDOR_AMD,
        15, 6, 1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        },
        "AMD Opteron 240 (Gen 1 Class Opteron)",
    },
    {
        "Opteron_G2",
        5, 0x80000008,
        CPUID_VENDOR_AMD,
        15, 6, 1,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_CX16 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_SVM | CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 22xx (Gen 2 Class Opteron)",
    },
    {
        "Opteron_G3",
        5, 0x80000008,
        CPUID_VENDOR_AMD,
        16, 2, 3,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_POPCNT | CPUID_EXT_CX16 | CPUID_EXT_MONITOR |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_MISALIGNSSE | CPUID_EXT3_SSE4A |
            CPUID_EXT3_ABM | CPUID_EXT3_SVM | CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 23xx (Gen 3 Class Opteron)",
    },
    {
        "Opteron_G4",
        0xd, 0x8000001A,
        CPUID_VENDOR_AMD,
        21, 1, 2,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_PDPE1GB | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_FMA4 | CPUID_EXT3_XOP |
            CPUID_EXT3_3DNOWPREFETCH | CPUID_EXT3_MISALIGNSSE |
            CPUID_EXT3_SSE4A | CPUID_EXT3_ABM | CPUID_EXT3_SVM |
            CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 62xx class CPU",
    },
    {
        "Opteron_G5",
        0xd, 0x8000001A,
        CPUID_VENDOR_AMD,
        21, 2, 0,
        {
        // FEAT_1_EDX
            CPUID_VME | CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_F16C | CPUID_EXT_AVX | CPUID_EXT_XSAVE |
            CPUID_EXT_AES | CPUID_EXT_POPCNT | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_FMA |
            CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_PDPE1GB | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_TBM | CPUID_EXT3_FMA4 | CPUID_EXT3_XOP |
            CPUID_EXT3_3DNOWPREFETCH | CPUID_EXT3_MISALIGNSSE |
            CPUID_EXT3_SSE4A | CPUID_EXT3_ABM | CPUID_EXT3_SVM |
            CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 63xx class CPU",
    },
    {
        "EPYC",
        0xd, 0x8000001E,
        CPUID_VENDOR_AMD,
        23, 1, 2,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX | CPUID_CLFLUSH |
            CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA | CPUID_PGE |
            CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 | CPUID_MCE |
            CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE | CPUID_DE |
            CPUID_VME | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_RDRAND | CPUID_EXT_F16C | CPUID_EXT_AVX |
            CPUID_EXT_XSAVE | CPUID_EXT_AES |  CPUID_EXT_POPCNT |
            CPUID_EXT_MOVBE | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_FMA | CPUID_EXT_SSSE3 |
            CPUID_EXT_MONITOR | CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_AVX2 |
            CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_RDSEED |
            CPUID_7_0_EBX_ADX | CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_CLFLUSHOPT |
            CPUID_7_0_EBX_SHA_NI,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_PDPE1GB |
            CPUID_EXT2_FFXSR | CPUID_EXT2_MMXEXT | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_OSVW | CPUID_EXT3_3DNOWPREFETCH |
            CPUID_EXT3_MISALIGNSSE | CPUID_EXT3_SSE4A | CPUID_EXT3_ABM |
            CPUID_EXT3_CR8LEG | CPUID_EXT3_SVM | CPUID_EXT3_LAHF_LM |
            CPUID_EXT3_TOPOEXT,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        /* Missing: XSAVES (not supported by some Linux versions,
         * including v4.1 to v4.12).
         * KVM doesn't yet expose any XSAVES state save component.
         */
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "AMD EPYC Processor",
        false,
        &epyc_cache_info,
    },
    {
        "EPYC-IBPB",
        0xd, 0x8000001E,
        CPUID_VENDOR_AMD,
        23, 1, 2,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX | CPUID_CLFLUSH |
            CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA | CPUID_PGE |
            CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 | CPUID_MCE |
            CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE | CPUID_DE |
            CPUID_VME | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_RDRAND | CPUID_EXT_F16C | CPUID_EXT_AVX |
            CPUID_EXT_XSAVE | CPUID_EXT_AES |  CPUID_EXT_POPCNT |
            CPUID_EXT_MOVBE | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_FMA | CPUID_EXT_SSSE3 |
            CPUID_EXT_MONITOR | CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_AVX2 |
            CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_RDSEED |
            CPUID_7_0_EBX_ADX | CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_CLFLUSHOPT |
            CPUID_7_0_EBX_SHA_NI,
        // FEAT_7_0_ECX
            0,
        // FEAT_7_0_EDX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_PDPE1GB |
            CPUID_EXT2_FFXSR | CPUID_EXT2_MMXEXT | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_OSVW | CPUID_EXT3_3DNOWPREFETCH |
            CPUID_EXT3_MISALIGNSSE | CPUID_EXT3_SSE4A | CPUID_EXT3_ABM |
            CPUID_EXT3_CR8LEG | CPUID_EXT3_SVM | CPUID_EXT3_LAHF_LM |
            CPUID_EXT3_TOPOEXT,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_8000_0008_EBX
            CPUID_8000_0008_EBX_IBPB,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        // FEAT_KVM_HINTS
            0,
        // FEAT_HYPERV_EAX
            0,
        // FEAT_HYPERV_EBX
            0,
        // FEAT_HYPERV_EDX
            0,
        // FEAT_SVM
            0,
        /* Missing: XSAVES (not supported by some Linux versions,
         * including v4.1 to v4.12).
         * KVM doesn't yet expose any XSAVES state save component.
         */
        // FEAT_XSAVE
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XGETBV1,
        // FEAT_6_EAX
            CPUID_6_EAX_ARAT,
        },
        "AMD EPYC Processor (with IBPB)",
        false,
        &epyc_cache_info,
    },
};

typedef struct PropValue {
    const char *prop, *value;
} PropValue;

/* TCG-specific defaults that override all CPU models when using TCG
 */
static PropValue tcg_default_props[] = {
    { "vme", "off" },
    { NULL, NULL },
};

static uint32_t x86_cpu_get_supported_feature_word(struct uc_struct *uc,
                                                   FeatureWord w, bool migratable);

static void report_unavailable_features(FeatureWord w, uint32_t mask)
{
    FeatureWordInfo *f = &feature_word_info[w];
    int i;

    for (i = 0; i < 32; ++i) {
        if ((1UL << i) & mask) {
            const char *reg = get_register_name_32(f->cpuid_reg);
            assert(reg);
            fprintf(stderr, "warning: %s doesn't support requested feature: "
                "CPUID.%02XH:%s%s%s [bit %d]\n",
                "TCG",
                f->cpuid_eax, reg,
                f->feat_names[i] ? "." : "",
                f->feat_names[i] ? f->feat_names[i] : "", i);
        }
    }
}

static void x86_cpuid_version_get_family(struct uc_struct *uc,
                                         Object *obj, Visitor *v,
                                         const char *name, void *opaque,
                                         Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    int64_t value;

    value = (env->cpuid_version >> 8) & 0xf;
    if (value == 0xf) {
        value += (env->cpuid_version >> 20) & 0xff;
    }
    visit_type_int(v, name, &value, errp);
}

static void x86_cpuid_version_set_family(struct uc_struct *uc,
                                         Object *obj, Visitor *v,
                                         const char *name, void *opaque,
                                         Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    const int64_t min = 0;
    const int64_t max = 0xff + 0xf;
    Error *local_err = NULL;
    int64_t value;

    visit_type_int(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (value < min || value > max) {
        error_setg(errp, QERR_PROPERTY_VALUE_OUT_OF_RANGE, "",
                   name ? name : "null", value, min, max);
        return;
    }

    env->cpuid_version &= ~0xff00f00;
    if (value > 0x0f) {
        env->cpuid_version |= 0xf00 | ((value - 0x0f) << 20);
    } else {
        env->cpuid_version |= value << 8;
    }
}

static void x86_cpuid_version_get_model(struct uc_struct *uc,
                                        Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    int64_t value;

    value = (env->cpuid_version >> 4) & 0xf;
    value |= ((env->cpuid_version >> 16) & 0xf) << 4;
    visit_type_int(v, name, &value, errp);
}

static void x86_cpuid_version_set_model(struct uc_struct *uc,
                                        Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    const int64_t min = 0;
    const int64_t max = 0xff;
    Error *local_err = NULL;
    int64_t value;

    visit_type_int(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (value < min || value > max) {
        error_setg(errp, QERR_PROPERTY_VALUE_OUT_OF_RANGE, "",
                   name ? name : "null", value, min, max);
        return;
    }

    env->cpuid_version &= ~0xf00f0;
    env->cpuid_version |= ((value & 0xf) << 4) | ((value >> 4) << 16);
}

static void x86_cpuid_version_get_stepping(struct uc_struct *uc,
                                           Object *obj, Visitor *v,
                                           const char *name, void *opaque,
                                           Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    int64_t value;

    value = env->cpuid_version & 0xf;
    visit_type_int(v, name, &value, errp);
}

static void x86_cpuid_version_set_stepping(struct uc_struct *uc,
                                           Object *obj, Visitor *v,
                                           const char *name, void *opaque,
                                           Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    const int64_t min = 0;
    const int64_t max = 0xf;
    Error *local_err = NULL;
    int64_t value;

    visit_type_int(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (value < min || value > max) {
        error_setg(errp, QERR_PROPERTY_VALUE_OUT_OF_RANGE, "",
                   name ? name : "null", value, min, max);
        return;
    }

    env->cpuid_version &= ~0xf;
    env->cpuid_version |= value & 0xf;
}

static char *x86_cpuid_get_vendor(struct uc_struct *uc, Object *obj, Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    char *value;

    value = (char *)g_malloc(CPUID_VENDOR_SZ + 1);
    x86_cpu_vendor_words2str(value, env->cpuid_vendor1, env->cpuid_vendor2,
                             env->cpuid_vendor3);
    return value;
}

static int x86_cpuid_set_vendor(struct uc_struct *uc, Object *obj,
                                const char *value, Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    int i;

    if (strlen(value) != CPUID_VENDOR_SZ) {
        error_setg(errp, QERR_PROPERTY_VALUE_BAD, "",
                   "vendor", value);
        return -1;
    }

    env->cpuid_vendor1 = 0;
    env->cpuid_vendor2 = 0;
    env->cpuid_vendor3 = 0;
    for (i = 0; i < 4; i++) {
        env->cpuid_vendor1 |= ((uint8_t)value[i    ]) << (8 * i);
        env->cpuid_vendor2 |= ((uint8_t)value[i + 4]) << (8 * i);
        env->cpuid_vendor3 |= ((uint8_t)value[i + 8]) << (8 * i);
    }

    return 0;
}

static char *x86_cpuid_get_model_id(struct uc_struct *uc, Object *obj, Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    char *value;
    int i;

    value = g_malloc(48 + 1);
    for (i = 0; i < 48; i++) {
        value[i] = env->cpuid_model[i >> 2] >> (8 * (i & 3));
    }
    value[48] = '\0';
    return value;
}

static int x86_cpuid_set_model_id(struct uc_struct *uc, Object *obj,
                                  const char *model_id, Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    CPUX86State *env = &cpu->env;
    int c, len, i;

    if (model_id == NULL) {
        model_id = "";
    }
    len = strlen(model_id);
    memset(env->cpuid_model, 0, 48);
    for (i = 0; i < 48; i++) {
        if (i >= len) {
            c = '\0';
        } else {
            c = (uint8_t)model_id[i];
        }
        env->cpuid_model[i >> 2] |= c << (8 * (i & 3));
    }

    return 0;
}

static void x86_cpuid_get_tsc_freq(struct uc_struct *uc,
                                   Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    int64_t value;

    value = cpu->env.tsc_khz * 1000;
    visit_type_int(v, name, &value, errp);
}

static void x86_cpuid_set_tsc_freq(struct uc_struct *uc,
                                   Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, obj);
    const int64_t min = 0;
    const int64_t max = INT64_MAX;
    Error *local_err = NULL;
    int64_t value;

    visit_type_int(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (value < min || value > max) {
        error_setg(errp, QERR_PROPERTY_VALUE_OUT_OF_RANGE, "",
                   name ? name : "null", value, min, max);
        return;
    }

    cpu->env.tsc_khz = (int)(value / 1000);
}

/* Generic getter for "feature-words" and "filtered-features" properties */
static void x86_cpu_get_feature_words(struct uc_struct *uc,
                                      Object *obj, Visitor *v,
                                      const char *name, void *opaque,
                                      Error **errp)
{
    uint32_t *array = (uint32_t *)opaque;
    FeatureWord w;

    // These all get setup below, so no need to initialise them here.
    X86CPUFeatureWordInfo word_infos[FEATURE_WORDS];
    X86CPUFeatureWordInfoList list_entries[FEATURE_WORDS];
    X86CPUFeatureWordInfoList *list = NULL;

    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *wi = &feature_word_info[w];
        X86CPUFeatureWordInfo *qwi = &word_infos[w];
        qwi->cpuid_input_eax = wi->cpuid_eax;
        qwi->has_cpuid_input_ecx = wi->cpuid_needs_ecx;
        qwi->cpuid_input_ecx = wi->cpuid_ecx;
        qwi->cpuid_register = x86_reg_info_32[wi->cpuid_reg].qapi_enum;
        qwi->features = array[w];

        /* List will be in reverse order, but order shouldn't matter */
        list_entries[w].next = list;
        list_entries[w].value = &word_infos[w];
        list = &list_entries[w];
    }

    visit_type_X86CPUFeatureWordInfoList(v, "feature-words", &list, errp);
}

/* Convert all '_' in a feature string option name to '-', to make feature
 * name conform to QOM property naming rule, which uses '-' instead of '_'.
 */
static inline void feat2prop(char *s)
{
    while ((s = strchr(s, '_'))) {
        *s = '-';
    }
}

/* Parse "+feature,-feature,feature=foo" CPU feature string
 */
static void x86_cpu_parse_featurestr(struct uc_struct *uc, const char *typename, char *features,
                                     Error **errp)
{
    X86CPU *cpu = X86_CPU(uc, uc->cpu);
    char *featurestr; /* Single 'key=value" string being parsed */
    Error *local_err = NULL;

    if (cpu->cpu_globals_initialized) {
        return;
    }
    cpu->cpu_globals_initialized = true;

    if (!features) {
        return;
    }

    for (featurestr = strtok(features, ",");
         featurestr  && !local_err;
         featurestr = strtok(NULL, ",")) {
        const char *name;
        const char *val = NULL;
        char *eq = NULL;
        char num[32];
        // Unicorn: If'd out
#if 0
        GlobalProperty *prop;
#endif

        /* Compatibility syntax: */
        if (featurestr[0] == '+') {
            add_flagname_to_bitmaps(featurestr + 1, cpu->plus_features, &local_err);
            continue;
        } else if (featurestr[0] == '-') {
            add_flagname_to_bitmaps(featurestr + 1, cpu->minus_features, &local_err);
            continue;
        }

        eq = strchr(featurestr, '=');
        if (eq) {
            *eq++ = 0;
            val = eq;
        } else {
            val = "on";
        }

        feat2prop(featurestr);
        name = featurestr;

        /* Special case: */
        if (!strcmp(name, "tsc-freq")) {
            int ret;
            uint64_t tsc_freq;

            ret = qemu_strtosz_metric(val, NULL, &tsc_freq);
            if (ret < 0 || tsc_freq > INT64_MAX) {
                error_setg(errp, "bad numerical value %s", val);
                return;
            }
            snprintf(num, sizeof(num), "%" PRId64, tsc_freq);
            val = num;
            name = "tsc-frequency";
        }

        // Unicorn: if'd out
#if 0
        prop = g_new0(GlobalProperty, 1);
        prop->driver = typename;
        prop->property = g_strdup(name);
        prop->value = g_strdup(val);
        prop->errp = &error_fatal;
        qdev_prop_register_global(prop);
#endif
    }

    if (local_err) {
        error_propagate(errp, local_err);
    }
}

static uint32_t x86_cpu_get_supported_feature_word(struct uc_struct *uc,
                                                   FeatureWord w, bool migratable_only)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint32_t r;

    if (tcg_enabled(uc)) {
        r = wi->tcg_features;
    } else {
        return ~0;
    }
    if (migratable_only) {
        r &= x86_cpu_get_migratable_flags(w);
    }
    return r;
}

static void x86_cpu_report_filtered_features(X86CPU *cpu)
{
    FeatureWord w;

    for (w = 0; w < FEATURE_WORDS; w++) {
        report_unavailable_features(w, cpu->filtered_features[w]);
    }
}

static void x86_cpu_apply_props(X86CPU *cpu, PropValue *props)
{
    CPUX86State *env = &cpu->env;
    PropValue *pv;
    for (pv = props; pv->prop; pv++) {
        if (!pv->value) {
            continue;
        }
        object_property_parse(env->uc, OBJECT(cpu), pv->value, pv->prop,
                              &error_abort);
    }
}

/* Load data from X86CPUDefinition
 */
static void x86_cpu_load_def(X86CPU *cpu, X86CPUDefinition *def, Error **errp)
{
    CPUX86State *env = &cpu->env;
    const char *vendor;
    FeatureWord w;

    object_property_set_int(env->uc, OBJECT(cpu), def->level, "level", errp);
    object_property_set_int(env->uc, OBJECT(cpu), def->family, "family", errp);
    object_property_set_int(env->uc, OBJECT(cpu), def->model, "model", errp);
    object_property_set_int(env->uc, OBJECT(cpu), def->stepping, "stepping", errp);
    object_property_set_int(env->uc, OBJECT(cpu), def->xlevel, "xlevel", errp);
    cpu->cache_info_passthrough = def->cache_info_passthrough;
    object_property_set_str(env->uc, OBJECT(cpu), def->model_id, "model-id", errp);
    for (w = 0; w < FEATURE_WORDS; w++) {
        env->features[w] = def->features[w];
    }

    /* Store Cache information from the X86CPUDefinition if available */
    /* legacy-cache defaults to 'off' if CPU model provides cache info */
    cpu->legacy_cache = !def->cache_info;

    if (tcg_enabled(env->uc)) {
        x86_cpu_apply_props(cpu, tcg_default_props);
    }

    env->features[FEAT_1_ECX] |= CPUID_EXT_HYPERVISOR;

    /* sysenter isn't supported in compatibility mode on AMD,
     * syscall isn't supported in compatibility mode on Intel.
     * Normally we advertise the actual CPU vendor, but you can
     * override this using the 'vendor' property if you want to use
     * KVM's sysenter/syscall emulation in compatibility mode and
     * when doing cross vendor migration
     */
    vendor = def->vendor;

    object_property_set_str(env->uc, OBJECT(cpu), vendor, "vendor", errp);
}

static void x86_cpu_cpudef_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    X86CPUDefinition *cpudef = data;
    X86CPUClass *xcc = X86_CPU_CLASS(uc, oc);

    xcc->cpu_def = cpudef;
}

static void x86_register_cpudef_type(struct uc_struct *uc, X86CPUDefinition *def)
{
    char *typename = x86_cpu_type_name(def->name);
    TypeInfo ti = {
        typename,
        TYPE_X86_CPU,

        0,
        0,
        NULL,

        NULL,
        NULL,
        NULL,

        def,

        x86_cpu_cpudef_class_init,
    };

    /* catch mistakes instead of silently truncating model_id when too long */
    assert(def->model_id && strlen(def->model_id) <= 48);

    type_register(uc, &ti);
    g_free(typename);
}

#if !defined(CONFIG_USER_ONLY)

void cpu_clear_apic_feature(CPUX86State *env)
{
    env->features[FEAT_1_EDX] &= ~CPUID_APIC;
}

#endif /* !CONFIG_USER_ONLY */

void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx)
{
    X86CPU *cpu = x86_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    uint32_t pkg_offset;
    uint32_t limit;
    uint32_t signature[3];

    /* Calculate & apply limits for different index ranges */
    if (index >= 0xC0000000) {
        limit = env->cpuid_xlevel2;
    } else if (index >= 0x80000000) {
        limit = env->cpuid_xlevel;
    } else if (index >= 0x40000000) {
        limit = 0x40000001;
    } else {
        limit = env->cpuid_level;
    }

    if (index > limit) {
        /* Intel documentation states that invalid EAX input will
         * return the same information as EAX=cpuid_level
         * (Intel SDM Vol. 2A - Instruction Set Reference - CPUID)
         */
        index = env->cpuid_level;
    }

    switch(index) {
    case 0:
        *eax = env->cpuid_level;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 1:
        *eax = env->cpuid_version;
        *ebx = (cpu->apic_id << 24) |
               8 << 8; /* CLFLUSH size in quad words, Linux wants it. */
        *ecx = env->features[FEAT_1_ECX];
        if ((*ecx & CPUID_EXT_XSAVE) && (env->cr[4] & CR4_OSXSAVE_MASK)) {
            *ecx |= CPUID_EXT_OSXSAVE;
        }
        *edx = env->features[FEAT_1_EDX];
        if (cs->nr_cores * cs->nr_threads > 1) {
            *ebx |= (cs->nr_cores * cs->nr_threads) << 16;
            *edx |= CPUID_HT;
        }
        break;
    case 2:
        /* cache info: needed for Pentium Pro compatibility */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = 1; /* Number of CPUID[EAX=2] calls required */
        *ebx = 0;
        if (!cpu->enable_l3_cache) {
            *ecx = 0;
        } else {
            *ecx = cpuid2_cache_descriptor(env->cache_info_cpuid2.l3_cache);
        }
        *edx = (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1d_cache) << 16) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1i_cache) <<  8) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l2_cache));
        break;
    case 4:
        /* cache info: needed for Core compatibility */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, count, eax, ebx, ecx, edx);
            /* QEMU gives out its own APIC IDs, never pass down bits 31..26.  */
            *eax &= ~0xFC000000;
            if ((*eax & 31) && cs->nr_cores > 1) {
                *eax |= (cs->nr_cores - 1) << 26;
            }
        } else {
            *eax = 0;
            switch (count) {
            case 0: /* L1 dcache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1d_cache,
                                    1, cs->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 1: /* L1 icache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1i_cache,
                                    1, cs->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 2: /* L2 cache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l2_cache,
                                    cs->nr_threads, cs->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 3: /* L3 cache info */
                pkg_offset = apicid_pkg_offset(cs->nr_cores, cs->nr_threads);
                if (cpu->enable_l3_cache) {
                    encode_cache_cpuid4(env->cache_info_cpuid4.l3_cache,
                                        (1 << pkg_offset), cs->nr_cores,
                                        eax, ebx, ecx, edx);
                    break;
                }
                /* fall through */
            default: /* end of info */
                *eax = *ebx = *ecx = *edx = 0;
                break;
            }
        }
        break;
    case 5:
        /* mwait info: needed for Core compatibility */
        *eax = 0; /* Smallest monitor-line size in bytes */
        *ebx = 0; /* Largest monitor-line size in bytes */
        *ecx = CPUID_MWAIT_EMX | CPUID_MWAIT_IBE;
        *edx = 0;
        break;
    case 6:
        /* Thermal and Power Leaf */
        *eax = env->features[FEAT_6_EAX];
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 7:
        /* Structured Extended Feature Flags Enumeration Leaf */
        if (count == 0) {
            *eax = 0; /* Maximum ECX value for sub-leaves */
            *ebx = env->features[FEAT_7_0_EBX]; /* Feature flags */
            *ecx = env->features[FEAT_7_0_ECX]; /* Feature flags */
            if ((*ecx & CPUID_7_0_ECX_PKU) && env->cr[4] & CR4_PKE_MASK) {
                *ecx |= CPUID_7_0_ECX_OSPKE;
            }
            *edx = env->features[FEAT_7_0_EDX]; /* Feature flags */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 9:
        /* Direct Cache Access Information Leaf */
        *eax = 0; /* Bits 0-31 in DCA_CAP MSR */
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xA:
        /* Architectural Performance Monitoring Leaf */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xB:
        /* Extended Topology Enumeration Leaf */
        if (!cpu->enable_cpuid_0xb) {
                *eax = *ebx = *ecx = *edx = 0;
                break;
        }

        *ecx = count & 0xff;
        *edx = cpu->apic_id;

        switch (count) {
        case 0:
            *eax = apicid_core_offset(smp_cores, smp_threads);
            *ebx = smp_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_pkg_offset(smp_cores, smp_threads);
            *ebx = smp_cores * smp_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }

        assert(!(*eax & ~0x1f));
        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0xD: {
        /* Processor Extended State */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
            break;
        }

        if (count == 0) {
            *ecx = xsave_area_size(x86_cpu_xsave_components(cpu));
            *eax = env->features[FEAT_XSAVE_COMP_LO];
            *edx = env->features[FEAT_XSAVE_COMP_HI];
            *ebx = *ecx;
        } else if (count == 1) {
            *eax = env->features[FEAT_XSAVE];
        } else if (count < ARRAY_SIZE(x86_ext_save_areas)) {
            if ((x86_cpu_xsave_components(cpu) >> count) & 1) {
                const ExtSaveArea *esa = &x86_ext_save_areas[count];
                *eax = esa->size;
                *ebx = esa->offset;
            }
        }
        break;
    }
    case 0x14: {
        /* Intel Processor Trace Enumeration */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;

        // Unicorn: if'd out
        #if 0
        if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT) ||
            !kvm_enabled()) {
            break;
        }

        if (count == 0) {
            *eax = INTEL_PT_MAX_SUBLEAF;
            *ebx = INTEL_PT_MINIMAL_EBX;
            *ecx = INTEL_PT_MINIMAL_ECX;
        } else if (count == 1) {
            *eax = INTEL_PT_MTC_BITMAP | INTEL_PT_ADDR_RANGES_NUM;
            *ebx = INTEL_PT_PSB_BITMAP | INTEL_PT_CYCLE_BITMAP;
        }
        #endif
        break;
    }
    case 0x40000000:
        /*
         * CPUID code in kvm_arch_init_vcpu() ignores stuff
         * set here, but we restrict to TCG none the less.
         */
        if (tcg_enabled(env->uc) && cpu->expose_tcg) {
            memcpy(signature, "TCGTCGTCGTCG", 12);
            *eax = 0x40000001;
            *ebx = signature[0];
            *ecx = signature[1];
            *edx = signature[2];
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x40000001:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x80000000:
        *eax = env->cpuid_xlevel;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 0x80000001:
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = env->features[FEAT_8000_0001_ECX];
        *edx = env->features[FEAT_8000_0001_EDX];

        /* The Linux kernel checks for the CMPLegacy bit and
         * discards multiple thread information if it is set.
         * So dont set it here for Intel to make Linux guests happy.
         */
        if (cs->nr_cores * cs->nr_threads > 1) {
            if (env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1 ||
                env->cpuid_vendor2 != CPUID_VENDOR_INTEL_2 ||
                env->cpuid_vendor3 != CPUID_VENDOR_INTEL_3) {
                *ecx |= 1 << 1;    /* CmpLegacy bit */
            }
        }
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        *eax = env->cpuid_model[(index - 0x80000002) * 4 + 0];
        *ebx = env->cpuid_model[(index - 0x80000002) * 4 + 1];
        *ecx = env->cpuid_model[(index - 0x80000002) * 4 + 2];
        *edx = env->cpuid_model[(index - 0x80000002) * 4 + 3];
        break;
    case 0x80000005:
        /* cache info (L1 cache) */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (L1_DTLB_2M_ASSOC << 24) | (L1_DTLB_2M_ENTRIES << 16) | \
               (L1_ITLB_2M_ASSOC <<  8) | (L1_ITLB_2M_ENTRIES);
        *ebx = (L1_DTLB_4K_ASSOC << 24) | (L1_DTLB_4K_ENTRIES << 16) | \
               (L1_ITLB_4K_ASSOC <<  8) | (L1_ITLB_4K_ENTRIES);
        *ecx = encode_cache_cpuid80000005(env->cache_info_amd.l1d_cache);
        *edx = encode_cache_cpuid80000005(env->cache_info_amd.l1i_cache);
        break;
    case 0x80000006:
        /* cache info (L2 cache) */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (AMD_ENC_ASSOC(L2_DTLB_2M_ASSOC) << 28) | \
               (L2_DTLB_2M_ENTRIES << 16) | \
               (AMD_ENC_ASSOC(L2_ITLB_2M_ASSOC) << 12) | \
               (L2_ITLB_2M_ENTRIES);
        *ebx = (AMD_ENC_ASSOC(L2_DTLB_4K_ASSOC) << 28) | \
               (L2_DTLB_4K_ENTRIES << 16) | \
               (AMD_ENC_ASSOC(L2_ITLB_4K_ASSOC) << 12) | \
               (L2_ITLB_4K_ENTRIES);
        encode_cache_cpuid80000006(env->cache_info_amd.l2_cache,
                                   cpu->enable_l3_cache ?
                                   env->cache_info_amd.l3_cache : NULL,
                                   ecx, edx);
        break;
    case 0x80000007:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_8000_0007_EDX];
        break;
    case 0x80000008:
        /* virtual & phys address size in low 2 bytes. */
        if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
            /* 64 bit processor */
            *eax = cpu->phys_bits; /* configurable physical bits */
            if  (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57) {
                *eax |= 0x00003900; /* 57 bits virtual */
            } else {
                *eax |= 0x00003000; /* 48 bits virtual */
            }
        } else {
            *eax = cpu->phys_bits;
        }
        *ebx = env->features[FEAT_8000_0008_EBX];
        *ecx = 0;
        *edx = 0;
        if (cs->nr_cores * cs->nr_threads > 1) {
            *ecx |= (cs->nr_cores * cs->nr_threads) - 1;
        }
        break;
    case 0x8000000A:
        if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
            *eax = 0x00000001; /* SVM Revision */
            *ebx = 0x00000010; /* nr of ASIDs */
            *ecx = 0;
            *edx = env->features[FEAT_SVM]; /* optional features */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x8000001D:
        *eax = 0;
        switch (count) {
        case 0: /* L1 dcache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1d_cache, cs,
                                       eax, ebx, ecx, edx);
            break;
        case 1: /* L1 icache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1i_cache, cs,
                                       eax, ebx, ecx, edx);
            break;
        case 2: /* L2 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l2_cache, cs,
                                       eax, ebx, ecx, edx);
            break;
        case 3: /* L3 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l3_cache, cs,
                                       eax, ebx, ecx, edx);
            break;
        default: /* end of info */
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        break;
    case 0x8000001E:
        assert(cpu->core_id <= 255);
        encode_topo_cpuid8000001e(cs, cpu,
                                  eax, ebx, ecx, edx);
        break;
    case 0xC0000000:
        *eax = env->cpuid_xlevel2;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xC0000001:
        /* Support for VIA CPU's CPUID instruction */
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_C000_0001_EDX];
        break;
    case 0xC0000002:
    case 0xC0000003:
    case 0xC0000004:
        /* Reserved for the future, and now filled with zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x8000001F:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    default:
        /* reserved values: zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    }
}

/* CPUClass::reset() */
static void x86_cpu_reset(CPUState *s)
{
    X86CPU *cpu = X86_CPU(s->uc, s);
    X86CPUClass *xcc = X86_CPU_GET_CLASS(s->uc, cpu);
    CPUX86State *env = &cpu->env;
    int i;
    target_ulong cr4;
    uint64_t xcr0;

    xcc->parent_reset(s);

    memset(env, 0, offsetof(CPUX86State, end_reset_fields));

    env->old_exception = -1;

    /* init to reset state */

    env->hflags2 |= HF2_GIF_MASK;

    cpu_x86_update_cr0(env, 0x60000010);
    env->a20_mask = ~0x0;
    env->smbase = 0x30000;
    env->msr_smi_count = 0;

    env->idt.limit = 0xffff;
    env->gdt.limit = 0xffff;
    env->ldt.limit = 0xffff;
    env->ldt.flags = DESC_P_MASK | (2 << DESC_TYPE_SHIFT);
    env->tr.limit = 0xffff;
    env->tr.flags = DESC_P_MASK | (11 << DESC_TYPE_SHIFT);

    cpu_x86_load_seg_cache(env, R_CS, 0xf000, 0xffff0000, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                           DESC_R_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_SS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);

    env->eip = 0xfff0;
    env->regs[R_EDX] = env->cpuid_version;

    env->eflags = 0x2;

    /* FPU init */
    for (i = 0; i < 8; i++) {
        env->fptags[i] = 1;
    }
    cpu_set_fpuc(env, 0x37f);

    env->mxcsr = 0x1f80;
    /* All units are in INIT state.  */
    env->xstate_bv = 0;

    env->pat = 0x0007040600070406ULL;
    env->msr_ia32_misc_enable = MSR_IA32_MISC_ENABLE_DEFAULT;

    memset(env->dr, 0, sizeof(env->dr));
    env->dr[6] = DR6_FIXED_1;
    env->dr[7] = DR7_FIXED_1;
    cpu_breakpoint_remove_all(s, BP_CPU);
    cpu_watchpoint_remove_all(s, BP_CPU);

    cr4 = 0;
    xcr0 = XSTATE_FP_MASK;

#ifdef CONFIG_USER_ONLY
    /* Enable all the features for user-mode.  */
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        xcr0 |= XSTATE_SSE_MASK;
    }
    for (i = 2; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        const ExtSaveArea *esa = &x86_ext_save_areas[i];
        if (env->features[esa->feature] & esa->bits) {
            xcr0 |= 1ull << i;
        }
    }

    if (env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE) {
        cr4 |= CR4_OSFXSR_MASK | CR4_OSXSAVE_MASK;
    }
    if (env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_FSGSBASE) {
        cr4 |= CR4_FSGSBASE_MASK;
    }
#endif

    env->xcr0 = xcr0;
    cpu_x86_update_cr4(env, cr4);

    /*
     * SDM 11.11.5 requires:
     *  - IA32_MTRR_DEF_TYPE MSR.E = 0
     *  - IA32_MTRR_PHYSMASKn.V = 0
     * All other bits are undefined.  For simplification, zero it all.
     */
    env->mtrr_deftype = 0;
    memset(env->mtrr_var, 0, sizeof(env->mtrr_var));
    memset(env->mtrr_fixed, 0, sizeof(env->mtrr_fixed));

#if !defined(CONFIG_USER_ONLY)
    /* We hard-wire the BSP to the first CPU. */
    apic_designate_bsp(env->uc, cpu->apic_state, s->cpu_index == 0);

    s->halted = !cpu_is_bsp(cpu);
#endif
}

#ifndef CONFIG_USER_ONLY
bool cpu_is_bsp(X86CPU *cpu)
{
    return (cpu_get_apic_base((&cpu->env)->uc, cpu->apic_state) & MSR_IA32_APICBASE_BSP) != 0;
}
#endif

static void mce_init(X86CPU *cpu)
{
    CPUX86State *cenv = &cpu->env;
    unsigned int bank;

    if (((cenv->cpuid_version >> 8) & 0xf) >= 6
        && (cenv->features[FEAT_1_EDX] & (CPUID_MCE | CPUID_MCA)) ==
            (CPUID_MCE | CPUID_MCA)) {
        cenv->mcg_cap = MCE_CAP_DEF | MCE_BANKS_DEF |
                        (cpu->enable_lmce ? MCG_LMCE_P : 0);
        cenv->mcg_ctl = ~(uint64_t)0;
        for (bank = 0; bank < MCE_BANKS_DEF; bank++) {
            cenv->mce_banks[bank * 4] = ~(uint64_t)0;
        }
    }
}

#ifndef CONFIG_USER_ONLY
static void x86_cpu_apic_create(X86CPU *cpu, Error **errp)
{
#if 0
    DeviceState *dev = DEVICE(cpu);
    APICCommonState *apic;
    const char *apic_type = "apic";

    cpu->apic_state = qdev_try_create(qdev_get_parent_bus(dev), apic_type);
    if (cpu->apic_state == NULL) {
        error_setg(errp, "APIC device '%s' could not be created", apic_type);
        return;
    }

    object_property_add_child(OBJECT(cpu), "lapic",
                              OBJECT(cpu->apic_state), &error_abort);
    object_unref(OBJECT(cpu->apic_state));
    //qdev_prop_set_uint8(cpu->apic_state, "id", cpu->apic_id);
    /* TODO: convert to link<> */
    apic = APIC_COMMON(cpu->apic_state);
    apic->cpu = cpu;
#endif
}

static void x86_cpu_apic_realize(X86CPU *cpu, Error **errp)
{
    if (cpu->apic_state == NULL) {
        return;
    }

    if (qdev_init(cpu->apic_state)) {
        error_setg(errp, "APIC device '%s' could not be initialized",
                   object_get_typename(OBJECT(cpu->apic_state)));
        return;
    }
}
#else
static void x86_cpu_apic_realize(X86CPU *cpu, Error **errp)
{
}
#endif

/* Note: Only safe for use on x86(-64) hosts */
static QEMU_UNUSED_FUNC uint32_t x86_host_phys_bits(void)
{
    uint32_t eax;
    uint32_t host_phys_bits;

    host_cpuid(0x80000000, 0, &eax, NULL, NULL, NULL);
    if (eax >= 0x80000008) {
        host_cpuid(0x80000008, 0, &eax, NULL, NULL, NULL);
        /* Note: According to AMD doc 25481 rev 2.34 they have a field
         * at 23:16 that can specify a maximum physical address bits for
         * the guest that can override this value; but I've not seen
         * anything with that set.
         */
        host_phys_bits = eax & 0xff;
    } else {
        /* It's an odd 64 bit machine that doesn't have the leaf for
         * physical address bits; fall back to 36 that's most older
         * Intel.
         */
        host_phys_bits = 36;
    }

    return host_phys_bits;
}

static void x86_cpu_adjust_level(X86CPU *cpu, uint32_t *min, uint32_t value)
{
    if (*min < value) {
        *min = value;
    }
}

/* Increase cpuid_min_{level,xlevel,xlevel2} automatically, if appropriate */
static void x86_cpu_adjust_feat_level(X86CPU *cpu, FeatureWord w)
{
    CPUX86State *env = &cpu->env;
    FeatureWordInfo *fi = &feature_word_info[w];
    uint32_t eax = fi->cpuid_eax;
    uint32_t region = eax & 0xF0000000;

    if (!env->features[w]) {
        return;
    }

    switch (region) {
    case 0x00000000:
        x86_cpu_adjust_level(cpu, &env->cpuid_min_level, eax);
    break;
    case 0x80000000:
        x86_cpu_adjust_level(cpu, &env->cpuid_min_xlevel, eax);
    break;
    case 0xC0000000:
        x86_cpu_adjust_level(cpu, &env->cpuid_min_xlevel2, eax);
    break;
    }
}

/* Calculate XSAVE components based on the configured CPU feature flags */
static void x86_cpu_enable_xsave_components(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    int i;
    uint64_t mask;

    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
        return;
    }

    mask = 0;
    for (i = 0; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        const ExtSaveArea *esa = &x86_ext_save_areas[i];
        if (env->features[esa->feature] & esa->bits) {
            mask |= (1ULL << i);
        }
    }

    env->features[FEAT_XSAVE_COMP_LO] = mask;
    env->features[FEAT_XSAVE_COMP_HI] = mask >> 32;
}

/***** Steps involved on loading and filtering CPUID data
 *
 * When initializing and realizing a CPU object, the steps
 * involved in setting up CPUID data are:
 *
 * 1) Loading CPU model definition (X86CPUDefinition). This is
 *    implemented by x86_cpu_load_def() and should be completely
 *    transparent, as it is done automatically by instance_init.
 *    No code should need to look at X86CPUDefinition structs
 *    outside instance_init.
 *
 * 2) CPU expansion. This is done by realize before CPUID
 *    filtering, and will make sure host/accelerator data is
 *    loaded for CPU models that depend on host capabilities
 *    (e.g. "host"). Done by x86_cpu_expand_features().
 *
 * 3) CPUID filtering. This initializes extra data related to
 *    CPUID, and checks if the host supports all capabilities
 *    required by the CPU. Runnability of a CPU model is
 *    determined at this step. Done by x86_cpu_filter_features().
 *
 * Some operations don't require all steps to be performed.
 * More precisely:
 *
 * - CPU instance creation (instance_init) will run only CPU
 *   model loading. CPU expansion can't run at instance_init-time
 *   because host/accelerator data may be not available yet.
 * - CPU realization will perform both CPU model expansion and CPUID
 *   filtering, and return an error in case one of them fails.
 * - query-cpu-definitions needs to run all 3 steps. It needs
 *   to run CPUID filtering, as the 'unavailable-features'
 *   field is set based on the filtering results.
 * - The query-cpu-model-expansion QMP command only needs to run
 *   CPU model loading and CPU expansion. It should not filter
 *   any CPUID data based on host capabilities.
 */

/* Expand CPU configuration data, based on configured features
 * and host/accelerator capabilities when appropriate.
 */
static void x86_cpu_expand_features(struct uc_struct *uc, X86CPU *cpu, Error **errp)
{
    CPUX86State *env = &cpu->env;
    FeatureWord w;
    Error *local_err = NULL;

    /*TODO: Now cpu->max_features doesn't overwrite features
     * set using QOM properties, and we can convert
     * plus_features & minus_features to global properties
     * inside x86_cpu_parse_featurestr() too.
     */
    if (cpu->max_features) {
        for (w = 0; w < FEATURE_WORDS; w++) {
            /* Override only features that weren't set explicitly
             * by the user.
             */
            env->features[w] |=
                x86_cpu_get_supported_feature_word(uc, w, cpu->migratable) &
                ~env->user_features[w];
        }
    }

    for (w = 0; w < FEATURE_WORDS; w++) {
        cpu->env.features[w] |= cpu->plus_features[w];
        cpu->env.features[w] &= ~cpu->minus_features[w];
    }

    // Unicorn: commented out
    //if (!kvm_enabled() || !cpu->expose_kvm) {
        env->features[FEAT_KVM] = 0;
    //}

    x86_cpu_enable_xsave_components(cpu);

    /* CPUID[EAX=7,ECX=0].EBX always increased level automatically: */
    x86_cpu_adjust_feat_level(cpu, FEAT_7_0_EBX);
    if (cpu->full_cpuid_auto_level) {
        x86_cpu_adjust_feat_level(cpu, FEAT_1_EDX);
        x86_cpu_adjust_feat_level(cpu, FEAT_1_ECX);
        x86_cpu_adjust_feat_level(cpu, FEAT_6_EAX);
        x86_cpu_adjust_feat_level(cpu, FEAT_7_0_ECX);
        x86_cpu_adjust_feat_level(cpu, FEAT_8000_0001_EDX);
        x86_cpu_adjust_feat_level(cpu, FEAT_8000_0001_ECX);
        x86_cpu_adjust_feat_level(cpu, FEAT_8000_0007_EDX);
        x86_cpu_adjust_feat_level(cpu, FEAT_8000_0008_EBX);
        x86_cpu_adjust_feat_level(cpu, FEAT_C000_0001_EDX);
        x86_cpu_adjust_feat_level(cpu, FEAT_SVM);
        x86_cpu_adjust_feat_level(cpu, FEAT_XSAVE);
        /* SVM requires CPUID[0x8000000A] */
        if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
            x86_cpu_adjust_level(cpu, &env->cpuid_min_xlevel, 0x8000000A);
        }
    }

    /* Set cpuid_*level* based on cpuid_min_*level, if not explicitly set */
    if (env->cpuid_level == UINT32_MAX) {
        env->cpuid_level = env->cpuid_min_level;
    }
    if (env->cpuid_xlevel == UINT32_MAX) {
        env->cpuid_xlevel = env->cpuid_min_xlevel;
    }
    if (env->cpuid_xlevel2 == UINT32_MAX) {
        env->cpuid_xlevel2 = env->cpuid_min_xlevel2;
    }

    if (local_err != NULL) {
        error_propagate(errp, local_err);
    }
}

/*
 * Finishes initialization of CPUID data, filters CPU feature
 * words based on host availability of each feature.
 *
 * Returns: 0 if all flags are supported by the host, non-zero otherwise.
 */
static int x86_cpu_filter_features(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    FeatureWord w;
    int rv = 0;

    for (w = 0; w < FEATURE_WORDS; w++) {
        uint32_t host_feat =
            x86_cpu_get_supported_feature_word(env->uc, w, false);
        uint32_t requested_features = env->features[w];
        env->features[w] &= host_feat;
        cpu->filtered_features[w] = requested_features & ~env->features[w];
        if (cpu->filtered_features[w]) {
            rv = 1;
        }
    }

    return rv;
}

#define IS_INTEL_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_INTEL_1 && \
                           (env)->cpuid_vendor2 == CPUID_VENDOR_INTEL_2 && \
                           (env)->cpuid_vendor3 == CPUID_VENDOR_INTEL_3)
#define IS_AMD_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_AMD_1 && \
                         (env)->cpuid_vendor2 == CPUID_VENDOR_AMD_2 && \
                         (env)->cpuid_vendor3 == CPUID_VENDOR_AMD_3)

static int x86_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    X86CPU *cpu = X86_CPU(uc, dev);
    X86CPUClass *xcc = X86_CPU_GET_CLASS(uc, dev);
    CPUX86State *env = &cpu->env;
    Error *local_err = NULL;

    object_property_set_int(uc, OBJECT(cpu), CPU(cpu)->cpu_index, "apic-id",
                            &local_err);
    if (local_err) {
        goto out;
    }

    if (cpu->apic_id == UNASSIGNED_APIC_ID) {
        error_setg(errp, "apic-id property was not initialized properly");
        return -1;
    }

    x86_cpu_expand_features(uc, cpu, &local_err);
    if (local_err) {
        goto out;
    }

    if (x86_cpu_filter_features(cpu) &&
        (cpu->check_cpuid || cpu->enforce_cpuid)) {
        x86_cpu_report_filtered_features(cpu);
        if (cpu->enforce_cpuid) {
            error_setg(&local_err,
                       "TCG doesn't support requested features");
            goto out;
        }
    }

    /* On AMD CPUs, some CPUID[8000_0001].EDX bits must match the bits on
     * CPUID[1].EDX.
     */
    if (IS_AMD_CPU(env)) {
        env->features[FEAT_8000_0001_EDX] &= ~CPUID_EXT2_AMD_ALIASES;
        env->features[FEAT_8000_0001_EDX] |= (env->features[FEAT_1_EDX]
           & CPUID_EXT2_AMD_ALIASES);
    }

    /* For 64bit systems think about the number of physical bits to present.
     * ideally this should be the same as the host; anything other than matching
     * the host can cause incorrect guest behaviour.
     * QEMU used to pick the magic value of 40 bits that corresponds to
     * consumer AMD devices but nothing else.
     */
    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        // Unicorn: removed KVM checks
        if (cpu->phys_bits && cpu->phys_bits != TCG_PHYS_ADDR_BITS) {
            error_setg(errp, "TCG only supports phys-bits=%u",
                              TCG_PHYS_ADDR_BITS);
            return -1;
        }
        /* 0 means it was not explicitly set by the user (or by machine
         * compat_props or by the host code above). In this case, the default
         * is the value used by TCG (40).
         */
        if (cpu->phys_bits == 0) {
            cpu->phys_bits = TCG_PHYS_ADDR_BITS;
        }
    } else {
        /* For 32 bit systems don't use the user set value, but keep
         * phys_bits consistent with what we tell the guest.
         */
        if (cpu->phys_bits != 0) {
            error_setg(errp, "phys-bits is not user-configurable in 32 bit");
            return -1;
        }

        if (env->features[FEAT_1_EDX] & CPUID_PSE36) {
            cpu->phys_bits = 36;
        } else {
            cpu->phys_bits = 32;
        }
    }

    /* Cache information initialization */
    if (!cpu->legacy_cache) {
        /* Unicorn: commented out
        if (!xcc->cpu_def || !xcc->cpu_def->cache_info) {
            char *name = x86_cpu_class_get_model_name(xcc);
            error_setg(errp,
                       "CPU model '%s' doesn't support legacy-cache=off", name);
            g_free(name);
            return;
        }
        */
        env->cache_info_cpuid2 = env->cache_info_cpuid4 = env->cache_info_amd =
            *xcc->cpu_def->cache_info;
    } else {
        /* Build legacy cache information */
        env->cache_info_cpuid2.l1d_cache = &legacy_l1d_cache;
        env->cache_info_cpuid2.l1i_cache = &legacy_l1i_cache;
        env->cache_info_cpuid2.l2_cache = &legacy_l2_cache_cpuid2;
        env->cache_info_cpuid2.l3_cache = &legacy_l3_cache;

        env->cache_info_cpuid4.l1d_cache = &legacy_l1d_cache;
        env->cache_info_cpuid4.l1i_cache = &legacy_l1i_cache;
        env->cache_info_cpuid4.l2_cache = &legacy_l2_cache;
        env->cache_info_cpuid4.l3_cache = &legacy_l3_cache;

        env->cache_info_amd.l1d_cache = &legacy_l1d_cache_amd;
        env->cache_info_amd.l1i_cache = &legacy_l1i_cache_amd;
        env->cache_info_amd.l2_cache = &legacy_l2_cache_amd;
        env->cache_info_amd.l3_cache = &legacy_l3_cache;
    }

    if (x86_cpu_filter_features(cpu) && cpu->enforce_cpuid) {
        error_setg(&local_err,
                       "TCG doesn't support requested features");
        goto out;
    }

#ifndef CONFIG_USER_ONLY
    //qemu_register_reset(x86_cpu_machine_reset_cb, cpu);

    if (cpu->env.features[FEAT_1_EDX] & CPUID_APIC || smp_cpus > 1) {
        x86_cpu_apic_create(cpu, &local_err);
        if (local_err != NULL) {
            goto out;
        }
    }
#endif

    mce_init(cpu);

#ifndef CONFIG_USER_ONLY
    if (tcg_enabled(uc)) {
        cpu->cpu_as_mem = g_new(MemoryRegion, 1);
        cpu->cpu_as_root = g_new(MemoryRegion, 1);

        /* Outer container... */
        memory_region_init(uc, cpu->cpu_as_root, OBJECT(cpu), "memory", ~0ull);
        memory_region_set_enabled(cpu->cpu_as_root, true);

        /* ... with two regions inside: normal system memory with low
         * priority, and...
         */
        memory_region_init_alias(uc, cpu->cpu_as_mem, OBJECT(cpu), "memory",
                                 get_system_memory(uc), 0, ~0ull);
        memory_region_add_subregion_overlap(cpu->cpu_as_root, 0, cpu->cpu_as_mem, 0);
        memory_region_set_enabled(cpu->cpu_as_mem, true);

        cs->num_ases = 2;
        cpu_address_space_init(cs, 0, "cpu-memory", cs->memory);
        cpu_address_space_init(cs, 1, "cpu-smm", cpu->cpu_as_root);
    }
#endif

    if (qemu_init_vcpu(cs)) {
        return -1;
    }

    x86_cpu_apic_realize(cpu, &local_err);
    if (local_err != NULL) {
        goto out;
    }
    cpu_reset(cs);

    xcc->parent_realize(uc, dev, &local_err);

out:
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return -1;
    }

    return 0;
}

static void x86_cpu_unrealizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    /* Unicorn: commented out
    X86CPU *cpu = X86_CPU(uc, dev);

#ifndef CONFIG_USER_ONLY
    cpu_remove_sync(CPU(dev));
    qemu_unregister_reset(x86_cpu_machine_reset_cb, dev);
#endif

    if (cpu->apic_state) {
        object_unparent(OBJECT(cpu->apic_state));
        cpu->apic_state = NULL;
    }*/
}

static void x86_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    //printf("... X86 initialize (object)\n");
    CPUState *cs = CPU(obj);
    X86CPU *cpu = X86_CPU(cs->uc, obj);
    X86CPUClass *xcc = X86_CPU_GET_CLASS(uc, obj);
    CPUX86State *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(cs, &error_abort, opaque);

    object_property_add(uc, obj, "family", "int",
                        x86_cpuid_version_get_family,
                        x86_cpuid_version_set_family, NULL, NULL, NULL);
    object_property_add(uc, obj, "model", "int",
                        x86_cpuid_version_get_model,
                        x86_cpuid_version_set_model, NULL, NULL, NULL);
    object_property_add(uc, obj, "stepping", "int",
                        x86_cpuid_version_get_stepping,
                        x86_cpuid_version_set_stepping, NULL, NULL, NULL);
    object_property_add_str(uc, obj, "vendor",
                            x86_cpuid_get_vendor,
                            x86_cpuid_set_vendor, NULL);
    object_property_add_str(uc, obj, "model-id",
                            x86_cpuid_get_model_id,
                            x86_cpuid_set_model_id, NULL);
    object_property_add(uc, obj, "tsc-frequency", "int",
                        x86_cpuid_get_tsc_freq,
                        x86_cpuid_set_tsc_freq, NULL, NULL, NULL);
    object_property_add(uc, obj, "feature-words", "X86CPUFeatureWordInfo",
                        x86_cpu_get_feature_words,
                        NULL, NULL, (void *)env->features, NULL);
    object_property_add(uc, obj, "filtered-features", "X86CPUFeatureWordInfo",
                        x86_cpu_get_feature_words,
                        NULL, NULL, (void *)cpu->filtered_features, NULL);

    cpu->hyperv_spinlock_attempts = HYPERV_SPINLOCK_NEVER_RETRY;
    // Unicorn: Should be removed with the commit backporting 2da00e3176abac34ca7a6aab1f5bbb94a0d03fc5
    //          from qemu, but left this in to keep the member value initialized
    cpu->apic_id = UNASSIGNED_APIC_ID;

    x86_cpu_load_def(cpu, xcc->cpu_def, &error_abort);
}

static int64_t x86_cpu_get_arch_id(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    return cpu->apic_id;
}

static bool x86_cpu_get_paging_enabled(const CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    return (cpu->env.cr[0] & CR0_PG_MASK) != 0;
}

static void x86_cpu_set_pc(CPUState *cs, vaddr value)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    cpu->env.eip = value;
}

static void x86_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    cpu->env.eip = tb->pc - tb->cs_base;
}

static bool x86_cpu_has_work(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

#if !defined(CONFIG_USER_ONLY)
    if (cs->interrupt_request & CPU_INTERRUPT_POLL) {
        apic_poll_irq(cpu->apic_state);
        cpu_reset_interrupt(cs, CPU_INTERRUPT_POLL);
    }
#endif

    return ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
            (env->eflags & IF_MASK)) ||
           (cs->interrupt_request & (CPU_INTERRUPT_NMI |
                                     CPU_INTERRUPT_INIT |
                                     CPU_INTERRUPT_SIPI |
                                     CPU_INTERRUPT_MCE)) ||
           ((cs->interrupt_request & CPU_INTERRUPT_SMI) &&
            !(env->hflags & HF_SMM_MASK));
}

static void x86_cpu_common_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    //printf("... init X86 cpu common class\n");
    X86CPUClass *xcc = X86_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, oc);
    DeviceClass *dc = DEVICE_CLASS(uc, oc);

    xcc->parent_realize = dc->realize;
    dc->realize = x86_cpu_realizefn;
    dc->unrealize = x86_cpu_unrealizefn;
    dc->bus_type = TYPE_ICC_BUS;

    xcc->parent_reset = cc->reset;
    cc->reset = x86_cpu_reset;
    cc->reset_dump_flags = CPU_DUMP_FPU | CPU_DUMP_CCOP;

    cc->class_by_name = x86_cpu_class_by_name;
    cc->parse_features = x86_cpu_parse_featurestr;
    cc->has_work = x86_cpu_has_work;
#ifdef CONFIG_TCG
    cc->do_interrupt = x86_cpu_do_interrupt;
    cc->cpu_exec_interrupt = x86_cpu_exec_interrupt;
#endif
    cc->dump_state = x86_cpu_dump_state;
    cc->set_pc = x86_cpu_set_pc;
    cc->synchronize_from_tb = x86_cpu_synchronize_from_tb;
    cc->get_arch_id = x86_cpu_get_arch_id;
    cc->get_paging_enabled = x86_cpu_get_paging_enabled;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = x86_cpu_handle_mmu_fault;
#else
    cc->asidx_from_attrs = x86_asidx_from_attrs;
    cc->get_memory_mapping = x86_cpu_get_memory_mapping;
    cc->get_phys_page_debug = x86_cpu_get_phys_page_debug;
#endif
#if defined(CONFIG_TCG) && !defined(CONFIG_USER_ONLY)
    cc->debug_excp_handler = breakpoint_handler;
#endif
    cc->cpu_exec_enter = x86_cpu_exec_enter;
    cc->cpu_exec_exit = x86_cpu_exec_exit;
    cc->tcg_initialize = tcg_x86_init;
}

void x86_cpu_register_types(void *opaque)
{
    const TypeInfo x86_cpu_type_info = {
        TYPE_X86_CPU,
        TYPE_CPU,

        sizeof(X86CPUClass),
        sizeof(X86CPU),
        opaque,

        x86_cpu_initfn,
        NULL,
        NULL,

        NULL,

        x86_cpu_common_class_init,
        NULL,
        NULL,

        true,
    };

    //printf("... register X86 cpu\n");
    int i;

    type_register_static(opaque, &x86_cpu_type_info);
    for (i = 0; i < ARRAY_SIZE(builtin_x86_defs); i++) {
        x86_register_cpudef_type(opaque, &builtin_x86_defs[i]);
    }
    //printf("... END OF register X86 cpu\n");
}
