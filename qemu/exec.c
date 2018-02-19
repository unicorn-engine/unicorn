/*
 *  Virtual page mapping
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
/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "config.h"
#ifndef _WIN32
#include <sys/types.h>
#include <sys/mman.h>
#endif

#include "qemu-common.h"
#include "cpu.h"
#include "tcg.h"
#include "hw/hw.h"
#include "hw/qdev.h"
#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "qemu/timer.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#if defined(CONFIG_USER_ONLY)
#include <qemu.h>
#endif
#include "exec/cpu-all.h"

#include "exec/cputlb.h"
#include "translate-all.h"

#include "exec/memory-internal.h"
#include "exec/ram_addr.h"

#include "qemu/range.h"
#ifndef _WIN32
#include "qemu/mmap-alloc.h"
#endif

#include "uc_priv.h"

//#define DEBUG_SUBPAGE

#if !defined(CONFIG_USER_ONLY)

/* RAM is pre-allocated and passed into qemu_ram_alloc_from_ptr */
#define RAM_PREALLOC   (1 << 0)

/* RAM is mmap-ed with MAP_SHARED */
#define RAM_SHARED     (1 << 1)

/* Only a portion of RAM (used_length) is actually used, and migrated.
 * This used_length size can change across reboots.
 */
#define RAM_RESIZEABLE (1 << 2)

#endif

#if !defined(CONFIG_USER_ONLY)
/* current CPU in the current thread. It is only valid inside
   cpu_exec() */
//DEFINE_TLS(CPUState *, current_cpu);

typedef struct PhysPageEntry PhysPageEntry;

struct PhysPageEntry {
    /* How many bits skip to next level (in units of L2_SIZE). 0 for a leaf. */
    uint32_t skip : 6;
    /* index into phys_sections (!skip) or phys_map_nodes (skip) */
    uint32_t ptr : 26;
};

#define PHYS_MAP_NODE_NIL (((uint32_t)~0) >> 6)

/* Size of the L2 (and L3, etc) page tables.  */
#define ADDR_SPACE_BITS 64

#define P_L2_BITS 9
#define P_L2_SIZE (1 << P_L2_BITS)

#define P_L2_LEVELS (((ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / P_L2_BITS) + 1)

typedef PhysPageEntry Node[P_L2_SIZE];

typedef struct PhysPageMap {
    unsigned sections_nb;
    unsigned sections_nb_alloc;
    unsigned nodes_nb;
    unsigned nodes_nb_alloc;
    Node *nodes;
    MemoryRegionSection *sections;
} PhysPageMap;

struct AddressSpaceDispatch {
    /* This is a multi-level map on the physical address space.
     * The bottom level has pointers to MemoryRegionSections.
     */
    PhysPageEntry phys_map;
    PhysPageMap map;
    AddressSpace *as;
};

#define SUBPAGE_IDX(addr) ((addr) & ~TARGET_PAGE_MASK)
typedef struct subpage_t {
    MemoryRegion iomem;
    AddressSpace *as;
    hwaddr base;
    uint16_t sub_section[TARGET_PAGE_SIZE];
} subpage_t;

#define PHYS_SECTION_UNASSIGNED 0
#define PHYS_SECTION_NOTDIRTY 1
#define PHYS_SECTION_ROM 2
#define PHYS_SECTION_WATCH 3

static void memory_map_init(struct uc_struct *uc);
static void tcg_commit(MemoryListener *listener);

#endif

#if !defined(CONFIG_USER_ONLY)

static void phys_map_node_reserve(PhysPageMap *map, unsigned nodes)
{
    if (map->nodes_nb + nodes > map->nodes_nb_alloc) {
        map->nodes_nb_alloc = MAX(map->nodes_nb_alloc * 2, 16);
        map->nodes_nb_alloc = MAX(map->nodes_nb_alloc, map->nodes_nb + nodes);
        map->nodes = g_renew(Node, map->nodes, map->nodes_nb_alloc);
    }
}

static uint32_t phys_map_node_alloc(PhysPageMap *map, bool leaf)
{
    unsigned i;
    uint32_t ret;
    PhysPageEntry e;
    PhysPageEntry *p;

    ret = map->nodes_nb++;
    p = map->nodes[ret];
    assert(ret != PHYS_MAP_NODE_NIL);
    assert(ret != map->nodes_nb_alloc);

    e.skip = leaf ? 0 : 1;
    e.ptr = leaf ? PHYS_SECTION_UNASSIGNED : PHYS_MAP_NODE_NIL;
    for (i = 0; i < P_L2_SIZE; ++i) {
        memcpy(&p[i], &e, sizeof(e));
    }
    return ret;
}

static void phys_page_set_level(PhysPageMap *map, PhysPageEntry *lp,
        hwaddr *index, hwaddr *nb, uint16_t leaf,
        int level)
{
    PhysPageEntry *p;
    hwaddr step = (hwaddr)1 << (level * P_L2_BITS);

    if (lp->skip && lp->ptr == PHYS_MAP_NODE_NIL) {
        lp->ptr = phys_map_node_alloc(map, level == 0);
    }
    p = map->nodes[lp->ptr];
    lp = &p[(*index >> (level * P_L2_BITS)) & (P_L2_SIZE - 1)];

    while (*nb && lp < &p[P_L2_SIZE]) {
        if ((*index & (step - 1)) == 0 && *nb >= step) {
            lp->skip = 0;
            lp->ptr = leaf;
            *index += step;
            *nb -= step;
        } else {
            phys_page_set_level(map, lp, index, nb, leaf, level - 1);
        }
        ++lp;
    }
}

static void phys_page_set(AddressSpaceDispatch *d,
        hwaddr index, hwaddr nb,
        uint16_t leaf)
{
    /* Wildly overreserve - it doesn't matter much. */
    phys_map_node_reserve(&d->map, 3 * P_L2_LEVELS);

    phys_page_set_level(&d->map, &d->phys_map, &index, &nb, leaf, P_L2_LEVELS - 1);
}

/* Compact a non leaf page entry. Simply detect that the entry has a single child,
 * and update our entry so we can skip it and go directly to the destination.
 */
static void phys_page_compact(PhysPageEntry *lp, Node *nodes, unsigned long *compacted)
{
    unsigned valid_ptr = P_L2_SIZE;
    int valid = 0;
    PhysPageEntry *p;
    int i;

    if (lp->ptr == PHYS_MAP_NODE_NIL) {
        return;
    }

    p = nodes[lp->ptr];
    for (i = 0; i < P_L2_SIZE; i++) {
        if (p[i].ptr == PHYS_MAP_NODE_NIL) {
            continue;
        }

        valid_ptr = i;
        valid++;
        if (p[i].skip) {
            phys_page_compact(&p[i], nodes, compacted);
        }
    }

    /* We can only compress if there's only one child. */
    if (valid != 1) {
        return;
    }

    assert(valid_ptr < P_L2_SIZE);

    /* Don't compress if it won't fit in the # of bits we have. */
    if (lp->skip + p[valid_ptr].skip >= (1 << 3)) {
        return;
    }

    lp->ptr = p[valid_ptr].ptr;
    if (!p[valid_ptr].skip) {
        /* If our only child is a leaf, make this a leaf. */
        /* By design, we should have made this node a leaf to begin with so we
         * should never reach here.
         * But since it's so simple to handle this, let's do it just in case we
         * change this rule.
         */
        lp->skip = 0;
    } else {
        lp->skip += p[valid_ptr].skip;
    }
}

static void phys_page_compact_all(AddressSpaceDispatch *d, int nodes_nb)
{
    //DECLARE_BITMAP(compacted, nodes_nb);
    // this isnt actually used
    unsigned long* compacted = NULL;

    if (d->phys_map.skip) {
        phys_page_compact(&d->phys_map, d->map.nodes, compacted);
    }
}

static MemoryRegionSection *phys_page_find(PhysPageEntry lp, hwaddr addr,
        Node *nodes, MemoryRegionSection *sections)
{
    PhysPageEntry *p;
    hwaddr index = addr >> TARGET_PAGE_BITS;
    int i;

    for (i = P_L2_LEVELS; lp.skip && (i -= lp.skip) >= 0;) {
        if (lp.ptr == PHYS_MAP_NODE_NIL) {
            return &sections[PHYS_SECTION_UNASSIGNED];
        }
        p = nodes[lp.ptr];
        lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
    }

    if (sections[lp.ptr].size.hi ||
            range_covers_byte(sections[lp.ptr].offset_within_address_space,
                sections[lp.ptr].size.lo, addr)) {
        return &sections[lp.ptr];
    } else {
        return &sections[PHYS_SECTION_UNASSIGNED];
    }
}

bool memory_region_is_unassigned(struct uc_struct* uc, MemoryRegion *mr)
{
    return mr != &uc->io_mem_rom && mr != &uc->io_mem_notdirty &&
        !mr->rom_device && mr != &uc->io_mem_watch;
}

static MemoryRegionSection *address_space_lookup_region(AddressSpaceDispatch *d,
        hwaddr addr,
        bool resolve_subpage)
{
    MemoryRegionSection *section;
    subpage_t *subpage;

    section = phys_page_find(d->phys_map, addr, d->map.nodes, d->map.sections);
    if (resolve_subpage && section->mr->subpage) {
        subpage = container_of(section->mr, subpage_t, iomem);
        section = &d->map.sections[subpage->sub_section[SUBPAGE_IDX(addr)]];
    }
    return section;
}

static MemoryRegionSection *
address_space_translate_internal(AddressSpaceDispatch *d, hwaddr addr, hwaddr *xlat,
        hwaddr *plen, bool resolve_subpage)
{
    MemoryRegionSection *section;
    MemoryRegion *mr;
    Int128 diff;

    section = address_space_lookup_region(d, addr, resolve_subpage);
    /* Compute offset within MemoryRegionSection */
    addr -= section->offset_within_address_space;

    /* Compute offset within MemoryRegion */
    *xlat = addr + section->offset_within_region;

    mr = section->mr;

    /* MMIO registers can be expected to perform full-width accesses based only
     * on their address, without considering adjacent registers that could
     * decode to completely different MemoryRegions.  When such registers
     * exist (e.g. I/O ports 0xcf8 and 0xcf9 on most PC chipsets), MMIO
     * regions overlap wildly.  For this reason we cannot clamp the accesses
     * here.
     *
     * If the length is small (as is the case for address_space_ldl/stl),
     * everything works fine.  If the incoming length is large, however,
     * the caller really has to do the clamping through memory_access_size.
     */
    if (memory_region_is_ram(mr)) {
        diff = int128_sub(section->size, int128_make64(addr));
        *plen = int128_get64(int128_min(diff, int128_make64(*plen)));
    }
    return section;
}

MemoryRegion *address_space_translate(AddressSpace *as, hwaddr addr,
        hwaddr *xlat, hwaddr *plen,
        bool is_write)
{
    IOMMUTLBEntry iotlb;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    hwaddr len = *plen;

    for (;;) {
        section = address_space_translate_internal(as->dispatch, addr, &addr, plen, true);
        mr = section->mr;
        if (mr->ops == NULL)
            return NULL;

        if (!mr->iommu_ops) {
            break;
        }

        iotlb = mr->iommu_ops->translate(mr, addr, is_write);
        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        len = MIN(len, (addr | iotlb.addr_mask) - addr + 1);
        if (!(iotlb.perm & (1 << is_write))) {
            mr = &as->uc->io_mem_unassigned;
            break;
        }

        as = iotlb.target_as;
    }

    *plen = len;
    *xlat = addr;
    return mr;
}

MemoryRegionSection *
address_space_translate_for_iotlb(CPUState *cpu, int asidx, hwaddr addr,
                                  hwaddr *xlat, hwaddr *plen)
{
    MemoryRegionSection *section;
    AddressSpaceDispatch *d = cpu->cpu_ases[asidx].memory_dispatch;

    section = address_space_translate_internal(d, addr, xlat, plen, false);

    assert(!section->mr->iommu_ops);
    return section;
}
#endif

CPUState *qemu_get_cpu(struct uc_struct *uc, int index)
{
    CPUState *cpu = uc->cpu;
    if (cpu->cpu_index == index) {
        return cpu;
    }
    return NULL;
}

#if !defined(CONFIG_USER_ONLY)
void cpu_address_space_init(CPUState *cpu, AddressSpace *as, int asidx)
{
    CPUAddressSpace *newas;

    /* Target code should have set num_ases before calling us */
    assert(asidx < cpu->num_ases);

    if (asidx == 0) {
        /* address space 0 gets the convenience alias */
        cpu->as = as;
    }

    /* KVM cannot currently support multiple address spaces. */
    // Unicorn: commented out
    //assert(asidx == 0 || !kvm_enabled());

    if (!cpu->cpu_ases) {
        cpu->cpu_ases = g_new0(CPUAddressSpace, cpu->num_ases);
    }

    newas = &cpu->cpu_ases[asidx];
    newas->cpu = cpu;
    newas->as = as;
    if (tcg_enabled(as->uc)) {
        newas->tcg_as_listener.commit = tcg_commit;
        memory_listener_register(as->uc, &newas->tcg_as_listener, as);
    }
}

AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx)
{
    /* Return the AddressSpace corresponding to the specified index */
    return cpu->cpu_ases[asidx].as;
}
#endif

void cpu_exec_init(CPUState *cpu, void *opaque)
{
    struct uc_struct *uc = opaque;
    CPUArchState *env = cpu->env_ptr;

    cpu->as = NULL;
    cpu->cpu_index = 0;
    cpu->num_ases = 0;
    cpu->uc = uc;
    env->uc = uc;

    // TODO: assert uc does not already have a cpu?
    uc->cpu = cpu;
}

#if defined(CONFIG_USER_ONLY)
static void breakpoint_invalidate(CPUState *cpu, target_ulong pc)
{
    tb_invalidate_phys_page_range(pc, pc + 1, 0);
}
#else
static void breakpoint_invalidate(CPUState *cpu, target_ulong pc)
{
    MemTxAttrs attrs;
    hwaddr phys = cpu_get_phys_page_attrs_debug(cpu, pc, &attrs);
    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    if (phys != -1) {
        tb_invalidate_phys_addr(cpu->cpu_ases[asidx].as,
                phys | (pc & ~TARGET_PAGE_MASK));
    }
}
#endif

#if defined(CONFIG_USER_ONLY)
void cpu_watchpoint_remove_all(CPUState *cpu, int mask)

{
}

int cpu_watchpoint_remove(CPUState *cpu, vaddr addr, vaddr len,
        int flags)
{
    return -ENOSYS;
}

void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{
}

int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
        int flags, CPUWatchpoint **watchpoint)
{
    return -ENOSYS;
}
#else
/* Add a watchpoint.  */
int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
        int flags, CPUWatchpoint **watchpoint)
{
    CPUWatchpoint *wp;

    /* forbid ranges which are empty or run off the end of the address space */
    if (len == 0 || (addr + len - 1) < addr) {
        return -EINVAL;
    }
    wp = g_malloc(sizeof(*wp));

    wp->vaddr = addr;
    wp->len = len;
    wp->flags = flags;

    /* keep all GDB-injected watchpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->watchpoints, wp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->watchpoints, wp, entry);
    }

    tlb_flush_page(cpu, addr);

    if (watchpoint)
        *watchpoint = wp;
    return 0;
}

/* Remove a specific watchpoint.  */
int cpu_watchpoint_remove(CPUState *cpu, vaddr addr, vaddr len,
        int flags)
{
    CPUWatchpoint *wp;

    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (addr == wp->vaddr && len == wp->len
                && flags == (wp->flags & ~BP_WATCHPOINT_HIT)) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific watchpoint by reference.  */
void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{
    QTAILQ_REMOVE(&cpu->watchpoints, watchpoint, entry);

    tlb_flush_page(cpu, watchpoint->vaddr);

    g_free(watchpoint);
}

/* Remove all matching watchpoints.  */
void cpu_watchpoint_remove_all(CPUState *cpu, int mask)
{
    CPUWatchpoint *wp, *next;

    QTAILQ_FOREACH_SAFE(wp, &cpu->watchpoints, entry, next) {
        if (wp->flags & mask) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
        }
    }
}

/* Return true if this watchpoint address matches the specified
 * access (ie the address range covered by the watchpoint overlaps
 * partially or completely with the address range covered by the
 * access).
 */
static inline bool cpu_watchpoint_address_matches(CPUWatchpoint *wp,
        vaddr addr,
        vaddr len)
{
    /* We know the lengths are non-zero, but a little caution is
     * required to avoid errors in the case where the range ends
     * exactly at the top of the address space and so addr + len
     * wraps round to zero.
     */
    vaddr wpend = wp->vaddr + wp->len - 1;
    vaddr addrend = addr + len - 1;

    return !(addr > wpend || wp->vaddr > addrend);
}

#endif

/* Add a breakpoint.  */
int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags,
        CPUBreakpoint **breakpoint)
{
    CPUBreakpoint *bp;

    bp = g_malloc(sizeof(*bp));

    bp->pc = pc;
    bp->flags = flags;

    /* keep all GDB-injected breakpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->breakpoints, bp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->breakpoints, bp, entry);
    }

    breakpoint_invalidate(cpu, pc);

    if (breakpoint) {
        *breakpoint = bp;
    }
    return 0;
}

/* Remove a specific breakpoint.  */
int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags)
{
    CPUBreakpoint *bp;

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        if (bp->pc == pc && bp->flags == flags) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific breakpoint by reference.  */
void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint)
{
    QTAILQ_REMOVE(&cpu->breakpoints, breakpoint, entry);

    breakpoint_invalidate(cpu, breakpoint->pc);

    g_free(breakpoint);
}

/* Remove all matching breakpoints. */
void cpu_breakpoint_remove_all(CPUState *cpu, int mask)
{
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &cpu->breakpoints, entry, next) {
        if (bp->flags & mask) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
        }
    }
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
void cpu_single_step(CPUState *cpu, int enabled)
{
    if (cpu->singlestep_enabled != enabled) {
        cpu->singlestep_enabled = enabled;
        /* must flush all the translated code to avoid inconsistencies */
        /* XXX: only flush what is necessary */
        tb_flush(cpu);
    }
}

void cpu_abort(CPUState *cpu, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    cpu_dump_state(cpu, stderr, fprintf, CPU_DUMP_FPU | CPU_DUMP_CCOP);
    if (qemu_log_enabled()) {
        qemu_log("qemu: fatal: ");
        qemu_log_vprintf(fmt, ap2);
        qemu_log("\n");
        log_cpu_state(cpu, CPU_DUMP_FPU | CPU_DUMP_CCOP);
        qemu_log_flush();
        qemu_log_close();
    }
    va_end(ap2);
    va_end(ap);
#if defined(CONFIG_USER_ONLY)
    {
        struct sigaction act;
        sigfillset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        sigaction(SIGABRT, &act, NULL);
    }
#endif
    abort();
}

#if !defined(CONFIG_USER_ONLY)
static RAMBlock *qemu_get_ram_block(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block;

    /* The list is protected by the iothread lock here.  */
    block = uc->ram_list.mru_block;
    if (block && addr - block->offset < block->max_length) {
        return block;
    }
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (addr - block->offset < block->max_length) {
            goto found;
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

found:
    uc->ram_list.mru_block = block;
    return block;
}

static void tlb_reset_dirty_range_all(struct uc_struct* uc,
    ram_addr_t start, ram_addr_t length)
{
    ram_addr_t start1;
    RAMBlock *block;
    ram_addr_t end;

    end = TARGET_PAGE_ALIGN(start + length);
    start &= TARGET_PAGE_MASK;

    block = qemu_get_ram_block(uc, start);
    assert(block == qemu_get_ram_block(uc, end - 1));
    start1 = (uintptr_t)ramblock_ptr(block, start - block->offset);
    cpu_tlb_reset_dirty_all(uc, start1, length);
}

/* Note: start and end must be within the same ram block.  */
bool cpu_physical_memory_test_and_clear_dirty(struct uc_struct *uc,
                                              ram_addr_t start,
                                              ram_addr_t length,
                                              unsigned client)
{
    unsigned long end, page;
    bool dirty;

    if (length == 0) {
        return false;
    }

    end = TARGET_PAGE_ALIGN(start + length) >> TARGET_PAGE_BITS;
    page = start >> TARGET_PAGE_BITS;
    dirty = bitmap_test_and_clear_atomic(uc->ram_list.dirty_memory[client],
                                         page, end - page);

    if (dirty && tcg_enabled(uc)) {
        tlb_reset_dirty_range_all(uc, start, length);
    }

    return dirty;
}

hwaddr memory_region_section_get_iotlb(CPUState *cpu,
        MemoryRegionSection *section,
        target_ulong vaddr,
        hwaddr paddr, hwaddr xlat,
        int prot,
        target_ulong *address)
{
    hwaddr iotlb;
    CPUWatchpoint *wp;

    if (memory_region_is_ram(section->mr)) {
        /* Normal RAM.  */
        iotlb = (memory_region_get_ram_addr(section->mr) & TARGET_PAGE_MASK)
            + xlat;
        if (!section->readonly) {
            iotlb |= PHYS_SECTION_NOTDIRTY;
        } else {
            iotlb |= PHYS_SECTION_ROM;
        }
    } else {
        AddressSpaceDispatch *d;

        // Unicorn: uses atomic_read instead of atomic_rcu_read
        d = atomic_read(&section->address_space->dispatch);
        iotlb = section - d->map.sections;
        iotlb += xlat;
    }

    /* Make accesses to pages with watchpoints go via the
       watchpoint trap routines.  */
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (cpu_watchpoint_address_matches(wp, vaddr, TARGET_PAGE_SIZE)) {
            /* Avoid trapping reads of pages with a write breakpoint. */
            if ((prot & PAGE_WRITE) || (wp->flags & BP_MEM_READ)) {
                iotlb = PHYS_SECTION_WATCH + paddr;
                *address |= TLB_MMIO;
                break;
            }
        }
    }

    return iotlb;
}
#endif /* defined(CONFIG_USER_ONLY) */

#if !defined(CONFIG_USER_ONLY)

static int subpage_register (subpage_t *mmio, uint32_t start, uint32_t end,
        uint16_t section);
static subpage_t *subpage_init(AddressSpace *as, hwaddr base);

static void *(*phys_mem_alloc)(size_t size, uint64_t *align) =
qemu_anon_ram_alloc;

/*
 * Set a custom physical guest memory alloator.
 * Accelerators with unusual needs may need this.  Hopefully, we can
 * get rid of it eventually.
 */
void phys_mem_set_alloc(void *(*alloc)(size_t, uint64_t *align))
{
    phys_mem_alloc = alloc;
}

static uint16_t phys_section_add(PhysPageMap *map,
        MemoryRegionSection *section)
{
    /* The physical section number is ORed with a page-aligned
     * pointer to produce the iotlb entries.  Thus it should
     * never overflow into the page-aligned value.
     */
    assert(map->sections_nb < TARGET_PAGE_SIZE);

    if (map->sections_nb == map->sections_nb_alloc) {
        map->sections_nb_alloc = MAX(map->sections_nb_alloc * 2, 16);
        map->sections = g_renew(MemoryRegionSection, map->sections,
                map->sections_nb_alloc);
    }
    map->sections[map->sections_nb] = *section;
    memory_region_ref(section->mr);
    return map->sections_nb++;
}

static void phys_section_destroy(MemoryRegion *mr)
{
    bool have_sub_page = mr->subpage;

    memory_region_unref(mr);

    if (have_sub_page) {
        subpage_t *subpage = container_of(mr, subpage_t, iomem);
        object_unref(mr->uc, OBJECT(&subpage->iomem));
        g_free(subpage);
    }
}

static void phys_sections_free(PhysPageMap *map)
{
    while (map->sections_nb > 0) {
        MemoryRegionSection *section = &map->sections[--map->sections_nb];
        phys_section_destroy(section->mr);
    }
    g_free(map->sections);
    g_free(map->nodes);
}

static void register_subpage(struct uc_struct* uc,
    AddressSpaceDispatch *d, MemoryRegionSection *section)
{
    subpage_t *subpage;
    hwaddr base = section->offset_within_address_space
        & TARGET_PAGE_MASK;
    MemoryRegionSection *existing = phys_page_find(d->phys_map, base,
            d->map.nodes, d->map.sections);
    hwaddr start, end;
    MemoryRegionSection subsection = MemoryRegionSection_make(NULL, NULL, 0, int128_make64(TARGET_PAGE_SIZE), base, false);

    assert(existing->mr->subpage || existing->mr == &uc->io_mem_unassigned);

    if (!(existing->mr->subpage)) {
        subpage = subpage_init(d->as, base);
        subsection.address_space = d->as;
        subsection.mr = &subpage->iomem;
        phys_page_set(d, base >> TARGET_PAGE_BITS, 1,
                phys_section_add(&d->map, &subsection));
    } else {
        subpage = container_of(existing->mr, subpage_t, iomem);
    }
    start = section->offset_within_address_space & ~TARGET_PAGE_MASK;
    end = start + int128_get64(section->size) - 1;
    subpage_register(subpage, start, end,
            phys_section_add(&d->map, section));
    //g_free(subpage);
}


static void register_multipage(AddressSpaceDispatch *d,
        MemoryRegionSection *section)
{
    hwaddr start_addr = section->offset_within_address_space;
    uint16_t section_index = phys_section_add(&d->map, section);
    uint64_t num_pages = int128_get64(int128_rshift(section->size,
                TARGET_PAGE_BITS));

    assert(num_pages);
    phys_page_set(d, start_addr >> TARGET_PAGE_BITS, num_pages, section_index);
}

static void mem_add(MemoryListener *listener, MemoryRegionSection *section)
{
    AddressSpace *as = container_of(listener, AddressSpace, dispatch_listener);
    AddressSpaceDispatch *d = as->next_dispatch;
    MemoryRegionSection now = *section, remain = *section;
    Int128 page_size = int128_make64(TARGET_PAGE_SIZE);

    if (now.offset_within_address_space & ~TARGET_PAGE_MASK) {
        uint64_t left = TARGET_PAGE_ALIGN(now.offset_within_address_space)
            - now.offset_within_address_space;

        now.size = int128_min(int128_make64(left), now.size);
        register_subpage(as->uc, d, &now);
    } else {
        now.size = int128_zero();
    }
    while (int128_ne(remain.size, now.size)) {
        remain.size = int128_sub(remain.size, now.size);
        remain.offset_within_address_space += int128_get64(now.size);
        remain.offset_within_region += int128_get64(now.size);
        now = remain;
        if (int128_lt(remain.size, page_size)) {
            register_subpage(as->uc, d, &now);
        } else if (remain.offset_within_address_space & ~TARGET_PAGE_MASK) {
            now.size = page_size;
            register_subpage(as->uc, d, &now);
        } else {
            now.size = int128_and(now.size, int128_neg(page_size));
            register_multipage(d, &now);
        }
    }
}

#ifdef __linux__

#include <sys/vfs.h>

#define HUGETLBFS_MAGIC       0x958458f6

#endif

static ram_addr_t find_ram_offset(struct uc_struct *uc, ram_addr_t size)
{
    RAMBlock *block, *next_block;
    ram_addr_t offset = RAM_ADDR_MAX, mingap = RAM_ADDR_MAX;

    assert(size != 0); /* it would hand out same offset multiple times */

    if (QLIST_EMPTY(&uc->ram_list.blocks)) {
        return 0;
    }

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        ram_addr_t end, next = RAM_ADDR_MAX;

        end = block->offset + block->max_length;

        QLIST_FOREACH(next_block, &uc->ram_list.blocks, next) {
            if (next_block->offset >= end) {
                next = MIN(next, next_block->offset);
            }
        }
        if (next - end >= size && next - end < mingap) {
            offset = end;
            mingap = next - end;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        fprintf(stderr, "Failed to find gap of requested size: %" PRIu64 "\n",
                (uint64_t)size);
        abort();
    }

    return offset;
}

ram_addr_t last_ram_offset(struct uc_struct *uc)
{
    RAMBlock *block;
    ram_addr_t last = 0;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        last = MAX(last, block->offset + block->max_length);
    }
    return last;
}

static void qemu_ram_setup_dump(void *addr, ram_addr_t size)
{
}

static RAMBlock *find_ram_block(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (block->offset == addr) {
            return block;
        }
    }

    return NULL;
}

const char *qemu_ram_get_idstr(RAMBlock *rb)
{
    return rb->idstr;
}

void qemu_ram_unset_idstr(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block = find_ram_block(uc, addr);

    if (block) {
        memset(block->idstr, 0, sizeof(block->idstr));
    }
}

static int memory_try_enable_merging(void *addr, size_t len)
{
    return 0;
}

/* Only legal before guest might have detected the memory size: e.g. on
 * incoming migration, or right after reset.
 *
 * As memory core doesn't know how is memory accessed, it is up to
 * resize callback to update device state and/or add assertions to detect
 * misuse, if necessary.
 */
int qemu_ram_resize(struct uc_struct *uc, ram_addr_t base, ram_addr_t newsize, Error **errp)
{
    RAMBlock *block = find_ram_block(uc, base);

    assert(block);

    newsize = TARGET_PAGE_ALIGN(newsize);

    if (block->used_length == newsize) {
        return 0;
    }

    if (!(block->flags & RAM_RESIZEABLE)) {
        error_setg_errno(errp, EINVAL,
                         "Length mismatch: %s: 0x" RAM_ADDR_FMT
                         " in != 0x" RAM_ADDR_FMT, block->idstr,
                         newsize, block->used_length);
        return -EINVAL;
    }

    if (block->max_length < newsize) {
        error_setg_errno(errp, EINVAL,
                         "Length too large: %s: 0x" RAM_ADDR_FMT
                         " > 0x" RAM_ADDR_FMT, block->idstr,
                         newsize, block->max_length);
        return -EINVAL;
    }

    cpu_physical_memory_clear_dirty_range(uc, block->offset, block->used_length);
    block->used_length = newsize;
    cpu_physical_memory_set_dirty_range(uc, block->offset, block->used_length,
                                        DIRTY_CLIENTS_ALL);
    memory_region_set_size(block->mr, newsize);
    if (block->resized) {
        block->resized(block->idstr, newsize, block->host);
    }
    return 0;
}

static ram_addr_t ram_block_add(struct uc_struct *uc, RAMBlock *new_block, Error **errp)
{
    RAMBlock *block;
    RAMBlock *last_block = NULL;
    ram_addr_t old_ram_size, new_ram_size;

    old_ram_size = last_ram_offset(uc) >> TARGET_PAGE_BITS;

    new_block->offset = find_ram_offset(uc, new_block->max_length);

    if (!new_block->host) {
        new_block->host = phys_mem_alloc(new_block->max_length,
                                         &new_block->mr->align);
        if (!new_block->host) {
            error_setg_errno(errp, errno,
                             "cannot set up guest memory '%s'",
                             memory_region_name(new_block->mr));
            return -1;
        }
        memory_try_enable_merging(new_block->host, new_block->max_length);
    }

    /* Keep the list sorted from biggest to smallest block.  Unlike QTAILQ,
     * QLIST (which has an RCU-friendly variant) does not have insertion at
     * tail, so save the last element in last_block.
     */
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        last_block = block;
        if (block->max_length < new_block->max_length) {
            break;
        }
    }
    if (block) {
        QLIST_INSERT_BEFORE(block, new_block, next);
    } else if (last_block) {
        QLIST_INSERT_AFTER(last_block, new_block, next);
    } else { /* list is empty */
        QLIST_INSERT_HEAD(&uc->ram_list.blocks, new_block, next);
    }
    uc->ram_list.mru_block = NULL;

    /* Write list before version */
    smp_wmb();
    uc->ram_list.version++;

    new_ram_size = last_ram_offset(uc) >> TARGET_PAGE_BITS;

    if (new_ram_size > old_ram_size) {
        int i;
        for (i = 0; i < DIRTY_MEMORY_NUM; i++) {
            uc->ram_list.dirty_memory[i] =
                bitmap_zero_extend(uc->ram_list.dirty_memory[i],
                        old_ram_size, new_ram_size);
        }
    }
    cpu_physical_memory_set_dirty_range(uc, new_block->offset,
                                        new_block->used_length,
                                        DIRTY_CLIENTS_ALL);

    if (new_block->host) {
        qemu_ram_setup_dump(new_block->host, new_block->max_length);
        // Unicorn: commented out
        //qemu_madvise(new_block->host, new_block->max_length, QEMU_MADV_HUGEPAGE);
        //qemu_madvise(new_block->host, new_block->max_length, QEMU_MADV_DONTFORK);
        //if (kvm_enabled()) {
        //    kvm_setup_guest_memory(new_block->host, new_block->max_length);
        //}
    }

    return new_block->offset;
}

// return -1 on error
static
ram_addr_t qemu_ram_alloc_internal(ram_addr_t size, ram_addr_t max_size,
                                   void (*resized)(const char*,
                                                   uint64_t length,
                                                   void *host),
                                   void *host, bool resizeable,
                                   MemoryRegion *mr, Error **errp)
{
    RAMBlock *new_block;
    ram_addr_t addr;
    Error *local_err = NULL;

    size = TARGET_PAGE_ALIGN(size);
    max_size = TARGET_PAGE_ALIGN(max_size);
    new_block = g_malloc0(sizeof(*new_block));
    if (new_block == NULL) {
        return -1;
    }
    new_block->mr = mr;
    new_block->resized = resized;
    new_block->used_length = size;
    new_block->max_length = max_size;
    assert(max_size >= size);
    new_block->fd = -1;
    new_block->host = host;
    if (host) {
        new_block->flags |= RAM_PREALLOC;
    }
    if (resizeable) {
        new_block->flags |= RAM_RESIZEABLE;
    }
    addr = ram_block_add(mr->uc, new_block, &local_err);
    if (local_err) {
        g_free(new_block);
        error_propagate(errp, local_err);
        return -1;
    }
    return addr;
}

ram_addr_t qemu_ram_alloc_from_ptr(ram_addr_t size, void *host,
                                   MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, size, NULL, host, false, mr, errp);
}

ram_addr_t qemu_ram_alloc(ram_addr_t size, MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, size, NULL, NULL, false, mr, errp);
}

ram_addr_t qemu_ram_alloc_resizeable(ram_addr_t size, ram_addr_t maxsz,
                                     void (*resized)(const char*,
                                                     uint64_t length,
                                                     void *host),
                                     MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, maxsz, resized, NULL, true, mr, errp);
}

static void reclaim_ramblock(RAMBlock *block)
{
    if (block->flags & RAM_PREALLOC) {
        ;
#ifndef _WIN32
    } else if (block->fd >= 0) {
        munmap(block->host, block->max_length);
        close(block->fd);
#endif
    } else {
        qemu_anon_ram_free(block->host, block->max_length);
    }
    g_free(block);
}

void qemu_ram_free(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (addr == block->offset) {
            QLIST_REMOVE(block, next);
            uc->ram_list.mru_block = NULL;
             /* Write list before version */
            smp_wmb();
            uc->ram_list.version++;
            // Unicorn: call directly instead of via call_rcu
            reclaim_ramblock(block);
            break;
        }
    }
}

#ifndef _WIN32
void qemu_ram_remap(struct uc_struct *uc, ram_addr_t addr, ram_addr_t length)
{
    RAMBlock *block;
    ram_addr_t offset;
    int flags;
    void *area, *vaddr;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        offset = addr - block->offset;
        if (offset < block->max_length) {
            vaddr = ramblock_ptr(block, offset);
            if (block->flags & RAM_PREALLOC) {
                ;
            } else {
                flags = MAP_FIXED;
                if (block->fd >= 0) {
                    flags |= (block->flags & RAM_SHARED ?
                            MAP_SHARED : MAP_PRIVATE);
                    area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                            flags, block->fd, offset);
                } else {
                    /*
                     * Remap needs to match alloc.  Accelerators that
                     * set phys_mem_alloc never remap.  If they did,
                     * we'd need a remap hook here.
                     */
                    assert(phys_mem_alloc == qemu_anon_ram_alloc);

                    flags |= MAP_PRIVATE | MAP_ANONYMOUS;
                    area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                            flags, -1, 0);
                }
                if (area != vaddr) {
                    fprintf(stderr, "Could not remap addr: "
                            RAM_ADDR_FMT "@" RAM_ADDR_FMT "\n",
                            length, addr);
                    exit(1);
                }
                memory_try_enable_merging(vaddr, length);
                qemu_ram_setup_dump(vaddr, length);
            }
            return;
        }
    }
}
#endif /* !_WIN32 */

int qemu_get_ram_fd(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block = qemu_get_ram_block(uc, addr);

    return block->fd;
}

void *qemu_get_ram_block_host_ptr(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block = qemu_get_ram_block(uc, addr);

    return ramblock_ptr(block, 0);
}

/* Return a host pointer to ram allocated with qemu_ram_alloc.
   With the exception of the softmmu code in this file, this should
   only be used for local memory (e.g. video ram) that the device owns,
   and knows it isn't going to access beyond the end of the block.

   It should not be used for general purpose DMA.
   Use cpu_physical_memory_map/cpu_physical_memory_rw instead.
   */
void *qemu_get_ram_ptr(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block = qemu_get_ram_block(uc, addr);

    return ramblock_ptr(block, addr - block->offset);
}

/* Return a host pointer to guest's ram. Similar to qemu_get_ram_ptr
 * but takes a size argument */
static void *qemu_ram_ptr_length(struct uc_struct *uc, ram_addr_t addr, hwaddr *size)
{
    RAMBlock *block;
    ram_addr_t offset_inside_block;
    if (*size == 0) {
        return NULL;
    }

    block = qemu_get_ram_block(uc, addr);
    offset_inside_block = addr - block->offset;
    *size = MIN(*size, block->max_length - offset_inside_block);

    // Unicorn: Commented out
    //if (xen_enabled() && block->host == NULL) {
    //    /* We need to check if the requested address is in the RAM
    //     * because we don't want to map the entire memory in QEMU.
    //     * In that case just map the requested area.
    //     */
    //    if (block->offset == 0) {
    //        return xen_map_cache(addr, *size, 1);
    //    }
    //
    //    block->host = xen_map_cache(block->offset, block->max_length, 1);
    //}

    return ramblock_ptr(block, offset_inside_block);
}

/*
 * Translates a host ptr back to a RAMBlock, a ram_addr and an offset
 * in that RAMBlock.
 *
 * ptr: Host pointer to look up
 * round_offset: If true round the result offset down to a page boundary
 * *ram_addr: set to result ram_addr
 * *offset: set to result offset within the RAMBlock
 *
 * Returns: RAMBlock (or NULL if not found)
 *
 *
 * By the time this function returns, the returned pointer is not protected
 * by RCU anymore.  If the caller is not within an RCU critical section and
 * does not hold the iothread lock, it must have other means of protecting the
 * pointer, such as a reference to the region that includes the incoming
 * ram_addr_t.
 */
RAMBlock *qemu_ram_block_from_host(struct uc_struct* uc, void *ptr, bool round_offset,
                                   ram_addr_t *ram_addr,
                                   ram_addr_t *offset)
{
    RAMBlock *block;
    uint8_t *host = ptr;

    block = uc->ram_list.mru_block;
    if (block && block->host && host - block->host < block->max_length) {
        goto found;
    }

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        /* This case append when the block is not mapped. */
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->max_length) {
            goto found;
        }
    }

    return NULL;

found:
    *offset = (host - block->host);
    if (round_offset) {
        *offset &= TARGET_PAGE_MASK;
    }
    *ram_addr = block->offset + *offset;
    return block;
}

/*
 * Finds the named RAMBlock
 *
 * name: The name of RAMBlock to find
 *
 * Returns: RAMBlock (or NULL if not found)
 */
RAMBlock *qemu_ram_block_by_name(struct uc_struct* uc, const char *name)
{
    RAMBlock *block;

    // Unicorn: Changed from QLIST_FOREACH_RCU to QLIST_FOREACH
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (!strcmp(name, block->idstr)) {
            return block;
        }
    }

    return NULL;
}

/* Some of the softmmu routines need to translate from a host pointer
   (typically a TLB entry) back to a ram offset.  */
MemoryRegion *qemu_ram_addr_from_host(struct uc_struct* uc, void *ptr, ram_addr_t *ram_addr)
{
    RAMBlock *block;
    ram_addr_t offset; /* Not used */

    block = qemu_ram_block_from_host(uc, ptr, false, ram_addr, &offset);

    if (!block) {
        return NULL;
    }

    return block->mr;
}

static MemTxResult subpage_read(struct uc_struct* uc, void *opaque, hwaddr addr,
                                uint64_t *data, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];
    MemTxResult res;

#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %u addr " TARGET_FMT_plx "\n", __func__,
            subpage, len, addr);
#endif
    res = address_space_read(subpage->as, addr + subpage->base,
                             attrs, buf, len);
    if (res) {
        return res;
    }
    switch (len) {
    case 1:
        *data = ldub_p(buf);
        return MEMTX_OK;
    case 2:
        *data = lduw_p(buf);
        return MEMTX_OK;
    case 4:
        *data = ldl_p(buf);
        return MEMTX_OK;
    case 8:
        *data = ldq_p(buf);
        return MEMTX_OK;
    default:
        abort();
    }
}

static MemTxResult subpage_write(struct uc_struct* uc, void *opaque, hwaddr addr,
                                 uint64_t value, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];

#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %u addr " TARGET_FMT_plx
            " value %"PRIx64"\n",
            __func__, subpage, len, addr, value);
#endif
    switch (len) {
    case 1:
        stb_p(buf, value);
        break;
    case 2:
        stw_p(buf, value);
        break;
    case 4:
        stl_p(buf, value);
        break;
    case 8:
        stq_p(buf, value);
        break;
    default:
        abort();
    }
    return address_space_write(subpage->as, addr + subpage->base,
                               attrs, buf, len);
}

static bool subpage_accepts(void *opaque, hwaddr addr,
        unsigned len, bool is_write)
{
    subpage_t *subpage = opaque;
#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p %c len %u addr " TARGET_FMT_plx "\n",
            __func__, subpage, is_write ? 'w' : 'r', len, addr);
#endif

    return address_space_access_valid(subpage->as, addr + subpage->base,
            len, is_write);
}

static const MemoryRegionOps subpage_ops = {
    NULL,
    NULL,
    subpage_read,
    subpage_write,
    DEVICE_NATIVE_ENDIAN,
    {
        1, 8, false, subpage_accepts,
    },
    {
        1, 8, false,
    }
};

static int subpage_register (subpage_t *mmio, uint32_t start, uint32_t end,
        uint16_t section)
{
    int idx, eidx;

    if (start >= TARGET_PAGE_SIZE || end >= TARGET_PAGE_SIZE)
        return -1;
    idx = SUBPAGE_IDX(start);
    eidx = SUBPAGE_IDX(end);
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p start %08x end %08x idx %08x eidx %08x section %d\n",
            __func__, mmio, start, end, idx, eidx, section);
#endif
    for (; idx <= eidx; idx++) {
        mmio->sub_section[idx] = section;
    }

    return 0;
}

static void notdirty_mem_write(struct uc_struct* uc, void *opaque, hwaddr ram_addr,
                               uint64_t val, unsigned size)
{
    if (!cpu_physical_memory_get_dirty_flag(uc, ram_addr, DIRTY_MEMORY_CODE)) {
        tb_invalidate_phys_page_fast(uc, ram_addr, size);
    }
    switch (size) {
    case 1:
        stb_p(qemu_get_ram_ptr(uc, ram_addr), val);
        break;
    case 2:
        stw_p(qemu_get_ram_ptr(uc, ram_addr), val);
        break;
    case 4:
        stl_p(qemu_get_ram_ptr(uc, ram_addr), val);
        break;
    default:
        abort();
    }
    /* we remove the notdirty callback only if the code has been
       flushed */
    if (!cpu_physical_memory_is_clean(uc, ram_addr)) {
        tlb_set_dirty(uc->current_cpu, uc->current_cpu->mem_io_vaddr);
    }
}

static bool notdirty_mem_accepts(void *opaque, hwaddr addr,
                                 unsigned size, bool is_write)
{
    return is_write;
}

static const MemoryRegionOps notdirty_mem_ops = {
    NULL,
    notdirty_mem_write,
    NULL,
    NULL,
    DEVICE_NATIVE_ENDIAN,
    {
        0, 0, false, notdirty_mem_accepts,
    },
};

static void io_mem_init(struct uc_struct* uc)
{
    memory_region_init_io(uc, &uc->io_mem_rom, NULL, &unassigned_mem_ops, NULL, NULL, UINT64_MAX);
    memory_region_init_io(uc, &uc->io_mem_unassigned, NULL, &unassigned_mem_ops, NULL,
                          NULL, UINT64_MAX);
    memory_region_init_io(uc, &uc->io_mem_notdirty, NULL, &notdirty_mem_ops, NULL,
                          NULL, UINT64_MAX);
    //memory_region_init_io(uc, &uc->io_mem_watch, NULL, &watch_mem_ops, NULL,
    //                      NULL, UINT64_MAX);
}

static subpage_t *subpage_init(AddressSpace *as, hwaddr base)
{
    subpage_t *mmio;

    mmio = g_malloc0(sizeof(subpage_t));

    mmio->as = as;
    mmio->base = base;
    memory_region_init_io(as->uc, &mmio->iomem, NULL, &subpage_ops, mmio,
            NULL, TARGET_PAGE_SIZE);
    mmio->iomem.subpage = true;
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p base " TARGET_FMT_plx " len %08x\n", __func__,
            mmio, base, TARGET_PAGE_SIZE);
#endif
    subpage_register(mmio, 0, TARGET_PAGE_SIZE-1, PHYS_SECTION_UNASSIGNED);

    return mmio;
}

static uint16_t dummy_section(PhysPageMap *map, AddressSpace *as,
        MemoryRegion *mr)
{
    MemoryRegionSection section = MemoryRegionSection_make(
        mr, as, 0,
        int128_2_64(),
        false,
        0
    );
    
    assert(as);

    return phys_section_add(map, &section);
}

MemoryRegion *iotlb_to_region(CPUState *cpu, hwaddr index, MemTxAttrs attrs)
{
    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    CPUAddressSpace *cpuas = &cpu->cpu_ases[asidx];
    // Unicorn: uses atomic_read instead of atomic_rcu_read
    AddressSpaceDispatch *d = atomic_read(&cpuas->memory_dispatch);
    MemoryRegionSection *sections = d->map.sections;

    return sections[index & ~TARGET_PAGE_MASK].mr;
}

void phys_mem_clean(struct uc_struct* uc)
{
    AddressSpaceDispatch* d = uc->as.next_dispatch;
    g_free(d->map.sections);
}

static void mem_begin(MemoryListener *listener)
{
    AddressSpace *as = container_of(listener, AddressSpace, dispatch_listener);
    AddressSpaceDispatch *d = g_new0(AddressSpaceDispatch, 1);
    uint16_t n;
    PhysPageEntry ppe = { 1, PHYS_MAP_NODE_NIL };
    struct uc_struct *uc = as->uc;

    n = dummy_section(&d->map, as, &uc->io_mem_unassigned);
    assert(n == PHYS_SECTION_UNASSIGNED);
    n = dummy_section(&d->map, as, &uc->io_mem_notdirty);
    assert(n == PHYS_SECTION_NOTDIRTY);
    n = dummy_section(&d->map, as, &uc->io_mem_rom);
    assert(n == PHYS_SECTION_ROM);
    // n = dummy_section(&d->map, as, &uc->io_mem_watch);
    // assert(n == PHYS_SECTION_WATCH);

    d->phys_map = ppe;
    d->as = as;
    as->next_dispatch = d;
}

static void mem_commit(MemoryListener *listener)
{
    AddressSpace *as = container_of(listener, AddressSpace, dispatch_listener);
    AddressSpaceDispatch *cur = as->dispatch;
    AddressSpaceDispatch *next = as->next_dispatch;

    phys_page_compact_all(next, next->map.nodes_nb);

    as->dispatch = next;

    if (cur) {
        phys_sections_free(&cur->map);
        g_free(cur);
    }
}

static void tcg_commit(MemoryListener *listener)
{
    CPUAddressSpace *cpuas;
    AddressSpaceDispatch *d;

    /* since each CPU stores ram addresses in its TLB cache, we must
       reset the modified entries */
    cpuas = container_of(listener, CPUAddressSpace, tcg_as_listener);

    /* The CPU and TLB are protected by the iothread lock.
     * We reload the dispatch pointer now because cpu_reloading_memory_map()
     * may have split the RCU critical section.
     */
    // Unicorn: uses atomic_read instead of atomic_rcu_read
    d = atomic_read(&cpuas->as->dispatch);
    cpuas->memory_dispatch = d;
    tlb_flush(cpuas->cpu, 1);
}

void address_space_init_dispatch(AddressSpace *as)
{
    MemoryListener ml = { 0 };

    ml.begin = mem_begin;
    ml.commit = mem_commit;
    ml.region_add = mem_add;
    ml.region_nop = mem_add;
    ml.priority = 0;

    as->dispatch = NULL;
    as->dispatch_listener = ml;
    memory_listener_register(as->uc, &as->dispatch_listener, as);
}

void address_space_unregister(AddressSpace *as)
{
    memory_listener_unregister(as->uc, &as->dispatch_listener);
}

void address_space_destroy_dispatch(AddressSpace *as)
{
    AddressSpaceDispatch *d = as->dispatch;

    memory_listener_unregister(as->uc, &as->dispatch_listener);
    g_free(d->map.nodes);
    g_free(d);

    if (as->dispatch != as->next_dispatch) {
        d = as->next_dispatch;
        g_free(d->map.nodes);
        g_free(d);
    }

    as->dispatch = NULL;
    as->next_dispatch = NULL;
}

static void memory_map_init(struct uc_struct *uc)
{
    uc->system_memory = g_malloc(sizeof(*(uc->system_memory)));

    memory_region_init(uc, uc->system_memory, NULL, "system", UINT64_MAX);
    address_space_init(uc, &uc->as, uc->system_memory, "memory");
}

void cpu_exec_init_all(struct uc_struct *uc)
{
    io_mem_init(uc);
#if !defined(CONFIG_USER_ONLY)
    memory_map_init(uc);
#endif
}

MemoryRegion *get_system_memory(struct uc_struct *uc)
{
    return uc->system_memory;
}

#endif /* !defined(CONFIG_USER_ONLY) */

/* physical memory access (slow version, mainly for debug) */
#if defined(CONFIG_USER_ONLY)
int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr,
        uint8_t *buf, int len, int is_write)
{
    int l, flags;
    target_ulong page;
    void * p;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        flags = page_get_flags(page);
        if (!(flags & PAGE_VALID))
            return -1;
        if (is_write) {
            if (!(flags & PAGE_WRITE))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_WRITE, addr, l, 0)))
                return -1;
            memcpy(p, buf, l);
            unlock_user(p, addr, l);
        } else {
            if (!(flags & PAGE_READ))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_READ, addr, l, 1)))
                return -1;
            memcpy(buf, p, l);
            unlock_user(p, addr, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

#else

static void invalidate_and_set_dirty(MemoryRegion *mr, hwaddr addr,
                                     hwaddr length)
{
    uint8_t dirty_log_mask = memory_region_get_dirty_log_mask(mr);

    if (dirty_log_mask) {
        dirty_log_mask =
            cpu_physical_memory_range_includes_clean(mr->uc, addr, length, dirty_log_mask);
    }
    if (dirty_log_mask & (1 << DIRTY_MEMORY_CODE)) {
        tb_invalidate_phys_range(mr->uc, addr, addr + length);
        dirty_log_mask &= ~(1 << DIRTY_MEMORY_CODE);
    }
    cpu_physical_memory_set_dirty_range(mr->uc, addr, length, dirty_log_mask);
}

static int memory_access_size(MemoryRegion *mr, unsigned l, hwaddr addr)
{
    unsigned access_size_max = mr->ops->valid.max_access_size;

    /* Regions are assumed to support 1-4 byte accesses unless
       otherwise specified.  */
    if (access_size_max == 0) {
        access_size_max = 4;
    }

    /* Bound the maximum access by the alignment of the address.  */
    if (!mr->ops->impl.unaligned) {
        unsigned align_size_max = addr & (0-addr);
        if (align_size_max != 0 && align_size_max < access_size_max) {
            access_size_max = align_size_max;
        }
    }

    /* Don't attempt accesses larger than the maximum.  */
    if (l > access_size_max) {
        l = access_size_max;
    }
    l = pow2floor(l);

    return l;
}

static MemTxResult address_space_write_continue(AddressSpace *as, hwaddr addr,
                                                MemTxAttrs attrs,
                                                const uint8_t *buf,
                                                int len, hwaddr addr1,
                                                hwaddr l, MemoryRegion *mr)
{
    uint8_t *ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    // Unicorn: commented out
    //bool release_lock = false;

    for (;;) {
        if (!mr)
            return true;

        if (!memory_access_is_direct(mr, true)) {
            // Unicorn: commented out
            //release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            /* XXX: could force current_cpu to NULL to avoid
               potential bugs */
            switch (l) {
            case 8:
                /* 64 bit write access */
                val = ldq_p(buf);
                result |= memory_region_dispatch_write(mr, addr1, val, 8,
                                                       attrs);
                break;
            case 4:
                /* 32 bit write access */
                val = ldl_p(buf);
                result |= memory_region_dispatch_write(mr, addr1, val, 4,
                                                       attrs);
                break;
            case 2:
                /* 16 bit write access */
                val = lduw_p(buf);
                result |= memory_region_dispatch_write(mr, addr1, val, 2,
                                                       attrs);
                break;
            case 1:
                /* 8 bit write access */
                val = ldub_p(buf);
                result |= memory_region_dispatch_write(mr, addr1, val, 1,
                                                       attrs);
                break;
            default:
                abort();
            }
        } else {
            addr1 += memory_region_get_ram_addr(mr);
            /* RAM case */
            ptr = qemu_get_ram_ptr(mr->uc, addr1);
            memcpy(ptr, buf, l);
            invalidate_and_set_dirty(mr, addr1, l);
        }

        /* Unicorn: commented out
        if (release_lock) {
            qemu_mutex_unlock_iothread();
            release_lock = false;
        }*/

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);
    }
    // Unicorn: commented out
    //rcu_read_unlock();

    return result;
}

MemTxResult address_space_write(AddressSpace *as, hwaddr addr, MemTxAttrs attrs,
                                const uint8_t *buf, int len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    if (len > 0) {
        // Unicorn: commented out
        //rcu_read_lock();
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);
        result = address_space_write_continue(as, addr, attrs, buf, len,
                                              addr1, l, mr);
        // Unicorn: commented out
        //rcu_read_unlock();
    }

    return result;
}

MemTxResult address_space_read_continue(AddressSpace *as, hwaddr addr,
                                        MemTxAttrs attrs, uint8_t *buf,
                                        int len, hwaddr addr1, hwaddr l,
                                        MemoryRegion *mr)
{
    uint8_t *ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    // Unicorn: commented out
    //bool release_lock = false;

    for (;;) {
        if (!memory_access_is_direct(mr, false)) {
            /* I/O case */
            // Unicorn: commented out
            //release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            switch (l) {
            case 8:
                /* 64 bit read access */
                result |= memory_region_dispatch_read(mr, addr1, &val, 8,
                                                      attrs);
                stq_p(buf, val);
                break;
            case 4:
                /* 32 bit read access */
                result |= memory_region_dispatch_read(mr, addr1, &val, 4,
                                                      attrs);
                stl_p(buf, val);
                break;
            case 2:
                /* 16 bit read access */
                result |= memory_region_dispatch_read(mr, addr1, &val, 2,
                                                      attrs);
                stw_p(buf, val);
                break;
            case 1:
                /* 8 bit read access */
                result |= memory_region_dispatch_read(mr, addr1, &val, 1,
                                                      attrs);
                stb_p(buf, val);
                break;
            default:
                abort();
            }
        } else {
            /* RAM case */
            ptr = qemu_get_ram_ptr(mr->uc, mr->ram_addr + addr1);
            memcpy(buf, ptr, l);
        }

        /* Unicorn: Commented out
        if (release_lock) {
            qemu_mutex_unlock_iothread();
            release_lock = false;
        }*/

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, false);
    }

    return result;
}

MemTxResult address_space_read_full(AddressSpace *as, hwaddr addr,
                                    MemTxAttrs attrs, uint8_t *buf, int len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    if (len > 0) {
        // Unicorn: commented out
        //rcu_read_lock();
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, false);
        result = address_space_read_continue(as, addr, attrs, buf, len,
                                             addr1, l, mr);
        // Unicorn: commented out
        //rcu_read_unlock();
    }
    return result;
}

MemTxResult address_space_rw(AddressSpace *as, hwaddr addr, MemTxAttrs attrs,
                             uint8_t *buf, int len, bool is_write)
{
    if (is_write) {
        return address_space_write(as, addr, attrs, (uint8_t *)buf, len);
    } else {
        return address_space_read(as, addr, attrs, (uint8_t *)buf, len);
    }
}

bool cpu_physical_memory_rw(AddressSpace *as, hwaddr addr, uint8_t *buf,
                            int len, int is_write)
{
    return address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED,
                            buf, len, is_write) == MEMTX_OK;
}

enum write_rom_type {
    WRITE_DATA,
    FLUSH_CACHE,
};

static inline void cpu_physical_memory_write_rom_internal(AddressSpace *as,
        hwaddr addr, const uint8_t *buf, int len, enum write_rom_type type)
{
    hwaddr l;
    uint8_t *ptr;
    hwaddr addr1;
    MemoryRegion *mr;

    while (len > 0) {
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);

        if (!(memory_region_is_ram(mr) ||
              memory_region_is_romd(mr))) {
            l = memory_access_size(mr, l, addr1);
        } else {
            addr1 += memory_region_get_ram_addr(mr);
            /* ROM/RAM case */
            ptr = qemu_get_ram_ptr(as->uc, addr1);
            switch (type) {
                case WRITE_DATA:
                    memcpy(ptr, buf, l);
                    invalidate_and_set_dirty(mr, addr1, l);
                    break;
                case FLUSH_CACHE:
                    flush_icache_range((uintptr_t)ptr, (uintptr_t)ptr + l);
                    break;
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
}

/* used for ROM loading : can write in RAM and ROM */
DEFAULT_VISIBILITY
void cpu_physical_memory_write_rom(AddressSpace *as, hwaddr addr,
        const uint8_t *buf, int len)
{
    cpu_physical_memory_write_rom_internal(as, addr, buf, len, WRITE_DATA);
}

void cpu_flush_icache_range(AddressSpace *as, hwaddr start, int len)
{
    /*
     * This function should do the same thing as an icache flush that was
     * triggered from within the guest. For TCG we are always cache coherent,
     * so there is no need to flush anything. For KVM / Xen we need to flush
     * the host's instruction cache at least.
     */
    if (tcg_enabled(as->uc)) {
        return;
    }

    cpu_physical_memory_write_rom_internal(as,
            start, NULL, len, FLUSH_CACHE);
}


bool address_space_access_valid(AddressSpace *as, hwaddr addr, int len, bool is_write)
{
    MemoryRegion *mr;
    hwaddr l, xlat;

    while (len > 0) {
        l = len;
        mr = address_space_translate(as, addr, &xlat, &l, is_write);
        if (!memory_access_is_direct(mr, is_write)) {
            l = memory_access_size(mr, l, addr);
            if (!memory_region_access_valid(mr, xlat, l, is_write)) {
                return false;
            }
        }

        len -= l;
        addr += l;
    }
    return true;
}

/* Map a physical memory region into a host virtual address.
 * May map a subset of the requested range, given by and returned in *plen.
 * May return NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 * Use cpu_register_map_client() to know when retrying the map operation is
 * likely to succeed.
 */
void *address_space_map(AddressSpace *as,
        hwaddr addr,
        hwaddr *plen,
        bool is_write)
{
    hwaddr len = *plen;
    hwaddr done = 0;
    hwaddr l, xlat, base;
    MemoryRegion *mr, *this_mr;
    ram_addr_t raddr;

    if (len == 0) {
        return NULL;
    }

    l = len;
    mr = address_space_translate(as, addr, &xlat, &l, is_write);
    if (!memory_access_is_direct(mr, is_write)) {
        if (atomic_xchg(&as->uc->bounce.in_use, true)) {
            return NULL;
        }
        /* Avoid unbounded allocations */
        l = MIN(l, TARGET_PAGE_SIZE);
        as->uc->bounce.buffer = qemu_memalign(TARGET_PAGE_SIZE, l);
        as->uc->bounce.addr = addr;
        as->uc->bounce.len = l;

        memory_region_ref(mr);
        as->uc->bounce.mr = mr;
        if (!is_write) {
            address_space_read(as, addr, MEMTXATTRS_UNSPECIFIED,
                               as->uc->bounce.buffer, l);
        }

        *plen = l;
        return as->uc->bounce.buffer;
    }

    base = xlat;
    raddr = memory_region_get_ram_addr(mr);

    for (;;) {
        len -= l;
        addr += l;
        done += l;
        if (len == 0) {
            break;
        }

        l = len;
        this_mr = address_space_translate(as, addr, &xlat, &l, is_write);
        if (this_mr != mr || xlat != base + done) {
            break;
        }
    }

    memory_region_ref(mr);
    *plen = done;
    return qemu_ram_ptr_length(as->uc, raddr + base, plen);
}

/* Unmaps a memory region previously mapped by address_space_map().
 * Will also mark the memory as dirty if is_write == 1.  access_len gives
 * the amount of memory that was actually read or written by the caller.
 */
void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
        int is_write, hwaddr access_len)
{
    if (buffer != as->uc->bounce.buffer) {
        MemoryRegion *mr;
        ram_addr_t addr1;

        mr = qemu_ram_addr_from_host(as->uc, buffer, &addr1);
        assert(mr != NULL);
        if (is_write) {
            invalidate_and_set_dirty(mr, addr1, access_len);
        }
        memory_region_unref(mr);
        return;
    }
    if (is_write) {
        address_space_write(as, as->uc->bounce.addr, MEMTXATTRS_UNSPECIFIED,
                            as->uc->bounce.buffer, access_len);
    }
    qemu_vfree(as->uc->bounce.buffer);
    as->uc->bounce.buffer = NULL;
    memory_region_unref(as->uc->bounce.mr);
    atomic_mb_set(&as->uc->bounce.in_use, false);
}

void *cpu_physical_memory_map(AddressSpace *as, hwaddr addr,
        hwaddr *plen,
        int is_write)
{
    return address_space_map(as, addr, plen, is_write);
}

void cpu_physical_memory_unmap(AddressSpace *as, void *buffer, hwaddr len,
        int is_write, hwaddr access_len)
{
    address_space_unmap(as, buffer, len, is_write, access_len);
}

/* warning: addr must be aligned */
static inline uint32_t address_space_ldl_internal(AddressSpace *as, hwaddr addr,
                                                  MemTxAttrs attrs,
                                                  MemTxResult *result,
                                                  enum device_endian endian)
{
    uint8_t *ptr;
    uint64_t val;
    MemoryRegion *mr;
    hwaddr l = 4;
    hwaddr addr1;
    MemTxResult r;

    mr = address_space_translate(as, addr, &addr1, &l, false);
    if (l < 4 || !memory_access_is_direct(mr, false)) {
        /* I/O case */
        r = memory_region_dispatch_read(mr, addr1, &val, 4, attrs);
#if defined(TARGET_WORDS_BIGENDIAN)
        if (endian == DEVICE_LITTLE_ENDIAN) {
            val = bswap32(val);
        }
#else
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap32(val);
        }
#endif
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr(as->uc, (memory_region_get_ram_addr(mr)
                    & TARGET_PAGE_MASK)
                + addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            val = ldl_le_p(ptr);
            break;
        case DEVICE_BIG_ENDIAN:
            val = ldl_be_p(ptr);
            break;
        default:
            val = ldl_p(ptr);
            break;
        }
        r = MEMTX_OK;
    }
    if (result) {
        *result = r;
    }
    return val;
}

uint32_t address_space_ldl(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_ldl_internal(as, addr, attrs, result,
                                      DEVICE_NATIVE_ENDIAN);
}

uint32_t address_space_ldl_le(AddressSpace *as, hwaddr addr,
                              MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_ldl_internal(as, addr, attrs, result,
                                      DEVICE_LITTLE_ENDIAN);
}

uint32_t address_space_ldl_be(AddressSpace *as, hwaddr addr,
                              MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_ldl_internal(as, addr, attrs, result,
                                      DEVICE_BIG_ENDIAN);
}

uint32_t ldl_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldl(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

uint32_t ldl_le_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldl_le(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

uint32_t ldl_be_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldl_be(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* warning: addr must be aligned */
static inline uint64_t address_space_ldq_internal(AddressSpace *as, hwaddr addr,
                                                  MemTxAttrs attrs,
                                                  MemTxResult *result,
                                                  enum device_endian endian)
{
    uint8_t *ptr;
    uint64_t val;
    MemoryRegion *mr;
    hwaddr l = 8;
    hwaddr addr1;
    MemTxResult r;

    mr = address_space_translate(as, addr, &addr1, &l,
                                 false);
    if (l < 8 || !memory_access_is_direct(mr, false)) {
        /* I/O case */
        r = memory_region_dispatch_read(mr, addr1, &val, 8, attrs);
#if defined(TARGET_WORDS_BIGENDIAN)
        if (endian == DEVICE_LITTLE_ENDIAN) {
            val = bswap64(val);
        }
#else
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap64(val);
        }
#endif
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr(as->uc, (memory_region_get_ram_addr(mr)
                    & TARGET_PAGE_MASK)
                + addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            val = ldq_le_p(ptr);
            break;
        case DEVICE_BIG_ENDIAN:
            val = ldq_be_p(ptr);
            break;
        default:
            val = ldq_p(ptr);
            break;
        }
        r = MEMTX_OK;
    }
    if (result) {
        *result = r;
    }
    return val;
}

uint64_t address_space_ldq(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_ldq_internal(as, addr, attrs, result,
                                      DEVICE_NATIVE_ENDIAN);
}

uint64_t address_space_ldq_le(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_ldq_internal(as, addr, attrs, result,
                                      DEVICE_LITTLE_ENDIAN);
}

uint64_t address_space_ldq_be(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_ldq_internal(as, addr, attrs, result,
                                      DEVICE_BIG_ENDIAN);
}

uint64_t ldq_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldq(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

uint64_t ldq_le_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldq_le(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

uint64_t ldq_be_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldq_be(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* XXX: optimize */
uint32_t address_space_ldub(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result)
{
    uint8_t val;
    MemTxResult r;

    r = address_space_rw(as, addr, attrs, &val, 1, 0);
    if (result) {
        *result = r;
    }
    return val;
}

uint32_t ldub_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_ldub(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* warning: addr must be aligned */
static inline uint32_t address_space_lduw_internal(AddressSpace *as,
                                                   hwaddr addr,
                                                   MemTxAttrs attrs,
                                                   MemTxResult *result,
                                                   enum device_endian endian)
{
    uint8_t *ptr;
    uint64_t val;
    MemoryRegion *mr;
    hwaddr l = 2;
    hwaddr addr1;
    MemTxResult r;

    mr = address_space_translate(as, addr, &addr1, &l,
                                 false);
    if (l < 2 || !memory_access_is_direct(mr, false)) {
        /* I/O case */
        r = memory_region_dispatch_read(mr, addr1, &val, 2, attrs);
#if defined(TARGET_WORDS_BIGENDIAN)
        if (endian == DEVICE_LITTLE_ENDIAN) {
            val = bswap16(val);
        }
#else
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap16(val);
        }
#endif
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr(as->uc, (memory_region_get_ram_addr(mr)
                    & TARGET_PAGE_MASK)
                + addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            val = lduw_le_p(ptr);
            break;
        case DEVICE_BIG_ENDIAN:
            val = lduw_be_p(ptr);
            break;
        default:
            val = lduw_p(ptr);
            break;
        }
        r = MEMTX_OK;
    }
    if (result) {
        *result = r;
    }
    return val;
}

uint32_t address_space_lduw(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_lduw_internal(as, addr, attrs, result,
                                       DEVICE_NATIVE_ENDIAN);
}

uint32_t address_space_lduw_le(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_lduw_internal(as, addr, attrs, result,
                                       DEVICE_LITTLE_ENDIAN);
}

uint32_t address_space_lduw_be(AddressSpace *as, hwaddr addr,
                           MemTxAttrs attrs, MemTxResult *result)
{
    return address_space_lduw_internal(as, addr, attrs, result,
                                       DEVICE_BIG_ENDIAN);
}

uint32_t lduw_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_lduw(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

uint32_t lduw_le_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_lduw_le(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

uint32_t lduw_be_phys(AddressSpace *as, hwaddr addr)
{
    return address_space_lduw_be(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* warning: addr must be aligned. The ram page is not masked as dirty
   and the code inside is not invalidated. It is useful if the dirty
   bits are used to track modified PTEs */
void address_space_stl_notdirty(AddressSpace *as, hwaddr addr, uint32_t val,
                                MemTxAttrs attrs, MemTxResult *result)
{
    uint8_t *ptr;
    MemoryRegion *mr;
    hwaddr l = 4;
    hwaddr addr1;
    MemTxResult r;

    mr = address_space_translate(as, addr, &addr1, &l,
                                 true);
    if (l < 4 || !memory_access_is_direct(mr, true)) {
        r = memory_region_dispatch_write(mr, addr1, val, 4, attrs);
    } else {
        addr1 += memory_region_get_ram_addr(mr) & TARGET_PAGE_MASK;
        ptr = qemu_get_ram_ptr(as->uc, addr1);
        stl_p(ptr, val);
        r = MEMTX_OK;
    }
    if (result) {
        *result = r;
    }
}

void stl_phys_notdirty(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stl_notdirty(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* warning: addr must be aligned */
static inline void address_space_stl_internal(AddressSpace *as,
                                              hwaddr addr, uint32_t val,
                                              MemTxAttrs attrs,
                                              MemTxResult *result,
                                              enum device_endian endian)
{
    uint8_t *ptr;
    MemoryRegion *mr;
    hwaddr l = 4;
    hwaddr addr1;
    MemTxResult r;

    mr = address_space_translate(as, addr, &addr1, &l,
                                 true);
    if (l < 4 || !memory_access_is_direct(mr, true)) {
#if defined(TARGET_WORDS_BIGENDIAN)
        if (endian == DEVICE_LITTLE_ENDIAN) {
            val = bswap32(val);
        }
#else
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap32(val);
        }
#endif
        r = memory_region_dispatch_write(mr, addr1, val, 4, attrs);
    } else {
        /* RAM case */
        addr1 += memory_region_get_ram_addr(mr) & TARGET_PAGE_MASK;
        ptr = qemu_get_ram_ptr(as->uc, addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            stl_le_p(ptr, val);
            break;
        case DEVICE_BIG_ENDIAN:
            stl_be_p(ptr, val);
            break;
        default:
            stl_p(ptr, val);
            break;
        }
        invalidate_and_set_dirty(mr, addr1, 4);
        r = MEMTX_OK;
    }
    if (result) {
        *result = r;
    }
}

void address_space_stl(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    address_space_stl_internal(as, addr, val, attrs, result,
                               DEVICE_NATIVE_ENDIAN);
}

void address_space_stl_le(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    address_space_stl_internal(as, addr, val, attrs, result,
                               DEVICE_LITTLE_ENDIAN);
}

void address_space_stl_be(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    address_space_stl_internal(as, addr, val, attrs, result,
                               DEVICE_BIG_ENDIAN);
}

void stl_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stl(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

void stl_le_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stl_le(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

void stl_be_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stl_be(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* XXX: optimize */
void address_space_stb(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    uint8_t v = val;
    MemTxResult r;

    r = address_space_rw(as, addr, attrs, &v, 1, 1);
    if (result) {
        *result = r;
    }
}

void stb_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stb(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* warning: addr must be aligned */
static inline void address_space_stw_internal(AddressSpace *as,
                                              hwaddr addr, uint32_t val,
                                              MemTxAttrs attrs,
                                              MemTxResult *result,
                                              enum device_endian endian)
{
    uint8_t *ptr;
    MemoryRegion *mr;
    hwaddr l = 2;
    hwaddr addr1;
    MemTxResult r;

    mr = address_space_translate(as, addr, &addr1, &l, true);
    if (l < 2 || !memory_access_is_direct(mr, true)) {
#if defined(TARGET_WORDS_BIGENDIAN)
        if (endian == DEVICE_LITTLE_ENDIAN) {
            val = bswap16(val);
        }
#else
        if (endian == DEVICE_BIG_ENDIAN) {
            val = bswap16(val);
        }
#endif
        r = memory_region_dispatch_write(mr, addr1, val, 2, attrs);
    } else {
        /* RAM case */
        addr1 += memory_region_get_ram_addr(mr) & TARGET_PAGE_MASK;
        ptr = qemu_get_ram_ptr(as->uc, addr1);
        switch (endian) {
        case DEVICE_LITTLE_ENDIAN:
            stw_le_p(ptr, val);
            break;
        case DEVICE_BIG_ENDIAN:
            stw_be_p(ptr, val);
            break;
        default:
            stw_p(ptr, val);
            break;
        }
        invalidate_and_set_dirty(mr, addr1, 2);
        r = MEMTX_OK;
    }
    if (result) {
        *result = r;
    }
}

void address_space_stw(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    address_space_stw_internal(as, addr, val, attrs, result,
                               DEVICE_NATIVE_ENDIAN);
}

void address_space_stw_le(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    address_space_stw_internal(as, addr, val, attrs, result,
                               DEVICE_LITTLE_ENDIAN);
}

void address_space_stw_be(AddressSpace *as, hwaddr addr, uint32_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    address_space_stw_internal(as, addr, val, attrs, result,
                               DEVICE_BIG_ENDIAN);
}

void stw_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stw(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

void stw_le_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stw_le(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

void stw_be_phys(AddressSpace *as, hwaddr addr, uint32_t val)
{
    address_space_stw_be(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* XXX: optimize */
void address_space_stq(AddressSpace *as, hwaddr addr, uint64_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    MemTxResult r;
    val = tswap64(val);
    r = address_space_rw(as, addr, attrs, (void *) &val, 8, 1);
    if (result) {
        *result = r;
    }
}
void address_space_stq_le(AddressSpace *as, hwaddr addr, uint64_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    MemTxResult r;
    val = cpu_to_le64(val);
    r = address_space_rw(as, addr, attrs, (void *) &val, 8, 1);
    if (result) {
        *result = r;
    }
}

void address_space_stq_be(AddressSpace *as, hwaddr addr, uint64_t val,
                       MemTxAttrs attrs, MemTxResult *result)
{
    MemTxResult r;
    val = cpu_to_be64(val);
    r = address_space_rw(as, addr, attrs, (void *) &val, 8, 1);
    if (result) {
        *result = r;
    }
}

void stq_phys(AddressSpace *as, hwaddr addr, uint64_t val)
{
    address_space_stq(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

void stq_le_phys(AddressSpace *as, hwaddr addr, uint64_t val)
{
    address_space_stq_le(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

void stq_be_phys(AddressSpace *as, hwaddr addr, uint64_t val)
{
    address_space_stq_be(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

/* virtual memory access for debug (includes writing to ROM) */
int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr,
        uint8_t *buf, int len, int is_write)
{
    int l;
    hwaddr phys_addr;
    target_ulong page;

    while (len > 0) {
        int asidx;
        MemTxAttrs attrs;

        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, page, &attrs);
        asidx = cpu_asidx_from_attrs(cpu, attrs);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        if (is_write) {
            cpu_physical_memory_write_rom(cpu->cpu_ases[asidx].as,
                                          phys_addr, buf, l);
        } else {
            address_space_rw(cpu->cpu_ases[asidx].as, phys_addr,
                             MEMTXATTRS_UNSPECIFIED,
                             buf, l, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}
#endif

/*
 * A helper function for the _utterly broken_ virtio device model to find out if
 * it's running on a big endian machine. Don't do this at home kids!
 */
bool target_words_bigendian(void);
bool target_words_bigendian(void)
{
#if defined(TARGET_WORDS_BIGENDIAN)
    return true;
#else
    return false;
#endif
}

#ifndef CONFIG_USER_ONLY
bool cpu_physical_memory_is_io(AddressSpace *as, hwaddr phys_addr)
{
    MemoryRegion*mr;
    hwaddr l = 1;

    mr = address_space_translate(as, phys_addr, &phys_addr, &l, false);

    return !(memory_region_is_ram(mr) ||
            memory_region_is_romd(mr));
}

int qemu_ram_foreach_block(struct uc_struct *uc, RAMBlockIterFunc func, void *opaque)
{
    RAMBlock *block;
    int ret = 0;

    // Unicorn: commented out
    //rcu_read_lock();
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        ret = func(block->idstr, block->host, block->offset,
                   block->used_length, opaque);
        if (ret) {
            break;
        }
    }
    // Unicorn: commented out
    //rcu_read_unlock();
    return ret;
}
#endif
