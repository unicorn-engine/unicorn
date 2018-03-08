/*
 * Physical memory management
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Avi Kivity <avi@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "qapi/error.h"
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/ioport.h"
#include "qapi/visitor.h"
#include "qemu/bitops.h"
#include "qom/object.h"

#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "sysemu/sysemu.h"

//#define DEBUG_UNASSIGNED

#define RAM_ADDR_INVALID (~(ram_addr_t)0)

// Unicorn engine
MemoryRegion *memory_map(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms)
{
    MemoryRegion *ram = g_new(MemoryRegion, 1);

    memory_region_init_ram_nomigrate(uc, ram, NULL, "pc.ram", size, perms, &error_abort);
    if (ram->ram_block == NULL) {
        // out of memory
        return NULL;
    }

    memory_region_add_subregion(get_system_memory(uc), begin, ram);

    if (uc->current_cpu)
        tlb_flush(uc->current_cpu);

    return ram;
}

MemoryRegion *memory_map_ptr(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms, void *ptr)
{
    MemoryRegion *ram = g_new(MemoryRegion, 1);

    memory_region_init_ram_ptr(uc, ram, NULL, "pc.ram", size, ptr);
    ram->perms = perms;
    if (ram->ram_block == NULL) {
        // out of memory
        return NULL;
    }

    memory_region_add_subregion(get_system_memory(uc), begin, ram);

    if (uc->current_cpu)
        tlb_flush(uc->current_cpu);

    return ram;
}

static void memory_region_update_container_subregions(MemoryRegion *subregion);

void memory_unmap(struct uc_struct *uc, MemoryRegion *mr)
{
    int i;
    target_ulong addr;
    Object *obj;

    // Make sure all pages associated with the MemoryRegion are flushed
    // Only need to do this if we are in a running state
    if (uc->current_cpu) {
        for (addr = mr->addr; addr < mr->end; addr += uc->target_page_size) {
           tlb_flush_page(uc->current_cpu, addr);
        }
    }
    memory_region_del_subregion(get_system_memory(uc), mr);

    for (i = 0; i < uc->mapped_block_count; i++) {
        if (uc->mapped_blocks[i] == mr) {
            uc->mapped_block_count--;
            //shift remainder of array down over deleted pointer
            memmove(&uc->mapped_blocks[i], &uc->mapped_blocks[i + 1], sizeof(MemoryRegion*) * (uc->mapped_block_count - i));
            mr->destructor(mr);
            obj = OBJECT(mr);
            obj->ref = 1;
            obj->free = g_free;
            g_free((char *)mr->name);
            mr->name = NULL;
            object_property_del_child(mr->uc, qdev_get_machine(mr->uc), obj, &error_abort);
            break;
        }
    }
}

int memory_free(struct uc_struct *uc)
{
    MemoryRegion *mr;
    Object *obj;
    int i;

    for (i = 0; i < uc->mapped_block_count; i++) {
        mr = uc->mapped_blocks[i];
        mr->enabled = false;
        memory_region_del_subregion(get_system_memory(uc), mr);
        mr->destructor(mr);
        obj = OBJECT(mr);
        obj->ref = 1;
        obj->free = g_free;
        object_property_del_child(mr->uc, qdev_get_machine(mr->uc), obj, &error_abort);
    }

    return 0;
}

static void memory_init(struct uc_struct *uc)
{
}

typedef struct AddrRange AddrRange;

/*
 * Note that signed integers are needed for negative offsetting in aliases
 * (large MemoryRegion::alias_offset).
 */
struct AddrRange {
    Int128 start;
    Int128 size;
};

static AddrRange addrrange_make(Int128 start, Int128 size)
{
    AddrRange ar;
    ar.start = start;
    ar.size = size;
    return ar;
}

static bool addrrange_equal(AddrRange r1, AddrRange r2)
{
    return int128_eq(r1.start, r2.start) && int128_eq(r1.size, r2.size);
}

static Int128 addrrange_end(AddrRange r)
{
    return int128_add(r.start, r.size);
}

static bool addrrange_contains(AddrRange range, Int128 addr)
{
    return int128_ge(addr, range.start)
        && int128_lt(addr, addrrange_end(range));
}

static bool addrrange_intersects(AddrRange r1, AddrRange r2)
{
    return addrrange_contains(r1, r2.start)
        || addrrange_contains(r2, r1.start);
}

static AddrRange addrrange_intersection(AddrRange r1, AddrRange r2)
{
    Int128 start = int128_max(r1.start, r2.start);
    Int128 end = int128_min(addrrange_end(r1), addrrange_end(r2));
    return addrrange_make(start, int128_sub(end, start));
}

enum ListenerDirection { Forward, Reverse };

#define MEMORY_LISTENER_CALL_GLOBAL(_callback, _direction, ...)    \
    do {                                                                \
        MemoryListener *_listener;                                      \
                                                                        \
        switch (_direction) {                                           \
        case Forward:                                                   \
            QTAILQ_FOREACH(_listener, &uc->memory_listeners, link) {        \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener, ##__VA_ARGS__);           \
                }                                                       \
            }                                                           \
            break;                                                      \
        case Reverse:                                                   \
            QTAILQ_FOREACH_REVERSE(_listener, &uc->memory_listeners,        \
                                   memory_listeners, link) {            \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener, ##__VA_ARGS__);           \
                }                                                       \
            }                                                           \
            break;                                                      \
        default:                                                        \
            abort();                                                    \
        }                                                               \
    } while (0)

#define MEMORY_LISTENER_CALL(_as, _callback, _direction, _section, ...) \
    do {                                                                \
        MemoryListener *_listener;                                      \
        struct memory_listeners_as *list = &(_as)->listeners;           \
                                                                        \
        switch (_direction) {                                           \
        case Forward:                                                   \
            QTAILQ_FOREACH(_listener, list, link_as) {                  \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener, _section, ##__VA_ARGS__); \
                }                                                       \
            }                                                           \
            break;                                                      \
        case Reverse:                                                   \
            QTAILQ_FOREACH_REVERSE(_listener, list, memory_listeners_as, \
                                   link_as) {                           \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener, _section, ##__VA_ARGS__); \
                }                                                       \
            }                                                           \
            break;                                                      \
        default:                                                        \
            abort();                                                    \
        }                                                               \
    } while (0)

/* No need to ref/unref .mr, the FlatRange keeps it alive.  */
#define MEMORY_LISTENER_UPDATE_REGION(fr, as, dir, callback, ...)     \
    do {                                                              \
        MemoryRegionSection mrs = section_from_flat_range(fr, as);    \
        MEMORY_LISTENER_CALL(as, callback, dir, &mrs, ##__VA_ARGS__); \
    } while(0);

typedef struct FlatRange FlatRange;
typedef struct FlatView FlatView;

/* Range of memory in the global map.  Addresses are absolute. */
struct FlatRange {
    MemoryRegion *mr;
    hwaddr offset_in_region;
    AddrRange addr;
    uint8_t dirty_log_mask;
    bool readonly;
};

/* Flattened global view of current active memory hierarchy.  Kept in sorted
 * order.
 */
struct FlatView {
    unsigned ref;
    FlatRange *ranges;
    unsigned nr;
    unsigned nr_allocated;
};

typedef struct AddressSpaceOps AddressSpaceOps;

#define FOR_EACH_FLAT_RANGE(var, view)          \
    for (var = (view)->ranges; var < (view)->ranges + (view)->nr; ++var)

static inline MemoryRegionSection
section_from_flat_range(FlatRange *fr, AddressSpace *as)
{
    MemoryRegionSection s = {0};
    s.mr = fr->mr;
    s.address_space = as;
    s.offset_within_region = fr->offset_in_region;
    s.size = fr->addr.size;
    s.offset_within_address_space = int128_get64(fr->addr.start);
    s.readonly = fr->readonly;
    return s;
}

static bool flatrange_equal(FlatRange *a, FlatRange *b)
{
    return a->mr == b->mr
        && addrrange_equal(a->addr, b->addr)
        && a->offset_in_region == b->offset_in_region
        && a->readonly == b->readonly;
}

static FlatView *flatview_new(void)
{
    FlatView *view;

    view = g_new0(FlatView, 1);
    view->ref = 1;

    return view;
}

/* Insert a range into a given position.  Caller is responsible for maintaining
 * sorting order.
 */
static void flatview_insert(FlatView *view, unsigned pos, FlatRange *range)
{
    if (view->nr == view->nr_allocated) {
        view->nr_allocated = MAX(2 * view->nr, 10);
        view->ranges = g_realloc(view->ranges,
                                    view->nr_allocated * sizeof(*view->ranges));
    }
    memmove(view->ranges + pos + 1, view->ranges + pos,
            (view->nr - pos) * sizeof(FlatRange));
    view->ranges[pos] = *range;
    memory_region_ref(range->mr);
    ++view->nr;
}

static void flatview_destroy(FlatView *view)
{
    int i;

    for (i = 0; i < view->nr; i++) {
        memory_region_unref(view->ranges[i].mr);
    }
    g_free(view->ranges);
    g_free(view);
}

static void flatview_ref(FlatView *view)
{
    atomic_inc(&view->ref);
}

static void flatview_unref(FlatView *view)
{
    if (atomic_fetch_dec(&view->ref) == 1) {
        flatview_destroy(view);
    }
}

static bool can_merge(FlatRange *r1, FlatRange *r2)
{
    return int128_eq(addrrange_end(r1->addr), r2->addr.start)
        && r1->mr == r2->mr
        && int128_eq(int128_add(int128_make64(r1->offset_in_region),
                                r1->addr.size),
                     int128_make64(r2->offset_in_region))
        && r1->dirty_log_mask == r2->dirty_log_mask
        && r1->readonly == r2->readonly;
}

/* Attempt to simplify a view by merging adjacent ranges */
static void flatview_simplify(FlatView *view)
{
    unsigned i, j;

    i = 0;
    while (i < view->nr) {
        j = i + 1;
        while (j < view->nr
               && can_merge(&view->ranges[j-1], &view->ranges[j])) {
            int128_addto(&view->ranges[i].addr.size, view->ranges[j].addr.size);
            ++j;
        }
        ++i;
        memmove(&view->ranges[i], &view->ranges[j],
                (view->nr - j) * sizeof(view->ranges[j]));
        view->nr -= j - i;
    }
}

static bool memory_region_big_endian(MemoryRegion *mr)
{
#ifdef TARGET_WORDS_BIGENDIAN
    return mr->ops->endianness != DEVICE_LITTLE_ENDIAN;
#else
    return mr->ops->endianness == DEVICE_BIG_ENDIAN;
#endif
}

static bool memory_region_wrong_endianness(MemoryRegion *mr)
{
#ifdef TARGET_WORDS_BIGENDIAN
    return mr->ops->endianness == DEVICE_LITTLE_ENDIAN;
#else
    return mr->ops->endianness == DEVICE_BIG_ENDIAN;
#endif
}

static void adjust_endianness(MemoryRegion *mr, uint64_t *data, unsigned size)
{
    if (memory_region_wrong_endianness(mr)) {
        switch (size) {
        case 1:
            break;
        case 2:
            *data = bswap16(*data);
            break;
        case 4:
            *data = bswap32(*data);
            break;
        case 8:
            *data = bswap64(*data);
            break;
        default:
            abort();
        }
    }
}

static MemTxResult memory_region_oldmmio_read_accessor(MemoryRegion *mr,
                                                       hwaddr addr,
                                                       uint64_t *value,
                                                       unsigned size,
                                                       unsigned shift,
                                                       uint64_t mask,
                                                       MemTxAttrs attrs)
{
    uint64_t tmp;

    tmp = mr->ops->old_mmio.read[ctz32(size)](mr->opaque, addr);
    // UNICORN: Commented out
    //trace_memory_region_ops_read(mr, addr, tmp, size);
    *value |= (tmp & mask) << shift;
    return MEMTX_OK;
}

static MemTxResult  memory_region_read_accessor(MemoryRegion *mr,
                                                hwaddr addr,
                                                uint64_t *value,
                                                unsigned size,
                                                unsigned shift,
                                                uint64_t mask,
                                                MemTxAttrs attrs)
{
    uint64_t tmp;

    // UNICORN: Commented out
    //if (mr->flush_coalesced_mmio) {
    //    qemu_flush_coalesced_mmio_buffer();
    //}
    tmp = mr->ops->read(mr->uc, mr->opaque, addr, size);
    *value |= (tmp & mask) << shift;
    return MEMTX_OK;
}

static MemTxResult memory_region_read_with_attrs_accessor(MemoryRegion *mr,
                                                          hwaddr addr,
                                                          uint64_t *value,
                                                          unsigned size,
                                                          unsigned shift,
                                                          uint64_t mask,
                                                          MemTxAttrs attrs)
{
    uint64_t tmp = 0;
    MemTxResult r;

    // UNICORN: commented out
    //if (mr->flush_coalesced_mmio) {
    //    qemu_flush_coalesced_mmio_buffer();
    //}
    r = mr->ops->read_with_attrs(mr->uc, mr->opaque, addr, &tmp, size, attrs);
    // UNICORN: Commented out
    //trace_memory_region_ops_read(mr, addr, tmp, size);
    *value |= (tmp & mask) << shift;
    return r;
}

static MemTxResult memory_region_oldmmio_write_accessor(MemoryRegion *mr,
                                                        hwaddr addr,
                                                        uint64_t *value,
                                                        unsigned size,
                                                        unsigned shift,
                                                        uint64_t mask,
                                                        MemTxAttrs attrs)
{
    uint64_t tmp;

    tmp = (*value >> shift) & mask;
    mr->ops->old_mmio.write[ctz32(size)](mr->opaque, addr, tmp);
    return MEMTX_OK;
}

static MemTxResult memory_region_write_accessor(MemoryRegion *mr,
                                                hwaddr addr,
                                                uint64_t *value,
                                                unsigned size,
                                                unsigned shift,
                                                uint64_t mask,
                                                MemTxAttrs attrs)
{
    uint64_t tmp;

    tmp = (*value >> shift) & mask;
    mr->ops->write(mr->uc, mr->opaque, addr, tmp, size);
    return MEMTX_OK;
}

static MemTxResult memory_region_write_with_attrs_accessor(MemoryRegion *mr,
                                                           hwaddr addr,
                                                           uint64_t *value,
                                                           unsigned size,
                                                           unsigned shift,
                                                           uint64_t mask,
                                                           MemTxAttrs attrs)
{
    uint64_t tmp;

    // UNICORN: Commented out
    //if (mr->flush_coalesced_mmio) {
    //    qemu_flush_coalesced_mmio_buffer();
    //}
    tmp = (*value >> shift) & mask;
    // UNICORN: Commented out
    //trace_memory_region_ops_write(mr, addr, tmp, size);
    return mr->ops->write_with_attrs(mr->uc, mr->opaque, addr, tmp, size, attrs);
}

static MemTxResult access_with_adjusted_size(hwaddr addr,
                                      uint64_t *value,
                                      unsigned size,
                                      unsigned access_size_min,
                                      unsigned access_size_max,
                                      MemTxResult (*access_fn)
                                                  (MemoryRegion *mr,
                                                   hwaddr addr,
                                                   uint64_t *value,
                                                   unsigned size,
                                                   unsigned shift,
                                                   uint64_t mask,
                                                   MemTxAttrs attrs),
                                      MemoryRegion *mr,
                                      MemTxAttrs attrs)
{
    uint64_t access_mask;
    unsigned access_size;
    unsigned i;
    MemTxResult r = MEMTX_OK;

    if (!access_size_min) {
        access_size_min = 1;
    }
    if (!access_size_max) {
        access_size_max = 4;
    }

    /* FIXME: support unaligned access? */
    access_size = MAX(MIN(size, access_size_max), access_size_min);
    access_mask = (0-1ULL) >> (64 - access_size * 8);
    if (memory_region_big_endian(mr)) {
        for (i = 0; i < size; i += access_size) {
            r |= access_fn(mr, addr + i, value, access_size,
                           (size - access_size - i) * 8, access_mask, attrs);
        }
    } else {
        for (i = 0; i < size; i += access_size) {
            r |= access_fn(mr, addr + i, value, access_size, i * 8,
                           access_mask, attrs);
        }
    }
    return r;
}

static AddressSpace *memory_region_to_address_space(MemoryRegion *mr)
{
    AddressSpace *as;

    while (mr->container) {
        mr = mr->container;
    }
    QTAILQ_FOREACH(as, &mr->uc->address_spaces, address_spaces_link) {
        if (mr == as->root) {
            return as;
        }
    }
    return NULL;
}

/* Render a memory region into the global view.  Ranges in @view obscure
 * ranges in @mr.
 */
static void render_memory_region(FlatView *view,
                                 MemoryRegion *mr,
                                 Int128 base,
                                 AddrRange clip,
                                 bool readonly)
{
    MemoryRegion *subregion;
    unsigned i;
    hwaddr offset_in_region;
    Int128 remain;
    Int128 now;
    FlatRange fr;
    AddrRange tmp;

    if (!mr->enabled) {
        return;
    }

    int128_addto(&base, int128_make64(mr->addr));
    readonly |= mr->readonly;

    tmp = addrrange_make(base, mr->size);

    if (!addrrange_intersects(tmp, clip)) {
        return;
    }

    clip = addrrange_intersection(tmp, clip);

    if (mr->alias) {
        int128_subfrom(&base, int128_make64(mr->alias->addr));
        int128_subfrom(&base, int128_make64(mr->alias_offset));
        render_memory_region(view, mr->alias, base, clip, readonly);
        return;
    }

    /* Render subregions in priority order. */
    QTAILQ_FOREACH(subregion, &mr->subregions, subregions_link) {
        render_memory_region(view, subregion, base, clip, readonly);
    }

    if (!mr->terminates) {
        return;
    }

    offset_in_region = int128_get64(int128_sub(clip.start, base));
    base = clip.start;
    remain = clip.size;

    fr.mr = mr;
    fr.dirty_log_mask = mr->dirty_log_mask;
    fr.readonly = readonly;

    /* Render the region itself into any gaps left by the current view. */
    for (i = 0; i < view->nr && int128_nz(remain); ++i) {
        if (int128_ge(base, addrrange_end(view->ranges[i].addr))) {
            continue;
        }
        if (int128_lt(base, view->ranges[i].addr.start)) {
            now = int128_min(remain,
                             int128_sub(view->ranges[i].addr.start, base));
            fr.offset_in_region = offset_in_region;
            fr.addr = addrrange_make(base, now);
            flatview_insert(view, i, &fr);
            ++i;
            int128_addto(&base, now);
            offset_in_region += int128_get64(now);
            int128_subfrom(&remain, now);
        }
        now = int128_sub(int128_min(int128_add(base, remain),
                                    addrrange_end(view->ranges[i].addr)),
                         base);
        int128_addto(&base, now);
        offset_in_region += int128_get64(now);
        int128_subfrom(&remain, now);
    }
    if (int128_nz(remain)) {
        fr.offset_in_region = offset_in_region;
        fr.addr = addrrange_make(base, remain);
        flatview_insert(view, i, &fr);
    }
}

/* Render a memory topology into a list of disjoint absolute ranges. */
static FlatView *generate_memory_topology(MemoryRegion *mr)
{
    FlatView *view;

    view = flatview_new();

    if (mr) {
        render_memory_region(view, mr, int128_zero(),
                             addrrange_make(int128_zero(), int128_2_64()), false);
    }
    flatview_simplify(view);

    return view;
}

static FlatView *address_space_get_flatview(AddressSpace *as)
{
    FlatView *view;

    view = as->current_map;
    flatview_ref(view);
    return view;
}

static void address_space_update_topology_pass(AddressSpace *as,
                                               const FlatView *old_view,
                                               const FlatView *new_view,
                                               bool adding)
{
    unsigned iold, inew;
    FlatRange *frold, *frnew;

    /* Generate a symmetric difference of the old and new memory maps.
     * Kill ranges in the old map, and instantiate ranges in the new map.
     */
    iold = inew = 0;
    while (iold < old_view->nr || inew < new_view->nr) {
        if (iold < old_view->nr) {
            frold = &old_view->ranges[iold];
        } else {
            frold = NULL;
        }
        if (inew < new_view->nr) {
            frnew = &new_view->ranges[inew];
        } else {
            frnew = NULL;
        }

        if (frold
            && (!frnew
                || int128_lt(frold->addr.start, frnew->addr.start)
                || (int128_eq(frold->addr.start, frnew->addr.start)
                    && !flatrange_equal(frold, frnew)))) {
            /* In old but not in new, or in both but attributes changed. */

            if (!adding) {
                MEMORY_LISTENER_UPDATE_REGION(frold, as, Reverse, region_del);
            }

            ++iold;
        } else if (frold && frnew && flatrange_equal(frold, frnew)) {
            /* In both and unchanged (except logging may have changed) */

            if (adding) {
                MEMORY_LISTENER_UPDATE_REGION(frnew, as, Forward, region_nop);
                if (frnew->dirty_log_mask & ~frold->dirty_log_mask) {
                    MEMORY_LISTENER_UPDATE_REGION(frnew, as, Forward, log_start,
                                                  frold->dirty_log_mask,
                                                  frnew->dirty_log_mask);
                }
                if (frold->dirty_log_mask & ~frnew->dirty_log_mask) {
                    MEMORY_LISTENER_UPDATE_REGION(frnew, as, Reverse, log_stop,
                                                  frold->dirty_log_mask,
                                                  frnew->dirty_log_mask);
                }
            }

            ++iold;
            ++inew;
        } else {
            /* In new */

            if (adding) {
                MEMORY_LISTENER_UPDATE_REGION(frnew, as, Forward, region_add);
            }

            ++inew;
        }
    }
}


static void address_space_update_topology(AddressSpace *as)
{
    FlatView *old_view = address_space_get_flatview(as);
    FlatView *new_view = generate_memory_topology(as->root);
    int i;

    mem_begin(as);
    for (i = 0; i < new_view->nr; i++) {
        MemoryRegionSection mrs =
            section_from_flat_range(&new_view->ranges[i], as);
        mem_add(as, &mrs);
    }
    mem_commit(as);

    if (!QTAILQ_EMPTY(&as->listeners)) {
        address_space_update_topology_pass(as, old_view, new_view, false);
        address_space_update_topology_pass(as, old_view, new_view, true);
    }

    flatview_unref(as->current_map);
    as->current_map = new_view;

    /* Note that all the old MemoryRegions are still alive up to this
     * point.  This relieves most MemoryListeners from the need to
     * ref/unref the MemoryRegions they get---unless they use them
     * outside the iothread mutex, in which case precise reference
     * counting is necessary.
     */
    flatview_unref(old_view);
}

void memory_region_transaction_begin(struct uc_struct *uc)
{
    ++uc->memory_region_transaction_depth;
}

static void memory_region_clear_pending(struct uc_struct *uc)
{
    uc->memory_region_update_pending = false;
}

void memory_region_transaction_commit(struct uc_struct *uc)
{
    AddressSpace *as;

    assert(uc->memory_region_transaction_depth);
    --uc->memory_region_transaction_depth;
    if (!uc->memory_region_transaction_depth) {
        if (uc->memory_region_update_pending) {
            MEMORY_LISTENER_CALL_GLOBAL(begin, Forward);

            QTAILQ_FOREACH(as, &uc->address_spaces, address_spaces_link) {
                address_space_update_topology(as);
            }

            MEMORY_LISTENER_CALL_GLOBAL(commit, Forward);
        }
        memory_region_clear_pending(uc);
   }
}

static void memory_region_destructor_none(MemoryRegion *mr)
{
}

static void memory_region_destructor_ram(MemoryRegion *mr)
{
    qemu_ram_free(mr->uc, memory_region_get_ram_addr(mr));
}

static bool memory_region_need_escape(char c)
{
    return c == '/' || c == '[' || c == '\\' || c == ']';
}

static char *memory_region_escape_name(const char *name)
{
    const char *p;
    char *escaped, *q;
    uint8_t c;
    size_t bytes = 0;

    for (p = name; *p; p++) {
        bytes += memory_region_need_escape(*p) ? 4 : 1;
    }
    if (bytes == p - name) {
       return g_memdup(name, bytes + 1);
    }

    escaped = g_malloc(bytes + 1);
    for (p = name, q = escaped; *p; p++) {
        c = *p;
        if (unlikely(memory_region_need_escape(c))) {
            *q++ = '\\';
            *q++ = 'x';
            *q++ = "0123456789abcdef"[c >> 4];
            c = "0123456789abcdef"[c & 15];
        }
        *q++ = c;
    }
    *q = 0;
    return escaped;
}

void memory_region_init(struct uc_struct *uc, MemoryRegion *mr,
                        Object *owner,
                        const char *name,
                        uint64_t size)
{
    object_initialize(uc, mr, sizeof(*mr), TYPE_MEMORY_REGION);
    mr->uc = uc;
    mr->size = int128_make64(size);
    if (size == UINT64_MAX) {
        mr->size = int128_2_64();
    }
    mr->name = g_strdup(name);
    mr->owner = owner;
    mr->ram_block = NULL;

    if (name) {
        char *escaped_name = memory_region_escape_name(name);
        char *name_array = g_strdup_printf("%s[*]", escaped_name);

        if (!owner) {
            owner = qdev_get_machine(uc);
            uc->owner = owner;
        }

        object_property_add_child(uc, owner, name_array, OBJECT(mr), &error_abort);
        object_unref(uc, OBJECT(mr));
        g_free(name_array);
        g_free(escaped_name);
    }
}

static void memory_region_get_addr(struct uc_struct *uc,
                                   Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);
    uint64_t value = mr->addr;

    visit_type_uint64(v, name, &value, errp);
}

static void memory_region_get_container(struct uc_struct *uc,
                                        Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);
    gchar *path = (gchar *)"";

    if (mr->container) {
        path = object_get_canonical_path(OBJECT(mr->container));
    }
    visit_type_str(v, name, &path, errp);
    if (mr->container) {
        g_free(path);
    }
}

static Object *memory_region_resolve_container(struct uc_struct *uc, Object *obj, void *opaque,
                                               const char *part)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);

    return OBJECT(mr->container);
}

static void memory_region_get_priority(struct uc_struct *uc,
                                       Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);
    int32_t value = mr->priority;

    visit_type_int32(v, name, &value, errp);
}

static void memory_region_get_size(struct uc_struct *uc,
                                   Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);
    uint64_t value = memory_region_size(mr);

    visit_type_uint64(v, name, &value, errp);
}

static void memory_region_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);
    ObjectProperty *op;

    mr->ops = &unassigned_mem_ops;
    mr->enabled = true;
    mr->romd_mode = true;
    mr->global_locking = true;
    mr->destructor = memory_region_destructor_none;
    QTAILQ_INIT(&mr->subregions);

    op = object_property_add(mr->uc, OBJECT(mr), "container",
                             "link<" TYPE_MEMORY_REGION ">",
                             memory_region_get_container,
                             NULL, /* memory_region_set_container */
                             NULL, NULL, &error_abort);
    op->resolve = memory_region_resolve_container;

    object_property_add(mr->uc, OBJECT(mr), "addr", "uint64",
                        memory_region_get_addr,
                        NULL, /* memory_region_set_addr */
                        NULL, NULL, &error_abort);
    object_property_add(mr->uc, OBJECT(mr), "priority", "uint32",
                        memory_region_get_priority,
                        NULL, /* memory_region_set_priority */
                        NULL, NULL, &error_abort);
    object_property_add(mr->uc, OBJECT(mr), "size", "uint64",
                        memory_region_get_size,
                        NULL, /* memory_region_set_size, */
                        NULL, NULL, &error_abort);
}

static uint64_t unassigned_mem_read(struct uc_struct* uc, hwaddr addr, unsigned size)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem read " TARGET_FMT_plx "\n", addr);
#endif
    if (uc->current_cpu != NULL) {
        cpu_unassigned_access(uc->current_cpu, addr, false, false, 0, size);
    }
    return 0;
}

static void unassigned_mem_write(struct uc_struct* uc, hwaddr addr,
                                 uint64_t val, unsigned size)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem write " TARGET_FMT_plx " = 0x%"PRIx64"\n", addr, val);
#endif
    if (uc->current_cpu != NULL) {
        cpu_unassigned_access(uc->current_cpu, addr, true, false, 0, size);
    }
}

static bool unassigned_mem_accepts(void *opaque, hwaddr addr,
                                   unsigned size, bool is_write)
{
    return false;
}

const MemoryRegionOps unassigned_mem_ops = {
    NULL,
    NULL,
    NULL,
    NULL,
    DEVICE_NATIVE_ENDIAN,

    {0,0,false,unassigned_mem_accepts},
};

static uint64_t memory_region_ram_device_read(struct uc_struct *uc,
                                              void *opaque, hwaddr addr,
                                              unsigned size)
{
    MemoryRegion *mr = opaque;
    uint64_t data = (uint64_t)~0;

    switch (size) {
    case 1:
        data = *(uint8_t *)(mr->ram_block->host + addr);
        break;
    case 2:
        data = *(uint16_t *)(mr->ram_block->host + addr);
        break;
    case 4:
        data = *(uint32_t *)(mr->ram_block->host + addr);
        break;
    case 8:
        data = *(uint64_t *)(mr->ram_block->host + addr);
        break;
    }

    // Unicorn: commented out
    //trace_memory_region_ram_device_read(get_cpu_index(), mr, addr, data, size);

    return data;
}

static void memory_region_ram_device_write(struct uc_struct *uc,
                                           void *opaque, hwaddr addr,
                                           uint64_t data, unsigned size)
{
    MemoryRegion *mr = opaque;

    // Unicorn: commented out
    //trace_memory_region_ram_device_write(get_cpu_index(), mr, addr, data, size);

    switch (size) {
    case 1:
        *(uint8_t *)(mr->ram_block->host + addr) = (uint8_t)data;
        break;
    case 2:
        *(uint16_t *)(mr->ram_block->host + addr) = (uint16_t)data;
        break;
    case 4:
        *(uint32_t *)(mr->ram_block->host + addr) = (uint32_t)data;
        break;
    case 8:
        *(uint64_t *)(mr->ram_block->host + addr) = data;
        break;
    }
}

static const MemoryRegionOps ram_device_mem_ops = {
    memory_region_ram_device_read,
    memory_region_ram_device_write,
    NULL,
    NULL,
    DEVICE_HOST_ENDIAN,
    // valid
    {
        1, 8,
        true,
    },
    // impl
    {
        1, 8,
        true,
    },
};

bool memory_region_access_valid(MemoryRegion *mr,
                                hwaddr addr,
                                unsigned size,
                                bool is_write)
{
    int access_size_min, access_size_max;
    int access_size, i;

    if (!mr->ops->valid.unaligned && (addr & (size - 1))) {
        return false;
    }

    if (!mr->ops->valid.accepts) {
        return true;
    }

    access_size_min = mr->ops->valid.min_access_size;
    if (!mr->ops->valid.min_access_size) {
        access_size_min = 1;
    }

    access_size_max = mr->ops->valid.max_access_size;
    if (!mr->ops->valid.max_access_size) {
        access_size_max = 4;
    }

    access_size = MAX(MIN(size, access_size_max), access_size_min);
    for (i = 0; i < size; i += access_size) {
        if (!mr->ops->valid.accepts(mr->opaque, addr + i, access_size,
                                    is_write)) {
            return false;
        }
    }

    return true;
}

static MemTxResult memory_region_dispatch_read1(MemoryRegion *mr,
                                                hwaddr addr,
                                                uint64_t *pval,
                                                unsigned size,
                                                MemTxAttrs attrs)
{
    *pval = 0;

    if (mr->ops->read) {
        return access_with_adjusted_size(addr, pval, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_read_accessor,
                                         mr, attrs);
    } else if (mr->ops->read_with_attrs) {
        return access_with_adjusted_size(addr, pval, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_read_with_attrs_accessor,
                                         mr, attrs);
    } else {
        return access_with_adjusted_size(addr, pval, size, 1, 4,
                                         memory_region_oldmmio_read_accessor,
                                         mr, attrs);
    }
}

MemTxResult memory_region_dispatch_read(MemoryRegion *mr,
                                        hwaddr addr,
                                        uint64_t *pval,
                                        unsigned size,
                                        MemTxAttrs attrs)
{
    MemTxResult r;

    if (!memory_region_access_valid(mr, addr, size, false)) {
        *pval = unassigned_mem_read(mr->uc, addr, size);
        return MEMTX_DECODE_ERROR;
    }

    r = memory_region_dispatch_read1(mr, addr, pval, size, attrs);
    adjust_endianness(mr, pval, size);
    return r;
}

MemTxResult memory_region_dispatch_write(MemoryRegion *mr,
                                         hwaddr addr,
                                         uint64_t data,
                                         unsigned size,
                                         MemTxAttrs attrs)
{
    if (!memory_region_access_valid(mr, addr, size, true)) {
        unassigned_mem_write(mr->uc, addr, data, size);
        return MEMTX_DECODE_ERROR;
    }

    adjust_endianness(mr, &data, size);

    if (mr->ops->write) {
        return access_with_adjusted_size(addr, &data, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_write_accessor, mr,
                                         attrs);
    } else if (mr->ops->write_with_attrs) {
        return
            access_with_adjusted_size(addr, &data, size,
                                      mr->ops->impl.min_access_size,
                                      mr->ops->impl.max_access_size,
                                      memory_region_write_with_attrs_accessor,
                                      mr, attrs);
    } else {
        return access_with_adjusted_size(addr, &data, size, 1, 4,
                                         memory_region_oldmmio_write_accessor,
                                         mr, attrs);
    }
}

void memory_region_init_io(struct uc_struct *uc, MemoryRegion *mr,
                           Object *owner,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           const char *name,
                           uint64_t size)
{
    memory_region_init(uc, mr, owner, name, size);
    mr->ops = ops ? ops : &unassigned_mem_ops;
    mr->opaque = opaque;
    mr->terminates = true;
}

void memory_region_init_ram_nomigrate(struct uc_struct *uc,
                                      MemoryRegion *mr,
                                      Object *owner,
                                      const char *name,
                                      uint64_t size,
                                      uint32_t perms,
                                      Error **errp)
{
    memory_region_init(uc, mr, owner, name, size);
    mr->ram = true;
    if (!(perms & UC_PROT_WRITE)) {
        mr->readonly = true;
    }
    mr->perms = perms;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;
    mr->ram_block = qemu_ram_alloc(size, mr, errp);
    mr->dirty_log_mask = tcg_enabled(uc) ? (1 << DIRTY_MEMORY_CODE) : 0;
}

void memory_region_init_ram_ptr(struct uc_struct *uc, MemoryRegion *mr,
                                Object *owner,
                                const char *name,
                                uint64_t size,
                                void *ptr)
{
    memory_region_init(uc, mr, owner, name, size);
    mr->ram = true;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;
    mr->dirty_log_mask = tcg_enabled(uc) ? (1 << DIRTY_MEMORY_CODE) : 0;

    /* qemu_ram_alloc_from_ptr cannot fail with ptr != NULL.  */
    assert(ptr != NULL);
    mr->ram_block = qemu_ram_alloc_from_ptr(size, ptr, mr, &error_fatal);
}

void memory_region_init_resizeable_ram(struct uc_struct *uc,
                                       MemoryRegion *mr,
                                       Object *owner,
                                       const char *name,
                                       uint64_t size,
                                       uint64_t max_size,
                                       void (*resized)(const char*,
                                                       uint64_t length,
                                                       void *host),
                                       Error **errp)
{
    memory_region_init(uc, mr, owner, name, size);
    mr->ram = true;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;
    mr->ram_block = qemu_ram_alloc_resizeable(size, max_size, resized,
                                              mr, errp);
    mr->dirty_log_mask = tcg_enabled(uc) ? (1 << DIRTY_MEMORY_CODE) : 0;
}

void memory_region_init_rom_nomigrate(struct uc_struct *uc,
                                      MemoryRegion *mr,
                                      struct Object *owner,
                                      const char *name,
                                      uint64_t size,
                                      Error **errp)
{
    memory_region_init(uc, mr, owner, name, size);
    mr->ram = true;
    mr->readonly = true;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;
    mr->ram_block = qemu_ram_alloc(size, mr, errp);
    mr->dirty_log_mask = tcg_enabled(uc) ? (1 << DIRTY_MEMORY_CODE) : 0;
}

void memory_region_init_ram_device_ptr(struct uc_struct *uc,
                                       MemoryRegion *mr,
                                       Object *owner,
                                       const char *name,
                                       uint64_t size,
                                       void *ptr)
{
    memory_region_init_ram_ptr(uc, mr, owner, name, size, ptr);
    mr->ram_device = true;
    mr->ops = &ram_device_mem_ops;
    mr->opaque = mr;
}

void memory_region_init_alias(struct uc_struct *uc, MemoryRegion *mr,
                              Object *owner,
                              const char *name,
                              MemoryRegion *orig,
                              hwaddr offset,
                              uint64_t size)
{
    memory_region_init(uc, mr, owner, name, size);
    mr->alias = orig;
    mr->alias_offset = offset;
}

static void memory_region_finalize(struct uc_struct *uc, Object *obj, void *opaque)
{
    MemoryRegion *mr = MEMORY_REGION(uc, obj);

    assert(!mr->container);

    /* We know the region is not visible in any address space (it
     * does not have a container and cannot be a root either because
     * it has no references, so we can blindly clear mr->enabled.
     * memory_region_set_enabled instead could trigger a transaction
     * and cause an infinite loop.
     */
    mr->enabled = false;
    memory_region_transaction_begin(uc);
    while (!QTAILQ_EMPTY(&mr->subregions)) {
        MemoryRegion *subregion = QTAILQ_FIRST(&mr->subregions);
        memory_region_del_subregion(mr, subregion);
    }
    memory_region_transaction_commit(uc);

    mr->destructor(mr);
    g_free((char *)mr->name);
}

void memory_region_ref(MemoryRegion *mr)
{
    /* MMIO callbacks most likely will access data that belongs
     * to the owner, hence the need to ref/unref the owner whenever
     * the memory region is in use.
     *
     * The memory region is a child of its owner.  As long as the
     * owner doesn't call unparent itself on the memory region,
     * ref-ing the owner will also keep the memory region alive.
     * Memory regions without an owner are supposed to never go away;
     * we do not ref/unref them because it slows down DMA sensibly.
     */
    if (mr && mr->owner) {
        object_ref(mr->owner);
    }
}

void memory_region_unref(MemoryRegion *mr)
{
    if (mr && mr->owner) {
        object_unref(mr->uc, mr->owner);
    }
}

uint64_t memory_region_size(MemoryRegion *mr)
{
    if (int128_eq(mr->size, int128_2_64())) {
        return UINT64_MAX;
    }
    return int128_get64(mr->size);
}

const char *memory_region_name(const MemoryRegion *mr)
{
    if (!mr->name) {
        ((MemoryRegion *)mr)->name =
            object_get_canonical_path_component(OBJECT(mr));
    }
    return mr->name;
}

bool memory_region_is_ram_device(MemoryRegion *mr)
{
    return mr->ram_device;
}

uint8_t memory_region_get_dirty_log_mask(MemoryRegion *mr)
{
    return mr->dirty_log_mask;
}

bool memory_region_is_logging(MemoryRegion *mr, uint8_t client)
{
    return memory_region_get_dirty_log_mask(mr) & (1 << client);
}

void memory_region_set_readonly(MemoryRegion *mr, bool readonly)
{
    if (mr->readonly != readonly) {
        memory_region_transaction_begin(mr->uc);
        mr->readonly = readonly;
        if (readonly) {
            mr->perms &= ~UC_PROT_WRITE;
        }
        else {
            mr->perms |= UC_PROT_WRITE;
        }
        mr->uc->memory_region_update_pending |= mr->enabled;
        memory_region_transaction_commit(mr->uc);
    }
}

void memory_region_clear_global_locking(MemoryRegion *mr)
{
    mr->global_locking = false;
}

void memory_region_rom_device_set_romd(MemoryRegion *mr, bool romd_mode)
{
    if (mr->romd_mode != romd_mode) {
        memory_region_transaction_begin(mr->uc);
        mr->romd_mode = romd_mode;
        mr->uc->memory_region_update_pending |= mr->enabled;
        memory_region_transaction_commit(mr->uc);
    }
}

int memory_region_get_fd(MemoryRegion *mr)
{
    int fd;

    // Unicorn: commented out
    //rcu_read_lock();
    while (mr->alias) {
        mr = mr->alias;
    }
    fd = mr->ram_block->fd;
    //rcu_read_unlock();

    return fd;
}

void *memory_region_get_ram_ptr(MemoryRegion *mr)
{
    void *ptr;
    uint64_t offset = 0;

    // Unicorn: commented out
    // rcu_read_lock();
    while (mr->alias) {
        offset += mr->alias_offset;
        mr = mr->alias;
    }

    assert(mr->ram_block);
    ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, offset);
    // Unicorn: commented out
    //rcu_read_unlock();

    return ptr;
}

MemoryRegion *memory_region_from_host(struct uc_struct *uc, void *ptr, ram_addr_t *offset)
{
    RAMBlock *block;

    block = qemu_ram_block_from_host(uc, ptr, false, offset);
    if (!block) {
        return NULL;
    }

    return block->mr;
}

ram_addr_t memory_region_get_ram_addr(MemoryRegion *mr)
{
    return mr->ram_block ? mr->ram_block->offset : RAM_ADDR_INVALID;
}

static void memory_region_update_container_subregions(MemoryRegion *subregion)
{
    MemoryRegion *mr = subregion->container;
    MemoryRegion *other;

    memory_region_transaction_begin(mr->uc);

    memory_region_ref(subregion);
    QTAILQ_FOREACH(other, &mr->subregions, subregions_link) {
        if (subregion->priority >= other->priority) {
            QTAILQ_INSERT_BEFORE(other, subregion, subregions_link);
            goto done;
        }
    }
    QTAILQ_INSERT_TAIL(&mr->subregions, subregion, subregions_link);
done:
    mr->uc->memory_region_update_pending |= mr->enabled && subregion->enabled;
    memory_region_transaction_commit(mr->uc);
}

static void memory_region_add_subregion_common(MemoryRegion *mr,
                                               hwaddr offset,
                                               MemoryRegion *subregion)
{
    assert(!subregion->container);
    subregion->container = mr;
    subregion->addr = offset;
    subregion->end = offset + int128_get64(subregion->size);
    memory_region_update_container_subregions(subregion);
}

void memory_region_add_subregion(MemoryRegion *mr,
                                 hwaddr offset,
                                 MemoryRegion *subregion)
{
    subregion->priority = 0;
    memory_region_add_subregion_common(mr, offset, subregion);
}

void memory_region_add_subregion_overlap(MemoryRegion *mr,
                                         hwaddr offset,
                                         MemoryRegion *subregion,
                                         int priority)
{
    subregion->priority = priority;
    memory_region_add_subregion_common(mr, offset, subregion);
}

void memory_region_del_subregion(MemoryRegion *mr,
                                 MemoryRegion *subregion)
{
    memory_region_transaction_begin(mr->uc);
    assert(subregion->container == mr);
    subregion->container = NULL;
    QTAILQ_REMOVE(&mr->subregions, subregion, subregions_link);
    memory_region_unref(subregion);
    mr->uc->memory_region_update_pending |= mr->enabled && subregion->enabled;
    memory_region_transaction_commit(mr->uc);
}

void memory_region_set_enabled(MemoryRegion *mr, bool enabled)
{
    if (enabled == mr->enabled) {
        return;
    }
    memory_region_transaction_begin(mr->uc);
    mr->enabled = enabled;
    mr->uc->memory_region_update_pending = true;
    memory_region_transaction_commit(mr->uc);
}

void memory_region_set_size(MemoryRegion *mr, uint64_t size)
{
    Int128 s = int128_make64(size);

    if (size == UINT64_MAX) {
        s = int128_2_64();
    }
    if (int128_eq(s, mr->size)) {
        return;
    }
    memory_region_transaction_begin(mr->uc);
    mr->size = s;
    mr->uc->memory_region_update_pending = true;
    memory_region_transaction_commit(mr->uc);
}

static void memory_region_readd_subregion(MemoryRegion *mr)
{
    MemoryRegion *container = mr->container;

    if (container) {
        memory_region_transaction_begin(mr->uc);
        memory_region_ref(mr);
        memory_region_del_subregion(container, mr);
        mr->container = container;
        memory_region_update_container_subregions(mr);
        memory_region_unref(mr);
        memory_region_transaction_commit(mr->uc);
    }
}

void memory_region_set_address(MemoryRegion *mr, hwaddr addr)
{
    if (addr != mr->addr) {
        mr->addr = addr;
        memory_region_readd_subregion(mr);
    }
}

void memory_region_set_alias_offset(MemoryRegion *mr, hwaddr offset)
{
    assert(mr->alias);

    if (offset == mr->alias_offset) {
        return;
    }

    memory_region_transaction_begin(mr->uc);
    mr->alias_offset = offset;
    mr->uc->memory_region_update_pending |= mr->enabled;
    memory_region_transaction_commit(mr->uc);
}

uint64_t memory_region_get_alignment(const MemoryRegion *mr)
{
    return mr->align;
}

static int cmp_flatrange_addr(const void *addr_, const void *fr_)
{
    const AddrRange *addr = addr_;
    const FlatRange *fr = fr_;

    if (int128_le(addrrange_end(*addr), fr->addr.start)) {
        return -1;
    } else if (int128_ge(addr->start, addrrange_end(fr->addr))) {
        return 1;
    }
    return 0;
}

static FlatRange *flatview_lookup(FlatView *view, AddrRange addr)
{
    return bsearch(&addr, view->ranges, view->nr,
                   sizeof(FlatRange), cmp_flatrange_addr);
}

bool memory_region_is_mapped(MemoryRegion *mr)
{
    return mr->container ? true : false;
}

/* Same as memory_region_find, but it does not add a reference to the
 * returned region.  It must be called from an RCU critical section.
 */
static MemoryRegionSection memory_region_find_rcu(MemoryRegion *mr,
                                                  hwaddr addr, uint64_t size)
{
    MemoryRegionSection ret = { NULL };
    MemoryRegion *root;
    AddressSpace *as;
    AddrRange range;
    FlatView *view;
    FlatRange *fr;

    addr += mr->addr;
    for (root = mr; root->container; ) {
        root = root->container;
        addr += root->addr;
    }

    as = memory_region_to_address_space(root);
    if (!as) {
        return ret;
    }
    range = addrrange_make(int128_make64(addr), int128_make64(size));

    // Unicorn: Uses atomic_read instead of atomic_rcu_read
    view = atomic_read(&as->current_map);
    fr = flatview_lookup(view, range);
    if (!fr) {
        return ret;
    }

    while (fr > view->ranges && addrrange_intersects(fr[-1].addr, range)) {
        --fr;
    }

    ret.mr = fr->mr;
    ret.address_space = as;
    range = addrrange_intersection(range, fr->addr);
    ret.offset_within_region = fr->offset_in_region;
    ret.offset_within_region += int128_get64(int128_sub(range.start,
                                                        fr->addr.start));
    ret.size = range.size;
    ret.offset_within_address_space = int128_get64(range.start);
    ret.readonly = fr->readonly;
    return ret;
}

MemoryRegionSection memory_region_find(MemoryRegion *mr,
                                       hwaddr addr, uint64_t size)
{
    MemoryRegionSection ret;
    // Unicorn: commented out
    //rcu_read_lock();
    ret = memory_region_find_rcu(mr, addr, size);
    if (ret.mr) {
        memory_region_ref(ret.mr);
    }
    // Unicorn: commented out
    //rcu_read_unlock();
    return ret;
}

bool memory_region_present(MemoryRegion *container, hwaddr addr)
{
    MemoryRegion *mr;

    // Unicorn: commented out
    //rcu_read_lock();
    mr = memory_region_find_rcu(container, addr, 1).mr;
    // Unicorn: commented out
    //rcu_read_unlock();
    return mr && mr != container;
}

static QEMU_UNUSED_FUNC void listener_add_address_space(MemoryListener *listener,
                                                        AddressSpace *as)
{
    FlatView *view;
    FlatRange *fr;

    if (listener->begin) {
        listener->begin(listener);
    }
    if (as->uc->global_dirty_log) {
        if (listener->log_global_start) {
            listener->log_global_start(listener);
        }
    }

    view = address_space_get_flatview(as);
    FOR_EACH_FLAT_RANGE(fr, view) {
        MemoryRegionSection section = MemoryRegionSection_make(
            fr->mr,
            as,
            fr->offset_in_region,
            fr->addr.size,
            int128_get64(fr->addr.start),
            fr->readonly);
        if (fr->dirty_log_mask && listener->log_start) {
            listener->log_start(listener, &section, 0, fr->dirty_log_mask);
        }
        if (listener->region_add) {
            listener->region_add(listener, &section);
        }
    }
    flatview_unref(view);
}

void memory_listener_register(struct uc_struct* uc, MemoryListener *listener, AddressSpace *as)
{
    MemoryListener *other = NULL;

    listener->address_space = as;
    if (QTAILQ_EMPTY(&uc->memory_listeners)
        || listener->priority >= QTAILQ_LAST(&uc->memory_listeners,
                                             memory_listeners)->priority) {
        QTAILQ_INSERT_TAIL(&uc->memory_listeners, listener, link);
    } else {
        QTAILQ_FOREACH(other, &uc->memory_listeners, link) {
            if (listener->priority < other->priority) {
                break;
            }
        }
        QTAILQ_INSERT_BEFORE(other, listener, link);
    }

    if (QTAILQ_EMPTY(&as->listeners)
        || listener->priority >= QTAILQ_LAST(&as->listeners,
                                             memory_listeners)->priority) {
        QTAILQ_INSERT_TAIL(&as->listeners, listener, link_as);
    } else {
        QTAILQ_FOREACH(other, &as->listeners, link_as) {
            if (listener->priority < other->priority) {
                break;
            }
        }
        QTAILQ_INSERT_BEFORE(other, listener, link_as);
    }

    // Unicorn: TODO: Handle leaks that occur when this is uncommented
    //listener_add_address_space(listener, as);
}

void memory_listener_unregister(struct uc_struct *uc, MemoryListener *listener)
{
    QTAILQ_REMOVE(&uc->memory_listeners, listener, link);
    QTAILQ_REMOVE(&listener->address_space->listeners, listener, link_as);
}

void address_space_init(struct uc_struct *uc, AddressSpace *as, MemoryRegion *root, const char *name)
{
    if (QTAILQ_EMPTY(&uc->address_spaces)) {
        memory_init(uc);
    }

    memory_region_transaction_begin(uc);
    as->ref_count = 1;
    as->uc = uc;
    as->root = root;
    as->malloced = false;
    as->current_map = flatview_new();
    QTAILQ_INIT(&as->listeners);
    QTAILQ_INSERT_TAIL(&uc->address_spaces, as, address_spaces_link);
    as->name = g_strdup(name ? name : "anonymous");
    as->dispatch = NULL;
    uc->memory_region_update_pending |= root->enabled;
    memory_region_transaction_commit(uc);
}

static void do_address_space_destroy(AddressSpace *as)
{
    // Unicorn: commented out
    bool do_free = as->malloced;

    address_space_destroy_dispatch(as);

    // TODO(danghvu): why assert fail here?
    //QTAILQ_FOREACH(listener, &as->uc->memory_listeners, link) {
    //    assert(QTAILQ_EMPTY(&as->listeners));
    //}

    flatview_unref(as->current_map);
    g_free(as->name);
    // Unicorn: commented out
    //g_free(as->ioeventfds);
    memory_region_unref(as->root);
    if (do_free) {
        g_free(as);
    }
}

AddressSpace *address_space_init_shareable(struct uc_struct *uc, MemoryRegion *root, const char *name)
{
    AddressSpace *as;

    QTAILQ_FOREACH(as, &uc->address_spaces, address_spaces_link) {
        if (root == as->root && as->malloced) {
            as->ref_count++;
            return as;
        }
    }

    as = g_malloc0(sizeof *as);
    address_space_init(uc, as, root, name);
    as->malloced = true;
    return as;
}

void address_space_destroy(AddressSpace *as)
{
    MemoryRegion *root = as->root;

    as->ref_count--;
    if (as->ref_count) {
        return;
    }

    /* Flush out anything from MemoryListeners listening in on this */
    memory_region_transaction_begin(as->uc);
    as->root = NULL;
    memory_region_transaction_commit(as->uc);
    QTAILQ_REMOVE(&as->uc->address_spaces, as, address_spaces_link);

    /* At this point, as->dispatch and as->current_map are dummy
     * entries that the guest should never use.  Wait for the old
     * values to expire before freeing the data.
     */
    as->root = root;
    do_address_space_destroy(as);

    // Unicorn: Commented out and call it directly
    // call_rcu(as, do_address_space_destroy, rcu);
}

typedef struct MemoryRegionList MemoryRegionList;

struct MemoryRegionList {
    const MemoryRegion *mr;
    QTAILQ_ENTRY(MemoryRegionList) queue;
};

typedef QTAILQ_HEAD(queue, MemoryRegionList) MemoryRegionListHead;

static const TypeInfo memory_region_info = {
    TYPE_MEMORY_REGION,
    TYPE_OBJECT,

    0,
    sizeof(MemoryRegion),
    NULL,

    memory_region_initfn,
    NULL,
    memory_region_finalize,
};

void memory_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &memory_region_info);
}

