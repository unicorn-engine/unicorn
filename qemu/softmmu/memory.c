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

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/memory.h"
#include "qemu/bitops.h"

#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "sysemu/tcg.h"
#include "exec/exec-all.h"
#include "uc_priv.h"

//#define DEBUG_UNASSIGNED

typedef struct AddrRange AddrRange;

/*
 * Note that signed integers are needed for negative offsetting in aliases
 * (large MemoryRegion::alias_offset).
 */
struct AddrRange {
    Int128 start;
    Int128 size;
};

// Unicorn engine
MemoryRegion *memory_map(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms)
{
    MemoryRegion *ram = g_new(MemoryRegion, 1);

    memory_region_init_ram(uc, ram, size, perms);
    if (ram->addr == -1) {
        // out of memory
        return NULL;
    }

    memory_region_add_subregion(uc->system_memory, begin, ram);

    if (uc->cpu) {
        tlb_flush(uc->cpu);
    }

    return ram;
}

MemoryRegion *memory_map_ptr(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms, void *ptr)
{
    MemoryRegion *ram = g_new(MemoryRegion, 1);

    memory_region_init_ram_ptr(uc, ram, size, ptr);
    ram->perms = perms;
    if (ram->addr == -1) {
        // out of memory
        return NULL;
    }

    memory_region_add_subregion(uc->system_memory, begin, ram);

    if (uc->cpu) {
        tlb_flush(uc->cpu);
    }

    return ram;
}

typedef struct _mmio_cbs {
    uc_cb_mmio_read_t read;
    void *user_data_read;
    uc_cb_mmio_write_t write;
    void *user_data_write;
} mmio_cbs;

static uint64_t mmio_read_wrapper(struct uc_struct *uc, void *opaque, hwaddr addr, unsigned size)
{
    mmio_cbs* cbs = (mmio_cbs*)opaque;
    
    if (cbs->read) {
        return cbs->read(uc, addr, size, cbs->user_data_read);
    } else {
        return 0;
    }
}

static void mmio_write_wrapper(struct uc_struct *uc, void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    mmio_cbs* cbs = (mmio_cbs*)opaque;
    
    if (cbs->write) {
        cbs->write(uc, addr, size, data, cbs->user_data_write);
    }
}

static void mmio_region_destructor_uc(MemoryRegion *mr)
{
    g_free(mr->opaque);
}

MemoryRegion *memory_map_io(struct uc_struct *uc, ram_addr_t begin, size_t size,
                            uc_cb_mmio_read_t read_cb, uc_cb_mmio_write_t write_cb,
                            void *user_data_read, void *user_data_write)
{
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegionOps *ops = g_new(MemoryRegionOps, 1);
    mmio_cbs* opaques = g_new(mmio_cbs, 1);
    opaques->read = read_cb;
    opaques->write = write_cb;
    opaques->user_data_read = user_data_read;
    opaques->user_data_write = user_data_write;

    memset(ops, 0, sizeof(*ops));

    ops->read = mmio_read_wrapper;
    ops->write = mmio_write_wrapper;
    ops->endianness = DEVICE_NATIVE_ENDIAN;

    memory_region_init_io(uc, mmio, ops, opaques, size);

    mmio->destructor = mmio_region_destructor_uc;

    mmio->perms = 0;

    if (read_cb)
        mmio->perms |= UC_PROT_READ;

    if (write_cb)
        mmio->perms |= UC_PROT_WRITE;

    memory_region_add_subregion(uc->system_memory, begin, mmio);

    if (uc->cpu)
        tlb_flush(uc->cpu);

    return mmio;
}

void memory_unmap(struct uc_struct *uc, MemoryRegion *mr)
{
    int i;
    hwaddr addr;

    // Make sure all pages associated with the MemoryRegion are flushed
    // Only need to do this if we are in a running state
    if (uc->cpu) {
        for (addr = mr->addr; addr < mr->end; addr += uc->target_page_size) {
           tlb_flush_page(uc->cpu, addr);
        }
    }
    memory_region_del_subregion(uc->system_memory, mr);

    for (i = 0; i < uc->mapped_block_count; i++) {
        if (uc->mapped_blocks[i] == mr) {
            uc->mapped_block_count--;
            //shift remainder of array down over deleted pointer
            memmove(&uc->mapped_blocks[i], &uc->mapped_blocks[i + 1], sizeof(MemoryRegion*) * (uc->mapped_block_count - i));
            mr->destructor(mr);
            g_free(mr);
            break;
        }
    }
}

int memory_free(struct uc_struct *uc)
{
    MemoryRegion *mr;
    int i;

    for (i = 0; i < uc->mapped_block_count; i++) {
        mr = uc->mapped_blocks[i];
        mr->enabled = false;
        memory_region_del_subregion(uc->system_memory, mr);
        mr->destructor(mr);
        /* destroy subregion */
        g_free(mr);
    }

    return 0;
}

static AddrRange addrrange_make(Int128 start, Int128 size)
{
    return (AddrRange) { start, size };
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

#define MEMORY_LISTENER_CALL_GLOBAL(uc, _callback, _direction)    \
    do {                                                                \
        MemoryListener *_listener;                                      \
                                                                        \
        switch (_direction) {                                           \
        case Forward:                                                   \
            QTAILQ_FOREACH(_listener, &uc->memory_listeners, link) {        \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener);           \
                }                                                       \
            }                                                           \
            break;                                                      \
        case Reverse:                                                   \
            QTAILQ_FOREACH_REVERSE(_listener, &uc->memory_listeners, link) { \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener);           \
                }                                                       \
            }                                                           \
            break;                                                      \
        default:                                                        \
            abort();                                                    \
        }                                                               \
    } while (0)

#define MEMORY_LISTENER_CALL(_as, _callback, _direction, _section) \
    do {                                                                \
        MemoryListener *_listener;                                      \
                                                                        \
        switch (_direction) {                                           \
        case Forward:                                                   \
            QTAILQ_FOREACH(_listener, &(_as)->listeners, link_as) {     \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener, _section); \
                }                                                       \
            }                                                           \
            break;                                                      \
        case Reverse:                                                   \
            QTAILQ_FOREACH_REVERSE(_listener, &(_as)->listeners, link_as) { \
                if (_listener->_callback) {                             \
                    _listener->_callback(_listener, _section); \
                }                                                       \
            }                                                           \
            break;                                                      \
        default:                                                        \
            abort();                                                    \
        }                                                               \
    } while (0)

/* No need to ref/unref .mr, the FlatRange keeps it alive.  */
#define MEMORY_LISTENER_UPDATE_REGION(fr, as, dir, callback)  \
    do {                                                                \
        MemoryRegionSection mrs = section_from_flat_range(fr,           \
                address_space_to_flatview(as));                         \
        MEMORY_LISTENER_CALL(as, callback, dir, &mrs);         \
    } while(0)

/* Range of memory in the global map.  Addresses are absolute. */
struct FlatRange {
    MemoryRegion *mr;
    hwaddr offset_in_region;
    AddrRange addr;
    bool readonly;
};

#define FOR_EACH_FLAT_RANGE(var, view)          \
    for (var = (view)->ranges; var < (view)->ranges + (view)->nr; ++var)

static inline MemoryRegionSection
section_from_flat_range(FlatRange *fr, FlatView *fv)
{
    return (MemoryRegionSection) {
        .mr = fr->mr,
        .fv = fv,
        .offset_within_region = fr->offset_in_region,
        .size = fr->addr.size,
        .offset_within_address_space = int128_get64(fr->addr.start),
        .readonly = fr->readonly,
    };
}

static bool flatrange_equal(FlatRange *a, FlatRange *b)
{
    return a->mr == b->mr
        && addrrange_equal(a->addr, b->addr)
        && a->offset_in_region == b->offset_in_region
        && a->readonly == b->readonly;
}

static FlatView *flatview_new(MemoryRegion *mr_root)
{
    FlatView *view;

    view = g_new0(FlatView, 1);
    view->ref = 1;
    view->root = mr_root;

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
    ++view->nr;
}

static inline void flatview_ref(FlatView *view)
{
    view->ref++;
}

static void flatview_destroy(FlatView *view)
{
    if (view->dispatch) {
        address_space_dispatch_free(view->dispatch);
    }
    g_free(view->ranges);
    g_free(view);
}

void flatview_unref(FlatView *view)
{
    view->ref--;
    if (view->ref <= 0) {
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

static void adjust_endianness(MemoryRegion *mr, uint64_t *data, MemOp op)
{
    if ((op & MO_BSWAP) != devend_memop(mr->ops->endianness)) {
        switch (op & MO_SIZE) {
        case MO_8:
            break;
        case MO_16:
            *data = bswap16(*data);
            break;
        case MO_32:
            *data = bswap32(*data);
            break;
        case MO_64:
            *data = bswap64(*data);
            break;
        default:
            g_assert_not_reached();
        }
    }
}

static inline void memory_region_shift_read_access(uint64_t *value,
                                                   signed shift,
                                                   uint64_t mask,
                                                   uint64_t tmp)
{
    if (shift >= 0) {
        *value |= (tmp & mask) << shift;
    } else {
        *value |= (tmp & mask) >> -shift;
    }
}

static inline uint64_t memory_region_shift_write_access(uint64_t *value,
                                                        signed shift,
                                                        uint64_t mask)
{
    uint64_t tmp;

    if (shift >= 0) {
        tmp = (*value >> shift) & mask;
    } else {
        tmp = (*value << -shift) & mask;
    }

    return tmp;
}

static MemTxResult  memory_region_read_accessor(struct uc_struct *uc, MemoryRegion *mr,
                                                hwaddr addr,
                                                uint64_t *value,
                                                unsigned size,
                                                signed shift,
                                                uint64_t mask,
                                                MemTxAttrs attrs)
{
    uint64_t tmp;

    tmp = mr->ops->read(uc, mr->opaque, addr, size);
    memory_region_shift_read_access(value, shift, mask, tmp);
    return MEMTX_OK;
}

static MemTxResult memory_region_read_with_attrs_accessor(struct uc_struct *uc, MemoryRegion *mr,
                                                          hwaddr addr,
                                                          uint64_t *value,
                                                          unsigned size,
                                                          signed shift,
                                                          uint64_t mask,
                                                          MemTxAttrs attrs)
{
    uint64_t tmp = 0;
    MemTxResult r;

    r = mr->ops->read_with_attrs(uc, mr->opaque, addr, &tmp, size, attrs);
    memory_region_shift_read_access(value, shift, mask, tmp);
    return r;
}

static MemTxResult memory_region_write_accessor(struct uc_struct *uc, MemoryRegion *mr,
                                                hwaddr addr,
                                                uint64_t *value,
                                                unsigned size,
                                                signed shift,
                                                uint64_t mask,
                                                MemTxAttrs attrs)
{
    uint64_t tmp = memory_region_shift_write_access(value, shift, mask);

    mr->ops->write(uc, mr->opaque, addr, tmp, size);
    return MEMTX_OK;
}

static MemTxResult memory_region_write_with_attrs_accessor(struct uc_struct *uc, MemoryRegion *mr,
                                                           hwaddr addr,
                                                           uint64_t *value,
                                                           unsigned size,
                                                           signed shift,
                                                           uint64_t mask,
                                                           MemTxAttrs attrs)
{
    uint64_t tmp = memory_region_shift_write_access(value, shift, mask);

    return mr->ops->write_with_attrs(uc, mr->opaque, addr, tmp, size, attrs);
}

static MemTxResult access_with_adjusted_size(struct uc_struct *uc, hwaddr addr,
                                      uint64_t *value,
                                      unsigned size,
                                      unsigned access_size_min,
                                      unsigned access_size_max,
                                      MemTxResult (*access_fn)
                                                  (struct uc_struct *uc,
                                                   MemoryRegion *mr,
                                                   hwaddr addr,
                                                   uint64_t *value,
                                                   unsigned size,
                                                   signed shift,
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
    access_mask = MAKE_64BIT_MASK(0, access_size * 8);
    if (memory_region_big_endian(mr)) {
        for (i = 0; i < size; i += access_size) {
            r |= access_fn(uc, mr, addr + i, value, access_size,
                        (size - access_size - i) * 8, access_mask, attrs);
        }
    } else {
        for (i = 0; i < size; i += access_size) {
            r |= access_fn(uc, mr, addr + i, value, access_size, i * 8,
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

static MemoryRegion *memory_region_get_flatview_root(MemoryRegion *mr)
{
    while (mr->enabled) {
        if (!mr->terminates) {
            unsigned int found = 0;
            MemoryRegion *child, *next = NULL;
            QTAILQ_FOREACH(child, &mr->subregions, subregions_link) {
                if (child->enabled) {
                    if (++found > 1) {
                        next = NULL;
                        break;
                    }
                    if (!child->addr && int128_ge(mr->size, child->size)) {
                        /* A child is included in its entirety.  If it's the only
                         * enabled one, use it in the hope of finding an alias down the
                         * way. This will also let us share FlatViews.
                         */
                        next = child;
                    }
                }
            }
            if (found == 0) {
                return NULL;
            }
            if (next) {
                mr = next;
                continue;
            }
        }

        return mr;
    }

    return NULL;
}

/* Render a memory topology into a list of disjoint absolute ranges. */
static FlatView *generate_memory_topology(struct uc_struct *uc, MemoryRegion *mr)
{
    int i;
    FlatView *view;
    FlatView *old_view;

    view = flatview_new(mr);

    if (mr) {
        render_memory_region(view, mr, int128_zero(),
                             addrrange_make(int128_zero(), int128_2_64()),
                             false);
    }
    flatview_simplify(view);

    view->dispatch = address_space_dispatch_new(uc, view);
    for (i = 0; i < view->nr; i++) {
        MemoryRegionSection mrs =
            section_from_flat_range(&view->ranges[i], view);
        flatview_add_to_dispatch(uc, view, &mrs);
    }
    address_space_dispatch_compact(view->dispatch);

    old_view = g_hash_table_lookup(uc->flat_views, mr);
    if (old_view != view) {
        g_hash_table_replace(uc->flat_views, mr, view);
        if (old_view) {
            flatview_unref(old_view);
        }
    }

    return view;
}

FlatView *address_space_get_flatview(AddressSpace *as)
{
    FlatView *view;

    view = address_space_to_flatview(as);

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

static void flatviews_init(struct uc_struct *uc)
{
    static FlatView *empty_view;

    if (uc->flat_views) {
        return;
    }

    uc->flat_views = g_hash_table_new_full(NULL, NULL, NULL,
                                       (GDestroyNotify) flatview_unref);

    if (!empty_view) {
        empty_view = generate_memory_topology(uc, NULL);
        /* We keep it alive forever in the global variable.  */
        flatview_ref(empty_view);
    } else {
        g_hash_table_replace(uc->flat_views, NULL, empty_view);
        flatview_ref(empty_view);
    }
}

static void flatviews_reset(struct uc_struct *uc)
{
    AddressSpace *as;

    if (uc->flat_views) {
        g_hash_table_destroy(uc->flat_views);
        uc->flat_views = NULL;
    }
    flatviews_init(uc);

    /* Render unique FVs */
    QTAILQ_FOREACH(as, &uc->address_spaces, address_spaces_link) {
        MemoryRegion *physmr = memory_region_get_flatview_root(as->root);

        if (g_hash_table_lookup(uc->flat_views, physmr)) {
            continue;
        }

        generate_memory_topology(uc, physmr);
    }
}

static void address_space_set_flatview(AddressSpace *as)
{
    FlatView *old_view = address_space_to_flatview(as);
    MemoryRegion *physmr = memory_region_get_flatview_root(as->root);
    FlatView *new_view = g_hash_table_lookup(as->uc->flat_views, physmr);

    assert(new_view);

    if (old_view == new_view) {
        return;
    }

    flatview_ref(new_view);
    if (!QTAILQ_EMPTY(&as->listeners)) {
        FlatView tmpview = { .nr = 0 }, *old_view2 = old_view;

        if (!old_view2) {
            old_view2 = &tmpview;
        }
        address_space_update_topology_pass(as, old_view2, new_view, false);
        address_space_update_topology_pass(as, old_view2, new_view, true);
    }

    as->current_map = new_view;
    if (old_view) {
        flatview_unref(old_view);
    }
}

static void address_space_update_topology(AddressSpace *as)
{
    MemoryRegion *physmr = memory_region_get_flatview_root(as->root);

    flatviews_init(as->uc);
    if (!g_hash_table_lookup(as->uc->flat_views, physmr)) {
        generate_memory_topology(as->uc, physmr);
    }
    address_space_set_flatview(as);
}

void memory_region_transaction_begin(void)
{
}

void memory_region_transaction_commit(MemoryRegion *mr)
{
    AddressSpace *as;

    if (mr->uc->memory_region_update_pending) {
        flatviews_reset(mr->uc);

        MEMORY_LISTENER_CALL_GLOBAL(mr->uc, begin, Forward);

        QTAILQ_FOREACH(as, &mr->uc->address_spaces, address_spaces_link) {
            address_space_set_flatview(as);
        }
        mr->uc->memory_region_update_pending = false;
        MEMORY_LISTENER_CALL_GLOBAL(mr->uc, commit, Forward);
    }
}

static void memory_region_destructor_none(MemoryRegion *mr)
{
}

static void memory_region_destructor_ram(MemoryRegion *mr)
{
    qemu_ram_free(mr->uc, mr->ram_block);
}

void memory_region_init(struct uc_struct *uc,
                        MemoryRegion *mr,
                        uint64_t size)
{
    memset(mr, 0, sizeof(*mr));
    mr->uc = uc;
    /* memory_region_initfn */
    mr->ops = &unassigned_mem_ops;
    mr->enabled = true;
    mr->destructor = memory_region_destructor_none;
    QTAILQ_INIT(&mr->subregions);

    mr->size = int128_make64(size);
    if (size == UINT64_MAX) {
        mr->size = int128_2_64();
    }
}

static uint64_t unassigned_mem_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem read " TARGET_FMT_plx "\n", addr);
#endif
    return 0;
}

static void unassigned_mem_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
{
#ifdef DEBUG_UNASSIGNED
    printf("Unassigned mem write " TARGET_FMT_plx " = 0x%"PRIx64"\n", addr, val);
#endif
}

static bool unassigned_mem_accepts(struct uc_struct *uc, void *opaque, hwaddr addr,
                                   unsigned size, bool is_write,
                                   MemTxAttrs attrs)
{
    return false;
}

const MemoryRegionOps unassigned_mem_ops = {
    .valid.accepts = unassigned_mem_accepts,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

bool memory_region_access_valid(struct uc_struct *uc, MemoryRegion *mr,
                                hwaddr addr,
                                unsigned size,
                                bool is_write,
                                MemTxAttrs attrs)
{
    if (mr->ops->valid.accepts
        && !mr->ops->valid.accepts(uc, mr->opaque, addr, size, is_write, attrs)) {
        return false;
    }

    if (!mr->ops->valid.unaligned && (addr & (size - 1))) {
        return false;
    }

    /* Treat zero as compatibility all valid */
    if (!mr->ops->valid.max_access_size) {
        return true;
    }

    if (size > mr->ops->valid.max_access_size
        || size < mr->ops->valid.min_access_size) {
        return false;
    }
    return true;
}

static MemTxResult memory_region_dispatch_read1(struct uc_struct *uc, MemoryRegion *mr,
                                                hwaddr addr,
                                                uint64_t *pval,
                                                unsigned size,
                                                MemTxAttrs attrs)
{
    *pval = 0;

    if (mr->ops->read) {
        return access_with_adjusted_size(uc, addr, pval, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_read_accessor,
                                         mr, attrs);
    } else {
        return access_with_adjusted_size(uc, addr, pval, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_read_with_attrs_accessor,
                                         mr, attrs);
    }
}

MemTxResult memory_region_dispatch_read(struct uc_struct *uc, MemoryRegion *mr,
                                        hwaddr addr,
                                        uint64_t *pval,
                                        MemOp op,
                                        MemTxAttrs attrs)
{
    unsigned size = memop_size(op);
    MemTxResult r;

    if (!memory_region_access_valid(uc, mr, addr, size, false, attrs)) {
        *pval = unassigned_mem_read(mr, addr, size);
        return MEMTX_DECODE_ERROR;
    }

    r = memory_region_dispatch_read1(uc, mr, addr, pval, size, attrs);
    adjust_endianness(mr, pval, op);
    return r;
}

MemTxResult memory_region_dispatch_write(struct uc_struct *uc, MemoryRegion *mr,
                                         hwaddr addr,
                                         uint64_t data,
                                         MemOp op,
                                         MemTxAttrs attrs)
{
    unsigned size = memop_size(op);

    if (!memory_region_access_valid(uc, mr, addr, size, true, attrs)) {
        unassigned_mem_write(mr, addr, data, size);
        return MEMTX_DECODE_ERROR;
    }

    adjust_endianness(mr, &data, op);

    if (mr->ops->write) {
        return access_with_adjusted_size(uc, addr, &data, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_write_accessor, mr,
                                         attrs);
    } else {
        return
            access_with_adjusted_size(uc, addr, &data, size,
                                      mr->ops->impl.min_access_size,
                                      mr->ops->impl.max_access_size,
                                      memory_region_write_with_attrs_accessor,
                                      mr, attrs);
    }
}

void memory_region_init_io(struct uc_struct *uc,
                           MemoryRegion *mr,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           uint64_t size)
{
    memory_region_init(uc, mr, size);
    mr->ops = ops ? ops : &unassigned_mem_ops;
    mr->opaque = opaque;
    mr->terminates = true;
}

void memory_region_init_ram_ptr(struct uc_struct *uc,
                                MemoryRegion *mr,
                                uint64_t size,
                                void *ptr)
{
    memory_region_init(uc, mr, size);
    mr->ram = true;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;

    /* qemu_ram_alloc_from_ptr cannot fail with ptr != NULL.  */
    assert(ptr != NULL);
    mr->ram_block = qemu_ram_alloc_from_ptr(uc, size, ptr, mr);
}

uint64_t memory_region_size(MemoryRegion *mr)
{
    if (int128_eq(mr->size, int128_2_64())) {
        return UINT64_MAX;
    }
    return int128_get64(mr->size);
}

void memory_region_set_readonly(MemoryRegion *mr, bool readonly)
{
    if (mr->readonly != readonly) {
        memory_region_transaction_begin();
        mr->readonly = readonly;
        mr->uc->memory_region_update_pending |= mr->enabled;
        memory_region_transaction_commit(mr);
    }
}

void *memory_region_get_ram_ptr(MemoryRegion *mr)
{
    void *ptr;

    ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, 0);

    return ptr;
}

MemoryRegion *memory_region_from_host(struct uc_struct *uc,
                                      void *ptr, ram_addr_t *offset)
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

    memory_region_transaction_begin();

    QTAILQ_FOREACH(other, &mr->subregions, subregions_link) {
        QTAILQ_INSERT_BEFORE(other, subregion, subregions_link);
        goto done;
    }
    QTAILQ_INSERT_TAIL(&mr->subregions, subregion, subregions_link);

done:
    mr->uc->memory_region_update_pending = true;
    memory_region_transaction_commit(mr);
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
    memory_region_add_subregion_common(mr, offset, subregion);
}

void memory_region_del_subregion(MemoryRegion *mr,
                                 MemoryRegion *subregion)
{
    memory_region_transaction_begin();
    assert(subregion->container == mr);
    subregion->container = NULL;
    QTAILQ_REMOVE(&mr->subregions, subregion, subregions_link);
    mr->uc->memory_region_update_pending = true;
    memory_region_transaction_commit(mr);
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

/* Same as memory_region_find, but it does not add a reference to the
 * returned region.  It must be called from an RCU critical section.
 */
static MemoryRegionSection memory_region_find_rcu(MemoryRegion *mr,
                                                  hwaddr addr, uint64_t size)
{
    MemoryRegionSection ret = { .mr = NULL };
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

    view = address_space_to_flatview(as);
    fr = flatview_lookup(view, range);
    if (!fr) {
        return ret;
    }

    while (fr > view->ranges && addrrange_intersects(fr[-1].addr, range)) {
        --fr;
    }

    ret.mr = fr->mr;
    ret.fv = view;
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

    ret = memory_region_find_rcu(mr, addr, size);
    return ret;
}

static void listener_add_address_space(MemoryListener *listener,
                                       AddressSpace *as)
{
    FlatView *view;
    FlatRange *fr;

    if (listener->begin) {
        listener->begin(listener);
    }

    view = address_space_get_flatview(as);
    FOR_EACH_FLAT_RANGE(fr, view) {
        MemoryRegionSection section = section_from_flat_range(fr, view);

        if (listener->region_add) {
            listener->region_add(listener, &section);
        }
    }
    if (listener->commit) {
        listener->commit(listener);
    }
}

static void listener_del_address_space(MemoryListener *listener,
                                       AddressSpace *as)
{
    FlatView *view;
    FlatRange *fr;

    if (listener->begin) {
        listener->begin(listener);
    }
    view = address_space_get_flatview(as);
    FOR_EACH_FLAT_RANGE(fr, view) {
        MemoryRegionSection section = section_from_flat_range(fr, view);

        if (listener->region_del) {
            listener->region_del(listener, &section);
        }
    }
    if (listener->commit) {
        listener->commit(listener);
    }
}

void memory_listener_register(MemoryListener *listener, AddressSpace *as)
{
    listener->address_space = as;
    QTAILQ_INSERT_TAIL(&as->uc->memory_listeners, listener, link);
    QTAILQ_INSERT_TAIL(&as->listeners, listener, link_as);

    listener_add_address_space(listener, as);
}

void memory_listener_unregister(MemoryListener *listener)
{
    if (!listener->address_space) {
        return;
    }

    listener_del_address_space(listener, listener->address_space);
    QTAILQ_REMOVE(&listener->address_space->uc->memory_listeners, listener, link);
    QTAILQ_REMOVE(&listener->address_space->listeners, listener, link_as);
    listener->address_space = NULL;
}

void address_space_remove_listeners(AddressSpace *as)
{
    while (!QTAILQ_EMPTY(&as->listeners)) {
        memory_listener_unregister(QTAILQ_FIRST(&as->listeners));
    }
}

void address_space_init(struct uc_struct *uc,
                        AddressSpace *as,
                        MemoryRegion *root)
{
    as->uc = uc;
    as->root = root;
    as->current_map = NULL;
    QTAILQ_INIT(&as->listeners);
    QTAILQ_INSERT_TAIL(&uc->address_spaces, as, address_spaces_link);
    address_space_update_topology(as);
}

void address_space_destroy(AddressSpace *as)
{
    MemoryRegion *root = as->root;

    /* Flush out anything from MemoryListeners listening in on this */
    memory_region_transaction_begin();
    as->root = NULL;
    memory_region_transaction_commit(root);
    QTAILQ_REMOVE(&as->uc->address_spaces, as, address_spaces_link);

    /* At this point, as->dispatch and as->current_map are dummy
     * entries that the guest should never use.  Wait for the old
     * values to expire before freeing the data.
     */
    as->root = root;
    flatview_unref(as->current_map);
}

void memory_region_init_ram(struct uc_struct *uc,
                            MemoryRegion *mr,
                            uint64_t size,
                            uint32_t perms)
{
    memory_region_init(uc, mr, size);
    mr->ram = true;
    if (!(perms & UC_PROT_WRITE)) {
        mr->readonly = true;
    }
    mr->perms = perms;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;
    mr->ram_block = qemu_ram_alloc(uc, size, mr);
}
