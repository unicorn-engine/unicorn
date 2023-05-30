/*
 * Physical memory management API
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Avi Kivity <avi@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef MEMORY_H
#define MEMORY_H

#include "exec/cpu-common.h"
#include "exec/hwaddr.h"
#include "exec/memattrs.h"
#include "exec/memop.h"
#include "exec/ramlist.h"
#include "qemu/bswap.h"
#include "qemu/queue.h"
#include "qemu/int128.h"

#define RAM_ADDR_INVALID (~(ram_addr_t)0)

#define MAX_PHYS_ADDR_SPACE_BITS 62
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)

typedef struct MemoryRegionOps MemoryRegionOps;

typedef struct IOMMUTLBEntry IOMMUTLBEntry;

typedef uint64_t (*uc_cb_mmio_read_t)(struct uc_struct *uc, uint64_t addr, unsigned size, void *user_data);
typedef void (*uc_cb_mmio_write_t)(struct uc_struct *uc, uint64_t addr, unsigned size, uint64_t data, void *user_data);

/* See address_space_translate: bit 0 is read, bit 1 is write.  */
typedef enum {
    IOMMU_NONE = 0,
    IOMMU_RO   = 1,
    IOMMU_WO   = 2,
    IOMMU_RW   = 3,
} IOMMUAccessFlags;

#define IOMMU_ACCESS_FLAG(r, w) (((r) ? IOMMU_RO : 0) | ((w) ? IOMMU_WO : 0))

struct IOMMUTLBEntry {
    AddressSpace    *target_as;
    hwaddr           iova;
    hwaddr           translated_addr;
    hwaddr           addr_mask;  /* 0xfff = 4k translation */
    IOMMUAccessFlags perm;
};

/*
 * Bitmap for different IOMMUNotifier capabilities. Each notifier can
 * register with one or multiple IOMMU Notifier capability bit(s).
 */
typedef enum {
    IOMMU_NOTIFIER_NONE = 0,
    /* Notify cache invalidations */
    IOMMU_NOTIFIER_UNMAP = 0x1,
    /* Notify entry changes (newly created entries) */
    IOMMU_NOTIFIER_MAP = 0x2,
} IOMMUNotifierFlag;

#define IOMMU_NOTIFIER_ALL (IOMMU_NOTIFIER_MAP | IOMMU_NOTIFIER_UNMAP)

struct IOMMUNotifier;
typedef void (*IOMMUNotify)(struct IOMMUNotifier *notifier,
                            IOMMUTLBEntry *data);

struct IOMMUNotifier {
    IOMMUNotify notify;
    IOMMUNotifierFlag notifier_flags;
    /* Notify for address space range start <= addr <= end */
    hwaddr start;
    hwaddr end;
    int iommu_idx;
    QLIST_ENTRY(IOMMUNotifier) node;
};
typedef struct IOMMUNotifier IOMMUNotifier;

/* RAM is pre-allocated and passed into qemu_ram_alloc_from_ptr */
#define RAM_PREALLOC   (1 << 0)

/* RAM is mmap-ed with MAP_SHARED */
#define RAM_SHARED     (1 << 1)

/* Only a portion of RAM (used_length) is actually used, and migrated.
 * This used_length size can change across reboots.
 */
#define RAM_RESIZEABLE (1 << 2)

/* UFFDIO_ZEROPAGE is available on this RAMBlock to atomically
 * zero the page and wake waiting processes.
 * (Set during postcopy)
 */
#define RAM_UF_ZEROPAGE (1 << 3)

/* RAM can be migrated */
#define RAM_MIGRATABLE (1 << 4)

/* RAM is a persistent kind memory */
#define RAM_PMEM (1 << 5)

static inline void iommu_notifier_init(IOMMUNotifier *n, IOMMUNotify fn,
                                       IOMMUNotifierFlag flags,
                                       hwaddr start, hwaddr end,
                                       int iommu_idx)
{
    n->notify = fn;
    n->notifier_flags = flags;
    n->start = start;
    n->end = end;
    n->iommu_idx = iommu_idx;
}

/*
 * Memory region callbacks
 */
struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t (*read)(struct uc_struct *uc,
                     void *opaque,
                     hwaddr addr,
                     unsigned size);
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(struct uc_struct *uc,
                  void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);

    MemTxResult (*read_with_attrs)(struct uc_struct *uc, void *opaque,
                                   hwaddr addr,
                                   uint64_t *data,
                                   unsigned size,
                                   MemTxAttrs attrs);

    MemTxResult (*write_with_attrs)(struct uc_struct *, void *opaque,
                                    hwaddr addr,
                                    uint64_t data,
                                    unsigned size,
                                    MemTxAttrs attrs);

    enum device_endian endianness;
    /* Guest-visible constraints: */
    struct {
        /* If nonzero, specify bounds on access sizes beyond which a machine
         * check is thrown.
         */
        unsigned min_access_size;
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise unaligned
         * accesses throw machine checks.
         */
         bool unaligned;
        /*
         * If present, and returns #false, the transaction is not accepted
         * by the device (and results in machine dependent behaviour such
         * as a machine check exception).
         */
        bool (*accepts)(struct uc_struct *uc, void *opaque, hwaddr addr,
                        unsigned size, bool is_write,
                        MemTxAttrs attrs);
    } valid;
    /* Internal implementation constraints: */
    struct {
        /* If nonzero, specifies the minimum size implemented.  Smaller sizes
         * will be rounded upwards and a partial result will be returned.
         */
        unsigned min_access_size;
        /* If nonzero, specifies the maximum size implemented.  Larger sizes
         * will be done as a series of accesses with smaller sizes.
         */
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise all accesses
         * are converted to (possibly multiple) naturally aligned accesses.
         */
        bool unaligned;
    } impl;
};

enum IOMMUMemoryRegionAttr {
    IOMMU_ATTR_SPAPR_TCE_FD
};

/**
 * IOMMUMemoryRegionClass:
 *
 * All IOMMU implementations need to subclass TYPE_IOMMU_MEMORY_REGION
 * and provide an implementation of at least the @translate method here
 * to handle requests to the memory region. Other methods are optional.
 *
 * The IOMMU implementation must use the IOMMU notifier infrastructure
 * to report whenever mappings are changed, by calling
 * memory_region_notify_iommu() (or, if necessary, by calling
 * memory_region_notify_one() for each registered notifier).
 *
 * Conceptually an IOMMU provides a mapping from input address
 * to an output TLB entry. If the IOMMU is aware of memory transaction
 * attributes and the output TLB entry depends on the transaction
 * attributes, we represent this using IOMMU indexes. Each index
 * selects a particular translation table that the IOMMU has:
 *   @attrs_to_index returns the IOMMU index for a set of transaction attributes
 *   @translate takes an input address and an IOMMU index
 * and the mapping returned can only depend on the input address and the
 * IOMMU index.
 *
 * Most IOMMUs don't care about the transaction attributes and support
 * only a single IOMMU index. A more complex IOMMU might have one index
 * for secure transactions and one for non-secure transactions.
 */
typedef struct IOMMUMemoryRegionClass {
    /*
     * Return a TLB entry that contains a given address.
     *
     * The IOMMUAccessFlags indicated via @flag are optional and may
     * be specified as IOMMU_NONE to indicate that the caller needs
     * the full translation information for both reads and writes. If
     * the access flags are specified then the IOMMU implementation
     * may use this as an optimization, to stop doing a page table
     * walk as soon as it knows that the requested permissions are not
     * allowed. If IOMMU_NONE is passed then the IOMMU must do the
     * full page table walk and report the permissions in the returned
     * IOMMUTLBEntry. (Note that this implies that an IOMMU may not
     * return different mappings for reads and writes.)
     *
     * The returned information remains valid while the caller is
     * holding the big QEMU lock or is inside an RCU critical section;
     * if the caller wishes to cache the mapping beyond that it must
     * register an IOMMU notifier so it can invalidate its cached
     * information when the IOMMU mapping changes.
     *
     * @iommu: the IOMMUMemoryRegion
     * @hwaddr: address to be translated within the memory region
     * @flag: requested access permissions
     * @iommu_idx: IOMMU index for the translation
     */
    IOMMUTLBEntry (*translate)(IOMMUMemoryRegion *iommu, hwaddr addr,
                               IOMMUAccessFlags flag, int iommu_idx);
    /* Returns minimum supported page size in bytes.
     * If this method is not provided then the minimum is assumed to
     * be TARGET_PAGE_SIZE.
     *
     * @iommu: the IOMMUMemoryRegion
     */
    uint64_t (*get_min_page_size)(IOMMUMemoryRegion *iommu);

    /* Get IOMMU misc attributes. This is an optional method that
     * can be used to allow users of the IOMMU to get implementation-specific
     * information. The IOMMU implements this method to handle calls
     * by IOMMU users to memory_region_iommu_get_attr() by filling in
     * the arbitrary data pointer for any IOMMUMemoryRegionAttr values that
     * the IOMMU supports. If the method is unimplemented then
     * memory_region_iommu_get_attr() will always return -EINVAL.
     *
     * @iommu: the IOMMUMemoryRegion
     * @attr: attribute being queried
     * @data: memory to fill in with the attribute data
     *
     * Returns 0 on success, or a negative errno; in particular
     * returns -EINVAL for unrecognized or unimplemented attribute types.
     */
    int (*get_attr)(IOMMUMemoryRegion *iommu, enum IOMMUMemoryRegionAttr attr,
                    void *data);

    /* Return the IOMMU index to use for a given set of transaction attributes.
     *
     * Optional method: if an IOMMU only supports a single IOMMU index then
     * the default implementation of memory_region_iommu_attrs_to_index()
     * will return 0.
     *
     * The indexes supported by an IOMMU must be contiguous, starting at 0.
     *
     * @iommu: the IOMMUMemoryRegion
     * @attrs: memory transaction attributes
     */
    int (*attrs_to_index)(IOMMUMemoryRegion *iommu, MemTxAttrs attrs);

    /* Return the number of IOMMU indexes this IOMMU supports.
     *
     * Optional method: if this method is not provided, then
     * memory_region_iommu_num_indexes() will return 1, indicating that
     * only a single IOMMU index is supported.
     *
     * @iommu: the IOMMUMemoryRegion
     */
    int (*num_indexes)(IOMMUMemoryRegion *iommu);
} IOMMUMemoryRegionClass;

/** MemoryRegion:
 *
 * A struct representing a memory region.
 */
struct MemoryRegion {
    /* private: */

    /* The following fields should fit in a cache line */
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool is_iommu;
    RAMBlock *ram_block;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool enabled;
    int32_t priority;
    QTAILQ_HEAD(, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;

    struct uc_struct *uc;
    uint32_t perms;
    hwaddr end;
};

struct IOMMUMemoryRegion {
    MemoryRegion parent_obj;

    QLIST_HEAD(, IOMMUNotifier) iommu_notify;
    IOMMUNotifierFlag iommu_notify_flags;

    IOMMUMemoryRegionClass cc;
};

#define MEMORY_REGION(obj) ((MemoryRegion *)obj)
#define IOMMU_MEMORY_REGION(obj) ((IOMMUMemoryRegion *)obj)
#define IOMMU_MEMORY_REGION_CLASS(klass) ((IOMMUMemoryRegionClass *)klass)
#define IOMMU_MEMORY_REGION_GET_CLASS(obj) (&((IOMMUMemoryRegion *)obj)->cc)

#define IOMMU_NOTIFIER_FOREACH(n, mr) \
    QLIST_FOREACH((n), &(mr)->iommu_notify, node)

/**
 * MemoryListener: callbacks structure for updates to the physical memory map
 *
 * Allows a component to adjust to changes in the guest-visible memory map.
 * Use with memory_listener_register() and memory_listener_unregister().
 */
struct MemoryListener {
    /**
     * @begin:
     *
     * Called at the beginning of an address space update transaction.
     * Followed by calls to #MemoryListener.region_add(),
     * #MemoryListener.region_del(), #MemoryListener.region_nop(),
     * #MemoryListener.log_start() and #MemoryListener.log_stop() in
     * increasing address order.
     *
     * @listener: The #MemoryListener.
     */
    void (*begin)(MemoryListener *listener);

    /**
     * @commit:
     *
     * Called at the end of an address space update transaction,
     * after the last call to #MemoryListener.region_add(),
     * #MemoryListener.region_del() or #MemoryListener.region_nop(),
     * #MemoryListener.log_start() and #MemoryListener.log_stop().
     *
     * @listener: The #MemoryListener.
     */
    void (*commit)(MemoryListener *listener);

    /**
     * @region_add:
     *
     * Called during an address space update transaction,
     * for a section of the address space that is new in this address space
     * space since the last transaction.
     *
     * @listener: The #MemoryListener.
     * @section: The new #MemoryRegionSection.
     */
    void (*region_add)(MemoryListener *listener, MemoryRegionSection *section);

    /**
     * @region_del:
     *
     * Called during an address space update transaction,
     * for a section of the address space that has disappeared in the address
     * space since the last transaction.
     *
     * @listener: The #MemoryListener.
     * @section: The old #MemoryRegionSection.
     */
    void (*region_del)(MemoryListener *listener, MemoryRegionSection *section);

    /**
     * @region_nop:
     *
     * Called during an address space update transaction,
     * for a section of the address space that is in the same place in the address
     * space as in the last transaction.
     *
     * @listener: The #MemoryListener.
     * @section: The #MemoryRegionSection.
     */
    void (*region_nop)(MemoryListener *listener, MemoryRegionSection *section);

    /* private: */
    AddressSpace *address_space;
    QTAILQ_ENTRY(MemoryListener) link;
    QTAILQ_ENTRY(MemoryListener) link_as;
};

/**
 * AddressSpace: describes a mapping of addresses to #MemoryRegion objects
 */
struct AddressSpace {
    /* private: */
    MemoryRegion *root;

    /* Accessed via RCU.  */
    struct FlatView *current_map;

    QTAILQ_HEAD(, MemoryListener) listeners;
    QTAILQ_ENTRY(AddressSpace) address_spaces_link;

    struct uc_struct *uc;
};

typedef struct AddressSpaceDispatch AddressSpaceDispatch;
typedef struct FlatRange FlatRange;

/* Flattened global view of current active memory hierarchy.  Kept in sorted
 * order.
 */
struct FlatView {
    unsigned ref;
    FlatRange *ranges;
    unsigned nr;
    unsigned nr_allocated;
    struct AddressSpaceDispatch *dispatch;
    MemoryRegion *root;
};

static inline FlatView *address_space_to_flatview(AddressSpace *as)
{
    return as->current_map;
}


/**
 * MemoryRegionSection: describes a fragment of a #MemoryRegion
 *
 * @mr: the region, or %NULL if empty
 * @fv: the flat view of the address space the region is mapped in
 * @offset_within_region: the beginning of the section, relative to @mr's start
 * @size: the size of the section; will not exceed @mr's boundaries
 * @offset_within_address_space: the address of the first byte of the section
 *     relative to the region's address space
 * @readonly: writes to this section are ignored
 */
struct MemoryRegionSection {
    Int128 size;
    MemoryRegion *mr;
    FlatView *fv;
    hwaddr offset_within_region;
    hwaddr offset_within_address_space;
    bool readonly;
};

static inline bool MemoryRegionSection_eq(MemoryRegionSection *a,
                                          MemoryRegionSection *b)
{
    return a->mr == b->mr &&
           a->fv == b->fv &&
           a->offset_within_region == b->offset_within_region &&
           a->offset_within_address_space == b->offset_within_address_space &&
           int128_eq(a->size, b->size) &&
           a->readonly == b->readonly;
}

/**
 * memory_region_init: Initialize a memory region
 *
 * The region typically acts as a container for other memory regions.  Use
 * memory_region_add_subregion() to add subregions.
 *
 * @mr: the #MemoryRegion to be initialized
 * @size: size of the region; any subregions beyond this size will be clipped
 */
void memory_region_init(struct uc_struct *uc,
                        MemoryRegion *mr,
                        uint64_t size);

/**
 * memory_region_ref: Add 1 to a memory region's reference count
 *
 * Whenever memory regions are accessed outside the BQL, they need to be
 * preserved against hot-unplug.  MemoryRegions actually do not have their
 * own reference count; they piggyback on a QOM object, their "owner".
 * This function adds a reference to the owner.
 *
 * All MemoryRegions must have an owner if they can disappear, even if the
 * device they belong to operates exclusively under the BQL.  This is because
 * the region could be returned at any time by memory_region_find, and this
 * is usually under guest control.
 *
 * @mr: the #MemoryRegion
 */
void memory_region_ref(MemoryRegion *mr);

/**
 * memory_region_init_io: Initialize an I/O memory region.
 *
 * Accesses into the region will cause the callbacks in @ops to be called.
 * if @size is nonzero, subregions will be clipped to @size.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @ops: a structure containing read and write callbacks to be used when
 *       I/O is performed on the region.
 * @opaque: passed to the read and write callbacks of the @ops structure.
 * @size: size of the region.
 */
void memory_region_init_io(struct uc_struct *uc,
                           MemoryRegion *mr,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           uint64_t size);

/**
 * memory_region_init_ram_ptr:  Initialize RAM memory region from a
 *                              user-provided pointer.  Accesses into the
 *                              region will modify memory directly.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @size: size of the region.
 * @ptr: memory to be mapped; must contain at least @size bytes.
 *
 * Note that this function does not do anything to cause the data in the
 * RAM memory region to be migrated; that is the responsibility of the caller.
 */
void memory_region_init_ram_ptr(struct uc_struct *uc,
                                MemoryRegion *mr,
                                uint64_t size,
                                void *ptr);

/**
 * memory_region_init_ram - Initialize RAM memory region.  Accesses into the
 *                          region will modify memory directly.
 *
 * @mr: the #MemoryRegion to be initialized
 *         TYPE_DEVICE or a subclass of TYPE_DEVICE, or NULL)
 * @size: size of the region in bytes
 *
 * This function allocates RAM for a board model or device, and
 * arranges for it to be migrated (by calling vmstate_register_ram()
 * if @owner is a DeviceState, or vmstate_register_ram_global() if
 * @owner is NULL).
 *
 * TODO: Currently we restrict @owner to being either NULL (for
 * global RAM regions with no owner) or devices, so that we can
 * give the RAM block a unique name for migration purposes.
 * We should lift this restriction and allow arbitrary Objects.
 * If you pass a non-NULL non-device @owner then we will assert.
 */
void memory_region_init_ram(struct uc_struct *uc,
                            MemoryRegion *mr,
                            uint64_t size,
                            uint32_t perms);

/**
 * memory_region_size: get a memory region's size.
 *
 * @mr: the memory region being queried.
 */
uint64_t memory_region_size(MemoryRegion *mr);

/**
 * memory_region_is_ram: check whether a memory region is random access
 *
 * Returns %true if a memory region is random access.
 *
 * @mr: the memory region being queried
 */
static inline bool memory_region_is_ram(MemoryRegion *mr)
{
    return mr->ram;
}

/**
 * memory_region_get_iommu: check whether a memory region is an iommu
 *
 * Returns pointer to IOMMUMemoryRegion if a memory region is an iommu,
 * otherwise NULL.
 *
 * @mr: the memory region being queried
 */
static inline IOMMUMemoryRegion *memory_region_get_iommu(MemoryRegion *mr)
{
    if (mr->is_iommu) {
        return (IOMMUMemoryRegion *) mr;
    }
    return NULL;
}

/**
 * memory_region_get_iommu_class_nocheck: returns iommu memory region class
 *   if an iommu or NULL if not
 *
 * Returns pointer to IOMMUMemoryRegionClass if a memory region is an iommu,
 * otherwise NULL. This is fast path avoiding QOM checking, use with caution.
 *
 * @iommu_mr: the memory region being queried
 */
static inline IOMMUMemoryRegionClass *memory_region_get_iommu_class_nocheck(
        IOMMUMemoryRegion *iommu_mr)
{
    return &iommu_mr->cc;
}

/**
 * memory_region_from_host: Convert a pointer into a RAM memory region
 * and an offset within it.
 *
 * Given a host pointer inside a RAM memory region (created with
 * memory_region_init_ram() or memory_region_init_ram_ptr()), return
 * the MemoryRegion and the offset within it.
 *
 * Use with care; by the time this function returns, the returned pointer is
 * not protected by RCU anymore.  If the caller is not within an RCU critical
 * section and does not hold the iothread lock, it must have other means of
 * protecting the pointer, such as a reference to the region that includes
 * the incoming ram_addr_t.
 *
 * @ptr: the host pointer to be converted
 * @offset: the offset within memory region
 */
MemoryRegion *memory_region_from_host(struct uc_struct *uc, void *ptr, ram_addr_t *offset);

/**
 * memory_region_set_readonly: Turn a memory region read-only (or read-write)
 *
 * Allows a memory region to be marked as read-only (turning it into a ROM).
 * only useful on RAM regions.
 *
 * @mr: the region being updated.
 * @readonly: whether rhe region is to be ROM or RAM.
 */
void memory_region_set_readonly(MemoryRegion *mr, bool readonly);

/**
 * memory_region_get_ram_ptr: Get a pointer into a RAM memory region.
 *
 * Returns a host pointer to a RAM memory region (created with
 * memory_region_init_ram() or memory_region_init_ram_ptr()).
 *
 * Use with care; by the time this function returns, the returned pointer is
 * not protected by RCU anymore.  If the caller is not within an RCU critical
 * section and does not hold the iothread lock, it must have other means of
 * protecting the pointer, such as a reference to the region that includes
 * the incoming ram_addr_t.
 *
 * @mr: the memory region being queried.
 */
void *memory_region_get_ram_ptr(MemoryRegion *mr);

/**
 * memory_region_add_subregion: Add a subregion to a container.
 *
 * Adds a subregion at @offset.  The subregion may not overlap with other
 * subregions (except for those explicitly marked as overlapping).  A region
 * may only be added once as a subregion (unless removed with
 * memory_region_del_subregion()); use memory_region_init_alias() if you
 * want a region to be a subregion in multiple locations.
 *
 * @mr: the region to contain the new subregion; must be a container
 *      initialized with memory_region_init().
 * @offset: the offset relative to @mr where @subregion is added.
 * @subregion: the subregion to be added.
 */
void memory_region_add_subregion(MemoryRegion *mr,
                                 hwaddr offset,
                                 MemoryRegion *subregion);

/**
 * memory_region_add_subregion_overlap: Add a subregion to a container
 *                                      with overlap.
 *
 * Adds a subregion at @offset.  The subregion may overlap with other
 * subregions.  Conflicts are resolved by having a higher @priority hide a
 * lower @priority. Subregions without priority are taken as @priority 0.
 * A region may only be added once as a subregion (unless removed with
 * memory_region_del_subregion()); use memory_region_init_alias() if you
 * want a region to be a subregion in multiple locations.
 *
 * @mr: the region to contain the new subregion; must be a container
 *      initialized with memory_region_init().
 * @offset: the offset relative to @mr where @subregion is added.
 * @subregion: the subregion to be added.
 * @priority: used for resolving overlaps; highest priority wins.
 */
void memory_region_add_subregion_overlap(MemoryRegion *mr,
                                         hwaddr offset,
                                         MemoryRegion *subregion,
                                         int priority);

/**
 * memory_region_filter_subregions: filter subregios by priority.
 *
 * remove all subregions beginning by a specified subregion
 */
void memory_region_filter_subregions(MemoryRegion *mr, int32_t level);

/**
 * memory_region_get_ram_addr: Get the ram address associated with a memory
 *                             region
 *
 * @mr: the region to be queried
 */
ram_addr_t memory_region_get_ram_addr(MemoryRegion *mr);

/**
 * memory_region_del_subregion: Remove a subregion.
 *
 * Removes a subregion from its container.
 *
 * @mr: the container to be updated.
 * @subregion: the region being removed; must be a current subregion of @mr.
 */
void memory_region_del_subregion(MemoryRegion *mr,
                                 MemoryRegion *subregion);

/**
 * memory_region_find: translate an address/size relative to a
 * MemoryRegion into a #MemoryRegionSection.
 *
 * Locates the first #MemoryRegion within @mr that overlaps the range
 * given by @addr and @size.
 *
 * Returns a #MemoryRegionSection that describes a contiguous overlap.
 * It will have the following characteristics:
 * - @size = 0 iff no overlap was found
 * - @mr is non-%NULL iff an overlap was found
 *
 * Remember that in the return value the @offset_within_region is
 * relative to the returned region (in the .@mr field), not to the
 * @mr argument.
 *
 * Similarly, the .@offset_within_address_space is relative to the
 * address space that contains both regions, the passed and the
 * returned one.  However, in the special case where the @mr argument
 * has no container (and thus is the root of the address space), the
 * following will hold:
 * - @offset_within_address_space >= @addr
 * - @offset_within_address_space + .@size <= @addr + @size
 *
 * @mr: a MemoryRegion within which @addr is a relative address
 * @addr: start of the area within @as to be searched
 * @size: size of the area to be searched
 */
MemoryRegionSection memory_region_find(MemoryRegion *mr,
                                       hwaddr addr, uint64_t size);

/**
 * memory_listener_register: register callbacks to be called when memory
 *                           sections are mapped or unmapped into an address
 *                           space
 *
 * @listener: an object containing the callbacks to be called
 * @filter: if non-%NULL, only regions in this address space will be observed
 */
void memory_listener_register(MemoryListener *listener, AddressSpace *filter);

/**
 * memory_listener_unregister: undo the effect of memory_listener_register()
 *
 * @listener: an object containing the callbacks to be removed
 */
void memory_listener_unregister(MemoryListener *listener);

/**
 * memory_region_dispatch_read: perform a read directly to the specified
 * MemoryRegion.
 *
 * @mr: #MemoryRegion to access
 * @addr: address within that region
 * @pval: pointer to uint64_t which the data is written to
 * @op: size, sign, and endianness of the memory operation
 * @attrs: memory transaction attributes to use for the access
 */
MemTxResult memory_region_dispatch_read(struct uc_struct *uc, MemoryRegion *mr,
                                        hwaddr addr,
                                        uint64_t *pval,
                                        MemOp op,
                                        MemTxAttrs attrs);
/**
 * memory_region_dispatch_write: perform a write directly to the specified
 * MemoryRegion.
 *
 * @mr: #MemoryRegion to access
 * @addr: address within that region
 * @data: data to write
 * @op: size, sign, and endianness of the memory operation
 * @attrs: memory transaction attributes to use for the access
 */
MemTxResult memory_region_dispatch_write(struct uc_struct *uc, MemoryRegion *mr,
                                         hwaddr addr,
                                         uint64_t data,
                                         MemOp op,
                                         MemTxAttrs attrs);

/**
 * address_space_init: initializes an address space
 *
 * @as: an uninitialized #AddressSpace
 * @root: a #MemoryRegion that routes addresses for the address space
 */
void address_space_init(struct uc_struct *uc, 
                        AddressSpace *as,
                        MemoryRegion *root);

/**
 * address_space_destroy: destroy an address space
 *
 * Releases all resources associated with an address space.  After an address space
 * is destroyed, its root memory region (given by address_space_init()) may be destroyed
 * as well.
 *
 * @as: address space to be destroyed
 */
void address_space_destroy(AddressSpace *as);

/**
 * address_space_remove_listeners: unregister all listeners of an address space
 *
 * Removes all callbacks previously registered with memory_listener_register()
 * for @as.
 *
 * @as: an initialized #AddressSpace
 */
void address_space_remove_listeners(AddressSpace *as);

/**
 * address_space_rw: read from or write to an address space.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 * @len: the number of bytes to read or write
 * @is_write: indicates the transfer direction
 */
MemTxResult address_space_rw(AddressSpace *as, hwaddr addr,
                             MemTxAttrs attrs, void *buf,
                             hwaddr len, bool is_write);

/**
 * address_space_write: write to address space.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 * @len: the number of bytes to write
 */
MemTxResult address_space_write(AddressSpace *as, hwaddr addr,
                                MemTxAttrs attrs,
                                const void *buf, hwaddr len);

/**
 * address_space_write_rom: write to address space, including ROM.
 *
 * This function writes to the specified address space, but will
 * write data to both ROM and RAM. This is used for non-guest
 * writes like writes from the gdb debug stub or initial loading
 * of ROM contents.
 *
 * Note that portions of the write which attempt to write data to
 * a device will be silently ignored -- only real RAM and ROM will
 * be written to.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 * @len: the number of bytes to write
 */
MemTxResult address_space_write_rom(AddressSpace *as, hwaddr addr,
                                    MemTxAttrs attrs,
                                    const void *buf, hwaddr len);

/* address_space_ld*: load from an address space
 * address_space_st*: store to an address space
 *
 * These functions perform a load or store of the byte, word,
 * longword or quad to the specified address within the AddressSpace.
 * The _le suffixed functions treat the data as little endian;
 * _be indicates big endian; no suffix indicates "same endianness
 * as guest CPU".
 *
 * The "guest CPU endianness" accessors are deprecated for use outside
 * target-* code; devices should be CPU-agnostic and use either the LE
 * or the BE accessors.
 *
 * @as #AddressSpace to be accessed
 * @addr: address within that address space
 * @val: data value, for stores
 * @attrs: memory transaction attributes
 * @result: location to write the success/failure of the transaction;
 *   if NULL, this information is discarded
 */

#ifdef UNICORN_ARCH_POSTFIX
#define SUFFIX       UNICORN_ARCH_POSTFIX
#else
#define SUFFIX
#endif
#define ARG1         as
#define ARG1_DECL    AddressSpace *as
#include "exec/memory_ldst.inc.h"

#ifdef UNICORN_ARCH_POSTFIX
#define SUFFIX       UNICORN_ARCH_POSTFIX
#else
#define SUFFIX
#endif
#define ARG1         as
#define ARG1_DECL    AddressSpace *as
#include "exec/memory_ldst_phys.inc.h"

struct MemoryRegionCache {
    void *ptr;
    hwaddr xlat;
    hwaddr len;
    FlatView *fv;
    MemoryRegionSection mrs;
    bool is_write;
};

#define MEMORY_REGION_CACHE_INVALID ((MemoryRegionCache) { .mrs.mr = NULL })


/* address_space_ld*_cached: load from a cached #MemoryRegion
 * address_space_st*_cached: store into a cached #MemoryRegion
 *
 * These functions perform a load or store of the byte, word,
 * longword or quad to the specified address.  The address is
 * a physical address in the AddressSpace, but it must lie within
 * a #MemoryRegion that was mapped with address_space_cache_init.
 *
 * The _le suffixed functions treat the data as little endian;
 * _be indicates big endian; no suffix indicates "same endianness
 * as guest CPU".
 *
 * The "guest CPU endianness" accessors are deprecated for use outside
 * target-* code; devices should be CPU-agnostic and use either the LE
 * or the BE accessors.
 *
 * @cache: previously initialized #MemoryRegionCache to be accessed
 * @addr: address within the address space
 * @val: data value, for stores
 * @attrs: memory transaction attributes
 * @result: location to write the success/failure of the transaction;
 *   if NULL, this information is discarded
 */

#ifdef UNICORN_ARCH_POSTFIX
#define SUFFIX       glue(_cached_slow, UNICORN_ARCH_POSTFIX)
#else
#define SUFFIX       _cached_slow
#endif
#define ARG1         cache
#define ARG1_DECL    MemoryRegionCache *cache
#include "exec/memory_ldst.inc.h"

/* Inline fast path for direct RAM access.  */
#ifdef UNICORN_ARCH_POSTFIX
static inline uint8_t glue(address_space_ldub_cached, UNICORN_ARCH_POSTFIX)(struct uc_struct *uc, MemoryRegionCache *cache,
#else
static inline uint8_t address_space_ldub_cached(struct uc_struct *uc, MemoryRegionCache *cache,
#endif
    hwaddr addr, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len);
    if (likely(cache->ptr)) {
        return ldub_p((char *)cache->ptr + addr);
    } else {
#ifdef UNICORN_ARCH_POSTFIX
        return glue(address_space_ldub_cached_slow, UNICORN_ARCH_POSTFIX)(uc, cache, addr, attrs, result);
#else
        return address_space_ldub_cached_slow(uc, cache, addr, attrs, result);
#endif
    }
}

#ifdef UNICORN_ARCH_POSTFIX
static inline void glue(address_space_stb_cached, UNICORN_ARCH_POSTFIX)(struct uc_struct *uc, MemoryRegionCache *cache,
#else
static inline void address_space_stb_cached(struct uc_struct *uc, MemoryRegionCache *cache,
#endif
    hwaddr addr, uint32_t val, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len);
    if (likely(cache->ptr)) {
        stb_p((char *)cache->ptr + addr, val);
    } else {
#ifdef UNICORN_ARCH_POSTFIX
        glue(address_space_stb_cached_slow, UNICORN_ARCH_POSTFIX)(uc, cache, addr, val, attrs, result);
#else
        address_space_stb_cached_slow(uc, cache, addr, val, attrs, result);
#endif
    }
}

#define ENDIANNESS   _le
#include "exec/memory_ldst_cached.inc.h"

#define ENDIANNESS   _be
#include "exec/memory_ldst_cached.inc.h"

#ifdef UNICORN_ARCH_POSTFIX
#define SUFFIX       glue(_cached, UNICORN_ARCH_POSTFIX)
#else
#define SUFFIX       _cached
#endif
#define ARG1         cache
#define ARG1_DECL    MemoryRegionCache *cache
#include "exec/memory_ldst_phys.inc.h"

/* address_space_translate: translate an address range into an address space
 * into a MemoryRegion and an address range into that section.  Should be
 * called from an RCU critical section, to avoid that the last reference
 * to the returned region disappears after address_space_translate returns.
 *
 * @fv: #FlatView to be accessed
 * @addr: address within that address space
 * @xlat: pointer to address within the returned memory region section's
 * #MemoryRegion.
 * @len: pointer to length
 * @is_write: indicates the transfer direction
 * @attrs: memory attributes
 */
MemoryRegion *flatview_translate(struct uc_struct *uc, FlatView *fv,
                                 hwaddr addr, hwaddr *xlat,
                                 hwaddr *len, bool is_write,
                                 MemTxAttrs attrs);

static inline MemoryRegion *address_space_translate(AddressSpace *as,
                                                    hwaddr addr, hwaddr *xlat,
                                                    hwaddr *len, bool is_write,
                                                    MemTxAttrs attrs)
{
    return flatview_translate(as->uc, address_space_to_flatview(as),
                              addr, xlat, len, is_write, attrs);
}

/* address_space_access_valid: check for validity of accessing an address
 * space range
 *
 * Check whether memory is assigned to the given address space range, and
 * access is permitted by any IOMMU regions that are active for the address
 * space.
 *
 * For now, addr and len should be aligned to a page size.  This limitation
 * will be lifted in the future.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @len: length of the area to be checked
 * @is_write: indicates the transfer direction
 * @attrs: memory attributes
 */
bool address_space_access_valid(AddressSpace *as, hwaddr addr, hwaddr len,
                                bool is_write, MemTxAttrs attrs);

/* address_space_map: map a physical memory region into a host virtual address
 *
 * May map a subset of the requested range, given by and returned in @plen.
 * May return %NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 * Use cpu_register_map_client() to know when retrying the map operation is
 * likely to succeed.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @plen: pointer to length of buffer; updated on return
 * @is_write: indicates the transfer direction
 * @attrs: memory attributes
 */
void *address_space_map(AddressSpace *as, hwaddr addr,
                        hwaddr *plen, bool is_write, MemTxAttrs attrs);

/* address_space_unmap: Unmaps a memory region previously mapped by address_space_map()
 *
 * Will also mark the memory as dirty if @is_write == %true.  @access_len gives
 * the amount of memory that was actually read or written by the caller.
 *
 * @as: #AddressSpace used
 * @buffer: host pointer as returned by address_space_map()
 * @len: buffer length as returned by address_space_map()
 * @access_len: amount of data actually transferred
 * @is_write: indicates the transfer direction
 */
void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
                         bool is_write, hwaddr access_len);


/* Internal functions, part of the implementation of address_space_read.  */
MemTxResult address_space_read_full(AddressSpace *as, hwaddr addr,
                                    MemTxAttrs attrs, void *buf, hwaddr len);
MemTxResult flatview_read_continue(struct uc_struct *, FlatView *fv, hwaddr addr,
                                   MemTxAttrs attrs, void *buf,
                                   hwaddr len, hwaddr addr1, hwaddr l,
                                   MemoryRegion *mr);
void *qemu_map_ram_ptr(struct uc_struct *uc, RAMBlock *ram_block, ram_addr_t addr);

static inline bool memory_access_is_direct(MemoryRegion *mr, bool is_write)
{
    if (is_write) {
        return memory_region_is_ram(mr) && !mr->readonly;
    } else {
        return memory_region_is_ram(mr);
    }
}

/**
 * address_space_read: read from an address space.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).  Called within RCU critical section.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 * @len: length of the data transferred
 */
#ifndef _MSC_VER
static inline __attribute__((__always_inline__))
#else
static inline
#endif
MemTxResult address_space_read(AddressSpace *as, hwaddr addr,
                               MemTxAttrs attrs, void *buf,
                               hwaddr len)
{
    MemTxResult result = MEMTX_OK;
#ifndef _MSC_VER
    hwaddr l, addr1;
    void *ptr;
    MemoryRegion *mr;
    FlatView *fv;

    if (__builtin_constant_p(len)) {
        if (len) {
            fv = address_space_to_flatview(as);
            l = len;
            mr = flatview_translate(as->uc, fv, addr, &addr1, &l, false, attrs);
            if (len == l && memory_access_is_direct(mr, false)) {
                ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, addr1);
                memcpy(buf, ptr, len);
            } else {
                result = flatview_read_continue(as->uc, fv, addr, attrs, buf, len,
                                                addr1, l, mr);
            }
        }
    } else {
        result = address_space_read_full(as, addr, attrs, buf, len);
    }
#else
    result = address_space_read_full(as, addr, attrs, buf, len);
#endif
    return result;
}

#ifdef NEED_CPU_H
/* enum device_endian to MemOp.  */
static inline MemOp devend_memop(enum device_endian end)
{
    QEMU_BUILD_BUG_ON(DEVICE_HOST_ENDIAN != DEVICE_LITTLE_ENDIAN &&
                      DEVICE_HOST_ENDIAN != DEVICE_BIG_ENDIAN);

#if defined(HOST_WORDS_BIGENDIAN) != defined(TARGET_WORDS_BIGENDIAN)
    /* Swap if non-host endianness or native (target) endianness */
    return (end == DEVICE_HOST_ENDIAN) ? 0 : MO_BSWAP;
#else
    const int non_host_endianness =
        DEVICE_LITTLE_ENDIAN ^ DEVICE_BIG_ENDIAN ^ DEVICE_HOST_ENDIAN;

    /* In this case, native (target) endianness needs no swap.  */
    return (end == non_host_endianness) ? MO_BSWAP : 0;
#endif
}
#endif

MemoryRegion *memory_map(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms);
MemoryRegion *memory_map_ptr(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms, void *ptr);
 MemoryRegion *memory_map_io(struct uc_struct *uc, ram_addr_t begin, size_t size, uc_cb_mmio_read_t read_cb,
                             uc_cb_mmio_write_t write_cb, void *user_data_read, void *user_data_write);
MemoryRegion *memory_cow(struct uc_struct *uc, MemoryRegion *parrent, hwaddr begin, size_t size);
void memory_unmap(struct uc_struct *uc, MemoryRegion *mr);
void memory_moveout(struct uc_struct *uc, MemoryRegion *mr);
void memory_movein(struct uc_struct *uc, MemoryRegion *mr);
int memory_free(struct uc_struct *uc);

#endif
