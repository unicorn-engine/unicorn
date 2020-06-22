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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef MEMORY_H
#define MEMORY_H

#ifndef CONFIG_USER_ONLY

#define DIRTY_MEMORY_CODE      0

#include "unicorn/platform.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "exec/hwaddr.h"
#include "qemu/int128.h"

#define MAX_PHYS_ADDR_SPACE_BITS 62
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)

typedef struct MemoryRegionOps MemoryRegionOps;

/*
 * Memory region callbacks
 */
struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t (*read)(struct uc_struct* uc, void *opaque,
                     hwaddr addr,
                     unsigned size);
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(struct uc_struct* uc, void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);

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
        bool (*accepts)(void *opaque, hwaddr addr,
                        unsigned size, bool is_write);
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

struct MemoryRegion {
    /* All fields are private - violators will be prosecuted */
    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    ram_addr_t ram_addr;
    uint64_t align;
    bool subpage;
    bool terminates;
    bool ram;
    bool readonly; /* For RAM regions */
    bool enabled;
    int32_t priority;
    bool may_overlap;
    QTAILQ_HEAD(subregions, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    struct uc_struct *uc;
    uint32_t perms;   //all perms, partially redundant with readonly
    uint64_t end;
};

/**
 * MemoryListener: callbacks structure for updates to the physical memory map
 *
 * Allows a component to adjust to changes in the guest-visible memory map.
 * Use with memory_listener_register() and memory_listener_unregister().
 */
struct MemoryListener {
    void (*begin)(MemoryListener *listener);
    void (*commit)(MemoryListener *listener);
    void (*region_add)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_del)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_nop)(MemoryListener *listener, MemoryRegionSection *section);
    /* Lower = earlier (during add), later (during del) */
    unsigned priority;
    AddressSpace *address_space_filter;
    QTAILQ_ENTRY(MemoryListener) link;
};

/**
 * AddressSpace: describes a mapping of addresses to #MemoryRegion objects
 */
struct AddressSpace {
    /* All fields are private. */
    MemoryRegion *root;
    struct FlatView *current_map;
    struct AddressSpaceDispatch *dispatch;
    struct AddressSpaceDispatch *next_dispatch;
    MemoryListener dispatch_listener;
    struct uc_struct* uc;

    QTAILQ_ENTRY(AddressSpace) address_spaces_link;
};

/**
 * MemoryRegionSection: describes a fragment of a #MemoryRegion
 *
 * @mr: the region, or %NULL if empty
 * @address_space: the address space the region is mapped in
 * @offset_within_region: the beginning of the section, relative to @mr's start
 * @size: the size of the section; will not exceed @mr's boundaries
 * @offset_within_address_space: the address of the first byte of the section
 *     relative to the region's address space
 * @readonly: writes to this section are ignored
 */
struct MemoryRegionSection {
    MemoryRegion *mr;
    AddressSpace *address_space;
    hwaddr offset_within_region;
    Int128 size;
    hwaddr offset_within_address_space;
    bool readonly;
};

static inline MemoryRegionSection MemoryRegionSection_make(MemoryRegion *mr, AddressSpace *address_space,
    hwaddr offset_within_region, Int128 size, hwaddr offset_within_address_space, bool readonly)
{
    MemoryRegionSection section;
    section.mr = mr;
    section.address_space = address_space;
    section.offset_within_region = offset_within_region;
    section.size = size;
    section.offset_within_address_space = offset_within_address_space;
    section.readonly = readonly;
    return section;
}

/**
 * memory_region_init: Initialize a memory region
 *
 * The region typically acts as a container for other memory regions.  Use
 * memory_region_add_subregion() to add subregions.
 *
 * @mr: the #MemoryRegion to be initialized
 * @owner: the object that tracks the region's reference count
 * @size: size of the region; any subregions beyond this size will be clipped
 */
void memory_region_init(struct uc_struct *uc, MemoryRegion *mr,
                        uint64_t size);

/**
 * memory_region_init_io: Initialize an I/O memory region.
 *
 * Accesses into the region will cause the callbacks in @ops to be called.
 * if @size is nonzero, subregions will be clipped to @size.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @ops: a structure containing read and write callbacks to be used when
 *       I/O is performed on the region.
 * @opaque: passed to to the read and write callbacks of the @ops structure.
 * @size: size of the region.
 */
void memory_region_init_io(struct uc_struct *uc, MemoryRegion *mr,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           uint64_t size);

/**
 * memory_region_init_ram:  Initialize RAM memory region.  Accesses into the
 *                          region will modify memory directly.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @size: size of the region.
 * @perms: permissions on the region (UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC).
 * @errp: pointer to Error*, to store an error if it happens.
 */
void memory_region_init_ram(struct uc_struct *uc, MemoryRegion *mr,
                            uint64_t size,
                            uint32_t perms);

/**
 * memory_region_init_ram_ptr:  Initialize RAM memory region from a
 *                              user-provided pointer.  Accesses into the
 *                              region will modify memory directly.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @size: size of the region.
 * @ptr: memory to be mapped; must contain at least @size bytes.
 */
void memory_region_init_ram_ptr(struct uc_struct *uc, MemoryRegion *mr,
                                uint64_t size,
                                void *ptr);

/**
 * memory_region_is_ram: check whether a memory region is random access
 *
 * Returns %true is a memory region is random access.
 *
 * @mr: the memory region being queried
 */
bool memory_region_is_ram(MemoryRegion *mr);

/**
 * memory_region_get_ram_ptr: Get a pointer into a RAM memory region.
 *
 * Returns a host pointer to a RAM memory region (created with
 * memory_region_init_ram() or memory_region_init_ram_ptr()).  Use with
 * care.
 *
 * @mr: the memory region being queried.
 */
void *memory_region_get_ram_ptr(MemoryRegion *mr);

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
 * memory_region_get_ram_addr: Get the ram address associated with a memory
 *                             region
 *
 * DO NOT USE THIS FUNCTION.  This is a temporary workaround while the Xen
 * code is being reworked.
 */
ram_addr_t memory_region_get_ram_addr(MemoryRegion *mr);

uint64_t memory_region_get_alignment(const MemoryRegion *mr);

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
 * memory_region_is_mapped: returns true if #MemoryRegion is mapped
 * into any address space.
 *
 * @mr: a #MemoryRegion which should be checked if it's mapped
 */
bool memory_region_is_mapped(MemoryRegion *mr);

/**
 * memory_region_find: translate an address/size relative to a
 * MemoryRegion into a #MemoryRegionSection.
 *
 * Locates the first #MemoryRegion within @mr that overlaps the range
 * given by @addr and @size.
 *
 * Returns a #MemoryRegionSection that describes a contiguous overlap.
 * It will have the following characteristics:
 *    .@size = 0 iff no overlap was found
 *    .@mr is non-%NULL iff an overlap was found
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
 *    .@offset_within_address_space >= @addr
 *    .@offset_within_address_space + .@size <= @addr + @size
 *
 * @mr: a MemoryRegion within which @addr is a relative address
 * @addr: start of the area within @as to be searched
 * @size: size of the area to be searched
 */
MemoryRegionSection memory_region_find(MemoryRegion *mr,
                                       hwaddr addr, uint64_t size);

/**
 * memory_region_transaction_begin: Start a transaction.
 *
 * During a transaction, changes will be accumulated and made visible
 * only when the transaction ends (is committed).
 */
void memory_region_transaction_begin(struct uc_struct*);

/**
 * memory_region_transaction_commit: Commit a transaction and make changes
 *                                   visible to the guest.
 */
void memory_region_transaction_commit(struct uc_struct*);

/**
 * memory_listener_register: register callbacks to be called when memory
 *                           sections are mapped or unmapped into an address
 *                           space
 *
 * @listener: an object containing the callbacks to be called
 * @filter: if non-%NULL, only regions in this address space will be observed
 */
void memory_listener_register(struct uc_struct* uc, MemoryListener *listener, AddressSpace *filter);

/**
 * memory_listener_unregister: undo the effect of memory_listener_register()
 *
 * @listener: an object containing the callbacks to be removed
 */
void memory_listener_unregister(struct uc_struct* uc, MemoryListener *listener);

/**
 * address_space_init: initializes an address space
 *
 * @as: an uninitialized #AddressSpace
 * @root: a #MemoryRegion that routes addesses for the address space
 */
void address_space_init(struct uc_struct *uc, AddressSpace *as, MemoryRegion *root);


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
 * address_space_rw: read from or write to an address space.
 *
 * Return true if the operation hit any unassigned memory or encountered an
 * IOMMU fault.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @buf: buffer with the data transferred
 * @is_write: indicates the transfer direction
 */
bool address_space_rw(AddressSpace *as, hwaddr addr, uint8_t *buf,
                      int len, bool is_write);

/**
 * address_space_write: write to address space.
 *
 * Return true if the operation hit any unassigned memory or encountered an
 * IOMMU fault.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @buf: buffer with the data transferred
 */
bool address_space_write(AddressSpace *as, hwaddr addr,
                         const uint8_t *buf, int len);

/**
 * address_space_read: read from an address space.
 *
 * Return true if the operation hit any unassigned memory or encountered an
 * IOMMU fault.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @buf: buffer with the data transferred
 */
bool address_space_read(AddressSpace *as, hwaddr addr, uint8_t *buf, int len);

/* address_space_translate: translate an address range into an address space
 * into a MemoryRegion and an address range into that section
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @xlat: pointer to address within the returned memory region section's
 * #MemoryRegion.
 * @len: pointer to length
 * @is_write: indicates the transfer direction
 */
MemoryRegion *address_space_translate(AddressSpace *as, hwaddr addr,
                                      hwaddr *xlat, hwaddr *len,
                                      bool is_write);

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
 */
bool address_space_access_valid(AddressSpace *as, hwaddr addr, int len, bool is_write);

/* address_space_map: map a physical memory region into a host virtual address
 *
 * May map a subset of the requested range, given by and returned in @plen.
 * May return %NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @plen: pointer to length of buffer; updated on return
 * @is_write: indicates the transfer direction
 */
void *address_space_map(AddressSpace *as, hwaddr addr,
                        hwaddr *plen, bool is_write);

/* address_space_unmap: Unmaps a memory region previously mapped by address_space_map()
 *
 * Will also mark the memory as dirty if @is_write == %true.  @access_len gives
 * the amount of memory that was actually read or written by the caller.
 *
 * @as: #AddressSpace used
 * @addr: address within that address space
 * @len: buffer length as returned by address_space_map()
 * @access_len: amount of data actually transferred
 * @is_write: indicates the transfer direction
 */
void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
                         int is_write, hwaddr access_len);


MemoryRegion *memory_map(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms);
MemoryRegion *memory_map_ptr(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms, void *ptr);
void memory_unmap(struct uc_struct *uc, MemoryRegion *mr);
int memory_free(struct uc_struct *uc);

#endif

#endif
