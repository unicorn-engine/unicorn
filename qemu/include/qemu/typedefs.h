#ifndef QEMU_TYPEDEFS_H
#define QEMU_TYPEDEFS_H

/*
 * This header is for selectively avoiding #include just to get a
 * typedef name.
 *
 * Declaring a typedef name in its "obvious" place can result in
 * inclusion cycles, in particular for complete struct and union
 * types that need more types for their members.  It can also result
 * in headers pulling in many more headers, slowing down builds.
 *
 * You can break such cycles and unwanted dependencies by declaring
 * the typedef name here.
 *
 * For struct types used in only a few headers, judicious use of the
 * struct tag instead of the typedef name is commonly preferable.
 */

/*
 * Incomplete struct types
 * Please keep this list in case-insensitive alphabetical order.
 */
typedef struct AddressSpace AddressSpace;
typedef struct CPUAddressSpace CPUAddressSpace;
typedef struct CPUState CPUState;
typedef struct FlatView FlatView;
typedef struct IOMMUMemoryRegion IOMMUMemoryRegion;
typedef struct MemoryListener MemoryListener;
typedef struct MemoryMappingList MemoryMappingList;
typedef struct MemoryRegion MemoryRegion;
typedef struct MemoryRegionCache MemoryRegionCache;
typedef struct MemoryRegionSection MemoryRegionSection;
typedef struct QEMUTimer QEMUTimer;
typedef struct QEMUTimerListGroup QEMUTimerListGroup;
typedef struct RAMBlock RAMBlock;
typedef struct Range Range;

/*
 * Pointer types
 * Such typedefs should be limited to cases where the typedef's users
 * are oblivious of its "pointer-ness".
 * Please keep this list in case-insensitive alphabetical order.
 */
typedef struct IRQState *qemu_irq;

#endif /* QEMU_TYPEDEFS_H */
