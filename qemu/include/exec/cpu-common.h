#ifndef CPU_COMMON_H
#define CPU_COMMON_H

/* CPU interfaces that are target independent.  */

#include "exec/hwaddr.h"

/* The CPU list lock nests outside page_(un)lock or mmap_(un)lock */
void qemu_init_cpu_list(void);
void cpu_list_lock(void);
void cpu_list_unlock(void);

void tcg_flush_softmmu_tlb(struct uc_struct *uc);

enum device_endian {
    DEVICE_NATIVE_ENDIAN,
    DEVICE_BIG_ENDIAN,
    DEVICE_LITTLE_ENDIAN,
};

#if defined(HOST_WORDS_BIGENDIAN)
#define DEVICE_HOST_ENDIAN DEVICE_BIG_ENDIAN
#else
#define DEVICE_HOST_ENDIAN DEVICE_LITTLE_ENDIAN
#endif

/* address in the RAM (different from a physical address) */
typedef uintptr_t ram_addr_t;
#  define RAM_ADDR_MAX UINTPTR_MAX
#  define RAM_ADDR_FMT "%" PRIxPTR

/* memory API */

typedef void CPUWriteMemoryFunc(void *opaque, hwaddr addr, uint32_t value);
typedef uint32_t CPUReadMemoryFunc(void *opaque, hwaddr addr);

/* This should not be used by devices.  */
ram_addr_t qemu_ram_addr_from_host(struct uc_struct *uc, void *ptr);
RAMBlock *qemu_ram_block_from_host(struct uc_struct *uc, void *ptr,
                                   bool round_offset, ram_addr_t *offset);
ram_addr_t qemu_ram_block_host_offset(RAMBlock *rb, void *host);
void *qemu_ram_get_host_addr(RAMBlock *rb);
ram_addr_t qemu_ram_get_offset(RAMBlock *rb);
ram_addr_t qemu_ram_get_used_length(RAMBlock *rb);
bool qemu_ram_is_shared(RAMBlock *rb);

size_t qemu_ram_pagesize(RAMBlock *block);
size_t qemu_ram_pagesize_largest(void);

bool cpu_physical_memory_rw(AddressSpace *as, hwaddr addr, void *buf,
                            hwaddr len, bool is_write);
static inline void cpu_physical_memory_read(AddressSpace *as, hwaddr addr,
                                            void *buf, hwaddr len)
{
    cpu_physical_memory_rw(as, addr, buf, len, false);
}
static inline void cpu_physical_memory_write(AddressSpace *as, hwaddr addr,
                                             const void *buf, hwaddr len)
{
    cpu_physical_memory_rw(as, addr, (void *)buf, len, true);
}
void *cpu_physical_memory_map(AddressSpace *as, hwaddr addr,
                              hwaddr *plen,
                              bool is_write);
void cpu_physical_memory_unmap(AddressSpace *as, void *buffer, hwaddr len,
                               bool is_write, hwaddr access_len);

bool cpu_physical_memory_is_io(AddressSpace *as, hwaddr phys_addr);

void cpu_flush_icache_range(AddressSpace *as, hwaddr start, hwaddr len);

int ram_block_discard_range(struct uc_struct *uc, RAMBlock *rb, uint64_t start, size_t length);

#endif /* CPU_COMMON_H */
