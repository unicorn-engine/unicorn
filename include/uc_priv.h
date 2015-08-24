/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_PRIV_H
#define UC_PRIV_H

#include <stdint.h>
#include <stdio.h>

#include "qemu.h"
#include "unicorn/unicorn.h"
#include "hook.h"

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

QTAILQ_HEAD(CPUTailQ, CPUState);

typedef struct ModuleEntry {
    void (*init)(void);
    QTAILQ_ENTRY(ModuleEntry) node;
    module_init_type type;
} ModuleEntry;

typedef QTAILQ_HEAD(, ModuleEntry) ModuleTypeList;

// return 0 on success, -1 on failure
typedef int (*reg_read_t)(uch handle, unsigned int regid, void *value);
typedef int (*reg_write_t)(uch handle, unsigned int regid, const void *value);

typedef void (*reg_reset_t)(uch handle);

typedef bool (*uc_write_mem_t)(AddressSpace *as, hwaddr addr, const uint8_t *buf, int len);

typedef bool (*uc_read_mem_t)(AddressSpace *as, hwaddr addr, uint8_t *buf, int len);

typedef void (*uc_args_void_t)(void*);

typedef void (*uc_args_uc_t)(struct uc_struct*);

typedef bool (*uc_args_tcg_enable_t)(struct uc_struct*);

typedef void (*uc_minit_t)(struct uc_struct*, ram_addr_t);

typedef void (*uc_args_uc_long_t)(struct uc_struct*, unsigned long);

typedef void (*uc_args_uc_u64_t)(struct uc_struct *, uint64_t addr);

typedef int (*uc_args_uc_ram_size_t)(struct uc_struct*,  ram_addr_t begin, size_t size);

// which interrupt should make emulation stop?
typedef bool (*uc_args_int_t)(int intno);


struct hook_struct {
    int hook_type; // uc_tracecode_type & uc_tracemem_type
    uint64_t begin, end;    // range of address to be monitored
    void *callback; // either uc_cb_tracecode_t or uc_cb_tracemem_t
    void *user_data;
};

// extend memory to keep 32 more hooks each time
#define HOOK_SIZE 32

struct uc_struct {
    uc_arch arch;
    uc_mode mode;
    QemuMutex qemu_global_mutex; // qemu/cpus.c
    QemuCond qemu_cpu_cond; // qemu/cpus.c
    QemuThread *tcg_cpu_thread; // qemu/cpus.c
    QemuCond *tcg_halt_cond; // qemu/cpus.c
    struct CPUTailQ cpus;   // qemu/cpu-exec.c
    uc_err errnum;  // qemu/cpu-exec.c
    AddressSpace as;
    reg_read_t reg_read;
    reg_write_t reg_write;
    reg_reset_t reg_reset;

    uc_write_mem_t write_mem;
    uc_read_mem_t read_mem;
    uc_args_void_t release;     // release resource when uc_close()
    uc_args_uc_u64_t set_pc;  // set PC for tracecode
    uc_args_int_t stop_interrupt;   // check if the interrupt should stop emulation

    uc_args_uc_t init_arch, pause_all_vcpus, vm_start, cpu_exec_init_all;
    uc_args_tcg_enable_t tcg_enabled;
    uc_args_uc_long_t tcg_exec_init;
    uc_args_uc_ram_size_t memory_map;
    // list of cpu
    void* cpu;

    MemoryRegion *system_memory;    // qemu/exec.c
    MemoryRegion *ram;
    MemoryRegion io_mem_rom;    // qemu/exec.c
    MemoryRegion io_mem_notdirty;   // qemu/exec.c
    MemoryRegion io_mem_unassigned; // qemu/exec.c
    MemoryRegion io_mem_watch;  // qemu/exec.c
    RAMList ram_list;   // qemu/exec.c
    CPUState *next_cpu; // qemu/cpus.c
    BounceBuffer bounce;    // qemu/cpu-exec.c
    volatile sig_atomic_t exit_request; // qemu/cpu-exec.c
    spinlock_t x86_global_cpu_lock; // for X86 arch only
    bool global_dirty_log;  // qemu/memory.c
    /* This is a multi-level map on the virtual address space.
       The bottom level has pointers to PageDesc.  */
    void *l1_map;  // qemu/translate-all.c
    size_t l1_map_size;
    /* code generation context */
    void *tcg_ctx;  // for "TCGContext tcg_ctx" in qemu/translate-all.c
    /* memory.c */
    unsigned memory_region_transaction_depth;
    bool memory_region_update_pending;
    bool ioeventfd_update_pending;
    QemuMutex flat_view_mutex;
    QTAILQ_HEAD(memory_listeners, MemoryListener) memory_listeners;
    QTAILQ_HEAD(, AddressSpace) address_spaces;
    // qom/object.c
    GHashTable *type_table;
    Type type_interface;
    Object *root;
    bool enumerating_types;
    // util/module.c
    ModuleTypeList init_type_list[MODULE_INIT_MAX];
    // hw/intc/apic_common.c
    DeviceState *vapic;
    int apic_no;
    bool mmio_registered;
    bool apic_report_tpr_access;
    CPUState *current_cpu;

    // all the hook callbacks
    size_t hook_size;
    struct hook_struct *hook_callbacks;

    // hook to count number of instructions for uc_emu_start()
    struct hook_struct hook_count;
    uc_cb_hookcode_t hook_count_callback;

    size_t emu_counter; // current counter of uc_emu_start()
    size_t emu_count; // save counter of uc_emu_start()

    // indexes if hooking ALL block/code/read/write events
    unsigned int hook_block_idx, hook_insn_idx, hook_read_idx, hook_write_idx;
    // boolean variables for quick check on hooking block, code, memory accesses
    bool hook_block, hook_insn, hook_mem_read, hook_mem_write;
    uint64_t block_addr;    // save the last block address we hooked
    // indexes to event callbacks
    int hook_mem_idx;  // for handling invalid memory access
    int hook_intr_idx; // for handling interrupt
    int hook_out_idx; // for handling OUT instruction (X86)
    int hook_in_idx; // for handling IN instruction (X86)
    int hook_syscall_idx; // for handling SYSCALL/SYSENTER (X86)


    bool init_tcg;      // already initialized local TCGv variables?
    bool stop_request;  // request to immediately stop emulation - for uc_emu_stop()
    bool emulation_done;  // emulation is done by uc_emu_start()
    QemuThread timer;   // timer for emulation timeout
    uint64_t timeout;   // timeout for uc_emu_start()

    uint64_t invalid_addr;  // invalid address to be accessed
    int invalid_error;  // invalid memory code: 1 = READ, 2 = WRITE, 3 = CODE

    uint64_t addr_end;  // address where emulation stops (@end param of uc_emu_start())

    int thumb;  // thumb mode for ARM
};

#include "qemu_macro.h"

// check if this address is mapped in (via uc_mem_map())
bool memory_mapping(uint64_t address);

#endif
