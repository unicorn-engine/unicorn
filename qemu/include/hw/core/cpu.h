/*
 * QEMU CPU model
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */
#ifndef QEMU_CPU_H
#define QEMU_CPU_H

#include "exec/hwaddr.h"
#include "exec/memattrs.h"
#include "qemu/bitmap.h"
#include "qemu/queue.h"
#include "qemu/thread.h"

/**
 * vaddr:
 * Type wide enough to contain any #target_ulong virtual address.
 */
typedef uint64_t vaddr;
#define VADDR_PRId PRId64
#define VADDR_PRIu PRIu64
#define VADDR_PRIo PRIo64
#define VADDR_PRIx PRIx64
#define VADDR_PRIX PRIX64
#define VADDR_MAX UINT64_MAX

typedef enum MMUAccessType {
    MMU_DATA_LOAD  = 0,
    MMU_DATA_STORE = 1,
    MMU_INST_FETCH = 2
} MMUAccessType;

typedef struct CPUWatchpoint CPUWatchpoint;

struct TranslationBlock;

/**
 * CPUClass:
 * @class_by_name: Callback to map -cpu command line model name to an
 * instantiatable CPU type.
 * @has_work: Callback for checking if there is work to do.
 * @do_interrupt: Callback for interrupt handling.
 * @do_unaligned_access: Callback for unaligned access handling, if
 * the target defines #TARGET_ALIGNED_ONLY.
 * @do_transaction_failed: Callback for handling failed memory transactions
 * (ie bus faults or external aborts; not MMU faults)
 * @get_arch_id: Callback for getting architecture-dependent CPU ID.
 * @get_paging_enabled: Callback for inquiring whether paging is enabled.
 * @get_memory_mapping: Callback for obtaining the memory mappings.
 * @set_pc: Callback for setting the Program Counter register. This
 *       should have the semantics used by the target architecture when
 *       setting the PC from a source such as an ELF file entry point;
 *       for example on Arm it will also set the Thumb mode bit based
 *       on the least significant bit of the new PC value.
 *       If the target behaviour here is anything other than "set
 *       the PC register to the value passed in" then the target must
 *       also implement the synchronize_from_tb hook.
 * @synchronize_from_tb: Callback for synchronizing state from a TCG
 *       #TranslationBlock. This is called when we abandon execution
 *       of a TB before starting it, and must set all parts of the CPU
 *       state which the previous TB in the chain may not have updated.
 *       This always includes at least the program counter; some targets
 *       will need to do more. If this hook is not implemented then the
 *       default is to call @set_pc(tb->pc).
 * @tlb_fill: Callback for handling a softmmu tlb miss or user-only
 *       address fault.  For system mode, if the access is valid, call
 *       tlb_set_page and return true; if the access is invalid, and
 *       probe is true, return false; otherwise raise an exception and
 *       do not return.  For user-only mode, always raise an exception
 *       and do not return.
 * @get_phys_page_debug: Callback for obtaining a physical address.
 * @get_phys_page_attrs_debug: Callback for obtaining a physical address and the
 *       associated memory transaction attributes to use for the access.
 *       CPUs which use memory transaction attributes should implement this
 *       instead of get_phys_page_debug.
 * @asidx_from_attrs: Callback to return the CPU AddressSpace to use for
 *       a memory access with the specified memory transaction attributes.
 * @debug_check_watchpoint: Callback: return true if the architectural
 *       watchpoint whose address has matched should really fire.
 * @debug_excp_handler: Callback for handling debug exceptions.
 * @cpu_exec_enter: Callback for cpu_exec preparation.
 * @cpu_exec_exit: Callback for cpu_exec cleanup.
 * @cpu_exec_interrupt: Callback for processing interrupts in cpu_exec.
 * @adjust_watchpoint_address: Perform a target-specific adjustment to an
 * address before attempting to match it against watchpoints.
 *
 * Represents a CPU family or model.
 */
typedef struct CPUClass {
    /* no DeviceClass->reset(), add here. */
    void (*reset)(CPUState *cpu);
    bool (*has_work)(CPUState *cpu);
    void (*do_interrupt)(CPUState *cpu);
    void (*do_unaligned_access)(CPUState *cpu, vaddr addr,
                                MMUAccessType access_type,
                                int mmu_idx, uintptr_t retaddr);
    int64_t (*get_arch_id)(CPUState *cpu);
    bool (*get_paging_enabled)(const CPUState *cpu);
    void (*get_memory_mapping)(CPUState *cpu, MemoryMappingList *list);
    void (*set_pc)(CPUState *cpu, vaddr value);
    void (*synchronize_from_tb)(CPUState *cpu, struct TranslationBlock *tb);
    bool (*tlb_fill)(CPUState *cpu, vaddr address, int size,
                     MMUAccessType access_type, int mmu_idx,
                     bool probe, uintptr_t retaddr);
    hwaddr (*get_phys_page_debug)(CPUState *cpu, vaddr addr);
    hwaddr (*get_phys_page_attrs_debug)(CPUState *cpu, vaddr addr,
                                        MemTxAttrs *attrs);
    int (*asidx_from_attrs)(CPUState *cpu, MemTxAttrs attrs);
    bool (*debug_check_watchpoint)(CPUState *cpu, CPUWatchpoint *wp);
    void (*debug_excp_handler)(CPUState *cpu);

    void (*cpu_exec_enter)(CPUState *cpu);
    void (*cpu_exec_exit)(CPUState *cpu);
    bool (*cpu_exec_interrupt)(CPUState *cpu, int interrupt_request);

    vaddr (*adjust_watchpoint_address)(CPUState *cpu, vaddr addr, int len);
    void (*tcg_initialize)(struct uc_struct *uc);
} CPUClass;

/*
 * Low 16 bits: number of cycles left, used only in icount mode.
 * High 16 bits: Set to -1 to force TCG to stop executing linked TBs
 * for this CPU and return to its top level loop (even in non-icount mode).
 * This allows a single read-compare-cbranch-write sequence to test
 * for both decrementer underflow and exceptions.
 */
typedef union IcountDecr {
    uint32_t u32;
    struct {
#ifdef HOST_WORDS_BIGENDIAN
        uint16_t high;
        uint16_t low;
#else
        uint16_t low;
        uint16_t high;
#endif
    } u16;
} IcountDecr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/* work queue */

/* The union type allows passing of 64 bit target pointers on 32 bit
 * hosts in a single parameter
 */
typedef union {
    int           host_int;
    unsigned long host_ulong;
    void         *host_ptr;
    vaddr         target_ptr;
} run_on_cpu_data;

#define RUN_ON_CPU_HOST_PTR(p)    ((run_on_cpu_data){.host_ptr = (p)})
#define RUN_ON_CPU_HOST_INT(i)    ((run_on_cpu_data){.host_int = (i)})
#define RUN_ON_CPU_HOST_ULONG(ul) ((run_on_cpu_data){.host_ulong = (ul)})
#define RUN_ON_CPU_TARGET_PTR(v)  ((run_on_cpu_data){.target_ptr = (v)})
#define RUN_ON_CPU_NULL           RUN_ON_CPU_HOST_PTR(NULL)

typedef void (*run_on_cpu_func)(CPUState *cpu, run_on_cpu_data data);

struct qemu_work_item;

#define CPU_UNSET_NUMA_NODE_ID -1
#define CPU_TRACE_DSTATE_MAX_EVENTS 32

/**
 * CPUState:
 * @cpu_index: CPU index (informative).
 * @cluster_index: Identifies which cluster this CPU is in.
 *   For boards which don't define clusters or for "loose" CPUs not assigned
 *   to a cluster this will be UNASSIGNED_CLUSTER_INDEX; otherwise it will
 *   be the same as the cluster-id property of the CPU object's TYPE_CPU_CLUSTER
 *   QOM parent.
 * @nr_cores: Number of cores within this CPU package.
 * @nr_threads: Number of threads within this CPU.
 * @running: #true if CPU is currently running (lockless).
 * @has_waiter: #true if a CPU is currently waiting for the cpu_exec_end;
 * valid under cpu_list_lock.
 * @created: Indicates whether the CPU thread has been successfully created.
 * @interrupt_request: Indicates a pending interrupt request.
 * @halted: Nonzero if the CPU is in suspended state.
 * @stop: Indicates a pending stop request.
 * @stopped: Indicates the CPU has been artificially stopped.
 * @unplug: Indicates a pending CPU unplug request.
 * @crash_occurred: Indicates the OS reported a crash (panic) for this CPU
 * @singlestep_enabled: Flags for single-stepping.
 * @icount_extra: Instructions until next timer event.
 * @can_do_io: Nonzero if memory-mapped IO is safe. Deterministic execution
 * requires that IO only be performed on the last instruction of a TB
 * so that interrupts take effect immediately.
 * @cpu_ases: Pointer to array of CPUAddressSpaces (which define the
 *            AddressSpaces this CPU has)
 * @num_ases: number of CPUAddressSpaces in @cpu_ases
 * @as: Pointer to the first AddressSpace, for the convenience of targets which
 *      only have a single AddressSpace
 * @env_ptr: Pointer to subclass-specific CPUArchState field.
 * @icount_decr_ptr: Pointer to IcountDecr field within subclass.
 * @next_cpu: Next CPU sharing TB cache.
 * @opaque: User data.
 * @mem_io_pc: Host Program Counter at which the memory was accessed.
 * @work_mutex: Lock to prevent multiple access to queued_work_*.
 * @queued_work_first: First asynchronous work pending.
 * @trace_dstate_delayed: Delayed changes to trace_dstate (includes all changes
 *                        to @trace_dstate).
 * @trace_dstate: Dynamic tracing state of events for this vCPU (bitmask).
 * @ignore_memory_transaction_failures: Cached copy of the MachineState
 *    flag of the same name: allows the board to suppress calling of the
 *    CPU do_transaction_failed hook function.
 *
 * State of one CPU core or thread.
 */
struct CPUState {
    int nr_cores;
    int nr_threads;

    struct QemuThread *thread;
#ifdef _WIN32
    HANDLE hThread;
#endif
#if 0
    int thread_id;
    bool running, has_waiter;
    struct QemuCond *halt_cond;
    bool thread_kicked;
#endif
    bool created;
    bool stop;
    bool stopped;
    bool unplug;
    bool crash_occurred;
    bool exit_request;
    bool in_exclusive_context;
    uint32_t cflags_next_tb;
    /* updates protected by BQL */
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_budget;
    int64_t icount_extra;
    uint64_t random_seed;
    sigjmp_buf jmp_env;

    CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    void *env_ptr; /* CPUArchState */
    IcountDecr *icount_decr_ptr;

    /* Accessed in parallel; all accesses must be atomic */
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];

    QTAILQ_ENTRY(CPUState) node;

    /* ice debug support */
    QTAILQ_HEAD(, CPUBreakpoint) breakpoints;

    QTAILQ_HEAD(, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    void *opaque;

    /* In order to avoid passing too many arguments to the MMIO helpers,
     * we store some rarely used information in the CPU context.
     */
    uintptr_t mem_io_pc;

    /* Used for events with 'vcpu' and *without* the 'disabled' properties */
    DECLARE_BITMAP(trace_dstate_delayed, CPU_TRACE_DSTATE_MAX_EVENTS);
    DECLARE_BITMAP(trace_dstate, CPU_TRACE_DSTATE_MAX_EVENTS);

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    int cluster_index;
    uint32_t halted;
    uint32_t can_do_io;
    int32_t exception_index;

    struct uc_struct* uc;

    /* pointer to CPUArchState.cc */
    struct CPUClass *cc;

    // Set to force TCG to stop executing linked TBs for this
    // CPU and return to its top level loop.
    volatile sig_atomic_t tcg_exit_req;
};

#define CPU(obj) ((CPUState *)(obj))
#define CPU_CLASS(class) ((CPUClass *)class)
#define CPU_GET_CLASS(obj) (((CPUState *)obj)->cc)

static inline void cpu_tb_jmp_cache_clear(CPUState *cpu)
{
    unsigned int i;

    for (i = 0; i < TB_JMP_CACHE_SIZE; i++) {
        cpu->tb_jmp_cache[i] = NULL;
    }
}

/**
 * cpu_paging_enabled:
 * @cpu: The CPU whose state is to be inspected.
 *
 * Returns: %true if paging is enabled, %false otherwise.
 */
bool cpu_paging_enabled(const CPUState *cpu);

/**
 * cpu_get_memory_mapping:
 * @cpu: The CPU whose memory mappings are to be obtained.
 * @list: Where to write the memory mappings to.
 */
void cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list);

/**
 * CPUDumpFlags:
 * @CPU_DUMP_CODE:
 * @CPU_DUMP_FPU: dump FPU register state, not just integer
 * @CPU_DUMP_CCOP: dump info about TCG QEMU's condition code optimization state
 */
enum CPUDumpFlags {
    CPU_DUMP_CODE = 0x00010000,
    CPU_DUMP_FPU  = 0x00020000,
    CPU_DUMP_CCOP = 0x00040000,
};

/**
 * cpu_get_phys_page_attrs_debug:
 * @cpu: The CPU to obtain the physical page address for.
 * @addr: The virtual address.
 * @attrs: Updated on return with the memory transaction attributes to use
 *         for this access.
 *
 * Obtains the physical page corresponding to a virtual one, together
 * with the corresponding memory transaction attributes to use for the access.
 * Use it only for debugging because no protection checks are done.
 *
 * Returns: Corresponding physical page address or -1 if no page found.
 */
static inline hwaddr cpu_get_phys_page_attrs_debug(CPUState *cpu, vaddr addr,
                                                   MemTxAttrs *attrs)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->get_phys_page_attrs_debug) {
        return cc->get_phys_page_attrs_debug(cpu, addr, attrs);
    }
    /* Fallback for CPUs which don't implement the _attrs_ hook */
    *attrs = MEMTXATTRS_UNSPECIFIED;
    return cc->get_phys_page_debug(cpu, addr);
}

/**
 * cpu_get_phys_page_debug:
 * @cpu: The CPU to obtain the physical page address for.
 * @addr: The virtual address.
 *
 * Obtains the physical page corresponding to a virtual one.
 * Use it only for debugging because no protection checks are done.
 *
 * Returns: Corresponding physical page address or -1 if no page found.
 */
static inline hwaddr cpu_get_phys_page_debug(CPUState *cpu, vaddr addr)
{
    MemTxAttrs attrs = { 0 };

    return cpu_get_phys_page_attrs_debug(cpu, addr, &attrs);
}

/** cpu_asidx_from_attrs:
 * @cpu: CPU
 * @attrs: memory transaction attributes
 *
 * Returns the address space index specifying the CPU AddressSpace
 * to use for a memory access with the given transaction attributes.
 */
static inline int cpu_asidx_from_attrs(CPUState *cpu, MemTxAttrs attrs)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret = 0;

    if (cc->asidx_from_attrs) {
        ret = cc->asidx_from_attrs(cpu, attrs);
        assert(ret < cpu->num_ases && ret >= 0);
    }
    return ret;
}

/**
 * cpu_reset:
 * @cpu: The CPU whose state is to be reset.
 */
void cpu_reset(CPUState *cpu);

/**
 * cpu_has_work:
 * @cpu: The vCPU to check.
 *
 * Checks whether the CPU has work to do.
 *
 * Returns: %true if the CPU has work, %false otherwise.
 */
static inline bool cpu_has_work(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    g_assert(cc->has_work);
    return cc->has_work(cpu);
}

/**
 * cpu_is_stopped:
 * @cpu: The CPU to check.
 *
 * Checks whether the CPU is stopped.
 *
 * Returns: %true if run state is not running or if artificially stopped;
 * %false otherwise.
 */
bool cpu_is_stopped(CPUState *cpu);

typedef void (*CPUInterruptHandler)(CPUState *, int);

extern CPUInterruptHandler cpu_interrupt_handler;

/**
 * cpu_interrupt:
 * @cpu: The CPU to set an interrupt on.
 * @mask: The interrupts to set.
 *
 * Invokes the interrupt handler.
 */
static inline void cpu_interrupt(CPUState *cpu, int mask)
{
    cpu_interrupt_handler(cpu, mask);
}

#ifdef NEED_CPU_H

static inline void cpu_unaligned_access(CPUState *cpu, vaddr addr,
                                        MMUAccessType access_type,
                                        int mmu_idx, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->do_unaligned_access(cpu, addr, access_type, mmu_idx, retaddr);
}

#endif /* NEED_CPU_H */

/**
 * cpu_set_pc:
 * @cpu: The CPU to set the program counter for.
 * @addr: Program counter value.
 *
 * Sets the program counter for a CPU.
 */
static inline void cpu_set_pc(CPUState *cpu, vaddr addr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->set_pc(cpu, addr);
}

/**
 * cpu_reset_interrupt:
 * @cpu: The CPU to clear the interrupt on.
 * @mask: The interrupt mask to clear.
 *
 * Resets interrupts on the vCPU @cpu.
 */
void cpu_reset_interrupt(CPUState *cpu, int mask);

/**
 * cpu_exit:
 * @cpu: The CPU to exit.
 *
 * Requests the CPU @cpu to exit execution.
 */
void cpu_exit(CPUState *cpu);

/**
 * cpu_resume:
 * @cpu: The CPU to resume.
 *
 * Resumes CPU, i.e. puts CPU into runnable state.
 */
void cpu_resume(CPUState *cpu);

/**
 * qemu_init_vcpu:
 * @cpu: The vCPU to initialize.
 *
 * Initializes a vCPU.
 */
void qemu_init_vcpu(CPUState *cpu);

#define SSTEP_ENABLE  0x1  /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2  /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4  /* Do not Timers while single stepping */

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
/* 0x08 currently unused */
#define BP_GDB                0x10
#define BP_CPU                0x20
#define BP_ANY                (BP_GDB | BP_CPU)
#define BP_WATCHPOINT_HIT_READ 0x40
#define BP_WATCHPOINT_HIT_WRITE 0x80
#define BP_WATCHPOINT_HIT (BP_WATCHPOINT_HIT_READ | BP_WATCHPOINT_HIT_WRITE)

int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags,
                          CPUBreakpoint **breakpoint);
int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags);
void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint);
void cpu_breakpoint_remove_all(CPUState *cpu, int mask);

/* Return true if PC matches an installed breakpoint.  */
static inline bool cpu_breakpoint_test(CPUState *cpu, vaddr pc, int mask)
{
    CPUBreakpoint *bp;

    if (unlikely(!QTAILQ_EMPTY(&cpu->breakpoints))) {
        QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
            if (bp->pc == pc && (bp->flags & mask)) {
                return true;
            }
        }
    }
    return false;
}

int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
                          int flags, CPUWatchpoint **watchpoint);
int cpu_watchpoint_remove(CPUState *cpu, vaddr addr,
                          vaddr len, int flags);
void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint);
void cpu_watchpoint_remove_all(CPUState *cpu, int mask);
void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len,
                          MemTxAttrs attrs, int flags, uintptr_t ra);
int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len);

/**
 * cpu_get_address_space:
 * @cpu: CPU to get address space from
 * @asidx: index identifying which address space to get
 *
 * Return the requested address space of this CPU. @asidx
 * specifies which address space to read.
 */
AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx);

void QEMU_NORETURN cpu_abort(CPUState *cpu, const char *fmt, ...)
    GCC_FMT_ATTR(2, 3);
void cpu_exec_initfn(CPUState *cpu);
void cpu_exec_realizefn(CPUState *cpu);
void cpu_exec_unrealizefn(CPUState *cpu);

/**
 * target_words_bigendian:
 * Returns true if the (default) endianness of the target is big endian,
 * false otherwise. Note that in target-specific code, you can use
 * TARGET_WORDS_BIGENDIAN directly instead. On the other hand, common
 * code should normally never need to know about the endianness of the
 * target, so please do *not* use this function unless you know very well
 * what you are doing!
 */
bool target_words_bigendian(void);

/* use original func name. */
void cpu_class_init(struct uc_struct *uc, CPUClass *k);
void cpu_common_initfn(struct uc_struct *uc, CPUState *cs);

void cpu_stop(struct uc_struct *uc);

#define UNASSIGNED_CPU_INDEX -1
#define UNASSIGNED_CLUSTER_INDEX -1

#endif
