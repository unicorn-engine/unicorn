/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef UC_PRIV_H
#define UC_PRIV_H

#include "unicorn/platform.h"
#include <stdio.h>

#include "qemu.h"
#include "unicorn/unicorn.h"
#include "list.h"

// These are masks of supported modes for each cpu/arch.
// They should be updated when changes are made to the uc_mode enum typedef.
#define UC_MODE_ARM_MASK                                                       \
    (UC_MODE_ARM | UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN | UC_MODE_MCLASS |    \
     UC_MODE_ARM926 | UC_MODE_ARM946 | UC_MODE_ARM1176 | UC_MODE_BIG_ENDIAN)
#define UC_MODE_MIPS_MASK                                                      \
    (UC_MODE_MIPS32 | UC_MODE_MIPS64 | UC_MODE_LITTLE_ENDIAN |                 \
     UC_MODE_BIG_ENDIAN)
#define UC_MODE_X86_MASK                                                       \
    (UC_MODE_16 | UC_MODE_32 | UC_MODE_64 | UC_MODE_LITTLE_ENDIAN)
#define UC_MODE_PPC_MASK (UC_MODE_PPC32 | UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN)
#define UC_MODE_SPARC_MASK                                                     \
    (UC_MODE_SPARC32 | UC_MODE_SPARC64 | UC_MODE_BIG_ENDIAN)
#define UC_MODE_M68K_MASK (UC_MODE_BIG_ENDIAN)
#define UC_MODE_RISCV_MASK                                                     \
    (UC_MODE_RISCV32 | UC_MODE_RISCV64 | UC_MODE_LITTLE_ENDIAN)

#define ARR_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define READ_QWORD(x) ((uint64_t)x)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_WORD(x) (x & 0xffff)
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)
#define WRITE_DWORD(x, w) (x = (x & ~0xffffffffLL) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | ((b & 0xff) << 8))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))

struct TranslationBlock;

typedef uc_err (*query_t)(struct uc_struct *uc, uc_query_type type,
                          size_t *result);

// return 0 on success, -1 on failure
typedef int (*reg_read_t)(struct uc_struct *uc, unsigned int *regs, void **vals,
                          int count);
typedef int (*reg_write_t)(struct uc_struct *uc, unsigned int *regs,
                           void *const *vals, int count);

typedef int (*context_reg_read_t)(struct uc_context *ctx, unsigned int *regs,
                                  void **vals, int count);
typedef int (*context_reg_write_t)(struct uc_context *ctx, unsigned int *regs,
                                   void *const *vals, int count);
typedef struct {
    context_reg_read_t context_reg_read;
    context_reg_write_t context_reg_write;
} context_reg_rw_t;

typedef void (*reg_reset_t)(struct uc_struct *uc);

typedef bool (*uc_write_mem_t)(AddressSpace *as, hwaddr addr,
                               const uint8_t *buf, int len);

typedef bool (*uc_read_mem_t)(AddressSpace *as, hwaddr addr, uint8_t *buf,
                              int len);

typedef void (*uc_args_void_t)(void *);

typedef void (*uc_args_uc_t)(struct uc_struct *);
typedef void (*uc_args_int_uc_t)(struct uc_struct *);

typedef void (*uc_args_uc_long_t)(struct uc_struct *, unsigned long);

typedef void (*uc_args_uc_u64_t)(struct uc_struct *, uint64_t addr);

typedef MemoryRegion *(*uc_args_uc_ram_size_t)(struct uc_struct *, hwaddr begin,
                                               size_t size, uint32_t perms);

typedef MemoryRegion *(*uc_args_uc_ram_size_ptr_t)(struct uc_struct *,
                                                   hwaddr begin, size_t size,
                                                   uint32_t perms, void *ptr);

typedef void (*uc_mem_unmap_t)(struct uc_struct *, MemoryRegion *mr);

typedef void (*uc_readonly_mem_t)(MemoryRegion *mr, bool readonly);

typedef int (*uc_cpus_init)(struct uc_struct *, const char *);

typedef MemoryRegion *(*uc_memory_map_io_t)(struct uc_struct *uc,
                                            ram_addr_t begin, size_t size,
                                            uc_cb_mmio_read_t read_cb,
                                            uc_cb_mmio_write_t write_cb,
                                            void *user_data_read,
                                            void *user_data_write);

// which interrupt should make emulation stop?
typedef bool (*uc_args_int_t)(struct uc_struct *uc, int intno);

// some architecture redirect virtual memory to physical memory like Mips
typedef uint64_t (*uc_mem_redirect_t)(uint64_t address);

// validate if Unicorn supports hooking a given instruction
typedef bool (*uc_insn_hook_validate)(uint32_t insn_enum);

typedef bool (*uc_opcode_hook_validate_t)(uint32_t op, uint32_t flags);

// init target page
typedef void (*uc_target_page_init)(struct uc_struct *);

// soft float init
typedef void (*uc_softfloat_initialize)(void);

// tcg flush softmmu tlb
typedef void (*uc_tcg_flush_tlb)(struct uc_struct *uc);

// Invalidate the TB at given address
typedef void (*uc_invalidate_tb_t)(struct uc_struct *uc, uint64_t start,
                                   size_t len);

// Request generating TB at given address
typedef uc_err (*uc_gen_tb_t)(struct uc_struct *uc, uint64_t pc, uc_tb *out_tb);

struct hook {
    int type;       // UC_HOOK_*
    int insn;       // instruction for HOOK_INSN
    int refs;       // reference count to free hook stored in multiple lists
    int op;         // opcode for HOOK_TCG_OPCODE
    int op_flags;   // opcode flags for HOOK_TCG_OPCODE
    bool to_delete; // set to true when the hook is deleted by the user. The
                    // destruction of the hook is delayed.
    uint64_t begin, end; // only trigger if PC or memory access is in this
                         // address (depends on hook type)
    void *callback;      // a uc_cb_* type
    void *user_data;
};

// hook list offsets
//
// The lowest 6 bits are used for hook type index while the others
// are used for hook flags.
//
// mirrors the order of uc_hook_type from include/unicorn/unicorn.h
typedef enum uc_hook_idx {
    UC_HOOK_INTR_IDX,
    UC_HOOK_INSN_IDX,
    UC_HOOK_CODE_IDX,
    UC_HOOK_BLOCK_IDX,
    UC_HOOK_MEM_READ_UNMAPPED_IDX,
    UC_HOOK_MEM_WRITE_UNMAPPED_IDX,
    UC_HOOK_MEM_FETCH_UNMAPPED_IDX,
    UC_HOOK_MEM_READ_PROT_IDX,
    UC_HOOK_MEM_WRITE_PROT_IDX,
    UC_HOOK_MEM_FETCH_PROT_IDX,
    UC_HOOK_MEM_READ_IDX,
    UC_HOOK_MEM_WRITE_IDX,
    UC_HOOK_MEM_FETCH_IDX,
    UC_HOOK_MEM_READ_AFTER_IDX,
    UC_HOOK_INSN_INVALID_IDX,
    UC_HOOK_EDGE_GENERATED_IDX,
    UC_HOOK_TCG_OPCODE_IDX,

    UC_HOOK_MAX,
} uc_hook_idx;

// Copy the essential information from TranslationBlock
#define UC_TB_COPY(uc_tb, tb)                                                  \
    do {                                                                       \
        (uc_tb)->pc = tb->pc;                                                  \
        (uc_tb)->icount = tb->icount;                                          \
        (uc_tb)->size = tb->size;                                              \
    } while (0)

// The lowest 6 bits are used for hook type index.
#define UC_HOOK_IDX_MASK ((1 << 6) - 1)

// hook flags
#define UC_HOOK_FLAG_NO_STOP                                                   \
    (1 << 6) // Don't stop emulation in this uc_tracecode.

// The rest of bits are reserved for hook flags.
#define UC_HOOK_FLAG_MASK (~(UC_HOOK_IDX_MASK))

#define HOOK_FOREACH_VAR_DECLARE struct list_item *cur

// for loop macro to loop over hook lists
#define HOOK_FOREACH(uc, hh, idx)                                              \
    for (cur = (uc)->hook[idx##_IDX].head;                                     \
         cur != NULL && ((hh) = (struct hook *)cur->data); cur = cur->next)

// if statement to check hook bounds
#define HOOK_BOUND_CHECK(hh, addr)                                             \
    ((((addr) >= (hh)->begin && (addr) <= (hh)->end) ||                        \
      (hh)->begin > (hh)->end) &&                                              \
     !((hh)->to_delete))

#define HOOK_EXISTS(uc, idx) ((uc)->hook[idx##_IDX].head != NULL)
#define HOOK_EXISTS_BOUNDED(uc, idx, addr)                                     \
    _hook_exists_bounded((uc)->hook[idx##_IDX].head, addr)

static inline bool _hook_exists_bounded(struct list_item *cur, uint64_t addr)
{
    while (cur != NULL) {
        if (HOOK_BOUND_CHECK((struct hook *)cur->data, addr))
            return true;
        cur = cur->next;
    }
    return false;
}

// relloc increment, KEEP THIS A POWER OF 2!
#define MEM_BLOCK_INCR 32

typedef struct TargetPageBits TargetPageBits;
typedef struct TCGContext TCGContext;

struct uc_struct {
    uc_arch arch;
    uc_mode mode;
    uc_err errnum; // qemu/cpu-exec.c
    AddressSpace address_space_memory;
    AddressSpace address_space_io;
    query_t query;
    reg_read_t reg_read;
    reg_write_t reg_write;
    reg_reset_t reg_reset;

    uc_write_mem_t write_mem;
    uc_read_mem_t read_mem;
    uc_args_void_t release;  // release resource when uc_close()
    uc_args_uc_u64_t set_pc; // set PC for tracecode
    uc_args_int_t
        stop_interrupt; // check if the interrupt should stop emulation
    uc_memory_map_io_t memory_map_io;

    uc_args_uc_t init_arch, cpu_exec_init_all;
    uc_args_int_uc_t vm_start;
    uc_args_uc_long_t tcg_exec_init;
    uc_args_uc_ram_size_t memory_map;
    uc_args_uc_ram_size_ptr_t memory_map_ptr;
    uc_mem_unmap_t memory_unmap;
    uc_readonly_mem_t readonly_mem;
    uc_mem_redirect_t mem_redirect;
    uc_cpus_init cpus_init;
    uc_target_page_init target_page;
    uc_softfloat_initialize softfloat_initialize;
    uc_tcg_flush_tlb tcg_flush_tlb;
    uc_invalidate_tb_t uc_invalidate_tb;
    uc_gen_tb_t uc_gen_tb;

    /*  only 1 cpu in unicorn,
        do not need current_cpu to handle current running cpu. */
    CPUState *cpu;

    uc_insn_hook_validate insn_hook_validate;
    uc_opcode_hook_validate_t opcode_hook_invalidate;

    MemoryRegion *system_memory;    // qemu/exec.c
    MemoryRegion *system_io;        // qemu/exec.c
    MemoryRegion io_mem_unassigned; // qemu/exec.c
    RAMList ram_list;               // qemu/exec.c
    /* qemu/exec.c */
    unsigned int alloc_hint;
    /* qemu/exec-vary.c */
    TargetPageBits *init_target_page;
    int target_bits; // User defined page bits by uc_ctl
    int cpu_model;
    BounceBuffer bounce;                // qemu/cpu-exec.c
    volatile sig_atomic_t exit_request; // qemu/cpu-exec.c
    /* qemu/accel/tcg/cpu-exec-common.c */
    /* always be true after call tcg_exec_init(). */
    bool tcg_allowed;
    /* This is a multi-level map on the virtual address space.
       The bottom level has pointers to PageDesc.  */
    void **l1_map; // qemu/accel/tcg/translate-all.c
    size_t l1_map_size;
    /* qemu/accel/tcg/translate-all.c */
    int v_l1_size;
    int v_l1_shift;
    int v_l2_levels;
    /* code generation context */
    TCGContext *tcg_ctx;
    /* memory.c */
    QTAILQ_HEAD(memory_listeners, MemoryListener) memory_listeners;
    QTAILQ_HEAD(, AddressSpace) address_spaces;
    GHashTable *flat_views;
    bool memory_region_update_pending;

    // linked lists containing hooks per type
    struct list hook[UC_HOOK_MAX];
    struct list hooks_to_del;

    // hook to count number of instructions for uc_emu_start()
    uc_hook count_hook;

    size_t emu_counter; // current counter of uc_emu_start()
    size_t emu_count;   // save counter of uc_emu_start()

    int size_recur_mem; // size for mem access when in a recursive call

    bool init_tcg;       // already initialized local TCGv variables?
    bool stop_request;   // request to immediately stop emulation - for
                         // uc_emu_stop()
    bool quit_request;   // request to quit the current TB, but continue to
                         // emulate - for uc_mem_protect()
    bool emulation_done; // emulation is done by uc_emu_start()
    bool timed_out;      // emulation timed out, that can retrieve via
                         // uc_query(UC_QUERY_TIMEOUT)
    QemuThread timer;    // timer for emulation timeout
    uint64_t timeout;    // timeout for uc_emu_start()

    uint64_t invalid_addr; // invalid address to be accessed
    int invalid_error;     // invalid memory code: 1 = READ, 2 = WRITE, 3 = CODE

    int use_exits;
    GTree *exits; // addresses where emulation stops (@until param of
                  // uc_emu_start()) Also see UC_CTL_USE_EXITS for more details.

    int thumb; // thumb mode for ARM
    MemoryRegion **mapped_blocks;
    uint32_t mapped_block_count;
    uint32_t mapped_block_cache_index;
    void *qemu_thread_data; // to support cross compile to Windows
                            // (qemu-thread-win32.c)
    uint32_t target_page_size;
    uint32_t target_page_align;
    uint64_t qemu_host_page_size;
    uint64_t qemu_real_host_page_size;
    int qemu_icache_linesize;
    /* ARCH_REGS_STORAGE_SIZE */
    int cpu_context_size;
    uint64_t next_pc; // save next PC for some special cases
    bool hook_insert; // insert new hook at begin of the hook list (append by
                      // default)
    bool first_tb; // is this the first Translation-Block ever generated since
                   // uc_emu_start()?
    struct list saved_contexts; // The contexts saved by this uc_struct.
    bool no_exit_request;       // Disable check_exit_request temporarily. A
                          // workaround to treat the IT block as a whole block.
    bool init_done; // Whether the initialization is done.
};

// Metadata stub for the variable-size cpu context used with uc_context_*()
// We also save cpu->jmp_env, so emulation can be reentrant
struct uc_context {
    size_t context_size; // size of the real internal context structure
    size_t jmp_env_size; // size of cpu->jmp_env
    uc_mode mode;        // the mode of this context (uc may be free-ed already)
    uc_arch arch;        // the arch of this context (uc may be free-ed already)
    struct uc_struct *uc; // the uc_struct which creates this context
    char data[0];         // context + cpu->jmp_env
};

// check if this address is mapped in (via uc_mem_map())
MemoryRegion *memory_mapping(struct uc_struct *uc, uint64_t address);

// We have to support 32bit system so we can't hold uint64_t on void*
static inline void uc_add_exit(uc_engine *uc, uint64_t addr)
{
    uint64_t *new_exit = g_malloc(sizeof(uint64_t));
    *new_exit = addr;
    g_tree_insert(uc->exits, (gpointer)new_exit, (gpointer)1);
}

// This function has to exist since we would like to accept uint32_t or
// it's complex to achieve so.
static inline int uc_addr_is_exit(uc_engine *uc, uint64_t addr)
{
    return g_tree_lookup(uc->exits, (gpointer)(&addr)) == (gpointer)1;
}

#endif
/* vim: set ts=4 noet:  */
