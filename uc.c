/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "unicorn/unicorn.h"
#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <time.h> // nanosleep
#include <string.h>

#include "uc_priv.h"

// target specific headers
#include "qemu/target/m68k/unicorn.h"
#include "qemu/target/i386/unicorn.h"
#include "qemu/target/arm/unicorn.h"
#include "qemu/target/mips/unicorn.h"
#include "qemu/target/sparc/unicorn.h"
#include "qemu/target/ppc/unicorn.h"
#include "qemu/target/riscv/unicorn.h"
#include "qemu/target/s390x/unicorn.h"
#include "qemu/target/tricore/unicorn.h"

#include "qemu/include/tcg/tcg-apple-jit.h"
#include "qemu/include/qemu/queue.h"
#include "qemu-common.h"

static void clear_deleted_hooks(uc_engine *uc);
static uc_err uc_snapshot(uc_engine *uc);
static uc_err uc_restore_latest_snapshot(uc_engine *uc);

#if defined(__APPLE__) && defined(HAVE_PTHREAD_JIT_PROTECT) &&                 \
    defined(HAVE_SPRR) && (defined(__arm__) || defined(__aarch64__))
static void save_jit_state(uc_engine *uc)
{
    if (!uc->nested) {
        uc->thread_executable_entry = thread_executable();
        uc->current_executable = uc->thread_executable_entry;
    }

    uc->nested += 1;
}

static void restore_jit_state(uc_engine *uc)
{
    assert(uc->nested > 0);
    if (uc->nested == 1) {
        assert(uc->current_executable == thread_executable());
        if (uc->current_executable != uc->thread_executable_entry) {
            if (uc->thread_executable_entry) {
                jit_write_protect(true);
            } else {
                jit_write_protect(false);
            }
        }
    }
    uc->nested -= 1;
}
#else
static void save_jit_state(uc_engine *uc)
{
    (void)uc;
}
static void restore_jit_state(uc_engine *uc)
{
    (void)uc;
}
#endif

static void *hook_insert(struct list *l, struct hook *h)
{
    void *item = list_insert(l, (void *)h);
    if (item) {
        h->refs++;
    }
    return item;
}

static void *hook_append(struct list *l, struct hook *h)
{
    void *item = list_append(l, (void *)h);
    if (item) {
        h->refs++;
    }
    return item;
}

static void hook_invalidate_region(void *key, void *data, void *opaq)
{
    uc_engine *uc = (uc_engine *)opaq;
    HookedRegion *region = (HookedRegion *)key;

    uc->uc_invalidate_tb(uc, region->start, region->length);
}

static void hook_delete(void *data)
{
    struct hook *h = (struct hook *)data;

    h->refs--;

    if (h->refs == 0) {
        g_hash_table_destroy(h->hooked_regions);
        free(h);
    }
}

UNICORN_EXPORT
unsigned int uc_version(unsigned int *major, unsigned int *minor)
{
    if (major != NULL && minor != NULL) {
        *major = UC_API_MAJOR;
        *minor = UC_API_MINOR;
    }

    return (UC_API_MAJOR << 24) + (UC_API_MINOR << 16) + (UC_API_PATCH << 8) +
           UC_API_EXTRA;
}

static uc_err default_reg_read(void *env, int mode, unsigned int regid,
                               void *value, size_t *size)
{
    return UC_ERR_HANDLE;
}

static uc_err default_reg_write(void *env, int mode, unsigned int regid,
                                const void *value, size_t *size, int *setpc)
{
    return UC_ERR_HANDLE;
}

UNICORN_EXPORT
uc_err uc_errno(uc_engine *uc)
{
    return uc->errnum;
}

UNICORN_EXPORT
const char *uc_strerror(uc_err code)
{
    switch (code) {
    default:
        return "Unknown error code";
    case UC_ERR_OK:
        return "OK (UC_ERR_OK)";
    case UC_ERR_NOMEM:
        return "No memory available or memory not present (UC_ERR_NOMEM)";
    case UC_ERR_ARCH:
        return "Invalid/unsupported architecture (UC_ERR_ARCH)";
    case UC_ERR_HANDLE:
        return "Invalid handle (UC_ERR_HANDLE)";
    case UC_ERR_MODE:
        return "Invalid mode (UC_ERR_MODE)";
    case UC_ERR_VERSION:
        return "Different API version between core & binding (UC_ERR_VERSION)";
    case UC_ERR_READ_UNMAPPED:
        return "Invalid memory read (UC_ERR_READ_UNMAPPED)";
    case UC_ERR_WRITE_UNMAPPED:
        return "Invalid memory write (UC_ERR_WRITE_UNMAPPED)";
    case UC_ERR_FETCH_UNMAPPED:
        return "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)";
    case UC_ERR_HOOK:
        return "Invalid hook type (UC_ERR_HOOK)";
    case UC_ERR_INSN_INVALID:
        return "Invalid instruction (UC_ERR_INSN_INVALID)";
    case UC_ERR_MAP:
        return "Invalid memory mapping (UC_ERR_MAP)";
    case UC_ERR_WRITE_PROT:
        return "Write to write-protected memory (UC_ERR_WRITE_PROT)";
    case UC_ERR_READ_PROT:
        return "Read from non-readable memory (UC_ERR_READ_PROT)";
    case UC_ERR_FETCH_PROT:
        return "Fetch from non-executable memory (UC_ERR_FETCH_PROT)";
    case UC_ERR_ARG:
        return "Invalid argument (UC_ERR_ARG)";
    case UC_ERR_READ_UNALIGNED:
        return "Read from unaligned memory (UC_ERR_READ_UNALIGNED)";
    case UC_ERR_WRITE_UNALIGNED:
        return "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)";
    case UC_ERR_FETCH_UNALIGNED:
        return "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)";
    case UC_ERR_RESOURCE:
        return "Insufficient resource (UC_ERR_RESOURCE)";
    case UC_ERR_EXCEPTION:
        return "Unhandled CPU exception (UC_ERR_EXCEPTION)";
    case UC_ERR_OVERFLOW:
        return "Provided buffer is too small (UC_ERR_OVERFLOW)";
    }
}

UNICORN_EXPORT
bool uc_arch_supported(uc_arch arch)
{
    switch (arch) {
#ifdef UNICORN_HAS_ARM
    case UC_ARCH_ARM:
        return true;
#endif
#ifdef UNICORN_HAS_ARM64
    case UC_ARCH_ARM64:
        return true;
#endif
#ifdef UNICORN_HAS_M68K
    case UC_ARCH_M68K:
        return true;
#endif
#ifdef UNICORN_HAS_MIPS
    case UC_ARCH_MIPS:
        return true;
#endif
#ifdef UNICORN_HAS_PPC
    case UC_ARCH_PPC:
        return true;
#endif
#ifdef UNICORN_HAS_SPARC
    case UC_ARCH_SPARC:
        return true;
#endif
#ifdef UNICORN_HAS_X86
    case UC_ARCH_X86:
        return true;
#endif
#ifdef UNICORN_HAS_RISCV
    case UC_ARCH_RISCV:
        return true;
#endif
#ifdef UNICORN_HAS_S390X
    case UC_ARCH_S390X:
        return true;
#endif
#ifdef UNICORN_HAS_TRICORE
    case UC_ARCH_TRICORE:
        return true;
#endif
    /* Invalid or disabled arch */
    default:
        return false;
    }
}

#define UC_INIT(uc)                                                            \
    save_jit_state(uc);                                                        \
    if (unlikely(!(uc)->init_done)) {                                          \
        int __init_ret = uc_init_engine(uc);                                   \
        if (unlikely(__init_ret != UC_ERR_OK)) {                               \
            return __init_ret;                                                 \
        }                                                                      \
    }

static gint uc_exits_cmp(gconstpointer a, gconstpointer b, gpointer user_data)
{
    uint64_t lhs = *((uint64_t *)a);
    uint64_t rhs = *((uint64_t *)b);

    if (lhs < rhs) {
        return -1;
    } else if (lhs == rhs) {
        return 0;
    } else {
        return 1;
    }
}

static uc_err uc_init_engine(uc_engine *uc)
{
    if (uc->init_done) {
        return UC_ERR_HANDLE;
    }

    uc->hooks_to_del.delete_fn = hook_delete;

    for (int i = 0; i < UC_HOOK_MAX; i++) {
        uc->hook[i].delete_fn = hook_delete;
    }

    uc->ctl_exits = g_tree_new_full(uc_exits_cmp, NULL, g_free, NULL);

    if (machine_initialize(uc)) {
        return UC_ERR_RESOURCE;
    }

    // init tlb function
    if (!uc->cpu->cc->tlb_fill) {
        uc->set_tlb(uc, UC_TLB_CPU);
    }

    // init fpu softfloat
    uc->softfloat_initialize();

    if (uc->reg_reset) {
        uc->reg_reset(uc);
    }

    uc->context_content = UC_CTL_CONTEXT_CPU;

    uc->unmapped_regions = g_array_new(false, false, sizeof(MemoryRegion *));

    uc->init_done = true;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_open(uc_arch arch, uc_mode mode, uc_engine **result)
{
    struct uc_struct *uc;

    if (arch < UC_ARCH_MAX) {
        uc = calloc(1, sizeof(*uc));
        if (!uc) {
            // memory insufficient
            return UC_ERR_NOMEM;
        }

        /* qemu/exec.c: phys_map_node_reserve() */
        uc->alloc_hint = 16;
        uc->errnum = UC_ERR_OK;
        uc->arch = arch;
        uc->mode = mode;
        uc->reg_read = default_reg_read;
        uc->reg_write = default_reg_write;

        // uc->ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };
        QLIST_INIT(&uc->ram_list.blocks);

        QTAILQ_INIT(&uc->memory_listeners);

        QTAILQ_INIT(&uc->address_spaces);

        switch (arch) {
        default:
            break;
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:
            if ((mode & ~UC_MODE_M68K_MASK) || !(mode & UC_MODE_BIG_ENDIAN)) {
                free(uc);
                return UC_ERR_MODE;
            }
            uc->init_arch = uc_init_m68k;
            break;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:
            if ((mode & ~UC_MODE_X86_MASK) || (mode & UC_MODE_BIG_ENDIAN) ||
                !(mode & (UC_MODE_16 | UC_MODE_32 | UC_MODE_64))) {
                free(uc);
                return UC_ERR_MODE;
            }
            uc->init_arch = uc_init_x86_64;
            break;
#endif
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            if ((mode & ~UC_MODE_ARM_MASK)) {
                free(uc);
                return UC_ERR_MODE;
            }
            uc->init_arch = uc_init_arm;

            if (mode & UC_MODE_THUMB) {
                uc->thumb = 1;
            }
            break;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64:
            if (mode & ~UC_MODE_ARM_MASK) {
                free(uc);
                return UC_ERR_MODE;
            }
            uc->init_arch = uc_init_aarch64;
            break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) ||                \
    defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
        case UC_ARCH_MIPS:
            if ((mode & ~UC_MODE_MIPS_MASK) ||
                !(mode & (UC_MODE_MIPS32 | UC_MODE_MIPS64))) {
                free(uc);
                return UC_ERR_MODE;
            }
            if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
                if (mode & UC_MODE_MIPS32) {
                    uc->init_arch = uc_init_mips;
                }
#endif
#ifdef UNICORN_HAS_MIPS64
                if (mode & UC_MODE_MIPS64) {
                    uc->init_arch = uc_init_mips64;
                }
#endif
            } else { // little endian
#ifdef UNICORN_HAS_MIPSEL
                if (mode & UC_MODE_MIPS32) {
                    uc->init_arch = uc_init_mipsel;
                }
#endif
#ifdef UNICORN_HAS_MIPS64EL
                if (mode & UC_MODE_MIPS64) {
                    uc->init_arch = uc_init_mips64el;
                }
#endif
            }
            break;
#endif

#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC:
            if ((mode & ~UC_MODE_SPARC_MASK) || !(mode & UC_MODE_BIG_ENDIAN) ||
                !(mode & (UC_MODE_SPARC32 | UC_MODE_SPARC64))) {
                free(uc);
                return UC_ERR_MODE;
            }
            if (mode & UC_MODE_SPARC64) {
                uc->init_arch = uc_init_sparc64;
            } else {
                uc->init_arch = uc_init_sparc;
            }
            break;
#endif
#ifdef UNICORN_HAS_PPC
        case UC_ARCH_PPC:
            if ((mode & ~UC_MODE_PPC_MASK) || !(mode & UC_MODE_BIG_ENDIAN) ||
                !(mode & (UC_MODE_PPC32 | UC_MODE_PPC64))) {
                free(uc);
                return UC_ERR_MODE;
            }
            if (mode & UC_MODE_PPC64) {
                uc->init_arch = uc_init_ppc64;
            } else {
                uc->init_arch = uc_init_ppc;
            }
            break;
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV:
            if ((mode & ~UC_MODE_RISCV_MASK) ||
                !(mode & (UC_MODE_RISCV32 | UC_MODE_RISCV64))) {
                free(uc);
                return UC_ERR_MODE;
            }
            if (mode & UC_MODE_RISCV32) {
                uc->init_arch = uc_init_riscv32;
            } else if (mode & UC_MODE_RISCV64) {
                uc->init_arch = uc_init_riscv64;
            } else {
                free(uc);
                return UC_ERR_MODE;
            }
            break;
#endif
#ifdef UNICORN_HAS_S390X
        case UC_ARCH_S390X:
            if ((mode & ~UC_MODE_S390X_MASK) || !(mode & UC_MODE_BIG_ENDIAN)) {
                free(uc);
                return UC_ERR_MODE;
            }
            uc->init_arch = uc_init_s390x;
            break;
#endif
#ifdef UNICORN_HAS_TRICORE
        case UC_ARCH_TRICORE:
            if ((mode & ~UC_MODE_TRICORE_MASK)) {
                free(uc);
                return UC_ERR_MODE;
            }
            uc->init_arch = uc_init_tricore;
            break;
#endif
        }

        if (uc->init_arch == NULL) {
            free(uc);
            return UC_ERR_ARCH;
        }

        uc->init_done = false;
        uc->cpu_model = INT_MAX; // INT_MAX means the default cpu model.

        *result = uc;

        return UC_ERR_OK;
    } else {
        return UC_ERR_ARCH;
    }
}

UNICORN_EXPORT
uc_err uc_close(uc_engine *uc)
{
    int i;
    MemoryRegion *mr;

    if (!uc->init_done) {
        free(uc);
        return UC_ERR_OK;
    }

    // Cleanup internally.
    if (uc->release) {
        uc->release(uc->tcg_ctx);
    }
    g_free(uc->tcg_ctx);

    // Cleanup CPU.
    g_free(uc->cpu->cpu_ases);
    g_free(uc->cpu->thread);

    /* cpu */
    free(uc->cpu);

    /* flatviews */
    g_hash_table_destroy(uc->flat_views);

    // During flatviews destruction, we may still access memory regions.
    // So we free them afterwards.
    /* memory */
    mr = &uc->io_mem_unassigned;
    mr->destructor(mr);
    mr = uc->system_io;
    mr->destructor(mr);
    mr = uc->system_memory;
    mr->destructor(mr);
    g_free(uc->system_memory);
    g_free(uc->system_io);
    for (size_t i = 0; i < uc->unmapped_regions->len; i++) {
        mr = g_array_index(uc->unmapped_regions, MemoryRegion *, i);
        mr->destructor(mr);
        g_free(mr);
    }
    g_array_free(uc->unmapped_regions, true);

    // Thread relateds.
    if (uc->qemu_thread_data) {
        g_free(uc->qemu_thread_data);
    }

    /* free */
    g_free(uc->init_target_page);

    // Other auxilaries.
    g_free(uc->l1_map);

    if (uc->bounce.buffer) {
        qemu_vfree(uc->bounce.buffer);
    }

    // free hooks and hook lists
    clear_deleted_hooks(uc);

    for (i = 0; i < UC_HOOK_MAX; i++) {
        list_clear(&uc->hook[i]);
    }

    free(uc->mapped_blocks);

    g_tree_destroy(uc->ctl_exits);

    // finally, free uc itself.
    memset(uc, 0, sizeof(*uc));
    free(uc);

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_read_batch(uc_engine *uc, int *regs, void **vals, int count)
{
    UC_INIT(uc);
    reg_read_t reg_read = uc->reg_read;
    void *env = uc->cpu->env_ptr;
    int mode = uc->mode;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        size_t size = (size_t)-1;
        uc_err err = reg_read(env, mode, regid, value, &size);
        if (err) {
            restore_jit_state(uc);
            return err;
        }
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_write_batch(uc_engine *uc, int *regs, void *const *vals,
                          int count)
{
    UC_INIT(uc);
    reg_write_t reg_write = uc->reg_write;
    void *env = uc->cpu->env_ptr;
    int mode = uc->mode;
    int setpc = 0;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        size_t size = (size_t)-1;
        uc_err err = reg_write(env, mode, regid, value, &size, &setpc);
        if (err) {
            restore_jit_state(uc);
            return err;
        }
    }
    if (setpc) {
        // force to quit execution and flush TB
        uc->quit_request = true;
        break_translation_loop(uc);
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_read_batch2(uc_engine *uc, int *regs, void *const *vals,
                          size_t *sizes, int count)
{
    UC_INIT(uc);
    reg_read_t reg_read = uc->reg_read;
    void *env = uc->cpu->env_ptr;
    int mode = uc->mode;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        uc_err err = reg_read(env, mode, regid, value, sizes + i);
        if (err) {
            restore_jit_state(uc);
            return err;
        }
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_write_batch2(uc_engine *uc, int *regs, const void *const *vals,
                           size_t *sizes, int count)
{
    UC_INIT(uc);
    reg_write_t reg_write = uc->reg_write;
    void *env = uc->cpu->env_ptr;
    int mode = uc->mode;
    int setpc = 0;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        uc_err err = reg_write(env, mode, regid, value, sizes + i, &setpc);
        if (err) {
            restore_jit_state(uc);
            return err;
        }
    }
    if (setpc) {
        // force to quit execution and flush TB
        uc->quit_request = true;
        break_translation_loop(uc);
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_read(uc_engine *uc, int regid, void *value)
{
    UC_INIT(uc);
    size_t size = (size_t)-1;
    uc_err err = uc->reg_read(uc->cpu->env_ptr, uc->mode, regid, value, &size);
    restore_jit_state(uc);
    return err;
}

UNICORN_EXPORT
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value)
{
    UC_INIT(uc);
    int setpc = 0;
    size_t size = (size_t)-1;
    uc_err err =
        uc->reg_write(uc->cpu->env_ptr, uc->mode, regid, value, &size, &setpc);
    if (err) {
        restore_jit_state(uc);
        return err;
    }
    if (setpc) {
        // force to quit execution and flush TB
        uc->quit_request = true;
        break_translation_loop(uc);
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_read2(uc_engine *uc, int regid, void *value, size_t *size)
{
    UC_INIT(uc);
    uc_err err = uc->reg_read(uc->cpu->env_ptr, uc->mode, regid, value, size);
    restore_jit_state(uc);
    return err;
}

UNICORN_EXPORT
uc_err uc_reg_write2(uc_engine *uc, int regid, const void *value, size_t *size)
{
    UC_INIT(uc);
    int setpc = 0;
    uc_err err =
        uc->reg_write(uc->cpu->env_ptr, uc->mode, regid, value, size, &setpc);
    if (err) {
        restore_jit_state(uc);
        return err;
    }
    if (setpc) {
        // force to quit execution and flush TB
        uc->quit_request = true;
        break_translation_loop(uc);
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

static size_t memory_region_len(uc_engine *uc, MemoryRegion *mr,
                                uint64_t address, size_t count)
{
    hwaddr end = mr->end;
    while (mr->container != uc->system_memory) {
        mr = mr->container;
        end += mr->addr;
    }
    return (size_t)MIN(count, end - address);
}

// check if a memory area is mapped
// this is complicated because an area can overlap adjacent blocks
static bool check_mem_area(uc_engine *uc, uint64_t address, size_t size)
{
    size_t count = 0, len;

    while (count < size) {
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        if (mr) {
            len = memory_region_len(uc, mr, address, size - count);
            count += len;
            address += len;
        } else { // this address is not mapped in yet
            break;
        }
    }

    return (count == size);
}

UNICORN_EXPORT
uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *_bytes, size_t size)
{
    size_t count = 0, len;
    uint8_t *bytes = _bytes;

    UC_INIT(uc);

    // qemu cpu_physical_memory_rw() size is an int
    if (size > INT_MAX) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    if (!check_mem_area(uc, address, size)) {
        restore_jit_state(uc);
        return UC_ERR_READ_UNMAPPED;
    }

    // memory area can overlap adjacent memory blocks
    while (count < size) {
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        if (mr) {
            len = memory_region_len(uc, mr, address, size - count);
            if (uc->read_mem(&uc->address_space_memory, address, bytes, len) ==
                false) {
                break;
            }
            count += len;
            address += len;
            bytes += len;
        } else { // this address is not mapped in yet
            break;
        }
    }

    if (count == size) {
        restore_jit_state(uc);
        return UC_ERR_OK;
    } else {
        restore_jit_state(uc);
        return UC_ERR_READ_UNMAPPED;
    }
}

UNICORN_EXPORT
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *_bytes,
                    size_t size)
{
    size_t count = 0, len;
    const uint8_t *bytes = _bytes;

    UC_INIT(uc);

    // qemu cpu_physical_memory_rw() size is an int
    if (size > INT_MAX) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    if (!check_mem_area(uc, address, size)) {
        restore_jit_state(uc);
        return UC_ERR_WRITE_UNMAPPED;
    }

    // memory area can overlap adjacent memory blocks
    while (count < size) {
        MemoryRegion *mr = uc->memory_mapping(uc, address);
        if (mr) {
            uint32_t operms = mr->perms;
            uint64_t align = uc->target_page_align;
            if (!(operms & UC_PROT_WRITE)) { // write protected
                // but this is not the program accessing memory, so temporarily
                // mark writable
                uc->readonly_mem(mr, false);
            }

            len = memory_region_len(uc, mr, address, size - count);
            if (uc->snapshot_level && uc->snapshot_level > mr->priority) {
                mr = uc->memory_cow(uc, mr, address & ~align,
                                    (len + (address & align) + align) & ~align);
                if (!mr) {
                    return UC_ERR_NOMEM;
                }
            }
            if (uc->write_mem(&uc->address_space_memory, address, bytes, len) ==
                false) {
                break;
            }

            if (!(operms & UC_PROT_WRITE)) { // write protected
                // now write protect it again
                uc->readonly_mem(mr, true);
            }

            count += len;
            address += len;
            bytes += len;
        } else { // this address is not mapped in yet
            break;
        }
    }

    if (count == size) {
        restore_jit_state(uc);
        return UC_ERR_OK;
    } else {
        restore_jit_state(uc);
        return UC_ERR_WRITE_UNMAPPED;
    }
}

#define TIMEOUT_STEP 2 // microseconds
static void *_timeout_fn(void *arg)
{
    struct uc_struct *uc = arg;
    int64_t current_time = get_clock();

    do {
        usleep(TIMEOUT_STEP);
        // perhaps emulation is even done before timeout?
        if (uc->emulation_done) {
            break;
        }
    } while ((uint64_t)(get_clock() - current_time) < uc->timeout);

    // timeout before emulation is done?
    if (!uc->emulation_done) {
        uc->timed_out = true;
        // force emulation to stop
        uc_emu_stop(uc);
    }

    return NULL;
}

static void enable_emu_timer(uc_engine *uc, uint64_t timeout)
{
    uc->timeout = timeout;
    qemu_thread_create(uc, &uc->timer, "timeout", _timeout_fn, uc,
                       QEMU_THREAD_JOINABLE);
}

static void hook_count_cb(struct uc_struct *uc, uint64_t address, uint32_t size,
                          void *user_data)
{
    // count this instruction. ah ah ah.
    uc->emu_counter++;
    // printf(":: emu counter = %u, at %lx\n", uc->emu_counter, address);

    if (uc->emu_counter > uc->emu_count) {
        // printf(":: emu counter = %u, stop emulation\n", uc->emu_counter);
        uc_emu_stop(uc);
    }
}

static void clear_deleted_hooks(uc_engine *uc)
{
    struct list_item *cur;
    struct hook *hook;
    int i;

    for (cur = uc->hooks_to_del.head;
         cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
        assert(hook->to_delete);
        for (i = 0; i < UC_HOOK_MAX; i++) {
            if (list_remove(&uc->hook[i], (void *)hook)) {
                break;
            }
        }
    }

    list_clear(&uc->hooks_to_del);
}

UNICORN_EXPORT
uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until,
                    uint64_t timeout, size_t count)
{
    uc_err err;

    // reset the counter
    uc->emu_counter = 0;
    uc->invalid_error = UC_ERR_OK;
    uc->emulation_done = false;
    uc->size_recur_mem = 0;
    uc->timed_out = false;
    uc->first_tb = true;

    // Avoid nested uc_emu_start saves wrong jit states.
    if (uc->nested_level == 0) {
        UC_INIT(uc);
    }

    // Advance the nested levels. We must decrease the level count by one when
    // we return from uc_emu_start.
    if (uc->nested_level >= UC_MAX_NESTED_LEVEL) {
        // We can't support so many nested levels.
        return UC_ERR_RESOURCE;
    }
    uc->nested_level++;

    uint32_t begin_pc32 = READ_DWORD(begin);
    switch (uc->arch) {
    default:
        break;
#ifdef UNICORN_HAS_M68K
    case UC_ARCH_M68K:
        uc_reg_write(uc, UC_M68K_REG_PC, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_X86
    case UC_ARCH_X86:
        switch (uc->mode) {
        default:
            break;
        case UC_MODE_16: {
            uint16_t ip;
            uint16_t cs;

            uc_reg_read(uc, UC_X86_REG_CS, &cs);
            // compensate for later adding up IP & CS
            ip = begin - cs * 16;
            uc_reg_write(uc, UC_X86_REG_IP, &ip);
            break;
        }
        case UC_MODE_32:
            uc_reg_write(uc, UC_X86_REG_EIP, &begin_pc32);
            break;
        case UC_MODE_64:
            uc_reg_write(uc, UC_X86_REG_RIP, &begin);
            break;
        }
        break;
#endif
#ifdef UNICORN_HAS_ARM
    case UC_ARCH_ARM:
        uc_reg_write(uc, UC_ARM_REG_R15, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_ARM64
    case UC_ARCH_ARM64:
        uc_reg_write(uc, UC_ARM64_REG_PC, &begin);
        break;
#endif
#ifdef UNICORN_HAS_MIPS
    case UC_ARCH_MIPS:
        // TODO: MIPS32/MIPS64/BIGENDIAN etc
        uc_reg_write(uc, UC_MIPS_REG_PC, &begin_pc32);
        break;
#endif
#ifdef UNICORN_HAS_SPARC
    case UC_ARCH_SPARC:
        // TODO: Sparc/Sparc64
        uc_reg_write(uc, UC_SPARC_REG_PC, &begin);
        break;
#endif
#ifdef UNICORN_HAS_PPC
    case UC_ARCH_PPC:
        if (uc->mode & UC_MODE_PPC64) {
            uc_reg_write(uc, UC_PPC_REG_PC, &begin);
        } else {
            uc_reg_write(uc, UC_PPC_REG_PC, &begin_pc32);
        }
        break;
#endif
#ifdef UNICORN_HAS_RISCV
    case UC_ARCH_RISCV:
        if (uc->mode & UC_MODE_RISCV64) {
            uc_reg_write(uc, UC_RISCV_REG_PC, &begin);
        } else {
            uc_reg_write(uc, UC_RISCV_REG_PC, &begin_pc32);
        }
        break;
#endif
#ifdef UNICORN_HAS_S390X
    case UC_ARCH_S390X:
        uc_reg_write(uc, UC_S390X_REG_PC, &begin);
        break;
#endif
#ifdef UNICORN_HAS_TRICORE
    case UC_ARCH_TRICORE:
        uc_reg_write(uc, UC_TRICORE_REG_PC, &begin_pc32);
        break;
#endif
    }

    uc->stop_request = false;

    uc->emu_count = count;
    // remove count hook if counting isn't necessary
    if (count <= 0 && uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;

        // In this case, we have to drop all translated blocks.
        uc->tb_flush(uc);
    }
    // set up count hook to count instructions.
    if (count > 0 && uc->count_hook == 0) {
        uc_err err;
        // callback to count instructions must be run before everything else,
        // so instead of appending, we must insert the hook at the begin
        // of the hook list
        uc->hook_insert = 1;
        err = uc_hook_add(uc, &uc->count_hook, UC_HOOK_CODE, hook_count_cb,
                          NULL, 1, 0);
        // restore to append mode for uc_hook_add()
        uc->hook_insert = 0;
        if (err != UC_ERR_OK) {
            uc->nested_level--;
            return err;
        }
    }

    // If UC_CTL_UC_USE_EXITS is set, then the @until param won't have any
    // effect. This is designed for the backward compatibility.
    if (!uc->use_exits) {
        uc->exits[uc->nested_level - 1] = until;
    }

    if (timeout) {
        enable_emu_timer(uc, timeout * 1000); // microseconds -> nanoseconds
    }

    uc->vm_start(uc);

    uc->nested_level--;

    // emulation is done if and only if we exit the outer uc_emu_start
    // or we may lost uc_emu_stop
    if (uc->nested_level == 0) {
        uc->emulation_done = true;

        // remove hooks to delete
        // make sure we delete all hooks at the first level.
        clear_deleted_hooks(uc);

        restore_jit_state(uc);
    }

    if (timeout) {
        // wait for the timer to finish
        qemu_thread_join(&uc->timer);
    }

    // We may be in a nested uc_emu_start and thus clear invalid_error
    // once we are done.
    err = uc->invalid_error;
    uc->invalid_error = 0;
    return err;
}

UNICORN_EXPORT
uc_err uc_emu_stop(uc_engine *uc)
{
    UC_INIT(uc);
    uc->stop_request = true;
    uc_err err = break_translation_loop(uc);
    restore_jit_state(uc);
    return err;
}

// return target index where a memory region at the address exists, or could be
// inserted
//
// address either is inside the mapping at the returned index, or is in free
// space before the next mapping.
//
// if there is overlap, between regions, ending address will be higher than the
// starting address of the mapping at returned index
static int bsearch_mapped_blocks(const uc_engine *uc, uint64_t address)
{
    int left, right, mid;
    MemoryRegion *mapping;

    left = 0;
    right = uc->mapped_block_count;

    while (left < right) {
        mid = left + (right - left) / 2;

        mapping = uc->mapped_blocks[mid];

        if (mapping->end - 1 < address) {
            left = mid + 1;
        } else if (mapping->addr > address) {
            right = mid;
        } else {
            return mid;
        }
    }

    return left;
}

// find if a memory range overlaps with existing mapped regions
static bool memory_overlap(struct uc_struct *uc, uint64_t begin, size_t size)
{
    unsigned int i;
    uint64_t end = begin + size - 1;

    i = bsearch_mapped_blocks(uc, begin);

    // is this the highest region with no possible overlap?
    if (i >= uc->mapped_block_count)
        return false;

    // end address overlaps this region?
    if (end >= uc->mapped_blocks[i]->addr)
        return true;

    // not found

    return false;
}

// common setup/error checking shared between uc_mem_map and uc_mem_map_ptr
static uc_err mem_map(uc_engine *uc, MemoryRegion *block)
{

    MemoryRegion **regions;
    int pos;

    if (block == NULL) {
        return UC_ERR_NOMEM;
    }

    if ((uc->mapped_block_count & (MEM_BLOCK_INCR - 1)) == 0) { // time to grow
        regions = (MemoryRegion **)g_realloc(
            uc->mapped_blocks,
            sizeof(MemoryRegion *) * (uc->mapped_block_count + MEM_BLOCK_INCR));
        if (regions == NULL) {
            return UC_ERR_NOMEM;
        }
        uc->mapped_blocks = regions;
    }

    pos = bsearch_mapped_blocks(uc, block->addr);

    // shift the array right to give space for the new pointer
    memmove(&uc->mapped_blocks[pos + 1], &uc->mapped_blocks[pos],
            sizeof(MemoryRegion *) * (uc->mapped_block_count - pos));

    uc->mapped_blocks[pos] = block;
    uc->mapped_block_count++;

    return UC_ERR_OK;
}

static uc_err mem_map_check(uc_engine *uc, uint64_t address, size_t size,
                            uint32_t perms)
{
    if (size == 0) {
        // invalid memory mapping
        return UC_ERR_ARG;
    }

    // address cannot wrapp around
    if (address + size - 1 < address) {
        return UC_ERR_ARG;
    }

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0) {
        return UC_ERR_ARG;
    }

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0) {
        return UC_ERR_ARG;
    }

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0) {
        return UC_ERR_ARG;
    }

    // this area overlaps existing mapped regions?
    if (memory_overlap(uc, address, size)) {
        return UC_ERR_MAP;
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    uc_err res;

    UC_INIT(uc);

    res = mem_map_check(uc, address, size, perms);
    if (res) {
        restore_jit_state(uc);
        return res;
    }

    res = mem_map(uc, uc->memory_map(uc, address, size, perms));
    restore_jit_state(uc);
    return res;
}

UNICORN_EXPORT
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size,
                      uint32_t perms, void *ptr)
{
    uc_err res;

    UC_INIT(uc);

    if (ptr == NULL) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    res = mem_map_check(uc, address, size, perms);
    if (res) {
        restore_jit_state(uc);
        return res;
    }

    res = mem_map(uc, uc->memory_map_ptr(uc, address, size, perms, ptr));
    restore_jit_state(uc);
    return res;
}

UNICORN_EXPORT
uc_err uc_mmio_map(uc_engine *uc, uint64_t address, size_t size,
                   uc_cb_mmio_read_t read_cb, void *user_data_read,
                   uc_cb_mmio_write_t write_cb, void *user_data_write)
{
    uc_err res;

    UC_INIT(uc);

    res = mem_map_check(uc, address, size, UC_PROT_ALL);
    if (res) {
        restore_jit_state(uc);
        return res;
    }

    // The callbacks do not need to be checked for NULL here, as their presence
    // (or lack thereof) will determine the permissions used.
    res = mem_map(uc, uc->memory_map_io(uc, address, size, read_cb, write_cb,
                                        user_data_read, user_data_write));
    restore_jit_state(uc);
    return res;
}

// Create a backup copy of the indicated MemoryRegion.
// Generally used in prepartion for splitting a MemoryRegion.
static uint8_t *copy_region(struct uc_struct *uc, MemoryRegion *mr)
{
    uint8_t *block = (uint8_t *)g_malloc0((size_t)int128_get64(mr->size));
    if (block != NULL) {
        uc_err err =
            uc_mem_read(uc, mr->addr, block, (size_t)int128_get64(mr->size));
        if (err != UC_ERR_OK) {
            free(block);
            block = NULL;
        }
    }

    return block;
}

/*
    This function is similar to split_region, but for MMIO memory.

    Note this function may be called recursively.
*/
static bool split_mmio_region(struct uc_struct *uc, MemoryRegion *mr,
                              uint64_t address, size_t size, bool do_delete)
{
    uint64_t begin, end, chunk_end;
    size_t l_size, r_size, m_size;
    mmio_cbs backup;

    chunk_end = address + size;

    // This branch also break recursion.
    if (address <= mr->addr && chunk_end >= mr->end) {
        return true;
    }

    if (size == 0) {
        return false;
    }

    begin = mr->addr;
    end = mr->end;

    memcpy(&backup, mr->opaque, sizeof(mmio_cbs));

    /* overlapping cases
     *               |------mr------|
     * case 1    |---size--|            // Is it possible???
     * case 2           |--size--|
     * case 3                  |---size--|
     */

    // unmap this region first, then do split it later
    if (uc_mem_unmap(uc, mr->addr, (size_t)int128_get64(mr->size)) !=
        UC_ERR_OK) {
        return false;
    }

    // adjust some things
    if (address < begin) {
        address = begin;
    }
    if (chunk_end > end) {
        chunk_end = end;
    }

    // compute sub region sizes
    l_size = (size_t)(address - begin);
    r_size = (size_t)(end - chunk_end);
    m_size = (size_t)(chunk_end - address);

    if (l_size > 0) {
        if (uc_mmio_map(uc, begin, l_size, backup.read, backup.user_data_read,
                        backup.write, backup.user_data_write) != UC_ERR_OK) {
            return false;
        }
    }

    if (m_size > 0 && !do_delete) {
        if (uc_mmio_map(uc, address, m_size, backup.read, backup.user_data_read,
                        backup.write, backup.user_data_write) != UC_ERR_OK) {
            return false;
        }
    }

    if (r_size > 0) {
        if (uc_mmio_map(uc, chunk_end, r_size, backup.read,
                        backup.user_data_read, backup.write,
                        backup.user_data_write) != UC_ERR_OK) {
            return false;
        }
    }

    return true;
}

/*
   Split the given MemoryRegion at the indicated address for the indicated size
   this may result in the create of up to 3 spanning sections. If the delete
   parameter is true, the no new section will be created to replace the indicate
   range. This functions exists to support uc_mem_protect and uc_mem_unmap.

   This is a static function and callers have already done some preliminary
   parameter validation.

   The do_delete argument indicates that we are being called to support
   uc_mem_unmap. In this case we save some time by choosing NOT to remap
   the areas that are intended to get unmapped
 */
// TODO: investigate whether qemu region manipulation functions already offered
// this capability
static bool split_region(struct uc_struct *uc, MemoryRegion *mr,
                         uint64_t address, size_t size, bool do_delete)
{
    uint8_t *backup;
    uint32_t perms;
    uint64_t begin, end, chunk_end;
    size_t l_size, m_size, r_size;
    RAMBlock *block = NULL;
    bool prealloc = false;

    chunk_end = address + size;

    // if this region belongs to area [address, address+size],
    // then there is no work to do.
    if (address <= mr->addr && chunk_end >= mr->end) {
        return true;
    }

    if (size == 0) {
        // trivial case
        return true;
    }

    if (address >= mr->end || chunk_end <= mr->addr) {
        // impossible case
        return false;
    }

    // Find the correct and large enough (which contains our target mr)
    // to create the content backup.
    block = mr->ram_block;

    if (block == NULL) {
        return false;
    }

    // RAM_PREALLOC is not defined outside exec.c and I didn't feel like
    // moving it
    prealloc = !!(block->flags & 1);

    if (block->flags & 1) {
        backup = block->host;
    } else {
        backup = copy_region(uc, mr);
        if (backup == NULL) {
            return false;
        }
    }

    // save the essential information required for the split before mr gets
    // deleted
    perms = mr->perms;
    begin = mr->addr;
    end = mr->end;

    // unmap this region first, then do split it later
    if (uc_mem_unmap(uc, mr->addr, (size_t)int128_get64(mr->size)) !=
        UC_ERR_OK) {
        goto error;
    }

    /* overlapping cases
     *               |------mr------|
     * case 1    |---size--|
     * case 2           |--size--|
     * case 3                  |---size--|
     */

    // adjust some things
    if (address < begin) {
        address = begin;
    }
    if (chunk_end > end) {
        chunk_end = end;
    }

    // compute sub region sizes
    l_size = (size_t)(address - begin);
    r_size = (size_t)(end - chunk_end);
    m_size = (size_t)(chunk_end - address);

    // If there are error in any of the below operations, things are too far
    // gone at that point to recover. Could try to remap orignal region, but
    // these smaller allocation just failed so no guarantee that we can recover
    // the original allocation at this point
    if (l_size > 0) {
        if (!prealloc) {
            if (uc_mem_map(uc, begin, l_size, perms) != UC_ERR_OK) {
                goto error;
            }
            if (uc_mem_write(uc, begin, backup, l_size) != UC_ERR_OK) {
                goto error;
            }
        } else {
            if (uc_mem_map_ptr(uc, begin, l_size, perms, backup) != UC_ERR_OK) {
                goto error;
            }
        }
    }

    if (m_size > 0 && !do_delete) {
        if (!prealloc) {
            if (uc_mem_map(uc, address, m_size, perms) != UC_ERR_OK) {
                goto error;
            }
            if (uc_mem_write(uc, address, backup + l_size, m_size) !=
                UC_ERR_OK) {
                goto error;
            }
        } else {
            if (uc_mem_map_ptr(uc, address, m_size, perms, backup + l_size) !=
                UC_ERR_OK) {
                goto error;
            }
        }
    }

    if (r_size > 0) {
        if (!prealloc) {
            if (uc_mem_map(uc, chunk_end, r_size, perms) != UC_ERR_OK) {
                goto error;
            }
            if (uc_mem_write(uc, chunk_end, backup + l_size + m_size, r_size) !=
                UC_ERR_OK) {
                goto error;
            }
        } else {
            if (uc_mem_map_ptr(uc, chunk_end, r_size, perms,
                               backup + l_size + m_size) != UC_ERR_OK) {
                goto error;
            }
        }
    }

    if (!prealloc) {
        free(backup);
    }
    return true;

error:
    if (!prealloc) {
        free(backup);
    }
    return false;
}

UNICORN_EXPORT
uc_err uc_mem_protect(struct uc_struct *uc, uint64_t address, size_t size,
                      uint32_t perms)
{
    MemoryRegion *mr;
    uint64_t addr = address;
    uint64_t pc;
    size_t count, len;
    bool remove_exec = false;

    UC_INIT(uc);

    // snapshot and protection can't be mixed
    if (uc->snapshot_level > 0) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    if (size == 0) {
        // trivial case, no change
        restore_jit_state(uc);
        return UC_ERR_OK;
    }

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    // check that user's entire requested block is mapped
    // TODO check if protected is possible
    // deny after cow
    if (!check_mem_area(uc, address, size)) {
        restore_jit_state(uc);
        return UC_ERR_NOMEM;
    }

    // Now we know entire region is mapped, so change permissions
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while (count < size) {
        mr = uc->memory_mapping(uc, addr);
        len = memory_region_len(uc, mr, addr, size - count);
        if (mr->ram) {
            if (!split_region(uc, mr, addr, len, false)) {
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }

            mr = uc->memory_mapping(uc, addr);
            // will this remove EXEC permission?
            if (((mr->perms & UC_PROT_EXEC) != 0) &&
                ((perms & UC_PROT_EXEC) == 0)) {
                remove_exec = true;
            }
            mr->perms = perms;
            uc->readonly_mem(mr, (perms & UC_PROT_WRITE) == 0);

        } else {
            if (!split_mmio_region(uc, mr, addr, len, false)) {
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }

            mr = uc->memory_mapping(uc, addr);
            mr->perms = perms;
        }

        count += len;
        addr += len;
    }

    // if EXEC permission is removed, then quit TB and continue at the same
    // place
    if (remove_exec) {
        pc = uc->get_pc(uc);
        if (pc < address + size && pc >= address) {
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

static uc_err uc_mem_unmap_snapshot(struct uc_struct *uc, uint64_t address,
                                    size_t size, MemoryRegion **ret)
{
    MemoryRegion *mr;

    mr = uc->memory_mapping(uc, address);
    while (mr->container != uc->system_memory) {
        mr = mr->container;
    }

    if (mr->addr != address || int128_get64(mr->size) != size) {
        return UC_ERR_ARG;
    }

    if (ret) {
        *ret = mr;
    }

    uc->memory_moveout(uc, mr);

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_unmap(struct uc_struct *uc, uint64_t address, size_t size)
{
    MemoryRegion *mr;
    uint64_t addr;
    size_t count, len;

    UC_INIT(uc);

    if (size == 0) {
        // nothing to unmap
        restore_jit_state(uc);
        return UC_ERR_OK;
    }

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0) {
        restore_jit_state(uc);
        return UC_ERR_ARG;
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size)) {
        restore_jit_state(uc);
        return UC_ERR_NOMEM;
    }

    if (uc->snapshot_level > 0) {
        uc_err res = uc_mem_unmap_snapshot(uc, address, size, NULL);
        restore_jit_state(uc);
        return res;
    }

    // Now we know entire region is mapped, so do the unmap
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while (count < size) {
        mr = uc->memory_mapping(uc, addr);
        len = memory_region_len(uc, mr, addr, size - count);
        if (!mr->ram) {
            if (!split_mmio_region(uc, mr, addr, len, true)) {
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }
        } else {
            if (!split_region(uc, mr, addr, len, true)) {
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }
        }

        // if we can retrieve the mapping, then no splitting took place
        // so unmap here
        mr = uc->memory_mapping(uc, addr);
        if (mr != NULL) {
            uc->memory_unmap(uc, mr);
        }
        count += len;
        addr += len;
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
                   void *user_data, uint64_t begin, uint64_t end, ...)
{
    int ret = UC_ERR_OK;
    int i = 0;

    UC_INIT(uc);

    struct hook *hook = calloc(1, sizeof(struct hook));
    if (hook == NULL) {
        restore_jit_state(uc);
        return UC_ERR_NOMEM;
    }

    hook->begin = begin;
    hook->end = end;
    hook->type = type;
    hook->callback = callback;
    hook->user_data = user_data;
    hook->refs = 0;
    hook->to_delete = false;
    hook->hooked_regions = g_hash_table_new_full(
        hooked_regions_hash, hooked_regions_equal, g_free, NULL);
    *hh = (uc_hook)hook;

    // UC_HOOK_INSN has an extra argument for instruction ID
    if (type & UC_HOOK_INSN) {
        va_list valist;

        va_start(valist, end);
        hook->insn = va_arg(valist, int);
        va_end(valist);

        if (uc->insn_hook_validate) {
            if (!uc->insn_hook_validate(hook->insn)) {
                free(hook);
                restore_jit_state(uc);
                return UC_ERR_HOOK;
            }
        }

        if (uc->hook_insert) {
            if (hook_insert(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }
        } else {
            if (hook_append(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }
        }

        uc->hooks_count[UC_HOOK_INSN_IDX]++;
        restore_jit_state(uc);
        return UC_ERR_OK;
    }

    if (type & UC_HOOK_TCG_OPCODE) {
        va_list valist;

        va_start(valist, end);
        hook->op = va_arg(valist, int);
        hook->op_flags = va_arg(valist, int);
        va_end(valist);

        if (uc->opcode_hook_invalidate) {
            if (!uc->opcode_hook_invalidate(hook->op, hook->op_flags)) {
                free(hook);
                restore_jit_state(uc);
                return UC_ERR_HOOK;
            }
        }

        if (uc->hook_insert) {
            if (hook_insert(&uc->hook[UC_HOOK_TCG_OPCODE_IDX], hook) == NULL) {
                free(hook);
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }
        } else {
            if (hook_append(&uc->hook[UC_HOOK_TCG_OPCODE_IDX], hook) == NULL) {
                free(hook);
                restore_jit_state(uc);
                return UC_ERR_NOMEM;
            }
        }

        uc->hooks_count[UC_HOOK_TCG_OPCODE_IDX]++;
        return UC_ERR_OK;
    }

    while ((type >> i) > 0) {
        if ((type >> i) & 1) {
            // TODO: invalid hook error?
            if (i < UC_HOOK_MAX) {
                if (uc->hook_insert) {
                    if (hook_insert(&uc->hook[i], hook) == NULL) {
                        free(hook);
                        restore_jit_state(uc);
                        return UC_ERR_NOMEM;
                    }
                } else {
                    if (hook_append(&uc->hook[i], hook) == NULL) {
                        free(hook);
                        restore_jit_state(uc);
                        return UC_ERR_NOMEM;
                    }
                }
                uc->hooks_count[i]++;
            }
        }
        i++;
    }

    // we didn't use the hook
    // TODO: return an error?
    if (hook->refs == 0) {
        free(hook);
    }

    restore_jit_state(uc);
    return ret;
}

UNICORN_EXPORT
uc_err uc_hook_del(uc_engine *uc, uc_hook hh)
{
    int i;
    struct hook *hook = (struct hook *)hh;

    UC_INIT(uc);

    // we can't dereference hook->type if hook is invalid
    // so for now we need to iterate over all possible types to remove the hook
    // which is less efficient
    // an optimization would be to align the hook pointer
    // and store the type mask in the hook pointer.
    for (i = 0; i < UC_HOOK_MAX; i++) {
        if (list_exists(&uc->hook[i], (void *)hook)) {
            g_hash_table_foreach(hook->hooked_regions, hook_invalidate_region,
                                 uc);
            g_hash_table_remove_all(hook->hooked_regions);
            hook->to_delete = true;
            uc->hooks_count[i]--;
            hook_append(&uc->hooks_to_del, hook);
        }
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

// TCG helper
// 2 arguments are enough for most opcodes. Load/Store needs 3 arguments but we
// have memory hooks already. We may exceed the maximum arguments of a tcg
// helper but that's easy to extend.
void helper_uc_traceopcode(struct hook *hook, uint64_t arg1, uint64_t arg2,
                           uint32_t size, void *handle, uint64_t address);
void helper_uc_traceopcode(struct hook *hook, uint64_t arg1, uint64_t arg2,
                           uint32_t size, void *handle, uint64_t address)
{
    struct uc_struct *uc = handle;

    if (unlikely(uc->stop_request)) {
        return;
    }

    if (unlikely(hook->to_delete)) {
        return;
    }

    // We did all checks in translation time.
    //
    // This could optimize the case that we have multiple hooks with different
    // opcodes and have one callback per opcode. Note that the assumption don't
    // hold in most cases for uc_tracecode.
    //
    // TODO: Shall we have a flag to allow users to control whether updating PC?
    JIT_CALLBACK_GUARD(((uc_hook_tcg_op_2)hook->callback)(
        uc, address, arg1, arg2, size, hook->user_data));

    if (unlikely(uc->stop_request)) {
        return;
    }
}

void helper_uc_tracecode(int32_t size, uc_hook_idx index, void *handle,
                         int64_t address);
void helper_uc_tracecode(int32_t size, uc_hook_idx index, void *handle,
                         int64_t address)
{
    struct uc_struct *uc = handle;
    struct list_item *cur;
    struct hook *hook;
    int hook_flags =
        index &
        UC_HOOK_FLAG_MASK; // The index here may contain additional flags. See
                           // the comments of uc_hook_idx for details.

    index = index & UC_HOOK_IDX_MASK;

    // This has been done in tcg code.
    // sync PC in CPUArchState with address
    // if (uc->set_pc) {
    //     uc->set_pc(uc, address);
    // }

    // the last callback may already asked to stop emulation
    if (uc->stop_request && !(hook_flags & UC_HOOK_FLAG_NO_STOP)) {
        return;
    }

    for (cur = uc->hook[index].head;
         cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
        if (hook->to_delete) {
            continue;
        }

        // on invalid block/instruction, call instruction counter (if enable),
        // then quit
        if (size == 0) {
            if (index == UC_HOOK_CODE_IDX && uc->count_hook) {
                // this is the instruction counter (first hook in the list)
                JIT_CALLBACK_GUARD(((uc_cb_hookcode_t)hook->callback)(
                    uc, address, size, hook->user_data));
            }

            return;
        }

        if (HOOK_BOUND_CHECK(hook, (uint64_t)address)) {
            JIT_CALLBACK_GUARD(((uc_cb_hookcode_t)hook->callback)(
                uc, address, size, hook->user_data));
        }

        // the last callback may already asked to stop emulation
        // Unicorn:
        //   In an ARM IT block, we behave like the emulation continues
        //   normally. No check_exit_request is generated and the hooks are
        //   triggered normally. In other words, the whole IT block is treated
        //   as a single instruction.
        if (uc->stop_request && !(hook_flags & UC_HOOK_FLAG_NO_STOP)) {
            break;
        }
    }
}

UNICORN_EXPORT
uc_err uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count)
{
    uint32_t i;
    uc_mem_region *r = NULL;

    UC_INIT(uc);

    *count = uc->mapped_block_count;

    if (*count) {
        r = g_malloc0(*count * sizeof(uc_mem_region));
        if (r == NULL) {
            // out of memory
            restore_jit_state(uc);
            return UC_ERR_NOMEM;
        }
    }

    for (i = 0; i < *count; i++) {
        r[i].begin = uc->mapped_blocks[i]->addr;
        r[i].end = uc->mapped_blocks[i]->end - 1;
        r[i].perms = uc->mapped_blocks[i]->perms;
    }

    *regions = r;

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result)
{
    UC_INIT(uc);

    switch (type) {
    default:
        return UC_ERR_ARG;

    case UC_QUERY_PAGE_SIZE:
        *result = uc->target_page_size;
        break;

    case UC_QUERY_ARCH:
        *result = uc->arch;
        break;

    case UC_QUERY_MODE:
#ifdef UNICORN_HAS_ARM
        if (uc->arch == UC_ARCH_ARM) {
            return uc->query(uc, type, result);
        }
#endif
        *result = uc->mode;
        break;

    case UC_QUERY_TIMEOUT:
        *result = uc->timed_out;
        break;
    }

    restore_jit_state(uc);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_alloc(uc_engine *uc, uc_context **context)
{
    struct uc_context **_context = context;
    size_t size = uc_context_size(uc);

    UC_INIT(uc);

    *_context = g_malloc(size);
    if (*_context) {
        (*_context)->context_size = size - sizeof(uc_context);
        (*_context)->arch = uc->arch;
        (*_context)->mode = uc->mode;
        restore_jit_state(uc);
        return UC_ERR_OK;
    } else {
        restore_jit_state(uc);
        return UC_ERR_NOMEM;
    }
}

UNICORN_EXPORT
uc_err uc_free(void *mem)
{
    g_free(mem);
    return UC_ERR_OK;
}

UNICORN_EXPORT
size_t uc_context_size(uc_engine *uc)
{
    UC_INIT(uc);

    restore_jit_state(uc);
    if (!uc->context_size) {
        // return the total size of struct uc_context
        return sizeof(uc_context) + uc->cpu_context_size;
    } else {
        return sizeof(uc_context) + uc->context_size(uc);
    }
}

UNICORN_EXPORT
uc_err uc_context_save(uc_engine *uc, uc_context *context)
{
    UC_INIT(uc);
    uc_err ret = UC_ERR_OK;

    if (uc->context_content & UC_CTL_CONTEXT_MEMORY) {
        ret = uc_snapshot(uc);
        if (ret != UC_ERR_OK) {
            restore_jit_state(uc);
            return ret;
        }
    }

    context->snapshot_level = uc->snapshot_level;

    if (uc->context_content & UC_CTL_CONTEXT_CPU) {
        if (!uc->context_save) {
            memcpy(context->data, uc->cpu->env_ptr, context->context_size);
            restore_jit_state(uc);
            return UC_ERR_OK;
        } else {
            ret = uc->context_save(uc, context);
            restore_jit_state(uc);
            return ret;
        }
    }
    restore_jit_state(uc);
    return ret;
}

// Keep in mind that we don't a uc_engine when r/w the registers of a context.
static context_reg_rw_t find_context_reg_rw(uc_arch arch, uc_mode mode)
{
    // We believe that the arch/mode pair is correct.
    context_reg_rw_t rw = {default_reg_read, default_reg_write};
    switch (arch) {
    default:
        break;
#ifdef UNICORN_HAS_M68K
    case UC_ARCH_M68K:
        rw.read = reg_read_m68k;
        rw.write = reg_write_m68k;
        break;
#endif
#ifdef UNICORN_HAS_X86
    case UC_ARCH_X86:
        rw.read = reg_read_x86_64;
        rw.write = reg_write_x86_64;
        break;
#endif
#ifdef UNICORN_HAS_ARM
    case UC_ARCH_ARM:
        rw.read = reg_read_arm;
        rw.write = reg_write_arm;
        break;
#endif
#ifdef UNICORN_HAS_ARM64
    case UC_ARCH_ARM64:
        rw.read = reg_read_aarch64;
        rw.write = reg_write_aarch64;
        break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) ||                \
    defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
    case UC_ARCH_MIPS:
        if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
            if (mode & UC_MODE_MIPS32) {
                rw.read = reg_read_mips;
                rw.write = reg_write_mips;
            }
#endif
#ifdef UNICORN_HAS_MIPS64
            if (mode & UC_MODE_MIPS64) {
                rw.read = reg_read_mips64;
                rw.write = reg_write_mips64;
            }
#endif
        } else { // little endian
#ifdef UNICORN_HAS_MIPSEL
            if (mode & UC_MODE_MIPS32) {
                rw.read = reg_read_mipsel;
                rw.write = reg_write_mipsel;
            }
#endif
#ifdef UNICORN_HAS_MIPS64EL
            if (mode & UC_MODE_MIPS64) {
                rw.read = reg_read_mips64el;
                rw.write = reg_write_mips64el;
            }
#endif
        }
        break;
#endif

#ifdef UNICORN_HAS_SPARC
    case UC_ARCH_SPARC:
        if (mode & UC_MODE_SPARC64) {
            rw.read = reg_read_sparc64;
            rw.write = reg_write_sparc64;
        } else {
            rw.read = reg_read_sparc;
            rw.write = reg_write_sparc;
        }
        break;
#endif
#ifdef UNICORN_HAS_PPC
    case UC_ARCH_PPC:
        if (mode & UC_MODE_PPC64) {
            rw.read = reg_read_ppc64;
            rw.write = reg_write_ppc64;
        } else {
            rw.read = reg_read_ppc;
            rw.write = reg_write_ppc;
        }
        break;
#endif
#ifdef UNICORN_HAS_RISCV
    case UC_ARCH_RISCV:
        if (mode & UC_MODE_RISCV32) {
            rw.read = reg_read_riscv32;
            rw.write = reg_write_riscv32;
        } else if (mode & UC_MODE_RISCV64) {
            rw.read = reg_read_riscv64;
            rw.write = reg_write_riscv64;
        }
        break;
#endif
#ifdef UNICORN_HAS_S390X
    case UC_ARCH_S390X:
        rw.read = reg_read_s390x;
        rw.write = reg_write_s390x;
        break;
#endif
#ifdef UNICORN_HAS_TRICORE
    case UC_ARCH_TRICORE:
        rw.read = reg_read_tricore;
        rw.write = reg_write_tricore;
        break;
#endif
    }

    return rw;
}

UNICORN_EXPORT
uc_err uc_context_reg_write(uc_context *ctx, int regid, const void *value)
{
    int setpc = 0;
    size_t size = (size_t)-1;
    return find_context_reg_rw(ctx->arch, ctx->mode)
        .write(ctx->data, ctx->mode, regid, value, &size, &setpc);
}

UNICORN_EXPORT
uc_err uc_context_reg_read(uc_context *ctx, int regid, void *value)
{
    size_t size = (size_t)-1;
    return find_context_reg_rw(ctx->arch, ctx->mode)
        .read(ctx->data, ctx->mode, regid, value, &size);
}

UNICORN_EXPORT
uc_err uc_context_reg_write2(uc_context *ctx, int regid, const void *value,
                             size_t *size)
{
    int setpc = 0;
    return find_context_reg_rw(ctx->arch, ctx->mode)
        .write(ctx->data, ctx->mode, regid, value, size, &setpc);
}

UNICORN_EXPORT
uc_err uc_context_reg_read2(uc_context *ctx, int regid, void *value,
                            size_t *size)
{
    return find_context_reg_rw(ctx->arch, ctx->mode)
        .read(ctx->data, ctx->mode, regid, value, size);
}

UNICORN_EXPORT
uc_err uc_context_reg_write_batch(uc_context *ctx, int *regs, void *const *vals,
                                  int count)
{
    reg_write_t reg_write = find_context_reg_rw(ctx->arch, ctx->mode).write;
    void *env = ctx->data;
    int mode = ctx->mode;
    int setpc = 0;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        size_t size = (size_t)-1;
        uc_err err = reg_write(env, mode, regid, value, &size, &setpc);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_reg_read_batch(uc_context *ctx, int *regs, void **vals,
                                 int count)
{
    reg_read_t reg_read = find_context_reg_rw(ctx->arch, ctx->mode).read;
    void *env = ctx->data;
    int mode = ctx->mode;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        size_t size = (size_t)-1;
        uc_err err = reg_read(env, mode, regid, value, &size);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_reg_write_batch2(uc_context *ctx, int *regs,
                                   const void *const *vals, size_t *sizes,
                                   int count)
{
    reg_write_t reg_write = find_context_reg_rw(ctx->arch, ctx->mode).write;
    void *env = ctx->data;
    int mode = ctx->mode;
    int setpc = 0;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        uc_err err = reg_write(env, mode, regid, value, sizes + i, &setpc);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_reg_read_batch2(uc_context *ctx, int *regs, void *const *vals,
                                  size_t *sizes, int count)
{
    reg_read_t reg_read = find_context_reg_rw(ctx->arch, ctx->mode).read;
    void *env = ctx->data;
    int mode = ctx->mode;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        uc_err err = reg_read(env, mode, regid, value, sizes + i);
        if (err) {
            return err;
        }
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_restore(uc_engine *uc, uc_context *context)
{
    UC_INIT(uc);
    uc_err ret;

    if (uc->context_content & UC_CTL_CONTEXT_MEMORY) {
        uc->snapshot_level = context->snapshot_level;
        ret = uc_restore_latest_snapshot(uc);
        if (ret != UC_ERR_OK) {
            return ret;
        }
        uc_snapshot(uc);
    }

    if (uc->context_content & UC_CTL_CONTEXT_CPU) {
        if (!uc->context_restore) {
            memcpy(uc->cpu->env_ptr, context->data, context->context_size);
            return UC_ERR_OK;
        } else {
            return uc->context_restore(uc, context);
        }
    }
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_free(uc_context *context)
{
    return uc_free(context);
}

typedef struct _uc_ctl_exit_request {
    uint64_t *array;
    size_t len;
} uc_ctl_exit_request;

static inline gboolean uc_read_exit_iter(gpointer key, gpointer val,
                                         gpointer data)
{
    uc_ctl_exit_request *req = (uc_ctl_exit_request *)data;

    req->array[req->len++] = *(uint64_t *)key;

    return false;
}

UNICORN_EXPORT
uc_err uc_ctl(uc_engine *uc, uc_control_type control, ...)
{
    int rw, type;
    uc_err err = UC_ERR_OK;
    va_list args;

    // MSVC Would do signed shift on signed integers.
    rw = (uint32_t)control >> 30;
    type = (control & ((1 << 16) - 1));
    va_start(args, control);

    switch (type) {
    case UC_CTL_UC_MODE: {
        if (rw == UC_CTL_IO_READ) {
            int *pmode = va_arg(args, int *);
            *pmode = uc->mode;
        } else {
            err = UC_ERR_ARG;
        }
        break;
    }

    case UC_CTL_UC_ARCH: {
        if (rw == UC_CTL_IO_READ) {
            int *arch = va_arg(args, int *);
            *arch = uc->arch;
        } else {
            err = UC_ERR_ARG;
        }
        break;
    }

    case UC_CTL_UC_TIMEOUT: {
        if (rw == UC_CTL_IO_READ) {
            uint64_t *arch = va_arg(args, uint64_t *);
            *arch = uc->timeout;
        } else {
            err = UC_ERR_ARG;
        }
        break;
    }

    case UC_CTL_UC_PAGE_SIZE: {
        if (rw == UC_CTL_IO_READ) {

            UC_INIT(uc);

            uint32_t *page_size = va_arg(args, uint32_t *);
            *page_size = uc->target_page_size;

            restore_jit_state(uc);
        } else {
            uint32_t page_size = va_arg(args, uint32_t);
            int bits = 0;

            if (uc->init_done) {
                err = UC_ERR_ARG;
                break;
            }

            if (uc->arch != UC_ARCH_ARM) {
                err = UC_ERR_ARG;
                break;
            }

            if ((page_size & (page_size - 1))) {
                err = UC_ERR_ARG;
                break;
            }

            // Bits is used to calculate the mask
            while (page_size > 1) {
                bits++;
                page_size >>= 1;
            }

            uc->target_bits = bits;

            err = UC_ERR_OK;
        }

        break;
    }

    case UC_CTL_UC_USE_EXITS: {
        if (rw == UC_CTL_IO_WRITE) {
            int use_exits = va_arg(args, int);
            uc->use_exits = use_exits;
        } else {
            err = UC_ERR_ARG;
        }
        break;
    }

    case UC_CTL_UC_EXITS_CNT: {

        UC_INIT(uc);

        if (!uc->use_exits) {
            err = UC_ERR_ARG;
        } else if (rw == UC_CTL_IO_READ) {
            size_t *exits_cnt = va_arg(args, size_t *);
            *exits_cnt = g_tree_nnodes(uc->ctl_exits);
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;
    }

    case UC_CTL_UC_EXITS: {

        UC_INIT(uc);

        if (!uc->use_exits) {
            err = UC_ERR_ARG;
        } else if (rw == UC_CTL_IO_READ) {
            uint64_t *exits = va_arg(args, uint64_t *);
            size_t cnt = va_arg(args, size_t);
            if (cnt < g_tree_nnodes(uc->ctl_exits)) {
                err = UC_ERR_ARG;
            } else {
                uc_ctl_exit_request req;
                req.array = exits;
                req.len = 0;

                g_tree_foreach(uc->ctl_exits, uc_read_exit_iter, (void *)&req);
            }
        } else if (rw == UC_CTL_IO_WRITE) {
            uint64_t *exits = va_arg(args, uint64_t *);
            size_t cnt = va_arg(args, size_t);

            g_tree_remove_all(uc->ctl_exits);

            for (size_t i = 0; i < cnt; i++) {
                uc_add_exit(uc, exits[i]);
            }
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;
    }

    case UC_CTL_CPU_MODEL: {
        if (rw == UC_CTL_IO_READ) {

            UC_INIT(uc);

            int *model = va_arg(args, int *);
            *model = uc->cpu_model;

            save_jit_state(uc);
        } else {
            int model = va_arg(args, int);

            if (model < 0 || uc->init_done) {
                err = UC_ERR_ARG;
                break;
            }

            if (uc->arch == UC_ARCH_X86) {
                if (model >= UC_CPU_X86_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_ARM) {
                if (model >= UC_CPU_ARM_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }

                if (uc->mode & UC_MODE_BIG_ENDIAN) {
                    // These cpu models don't support big endian code access.
                    if (model <= UC_CPU_ARM_CORTEX_A15 &&
                        model >= UC_CPU_ARM_CORTEX_A7) {
                        err = UC_ERR_ARG;
                        break;
                    }
                }
            } else if (uc->arch == UC_ARCH_ARM64) {
                if (model >= UC_CPU_ARM64_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_MIPS) {
                if (uc->mode & UC_MODE_32 && model >= UC_CPU_MIPS32_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }

                if (uc->mode & UC_MODE_64 && model >= UC_CPU_MIPS64_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_PPC) {
                // UC_MODE_PPC32 == UC_MODE_32
                if (uc->mode & UC_MODE_32 && model >= UC_CPU_PPC32_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }

                if (uc->mode & UC_MODE_64 && model >= UC_CPU_PPC64_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_RISCV) {
                if (uc->mode & UC_MODE_32 && model >= UC_CPU_RISCV32_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }

                if (uc->mode & UC_MODE_64 && model >= UC_CPU_RISCV64_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_S390X) {
                if (model >= UC_CPU_S390X_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_SPARC) {
                if (uc->mode & UC_MODE_32 && model >= UC_CPU_SPARC32_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
                if (uc->mode & UC_MODE_64 && model >= UC_CPU_SPARC64_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else if (uc->arch == UC_ARCH_M68K) {
                if (model >= UC_CPU_M68K_ENDING) {
                    err = UC_ERR_ARG;
                    break;
                }
            } else {
                err = UC_ERR_ARG;
                break;
            }

            uc->cpu_model = model;

            err = UC_ERR_OK;
        }
        break;
    }

    case UC_CTL_TB_REQUEST_CACHE: {

        UC_INIT(uc);

        if (rw == UC_CTL_IO_READ_WRITE) {
            uint64_t addr = va_arg(args, uint64_t);
            uc_tb *tb = va_arg(args, uc_tb *);
            err = uc->uc_gen_tb(uc, addr, tb);
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;
    }

    case UC_CTL_TB_REMOVE_CACHE: {

        UC_INIT(uc);

        if (rw == UC_CTL_IO_WRITE) {
            uint64_t addr = va_arg(args, uint64_t);
            uint64_t end = va_arg(args, uint64_t);
            if (end <= addr) {
                err = UC_ERR_ARG;
            } else {
                uc->uc_invalidate_tb(uc, addr, end - addr);
            }
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;
    }

    case UC_CTL_TB_FLUSH:

        UC_INIT(uc);

        if (rw == UC_CTL_IO_WRITE) {
            uc->tb_flush(uc);
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;

    case UC_CTL_TLB_FLUSH:

        UC_INIT(uc);

        if (rw == UC_CTL_IO_WRITE) {
            uc->tcg_flush_tlb(uc);
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;

    case UC_CTL_TLB_TYPE: {

        UC_INIT(uc);

        if (rw == UC_CTL_IO_WRITE) {
            int mode = va_arg(args, int);
            err = uc->set_tlb(uc, mode);
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;
    }

    case UC_CTL_TCG_BUFFER_SIZE: {
        if (rw == UC_CTL_IO_WRITE) {
            uint32_t size = va_arg(args, uint32_t);
            uc->tcg_buffer_size = size;
        } else {

            UC_INIT(uc);

            uint32_t *size = va_arg(args, uint32_t *);
            *size = uc->tcg_buffer_size;

            restore_jit_state(uc);
        }
        break;
    }

    case UC_CTL_CONTEXT_MODE:

        UC_INIT(uc);

        if (rw == UC_CTL_IO_WRITE) {
            int mode = va_arg(args, int);
            uc->context_content = mode;
            err = UC_ERR_OK;
        } else {
            err = UC_ERR_ARG;
        }

        restore_jit_state(uc);
        break;

    default:
        err = UC_ERR_ARG;
        break;
    }

    va_end(args);

    return err;
}

static uc_err uc_snapshot(struct uc_struct *uc)
{
    if (uc->snapshot_level == INT32_MAX) {
        return UC_ERR_RESOURCE;
    }
    uc->snapshot_level++;
    return UC_ERR_OK;
}

static uc_err uc_restore_latest_snapshot(struct uc_struct *uc)
{
    MemoryRegion *subregion, *subregion_next, *mr, *initial_mr;
    int level;

    QTAILQ_FOREACH_SAFE(subregion, &uc->system_memory->subregions,
                        subregions_link, subregion_next)
    {
        uc->memory_filter_subregions(subregion, uc->snapshot_level);
        if (subregion->priority >= uc->snapshot_level ||
            (!subregion->terminates && QTAILQ_EMPTY(&subregion->subregions))) {
            uc->memory_unmap(uc, subregion);
        }
    }

    for (size_t i = uc->unmapped_regions->len; i-- > 0;) {
        mr = g_array_index(uc->unmapped_regions, MemoryRegion *, i);
        // same dirty hack as in memory_moveout see qemu/softmmu/memory.c
        initial_mr = QTAILQ_FIRST(&mr->subregions);
        if (!initial_mr) {
            initial_mr = mr;
        }
        /* same dirty hack as in memory_moveout see qemu/softmmu/memory.c */
        level = (intptr_t)mr->container;
        mr->container = NULL;

        if (level < uc->snapshot_level) {
            break;
        }
        if (memory_overlap(uc, mr->addr, int128_get64(mr->size))) {
            return UC_ERR_MAP;
        }
        uc->memory_movein(uc, mr);
        uc->memory_filter_subregions(mr, uc->snapshot_level);
        if (initial_mr != mr && QTAILQ_EMPTY(&mr->subregions)) {
            uc->memory_unmap(uc, subregion);
        }
        mem_map(uc, initial_mr);
        g_array_remove_range(uc->unmapped_regions, i, 1);
    }
    uc->snapshot_level--;
    return UC_ERR_OK;
}

#ifdef UNICORN_TRACER
uc_tracer *get_tracer()
{
    static uc_tracer tracer;
    return &tracer;
}

void trace_start(uc_tracer *tracer, trace_loc loc)
{
    tracer->starts[loc] = get_clock();
}

void trace_end(uc_tracer *tracer, trace_loc loc, const char *fmt, ...)
{
    va_list args;
    int64_t end = get_clock();

    va_start(args, fmt);

    vfprintf(stderr, fmt, args);

    va_end(args);

    fprintf(stderr, "%.6fus\n",
            (double)(end - tracer->starts[loc]) / (double)(1000));
}
#endif
