/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <time.h>   // nanosleep
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

#include "qemu/include/qemu/queue.h"

#ifdef UNICORN_HAS_AFL
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>
#include "afl/config.h"
#include "afl/types.h"
#endif

UNICORN_EXPORT
unsigned int uc_version(unsigned int *major, unsigned int *minor)
{
    if (major != NULL && minor != NULL) {
        *major = UC_API_MAJOR;
        *minor = UC_API_MINOR;
    }

    return (UC_API_MAJOR << 8) + UC_API_MINOR;
}


UNICORN_EXPORT
uc_err uc_errno(uc_engine *uc)
{
    return uc->errnum;
}


UNICORN_EXPORT
const char *uc_strerror(uc_err code)
{
    switch(code) {
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
        case UC_ERR_AFL_RET_ERROR:
            return "Something went horribly wrong in the parent (UC_ERR_AFL_RET_ERROR)";
        case UC_ERR_AFL_RET_NO_AFL:
            return "No AFL, no need to fork (UC_ERR_AFL_RET_NO_AFL)";
        case UC_ERR_AFL_RET_CALLED_TWICE:
            return "AFL has already been started before (UC_ERR_AFL_RET_CALLED_TWICE)";
        case UC_ERR_AFL_RET_FINISHED:
            return "We forked before but now parent is gone (UC_ERR_AFL_RET_FINISHED)";
    }
}


UNICORN_EXPORT
bool uc_arch_supported(uc_arch arch)
{
    switch (arch) {
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:   return true;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64: return true;
#endif
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:  return true;
#endif
#ifdef UNICORN_HAS_MIPS
        case UC_ARCH_MIPS:  return true;
#endif
#ifdef UNICORN_HAS_PPC
        case UC_ARCH_PPC:   return true;
#endif
#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC: return true;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:   return true;
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV:   return true;
#endif
        /* Invalid or disabled arch */
        default:            return false;
    }
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

        if (mode & UC_MODE_AFL) {
            uc->afl = true;
            mode &= (~UC_MODE_AFL);
        }

        /* qemu/exec.c: phys_map_node_reserve() */
        uc->alloc_hint = 16;
        uc->errnum = UC_ERR_OK;
        uc->arch = arch;
        uc->mode = mode;

        // uc->ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };
        QLIST_INIT(&uc->ram_list.blocks);

        QTAILQ_INIT(&uc->memory_listeners);

        QTAILQ_INIT(&uc->address_spaces);

        switch(arch) {
            default:
                break;
#ifdef UNICORN_HAS_M68K
            case UC_ARCH_M68K:
                if ((mode & ~UC_MODE_M68K_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN)) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                uc->init_arch = m68k_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_X86
            case UC_ARCH_X86:
                if ((mode & ~UC_MODE_X86_MASK) ||
                        (mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_16|UC_MODE_32|UC_MODE_64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                uc->init_arch = x86_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_ARM
            case UC_ARCH_ARM:
                if ((mode & ~UC_MODE_ARM_MASK)) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
                    uc->init_arch = armeb_uc_init;
                } else {
                    uc->init_arch = arm_uc_init;
                }

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
                if (mode & UC_MODE_BIG_ENDIAN) {
                    uc->init_arch = arm64eb_uc_init;
                } else {
                    uc->init_arch = arm64_uc_init;
                }
                break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) || defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
            case UC_ARCH_MIPS:
                if ((mode & ~UC_MODE_MIPS_MASK) ||
                        !(mode & (UC_MODE_MIPS32|UC_MODE_MIPS64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
                    if (mode & UC_MODE_MIPS32) {
                        uc->init_arch = mips_uc_init;
                    }
#endif
#ifdef UNICORN_HAS_MIPS64
                    if (mode & UC_MODE_MIPS64) {
                        uc->init_arch = mips64_uc_init;
                    }
#endif
                } else {    // little endian
#ifdef UNICORN_HAS_MIPSEL
                    if (mode & UC_MODE_MIPS32) {
                        uc->init_arch = mipsel_uc_init;
                    }
#endif
#ifdef UNICORN_HAS_MIPS64EL
                    if (mode & UC_MODE_MIPS64) {
                        uc->init_arch = mips64el_uc_init;
                    }
#endif
                }
                break;
#endif

#ifdef UNICORN_HAS_SPARC
            case UC_ARCH_SPARC:
                if ((mode & ~UC_MODE_SPARC_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_SPARC32|UC_MODE_SPARC64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_SPARC64) {
                    uc->init_arch = sparc64_uc_init;
                } else {
                    uc->init_arch = sparc_uc_init;
                }
                break;
#endif
#ifdef UNICORN_HAS_PPC
            case UC_ARCH_PPC:
                if ((mode & ~UC_MODE_PPC_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_PPC32|UC_MODE_PPC64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_PPC64) {
                    uc->init_arch = ppc64_uc_init;
                } else {
                    uc->init_arch = ppc_uc_init;
                }
                break;
#endif
#ifdef UNICORN_HAS_RISCV
            case UC_ARCH_RISCV:
                if ((mode & ~UC_MODE_RISCV_MASK) ||
                        !(mode & (UC_MODE_RISCV32|UC_MODE_RISCV64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_RISCV32) {
                    uc->init_arch = riscv32_uc_init;
                } else if (mode & UC_MODE_RISCV64) {
                    uc->init_arch =riscv64_uc_init;
                } else {
                    free(uc);
                    return UC_ERR_MODE;
                }
                break;
#endif

        }

        if (uc->init_arch == NULL) {
            return UC_ERR_ARCH;
        }

        if (machine_initialize(uc)) {
            return UC_ERR_RESOURCE;
        }

        // init fpu softfloat
        uc->softfloat_initialize();

        *result = uc;

        if (uc->reg_reset) {
            uc->reg_reset(uc);
        }

        return UC_ERR_OK;
    } else {
        return UC_ERR_ARCH;
    }
}


UNICORN_EXPORT
uc_err uc_close(uc_engine *uc)
{
    int i;
    struct list_item *cur;
    struct hook *hook;
    MemoryRegion *mr;

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

    // Thread relateds.
    if (uc->qemu_thread_data) {
        g_free(uc->qemu_thread_data);
    }

    /* free */
    g_free(uc->init_target_page);

    // Other auxilaries.
    g_free(uc->l1_map);

    if (uc->bounce.buffer) {
        free(uc->bounce.buffer);
    }

    // free hooks and hook lists
    for (i = 0; i < UC_HOOK_MAX; i++) {
        cur = uc->hook[i].head;
        // hook can be in more than one list
        // so we refcount to know when to free
        while (cur) {
            hook = (struct hook *)cur->data;
            if (--hook->refs == 0) {
                free(hook);
            }
            cur = cur->next;
        }
        list_clear(&uc->hook[i]);
    }

    free(uc->mapped_blocks);

    // free the saved contexts list and notify them that uc has been closed.
    cur = uc->saved_contexts.head;
    while (cur != NULL) {
        struct list_item *next = cur->next;
        struct uc_context *context = (struct uc_context*)cur->data;
        context->uc = NULL;
        cur = next;
    }
    list_clear(&uc->saved_contexts);

    // finally, free uc itself.
    memset(uc, 0, sizeof(*uc));
    free(uc);

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_reg_read_batch(uc_engine *uc, int *ids, void **vals, int count)
{
    int ret = UC_ERR_OK;
    if (uc->reg_read) {
        ret = uc->reg_read(uc, (unsigned int *)ids, vals, count);
    } else {
        return UC_ERR_HANDLE;
    }

    return ret;
}


UNICORN_EXPORT
uc_err uc_reg_write_batch(uc_engine *uc, int *ids, void *const *vals, int count)
{
    int ret = UC_ERR_OK;
    if (uc->reg_write) {
        ret = uc->reg_write(uc, (unsigned int *)ids, vals, count);
    } else {
        return UC_ERR_HANDLE;
    }

    return ret;
}


UNICORN_EXPORT
uc_err uc_reg_read(uc_engine *uc, int regid, void *value)
{
    return uc_reg_read_batch(uc, &regid, &value, 1);
}

UNICORN_EXPORT
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value)
{
    return uc_reg_write_batch(uc, &regid, (void *const *)&value, 1);
}

// check if a memory area is mapped
// this is complicated because an area can overlap adjacent blocks
static bool check_mem_area(uc_engine *uc, uint64_t address, size_t size)
{
    size_t count = 0, len;

    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            count += len;
            address += len;
        } else {// this address is not mapped in yet
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

    // qemu cpu_physical_memory_rw() size is an int
    if (size > INT_MAX)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    if (!check_mem_area(uc, address, size)) {
        return UC_ERR_READ_UNMAPPED;
    }

    // memory area can overlap adjacent memory blocks
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            if (uc->read_mem(&uc->address_space_memory, address, bytes, len) == false) {
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
        return UC_ERR_OK;
    } else {
        return UC_ERR_READ_UNMAPPED;
    }
}

UNICORN_EXPORT
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *_bytes, size_t size)
{
    size_t count = 0, len;
    const uint8_t *bytes = _bytes;

    // qemu cpu_physical_memory_rw() size is an int
    if (size > INT_MAX)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    if (!check_mem_area(uc, address, size)) {
        return UC_ERR_WRITE_UNMAPPED;
    }

    // memory area can overlap adjacent memory blocks
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            uint32_t operms = mr->perms;
            if (!(operms & UC_PROT_WRITE)) {// write protected
                // but this is not the program accessing memory, so temporarily mark writable
                uc->readonly_mem(mr, false);
            }

            len = (size_t)MIN(size - count, mr->end - address);
            if (uc->write_mem(&uc->address_space_memory, address, bytes, len) == false) {
                break;
            }

            if (!(operms & UC_PROT_WRITE)) {// write protected
                // now write protect it again
                uc->readonly_mem(mr, true);
            }

            count += len;
            address += len;
            bytes += len;
        } else {// this address is not mapped in yet
            break;
        }
    }

    if (count == size) {
        return UC_ERR_OK;
    } else {
        return UC_ERR_WRITE_UNMAPPED;
    }
}

#define TIMEOUT_STEP 2    // microseconds
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
    } while((uint64_t)(get_clock() - current_time) < uc->timeout);

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
    qemu_thread_create(uc, &uc->timer, "timeout", _timeout_fn,
            uc, QEMU_THREAD_JOINABLE);
}

static void hook_count_cb(struct uc_struct *uc, uint64_t address, uint32_t size, void *user_data)
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
    struct list_item * cur;
    struct hook * hook;
    int i;
    
    for (cur = uc->hooks_to_del.head; cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
        assert(hook->to_delete);
        for (i = 0; i < UC_HOOK_MAX; i++) {
            if (list_remove(&uc->hook[i], (void *)hook)) {
                if (--hook->refs == 0) {
                    free(hook);
                }

                // a hook cannot be twice in the same list
                break;
            }
        }
    }

    list_clear(&uc->hooks_to_del);
}

UNICORN_EXPORT
uc_err uc_emu_start(uc_engine* uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
    // reset the counter
    uc->emu_counter = 0;
    uc->invalid_error = UC_ERR_OK;
    uc->emulation_done = false;
    uc->size_recur_mem = 0;
    uc->timed_out = false;
    uc->first_tb = true;

    switch(uc->arch) {
        default:
            break;
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:
            uc_reg_write(uc, UC_M68K_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_16: {
                    uint64_t ip;
                    uint16_t cs;

                    uc_reg_read(uc, UC_X86_REG_CS, &cs);
                    // compensate for later adding up IP & CS
                    ip = begin - cs*16;
                    uc_reg_write(uc, UC_X86_REG_IP, &ip);
                    break;
                }
                case UC_MODE_32:
                    uc_reg_write(uc, UC_X86_REG_EIP, &begin);
                    break;
                case UC_MODE_64:
                    uc_reg_write(uc, UC_X86_REG_RIP, &begin);
                    break;
            }
            break;
#endif
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            uc_reg_write(uc, UC_ARM_REG_R15, &begin);
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
            uc_reg_write(uc, UC_MIPS_REG_PC, &begin);
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
            uc_reg_write(uc, UC_PPC_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV:
            uc_reg_write(uc, UC_RISCV_REG_PC, &begin);
            break;
#endif
    }

    uc->stop_request = false;

    uc->emu_count = count;
    // remove count hook if counting isn't necessary
    if (count <= 0 && uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
    }
    // set up count hook to count instructions.
    if (count > 0 && uc->count_hook == 0) {
        uc_err err;
        // callback to count instructions must be run before everything else,
        // so instead of appending, we must insert the hook at the begin
        // of the hook list
        uc->hook_insert = 1;
        err = uc_hook_add(uc, &uc->count_hook, UC_HOOK_CODE, hook_count_cb, NULL, 1, 0);
        // restore to append mode for uc_hook_add()
        uc->hook_insert = 0;
        if (err != UC_ERR_OK) {
            return err;
        }
    }

    uc->addr_end = until;

    if (timeout) {
        enable_emu_timer(uc, timeout * 1000);   // microseconds -> nanoseconds
    }

    uc->vm_start(uc);

    // emulation is done
    uc->emulation_done = true;

    // remove hooks to delete
    clear_deleted_hooks(uc);

    if (timeout) {
        // wait for the timer to finish
        qemu_thread_join(&uc->timer);
    }

    return uc->invalid_error;
}


static inline uc_afl_ret uc_afl_forkserver_start(uc_engine *uc, uint64_t *exits, size_t exit_count)
{
    /*
    Why we need exits as parameter to forkserver:
    In the original unicorn-afl, Unicorn needed to flush the tb cache for every iteration.
    This is super slow.
    Problem was, that the original forked server doesn't know about possible future exits.
    The cached blocks, in the next child, therefore would have no exit set and run forever.
    Also it's nice to have multiple exits, so let's just do it right.
    */

    if (!uc) {
        fprintf(stderr, "[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exits) {
        fprintf(stderr, "[!] Nullptr provided for exits.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exit_count) {
        fprintf(stderr, "[!] No exits provided (exit_count was 0).\n");
        return UC_AFL_RET_ERROR;
    }
    if (unlikely(uc->afl_area_ptr)) {
#if defined(AFL_DEBUG)
        fprintf(stderr, "[!] forkserver_start(...) called twice. Already fuzzing!\n");
#endif
        return UC_AFL_RET_CALLED_TWICE; // AFL has already been started before.
    }

    /* Copy exits to unicorn env buffer */
    uc->exits = g_realloc(uc->exits, sizeof(exits[0]) * exit_count);
    if (uc->exits == NULL) {
        perror("[!] malloc failed when starting forkserver.");
        return UC_AFL_RET_ERROR;
    }
    memcpy(uc->exits, exits, sizeof(exits[0]) * exit_count);
    uc->exit_count = exit_count;
    // Set addr_end to make sure unicorn will not stop at addr 0x0.
    uc->addr_end = uc->exits[0];

    /* Fork() :) */
    return uc->afl_forkserver_start(uc);

}

/* AFL++ supports testcase forwarding via shared map.
   If the env variable is set, get the shared map here.
   returns true if we enabled shmap fuzzing, false otherwise. */
static bool uc_afl_enable_shm_testcases(uc_engine *uc) {

    char *id_str = getenv(SHM_FUZZ_ENV_VAR);
    if (id_str) {
        int shm_id = atoi(id_str);
        char *map = (char *)shmat(shm_id, NULL, 0);
        if (!map || map == (void *)-1) {
            perror("[!] could not access fuzzing shared memory");
            exit(1);
        }
        uc->afl_testcase_size_p = (u32 *)map;
        uc->afl_testcase_ptr = (map + sizeof(u32));
#if defined(AFL_DEBUG)
        printf("[d] successfully opened shared memory for testcases with id %d\n", shm_id);
#endif
        return true;

    } else {
#if defined(AFL_DEBUG)
        printf("[d] SHM_FUZZ_ENV_VAR not set - not using shared map fuzzing.\n");
#endif
        return false;
    }

}

/* returns the filesize in bytes, -1 or error. */
static inline off_t uc_afl_mmap_file(char *filename, char **buf_ptr) {

    off_t ret = -1;

    int fd = open(filename, O_RDONLY);

    struct stat st = {0};
    if (fstat(fd, &st)) goto exit;

    off_t in_len = st.st_size;

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;

}

/* A start with "less features" for our afl use-case */
/* this is largely copied from uc_emu_start, just without setting the entry point, counter and timeout. */
int uc_afl_emu_start(uc_engine *uc) {

    uc->emu_counter = 0;
    uc->invalid_error = UC_ERR_OK;
    uc->emulation_done = false;
    uc->stop_request = false;

    // remove count hook if counting isn't necessary
    if (uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
    }

    uc->vm_start(uc);

    // emulation is done
    uc->emulation_done = true;

    return uc->invalid_error;

}

/* afl_next that expects you know what you're doing
   Specifically, it won't check for afl_area_ptr and next to be set. */
static inline uc_afl_ret uc_afl_next_inl(uc_engine *uc, bool crash_found)
{
    // Tell the parent we need a new testcase, then stop until testcase is available.
    if (uc->afl_child_request_next(uc, crash_found) == UC_AFL_RET_ERROR) return UC_AFL_RET_ERROR;
    return UC_AFL_RET_CHILD;

}


/* similar to __afl_persistent loop */
static inline uc_afl_ret uc_afl_next(uc_engine *uc, bool crash_found)
{

    if (unlikely(!uc->afl_area_ptr)) {
        fprintf(stderr, "[!] uc_afl_next(...) called before forkserver_start(...).");
        return UC_AFL_RET_ERROR;
    }

    // Tell the parent we need a new testcase, then stop until testcase is available.
    if (uc->afl_child_request_next) {

        return uc_afl_next_inl(uc, crash_found);

    }

    return UC_AFL_RET_NO_AFL;
}

UNICORN_EXPORT
uc_err uc_afl_fuzz(
        uc_engine *uc,
        char* input_file,
        uc_afl_cb_place_input_t place_input_callback,
        uint64_t *exits,
        size_t exit_count,
        uc_afl_cb_validate_crash_t validate_crash_callback,
        bool always_validate,
        uint32_t persistent_iters,
        void *data
){
#ifndef UNICORN_HAS_AFL
    return UC_ERR_MODE;
#else
    if (!uc) {
        UCLOG(stderr, "[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_ERR_AFL_RET_ERROR;
    }
    if (!(uc->afl)) {
        return UC_ERR_MODE;
    }
    if (!input_file || input_file[0] == 0) {
        UCLOG(stderr, "[!] No input file provided to uc_afl_fuzz.\n");
        return UC_ERR_AFL_RET_ERROR;
    }
    if (!place_input_callback) {
        UCLOG(stderr, "[!] no place_input_callback set.\n");
        return UC_ERR_AFL_RET_ERROR;
    }
    if (always_validate && !validate_crash_callback) {
        UCLOG(stderr, "[!] always_validate set but validate_crash_callback is missing.\n");
        return UC_ERR_AFL_RET_ERROR;
    }
    if (!exit_count) {
        UCLOG(stderr, "[!] Nullptr provided for exits.\n");
        return UC_ERR_AFL_RET_ERROR;
    }

    uint32_t mmap_in_len = 0;
    char *in_buf = NULL;
    uint32_t *in_len_p = NULL;

    bool use_shmap_input = uc_afl_enable_shm_testcases(uc);
    if (use_shmap_input) {
        /* For shared map fuzzing, the ptr stays the same */
        in_buf = uc->afl_testcase_ptr;
        in_len_p = uc->afl_testcase_size_p;
    } else {
        in_len_p = &mmap_in_len;
    }

    uc_afl_ret afl_ret = uc_afl_forkserver_start(uc, exits, exit_count);
    switch(afl_ret) {
        case UC_AFL_RET_CHILD:
            break;
        case UC_AFL_RET_NO_AFL:
            // Not running in AFL.
            persistent_iters = 1;
            break;
        case UC_AFL_RET_FINISHED:
            // Nothing more to do
            return UC_ERR_AFL_RET_FINISHED;
        case UC_AFL_RET_ERROR:
            return UC_ERR_AFL_RET_ERROR;
        case UC_AFL_RET_CALLED_TWICE:
            // Nothing more we can do
            return UC_ERR_AFL_RET_CALLED_TWICE;
        default:
            // What have we done
            UCLOG(stderr, "[!] Unexpected forkserver return: %d", afl_ret);
            return UC_ERR_AFL_RET_ERROR;
    }

    bool first_round = true;
    bool crash_found = false;

#if defined(AFL_DEBUG)
    if (uc->afl_testcase_ptr) {
        UCLOG("[d] uc->afl_testcase_ptr = %p, len = %d\n", uc->afl_testcase_ptr, *uc->afl_testcase_size_p);
    }
#endif

    // 0 means never stop child in persistence mode.
    uint32_t i;
    for (i = 0; persistent_iters == 0 || i < persistent_iters; i++) {

        // The main fuzz loop starts here :)
        if (first_round) {
            first_round = false;
        } else {
            if (uc_afl_next_inl(uc, crash_found) == UC_AFL_RET_ERROR) {
                /* parent is probably gone */
                exit(1);
            }
            crash_found = false;
        }

        /* get input, call place input callback, emulate, unmap input (if needed) */
        if (unlikely(!use_shmap_input)) {
            /* in_buf and the len are not in a shared map (as it would be for sharedmem fuzzing
               No shmap fuzzing involved - Let's read a "normal" file. */
            off_t in_len = uc_afl_mmap_file(input_file, &in_buf);
            if (unlikely(in_len < 0)) {
                UCLOG(stderr, "[!] Unable to mmap file: %s (return was %ld)\n", input_file, (long int) in_len);
                perror("mmap");
                fflush(stderr);
                return UC_AFL_RET_ERROR;
            }
            mmap_in_len = in_len;
        }
        bool input_accepted = place_input_callback(uc, in_buf, *in_len_p, i, data);

        if (unlikely(!input_accepted)) {
            // Apparently the input was not to the users' liking. Let's continue.
            goto next_iter;
        }

        uc_err uc_emu_ret = uc_afl_emu_start(uc);

        if (unlikely((uc_emu_ret != UC_ERR_OK) || (always_validate && validate_crash_callback))) {

            if (validate_crash_callback != NULL && validate_crash_callback(
                    uc, uc_emu_ret, in_buf, *in_len_p, i, data) != true) {
                // The callback thinks this is not a valid crash. Ignore.
                goto next_iter;
            }
            if (persistent_iters != 1) {
                // We're inpersistent mode and can report the crash via afl_next. No reason to die.
                crash_found = true;
                goto next_iter;
            }

            UCLOG(stderr, "[!] UC returned Error: '%s' - let's abort().\n", uc_strerror(uc_emu_ret));
            fflush(stderr);

            abort();

        }
next_iter:
        if (!use_shmap_input) munmap(in_buf, mmap_in_len);
    }
    // UC_AFL_RET_CHILD -> We looped through all iters.
    // We are still in the child, nothing good will come after this.
    // Exit and let the next generation run.
    if (likely(afl_ret == UC_AFL_RET_CHILD)) {
        exit(0);
    }

    if (uc->afl_area_ptr) {
        // Nothing should ever come after this but clean it up still.
        // shmdt(uc->afl_area_ptr);
        uc->afl_area_ptr = NULL;
        uc->afl_testcase_ptr = NULL;

    }

    // UC_AFL_RET_NO_AFL -> Not fuzzing. We ran once.
    return UC_AFL_RET_NO_AFL;
#endif
}

UNICORN_EXPORT
uc_err uc_emu_stop(uc_engine *uc)
{
    if (uc->emulation_done) {
        return UC_ERR_OK;
    }

    uc->stop_request = true;
    // TODO: make this atomic somehow?
    if (uc->cpu) {
        // exit the current TB
        cpu_exit(uc->cpu);
    }

    return UC_ERR_OK;
}

// find if a memory range overlaps with existing mapped regions
static bool memory_overlap(struct uc_struct *uc, uint64_t begin, size_t size)
{
    unsigned int i;
    uint64_t end = begin + size - 1;

    for(i = 0; i < uc->mapped_block_count; i++) {
        // begin address falls inside this region?
        if (begin >= uc->mapped_blocks[i]->addr && begin <= uc->mapped_blocks[i]->end - 1) {
            return true;
        }
        // end address falls inside this region?
        if (end >= uc->mapped_blocks[i]->addr && end <= uc->mapped_blocks[i]->end - 1) {
            return true;
        }
        // this region falls totally inside this range?
        if (begin < uc->mapped_blocks[i]->addr && end > uc->mapped_blocks[i]->end - 1) {
            return true;
        }
    }

    // not found
    return false;
}

// common setup/error checking shared between uc_mem_map and uc_mem_map_ptr
static uc_err mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, MemoryRegion *block)
{
    MemoryRegion **regions;

    if (block == NULL) {
        return UC_ERR_NOMEM;
    }

    if ((uc->mapped_block_count & (MEM_BLOCK_INCR - 1)) == 0) {  //time to grow
        regions = (MemoryRegion**)g_realloc(uc->mapped_blocks,
                sizeof(MemoryRegion*) * (uc->mapped_block_count + MEM_BLOCK_INCR));
        if (regions == NULL) {
            return UC_ERR_NOMEM;
        }
        uc->mapped_blocks = regions;
    }

    uc->mapped_blocks[uc->mapped_block_count] = block;
    uc->mapped_block_count++;

    return UC_ERR_OK;
}

static uc_err mem_map_check(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
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

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    res = mem_map_check(uc, address, size, perms);
    if (res) {
        return res;
    }

    return mem_map(uc, address, size, perms, uc->memory_map(uc, address, size, perms));
}

UNICORN_EXPORT
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr)
{
    uc_err res;

    if (ptr == NULL) {
        return UC_ERR_ARG;
    }

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    res = mem_map_check(uc, address, size, perms);
    if (res) {
        return res;
    }

    return mem_map(uc, address, size, UC_PROT_ALL, uc->memory_map_ptr(uc, address, size, perms, ptr));
}

UNICORN_EXPORT
uc_err uc_mmio_map(uc_engine *uc, uint64_t address, size_t size,
                   uc_cb_mmio_read_t read_cb, void *user_data_read,
                   uc_cb_mmio_write_t write_cb, void *user_data_write)
{
    uc_err res;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    res = mem_map_check(uc, address, size, UC_PROT_ALL);
    if (res)
        return res;

    // The callbacks do not need to be checked for NULL here, as their presence
    // (or lack thereof) will determine the permissions used.
    return mem_map(uc, address, size, UC_PROT_NONE,
                   uc->memory_map_io(uc, address, size, read_cb, write_cb, user_data_read, user_data_write));
}

// Create a backup copy of the indicated MemoryRegion.
// Generally used in prepartion for splitting a MemoryRegion.
static uint8_t *copy_region(struct uc_struct *uc, MemoryRegion *mr)
{
    uint8_t *block = (uint8_t *)g_malloc0((size_t)int128_get64(mr->size));
    if (block != NULL) {
        uc_err err = uc_mem_read(uc, mr->addr, block, (size_t)int128_get64(mr->size));
        if (err != UC_ERR_OK) {
            free(block);
            block = NULL;
        }
    }

    return block;
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
static bool split_region(struct uc_struct *uc, MemoryRegion *mr, uint64_t address,
        size_t size, bool do_delete)
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

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (block->offset <= mr->addr && block->used_length >= (mr->end - mr->addr)) {
            break;
        }
    }

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

    // save the essential information required for the split before mr gets deleted
    perms = mr->perms;
    begin = mr->addr;
    end = mr->end;

    // unmap this region first, then do split it later
    if (uc_mem_unmap(uc, mr->addr, (size_t)int128_get64(mr->size)) != UC_ERR_OK) {
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

    // If there are error in any of the below operations, things are too far gone
    // at that point to recover. Could try to remap orignal region, but these smaller
    // allocation just failed so no guarantee that we can recover the original
    // allocation at this point
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
            if (uc_mem_write(uc, address, backup + l_size, m_size) != UC_ERR_OK) {
                goto error;
            }
        } else {
            if (uc_mem_map_ptr(uc, address, m_size, perms, backup + l_size) != UC_ERR_OK) {
                goto error;
            }
        }
    }

    if (r_size > 0) {
        if (!prealloc) {
            if (uc_mem_map(uc, chunk_end, r_size, perms) != UC_ERR_OK) {
                goto error;
            }
            if (uc_mem_write(uc, chunk_end, backup + l_size + m_size, r_size) != UC_ERR_OK) {
                goto error;
            }
        } else {
            if (uc_mem_map_ptr(uc, chunk_end, r_size, perms, backup + l_size + m_size) != UC_ERR_OK) {
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
uc_err uc_mem_protect(struct uc_struct *uc, uint64_t address, size_t size, uint32_t perms)
{
    MemoryRegion *mr;
    uint64_t addr = address;
    size_t count, len;
    bool remove_exec = false;

    if (size == 0) {
        // trivial case, no change
        return UC_ERR_OK;
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

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size)) {
        return UC_ERR_NOMEM;
    }

    // Now we know entire region is mapped, so change permissions
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, false)) {
            return UC_ERR_NOMEM;
        }

        mr = memory_mapping(uc, addr);
        // will this remove EXEC permission?
        if (((mr->perms & UC_PROT_EXEC) != 0) && ((perms & UC_PROT_EXEC) == 0)) {
            remove_exec = true;
        }
        mr->perms = perms;
        uc->readonly_mem(mr, (perms & UC_PROT_WRITE) == 0);

        count += len;
        addr += len;
    }

    // if EXEC permission is removed, then quit TB and continue at the same place
    if (remove_exec) {
        uc->quit_request = true;
        uc_emu_stop(uc);
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_unmap(struct uc_struct *uc, uint64_t address, size_t size)
{
    MemoryRegion *mr;
    uint64_t addr;
    size_t count, len;

    if (size == 0) {
        // nothing to unmap
        return UC_ERR_OK;
    }

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0) {
        return UC_ERR_ARG;
    }

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0) {
        return UC_ERR_ARG;
    }

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size)) {
        return UC_ERR_NOMEM;
    }

    // Now we know entire region is mapped, so do the unmap
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, true)) {
            return UC_ERR_NOMEM;
        }

        // if we can retrieve the mapping, then no splitting took place
        // so unmap here
        mr = memory_mapping(uc, addr);
        if (mr != NULL) {
           uc->memory_unmap(uc, mr);
        }
        count += len;
        addr += len;
    }

    return UC_ERR_OK;
}

// find the memory region of this address
MemoryRegion *memory_mapping(struct uc_struct* uc, uint64_t address)
{
    unsigned int i;

    if (uc->mapped_block_count == 0) {
        return NULL;
    }

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // try with the cache index first
    i = uc->mapped_block_cache_index;

    if (i < uc->mapped_block_count && address >= uc->mapped_blocks[i]->addr && address < uc->mapped_blocks[i]->end) {
        return uc->mapped_blocks[i];
    }

    for(i = 0; i < uc->mapped_block_count; i++) {
        if (address >= uc->mapped_blocks[i]->addr && address <= uc->mapped_blocks[i]->end - 1) {
            // cache this index for the next query
            uc->mapped_block_cache_index = i;
            return uc->mapped_blocks[i];
        }
    }

    // not found
    return NULL;
}

UNICORN_EXPORT
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
        void *user_data, uint64_t begin, uint64_t end, ...)
{
    int ret = UC_ERR_OK;
    int i = 0;

    struct hook *hook = calloc(1, sizeof(struct hook));
    if (hook == NULL) {
        return UC_ERR_NOMEM;
    }

    hook->begin = begin;
    hook->end = end;
    hook->type = type;
    hook->callback = callback;
    hook->user_data = user_data;
    hook->refs = 0;
    hook->to_delete = false;
    *hh = (uc_hook)hook;

    // UC_HOOK_INSN has an extra argument for instruction ID
    if (type & UC_HOOK_INSN) {
        va_list valist;

        va_start(valist, end);
        hook->insn = va_arg(valist, int);
        va_end(valist);

        if (uc->insn_hook_validate) {
            if (! uc->insn_hook_validate(hook->insn)) {
                free(hook);
                return UC_ERR_HOOK;
            }
        }

        if (uc->hook_insert) {
            if (list_insert(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return UC_ERR_NOMEM;
            }
        } else {
            if (list_append(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return UC_ERR_NOMEM;
            }
        }

        hook->refs++;
        return UC_ERR_OK;
    }

    while ((type >> i) > 0) {
        if ((type >> i) & 1) {
            // TODO: invalid hook error?
            if (i < UC_HOOK_MAX) {
                if (uc->hook_insert) {
                    if (list_insert(&uc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return UC_ERR_NOMEM;
                    }
                } else {
                    if (list_append(&uc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return UC_ERR_NOMEM;
                    }
                }
                hook->refs++;
            }
        }
        i++;
    }

    // we didn't use the hook
    // TODO: return an error?
    if (hook->refs == 0) {
        free(hook);
    }

    return ret;
}


UNICORN_EXPORT
uc_err uc_hook_del(uc_engine *uc, uc_hook hh)
{
    int i;
    struct hook *hook = (struct hook *)hh;

    // we can't dereference hook->type if hook is invalid
    // so for now we need to iterate over all possible types to remove the hook
    // which is less efficient
    // an optimization would be to align the hook pointer
    // and store the type mask in the hook pointer.
    for (i = 0; i < UC_HOOK_MAX; i++) {
        if (list_exists(&uc->hook[i], (void *) hook)) {
            hook->to_delete = true;
            list_append(&uc->hooks_to_del, hook);
        }
    }

    return UC_ERR_OK;
}

// TCG helper
void helper_uc_tracecode(int32_t size, uc_hook_idx index, void *handle, int64_t address);
void helper_uc_tracecode(int32_t size, uc_hook_idx index, void *handle, int64_t address)
{
    struct uc_struct *uc = handle;
    struct list_item *cur;
    struct hook *hook;
    int hook_flags = index & UC_HOOK_FLAG_MASK; // The index here may contain additional flags. See the comments of uc_hook_idx for details.

    index = index & UC_HOOK_IDX_MASK;

    // sync PC in CPUArchState with address
    if (uc->set_pc) {
        uc->set_pc(uc, address);
    }

    // the last callback may already asked to stop emulation
    if (uc->stop_request && !(hook_flags & UC_HOOK_FLAG_NO_STOP)) {
        return;
    }

    for (cur = uc->hook[index].head; cur != NULL && (hook = (struct hook *)cur->data); cur = cur->next) {
        if (hook->to_delete) {
            continue;
        }

        // on invalid block/instruction, call instruction counter (if enable), then quit
        if (size == 0) {
            if (index == UC_HOOK_CODE_IDX && uc->count_hook) {
                // this is the instruction counter (first hook in the list)
                ((uc_cb_hookcode_t)hook->callback)(uc, address, size, hook->user_data);
            }

            return;
        }

        if (HOOK_BOUND_CHECK(hook, (uint64_t)address)) {
            ((uc_cb_hookcode_t)hook->callback)(uc, address, size, hook->user_data);
        }

        // the last callback may already asked to stop emulation
        // Unicorn:
        //   In an ARM IT block, we behave like the emulation continues normally. No check_exit_request
        //   is generated and the hooks are triggered normally. In other words, the whole IT block is
        //   treated as a single instruction.
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

    *count = uc->mapped_block_count;

    if (*count) {
        r = g_malloc0(*count * sizeof(uc_mem_region));
        if (r == NULL) {
            // out of memory
            return UC_ERR_NOMEM;
        }
    }

    for (i = 0; i < *count; i++) {
        r[i].begin = uc->mapped_blocks[i]->addr;
        r[i].end = uc->mapped_blocks[i]->end - 1;
        r[i].perms = uc->mapped_blocks[i]->perms;
    }

    *regions = r;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result)
{
    switch(type) {
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
            return UC_ERR_ARG;

        case UC_QUERY_TIMEOUT:
            *result = uc->timed_out;
            break;
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_alloc(uc_engine *uc, uc_context **context)
{
    struct uc_context **_context = context;
    size_t size = uc_context_size(uc);

    *_context = g_malloc(size);
    if (*_context) {
        (*_context)->jmp_env_size = sizeof(*uc->cpu->jmp_env);
        (*_context)->context_size = uc->cpu_context_size;
        (*_context)->arch = uc->arch;
        (*_context)->mode = uc->mode;
        (*_context)->uc = uc;
        if (list_insert(&uc->saved_contexts, *_context)) {
            return UC_ERR_OK;
        } else {
            return UC_ERR_NOMEM;
        }
    } else {
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
    // return the total size of struct uc_context
    return sizeof(uc_context) + uc->cpu_context_size + sizeof(*uc->cpu->jmp_env);
}

UNICORN_EXPORT
uc_err uc_context_save(uc_engine *uc, uc_context *context)
{
    memcpy(context->data, uc->cpu->env_ptr, context->context_size);
    memcpy(context->data + context->context_size, uc->cpu->jmp_env, context->jmp_env_size);

    return UC_ERR_OK;
}



UNICORN_EXPORT
uc_err uc_context_reg_write(uc_context *ctx, int regid, const void *value)
{
    return uc_context_reg_write_batch(ctx, &regid, (void *const *)&value, 1);
}

UNICORN_EXPORT
uc_err uc_context_reg_read(uc_context *ctx, int regid, void *value)
{
    return uc_context_reg_read_batch(ctx, &regid, &value, 1);
}

// Keep in mind that we don't a uc_engine when r/w the registers of a context.
static void find_context_reg_rw_function(uc_arch arch, uc_mode mode, context_reg_rw_t *rw)
{
    // We believe that the arch/mode pair is correct.
    switch(arch) {
        default:
            rw->context_reg_read = NULL;
            rw->context_reg_write = NULL;
            break;
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:
            rw->context_reg_read = m68k_context_reg_read;
            rw->context_reg_write = m68k_context_reg_write;
            break;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:
            rw->context_reg_read = x86_context_reg_read;
            rw->context_reg_write = x86_context_reg_write;
            break;
#endif
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            if (mode & UC_MODE_BIG_ENDIAN) {
                rw->context_reg_read = armeb_context_reg_read;
                rw->context_reg_write = armeb_context_reg_write;
            } else {
                rw->context_reg_read = arm_context_reg_read;
                rw->context_reg_write = arm_context_reg_write;
            }
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64:
            if (mode & UC_MODE_BIG_ENDIAN) {
                rw->context_reg_read = arm64eb_context_reg_read;
                rw->context_reg_write = arm64eb_context_reg_write;
            } else {
                rw->context_reg_read = arm64_context_reg_read;
                rw->context_reg_write = arm64_context_reg_write;
            }
            break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) || defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
        case UC_ARCH_MIPS:
            if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
                if (mode & UC_MODE_MIPS32) {
                    rw->context_reg_read = mips_context_reg_read;
                    rw->context_reg_write = mips_context_reg_write;
                }
#endif
#ifdef UNICORN_HAS_MIPS64
                if (mode & UC_MODE_MIPS64) {
                    rw->context_reg_read = mips64_context_reg_read;
                    rw->context_reg_write = mips64_context_reg_write;
                }
#endif
            } else {    // little endian
#ifdef UNICORN_HAS_MIPSEL
                if (mode & UC_MODE_MIPS32) {
                    rw->context_reg_read = mipsel_context_reg_read;
                    rw->context_reg_write = mipsel_context_reg_write;
                }
#endif
#ifdef UNICORN_HAS_MIPS64EL
                if (mode & UC_MODE_MIPS64) {
                    rw->context_reg_read = mips64el_context_reg_read;
                    rw->context_reg_write = mips64el_context_reg_write;
                }
#endif
            }
            break;
#endif

#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC:
            if (mode & UC_MODE_SPARC64) {
                rw->context_reg_read = sparc64_context_reg_read;
                rw->context_reg_write = sparc64_context_reg_write;
            } else {
                rw->context_reg_read = sparc_context_reg_read;
                rw->context_reg_write = sparc_context_reg_write;
            }
            break;
#endif
#ifdef UNICORN_HAS_PPC
        case UC_ARCH_PPC:
            if (mode & UC_MODE_PPC64) {
                rw->context_reg_read = ppc64_context_reg_read;
                rw->context_reg_write = ppc64_context_reg_write;
            } else {
                rw->context_reg_read = ppc_context_reg_read;
                rw->context_reg_write = ppc_context_reg_write;
            }
            break;
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV:
            if (mode & UC_MODE_RISCV32) {
                rw->context_reg_read = riscv32_context_reg_read;
                rw->context_reg_write = riscv32_context_reg_write;
            } else if (mode & UC_MODE_RISCV64) {
                rw->context_reg_read = riscv64_context_reg_read;
                rw->context_reg_write = riscv64_context_reg_write;
            }
            break;
#endif
    }
    
    return;
}

UNICORN_EXPORT
uc_err uc_context_reg_write_batch(uc_context *ctx, int *ids, void *const *vals, int count)
{
    int ret = UC_ERR_OK;
    context_reg_rw_t rw;

    find_context_reg_rw_function(ctx->arch, ctx->mode, &rw);
    if (rw.context_reg_write) {
        ret = rw.context_reg_write(ctx, (unsigned int *)ids, vals, count);
    } else {
        return UC_ERR_HANDLE;
    }

    return ret;
}

UNICORN_EXPORT
uc_err uc_context_reg_read_batch(uc_context *ctx, int *ids, void **vals, int count)
{
    int ret = UC_ERR_OK;
    context_reg_rw_t rw;

    find_context_reg_rw_function(ctx->arch, ctx->mode, &rw);
    if (rw.context_reg_read) {
        ret = rw.context_reg_read(ctx, (unsigned int *)ids, vals, count);
    } else {
        return UC_ERR_HANDLE;
    }

    return ret;
}

UNICORN_EXPORT
uc_err uc_context_restore(uc_engine *uc, uc_context *context)
{
    memcpy(uc->cpu->env_ptr, context->data, context->context_size);
    if (list_exists(&uc->saved_contexts, context)) {
        memcpy(uc->cpu->jmp_env, context->data + context->context_size, context->jmp_env_size);
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_free(uc_context *context)
{
    uc_engine* uc = context->uc;
    // if uc is NULL, it means that uc_engine has been free-ed.
    if (uc) {
        list_remove(&uc->saved_contexts, context);
    }
    return uc_free(context);
}
