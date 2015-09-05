/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
#pragma warning(disable:4996)
#endif
#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <time.h>   // nanosleep

#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "uc_priv.h"
#include "hook.h"

// target specific headers
#include "qemu/target-m68k/unicorn.h"
#include "qemu/target-i386/unicorn.h"
#include "qemu/target-arm/unicorn.h"
#include "qemu/target-mips/unicorn.h"
#include "qemu/target-sparc/unicorn.h"

#include "qemu/include/hw/boards.h"


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
            return "Invalid/unsupported architecture(UC_ERR_ARCH)";
        case UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)";
        case UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)";
        case UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)";
        case UC_ERR_MEM_READ:
            return "Invalid memory read (UC_ERR_MEM_READ)";
        case UC_ERR_MEM_WRITE:
            return "Invalid memory write (UC_ERR_MEM_WRITE)";
        case UC_ERR_MEM_FETCH:
            return "Invalid memory fetch (UC_ERR_MEM_FETCH)";
        case UC_ERR_CODE_INVALID:
            return "Invalid code address (UC_ERR_CODE_INVALID)";
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
        case UC_ERR_EXEC_PROT:
            return "Fetch from non-executable memory (UC_ERR_EXEC_PROT)";
        case UC_ERR_INVAL:
            return "Invalid argumet (UC_ERR_INVAL)";
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

        uc->errnum = UC_ERR_OK;
        uc->arch = arch;
        uc->mode = mode;

        // uc->cpus = QTAILQ_HEAD_INITIALIZER(uc->cpus);
        uc->cpus.tqh_first = NULL;
        uc->cpus.tqh_last = &(uc->cpus.tqh_first);
        // uc->ram_list = { .blocks = QTAILQ_HEAD_INITIALIZER(ram_list.blocks) };
        uc->ram_list.blocks.tqh_first = NULL;
        uc->ram_list.blocks.tqh_last = &(uc->ram_list.blocks.tqh_first);

        uc->x86_global_cpu_lock = SPIN_LOCK_UNLOCKED;

        uc->memory_listeners.tqh_first = NULL;
        uc->memory_listeners.tqh_last = &uc->memory_listeners.tqh_first;

        uc->address_spaces.tqh_first = NULL;
        uc->address_spaces.tqh_last = &uc->address_spaces.tqh_first;

        switch(arch) {
            default:
                break;
#ifdef UNICORN_HAS_M68K
            case UC_ARCH_M68K:
                uc->init_arch = m68k_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_X86
            case UC_ARCH_X86:
                uc->init_arch = x86_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_ARM
            case UC_ARCH_ARM:
                uc->init_arch = arm_uc_init;

                // verify mode
                if (mode != UC_MODE_ARM && mode != UC_MODE_THUMB) {
                    free(uc);
                    return UC_ERR_MODE;
                }

                if (mode == UC_MODE_THUMB)
                    uc->thumb = 1;
                break;
#endif
#ifdef UNICORN_HAS_ARM64
            case UC_ARCH_ARM64:
                uc->init_arch = arm64_uc_init;
                break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) || defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
            case UC_ARCH_MIPS:
                if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
                    if (mode & UC_MODE_MIPS32)
                        uc->init_arch = mips_uc_init;
#endif
#ifdef UNICORN_HAS_MIPS64
                    if (mode & UC_MODE_MIPS64)
                        uc->init_arch = mips64_uc_init;
#endif
                } else {    // little endian
#ifdef UNICORN_HAS_MIPSEL
                    if (mode & UC_MODE_MIPS32)
                        uc->init_arch = mipsel_uc_init;
#endif
#ifdef UNICORN_HAS_MIPS64EL
                    if (mode & UC_MODE_MIPS64)
                        uc->init_arch = mips64el_uc_init;
#endif
                }
                break;
#endif

#ifdef UNICORN_HAS_SPARC
            case UC_ARCH_SPARC:
                if (mode & UC_MODE_64)
                    uc->init_arch = sparc64_uc_init;
                else
                    uc->init_arch = sparc_uc_init;
                break;
#endif
        }

        if (uc->init_arch == NULL) {
            return UC_ERR_ARCH;
        }

        machine_initialize(uc);

        *result = uc;

        if (uc->reg_reset)
            uc->reg_reset(uc);

        uc->hook_size = HOOK_SIZE;
        uc->hook_callbacks = calloc(1, sizeof(uc->hook_callbacks[0]) * HOOK_SIZE);

        return UC_ERR_OK;
    } else {
        return UC_ERR_ARCH;
    }
}


UNICORN_EXPORT
uc_err uc_close(uc_engine *uc)
{
    if (uc->release)
        uc->release(uc->tcg_ctx);

#ifndef _WIN32
    free(uc->l1_map);
#endif

    if (uc->bounce.buffer) {
        free(uc->bounce.buffer);
    }

    g_free(uc->tcg_ctx);

    free((void*) uc->system_memory->name);
    g_free(uc->system_memory);
    g_hash_table_destroy(uc->type_table);

    int i;
    for (i = 0; i < DIRTY_MEMORY_NUM; i++) {
        free(uc->ram_list.dirty_memory[i]);
    }

    // TODO: remove uc->root    (created with object_new())
    uc->root->free(uc->root);

    free(uc->hook_callbacks);
    
    free(uc->mapped_blocks);

    // finally, free uc itself.
    memset(uc, 0, sizeof(*uc));
    free(uc);

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_reg_read(uc_engine *uc, int regid, void *value)
{
    if (uc->reg_read)
        uc->reg_read(uc, regid, value);
    else
        return -1;  // FIXME: need a proper uc_err

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value)
{
    if (uc->reg_write)
        uc->reg_write(uc, regid, value);
    else
        return -1;  // FIXME: need a proper uc_err

    return UC_ERR_OK;
}


// check if a memory area is mapped
// this is complicated because an area can overlap adjacent blocks
static bool check_mem_area(uc_engine *uc, uint64_t address, size_t size)
{
    size_t count = 0, len;

    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = MIN(size - count, mr->end - address);
            count += len;
            address += len;
        } else  // this address is not mapped in yet
            break;
    }

    return (count == size);
}


UNICORN_EXPORT
uc_err uc_mem_read(uc_engine *uc, uint64_t address, uint8_t *bytes, size_t size)
{
    if (!check_mem_area(uc, address, size))
        return UC_ERR_MEM_READ;

    size_t count = 0, len;

    // memory area can overlap adjacent memory blocks
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = MIN(size - count, mr->end - address);
            if (uc->read_mem(&uc->as, address, bytes, len) == false)
                break;
            count += len;
            address += len;
            bytes += len;
        } else  // this address is not mapped in yet
            break;
    }

    if (count == size)
        return UC_ERR_OK;
    else
        return UC_ERR_MEM_READ;
}

UNICORN_EXPORT
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const uint8_t *bytes, size_t size)
{
    if (!check_mem_area(uc, address, size))
        return UC_ERR_MEM_WRITE;

    size_t count = 0, len;

    // memory area can overlap adjacent memory blocks
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            uint32_t operms = mr->perms;
            if (!(operms & UC_PROT_WRITE)) // write protected
                // but this is not the program accessing memory, so temporarily mark writable
                uc->readonly_mem(mr, false);

            len = MIN(size - count, mr->end - address);
            if (uc->write_mem(&uc->as, address, bytes, len) == false)
                break;

            if (!(operms & UC_PROT_WRITE)) // write protected
                // now write protect it again
                uc->readonly_mem(mr, true);

            count += len;
            address += len;
            bytes += len;
        } else  // this address is not mapped in yet
            break;
    }

    if (count == size)
        return UC_ERR_OK;
    else
        return UC_ERR_MEM_WRITE;
}

#define TIMEOUT_STEP 2    // microseconds
static void *_timeout_fn(void *arg)
{
    struct uc_struct *uc = arg;
    int64_t current_time = get_clock();

    do {
        usleep(TIMEOUT_STEP);
        // perhaps emulation is even done before timeout?
        if (uc->emulation_done)
            break;
    } while(get_clock() - current_time < uc->timeout);

    // timeout before emulation is done?
    if (!uc->emulation_done) {
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

UNICORN_EXPORT
uc_err uc_emu_start(uc_engine* uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
    // reset the counter
    uc->emu_counter = 0;
    uc->stop_request = false;
    uc->invalid_error = UC_ERR_OK;
    uc->block_full = false;
    uc->emulation_done = false;

    switch(uc->arch) {
        default:
            break;

        case UC_ARCH_M68K:
            uc_reg_write(uc, UC_M68K_REG_PC, &begin);
            break;

        case UC_ARCH_X86:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_16:
                    uc_reg_write(uc, UC_X86_REG_IP, &begin);
                    break;
                case UC_MODE_32:
                    uc_reg_write(uc, UC_X86_REG_EIP, &begin);
                    break;
                case UC_MODE_64:
                    uc_reg_write(uc, UC_X86_REG_RIP, &begin);
                    break;
            }
            break;

        case UC_ARCH_ARM:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_THUMB:
                case UC_MODE_ARM:
                    uc_reg_write(uc, UC_ARM_REG_R15, &begin);
                    break;
            }
            break;

        case UC_ARCH_ARM64:
            uc_reg_write(uc, UC_ARM64_REG_PC, &begin);
            break;

        case UC_ARCH_MIPS:
            // TODO: MIPS32/MIPS64/BIGENDIAN etc
            uc_reg_write(uc, UC_MIPS_REG_PC, &begin);
            break;

        case UC_ARCH_SPARC:
            // TODO: Sparc/Sparc64
            uc_reg_write(uc, UC_SPARC_REG_PC, &begin);
            break;
    }

    uc->emu_count = count;
    if (count > 0) {
        uc->hook_insn = true;
    }

    uc->addr_end = until;

    uc->vm_start(uc);
    if (timeout)
        enable_emu_timer(uc, timeout * 1000);   // microseconds -> nanoseconds
    uc->pause_all_vcpus(uc);
    // emulation is done
    uc->emulation_done = true;

    if (timeout) {
        // wait for the timer to finish
        qemu_thread_join(&uc->timer);
    }

    return uc->invalid_error;
}


UNICORN_EXPORT
uc_err uc_emu_stop(uc_engine *uc)
{
    if (uc->emulation_done)
        return UC_ERR_OK;

    uc->stop_request = true;
    // exit the current TB
    cpu_exit(uc->current_cpu);

    return UC_ERR_OK;
}


static int _hook_code(uc_engine *uc, int type, uint64_t begin, uint64_t end,
        void *callback, void *user_data, uc_hook *hh)
{
    int i;

    i = hook_add(uc, type, begin, end, callback, user_data);
    if (i == 0)
        return UC_ERR_NOMEM;  // FIXME

    *hh = i;

    return UC_ERR_OK;
}


static uc_err _hook_mem_access(uc_engine *uc, uc_hook_type type,
        uint64_t begin, uint64_t end,
        void *callback, void *user_data, uc_hook *hh)
{
    int i;

    i = hook_add(uc, type, begin, end, callback, user_data);
    if (i == 0)
        return UC_ERR_NOMEM;  // FIXME

    *hh = i;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    MemoryRegion **regions;

    if (size == 0)
        // invalid memory mapping
        return UC_ERR_INVAL;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_INVAL;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_INVAL;

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0)
        return UC_ERR_INVAL;

    if ((uc->mapped_block_count & (MEM_BLOCK_INCR - 1)) == 0) {  //time to grow
        regions = (MemoryRegion**)realloc(uc->mapped_blocks,
                sizeof(MemoryRegion*) * (uc->mapped_block_count + MEM_BLOCK_INCR));
        if (regions == NULL) {
            return UC_ERR_NOMEM;
        }
        uc->mapped_blocks = regions;
    }
    uc->mapped_blocks[uc->mapped_block_count] = uc->memory_map(uc, address, size, perms);
    uc->mapped_block_count++;

    return UC_ERR_OK;
}

// Create a backup copy of the indicated MemoryRegion.
// Generally used in prepartion for splitting a MemoryRegion.
static uint8_t *copy_region(struct uc_struct *uc, MemoryRegion *mr)
{
    uint8_t *block = (uint8_t *)malloc(int128_get64(mr->size));
    if (block != NULL) {
        uc_err err = uc_mem_read(uc, mr->addr, block, int128_get64(mr->size));
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

    chunk_end = address + size;

    // if this region belongs to area [address, address+size],
    // then there is no work to do.
    if (address <= mr->addr && chunk_end >= mr->end)
        return true;

    if (size == 0)
        // trivial case
        return true;

    if (address >= mr->end || chunk_end <= mr->addr)
        // impossible case
        return false;

    backup = copy_region(uc, mr);
    if (backup == NULL)
        return false;

    // save the essential information required for the split before mr gets deleted
    perms = mr->perms;
    begin = mr->addr;
    end = mr->end;

    // unmap this region first, then do split it later
    if (uc_mem_unmap(uc, mr->addr, int128_get64(mr->size)) != UC_ERR_OK)
        goto error;

    /* overlapping cases
     *               |------mr------|
     * case 1    |---size--|
     * case 2           |--size--|
     * case 3                  |---size--|
     */

    // adjust some things
    if (address < begin)
        address = begin;
    if (chunk_end > end)
        chunk_end = end;

    // compute sub region sizes
    l_size = (size_t)(address - begin);
    r_size = (size_t)(end - chunk_end);
    m_size = (size_t)(chunk_end - address);

    // If there are error in any of the below operations, things are too far gone
    // at that point to recover. Could try to remap orignal region, but these smaller
    // allocation just failed so no guarantee that we can recover the original
    // allocation at this point
    if (l_size > 0) {
        if (uc_mem_map(uc, begin, l_size, perms) != UC_ERR_OK)
            goto error;
        if (uc_mem_write(uc, begin, backup, l_size) != UC_ERR_OK)
            goto error;
    }

    if (m_size > 0 && !do_delete) {
        if (uc_mem_map(uc, address, m_size, perms) != UC_ERR_OK)
            goto error;
        if (uc_mem_write(uc, address, backup + l_size, m_size) != UC_ERR_OK)
            goto error;
    }

    if (r_size > 0) {
        if (uc_mem_map(uc, chunk_end, r_size, perms) != UC_ERR_OK)
            goto error;
        if (uc_mem_write(uc, chunk_end, backup + l_size + m_size, r_size) != UC_ERR_OK)
            goto error;
    }

    return true;

error:
    free(backup);
    return false;
}

UNICORN_EXPORT
uc_err uc_mem_protect(struct uc_struct *uc, uint64_t address, size_t size, uint32_t perms)
{
    MemoryRegion *mr;
    uint64_t addr = address;
    size_t count, len;

    if (size == 0)
        // trivial case, no change
        return UC_ERR_OK;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_INVAL;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_INVAL;

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0)
        return UC_ERR_INVAL;

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size))
        return UC_ERR_NOMEM;

    // Now we know entire region is mapped, so change permissions
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, false))
            return UC_ERR_NOMEM;

        mr = memory_mapping(uc, addr);
        mr->perms = perms;
        uc->readonly_mem(mr, (perms & UC_PROT_WRITE) == 0);

        count += len;
        addr += len;
    }
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_unmap(struct uc_struct *uc, uint64_t address, size_t size)
{
    MemoryRegion *mr;
    uint64_t addr;
    size_t count, len;

    if (size == 0)
        // nothing to unmap
        return UC_ERR_OK;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_INVAL;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_MAP;

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size))
        return UC_ERR_NOMEM;

    // Now we know entire region is mapped, so do the unmap
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, true))
            return UC_ERR_NOMEM;
        // if we can retrieve the mapping, then no splitting took place
        // so unmap here
        mr = memory_mapping(uc, addr);
        if (mr != NULL)
           uc->memory_unmap(uc, mr);
        count += len;
        addr += len;
    }
    return UC_ERR_OK;
}

MemoryRegion *memory_mapping(struct uc_struct* uc, uint64_t address)
{
    unsigned int i;

    // try with the cache index first
    i = uc->mapped_block_cache_index;

    if (address >= uc->mapped_blocks[i]->addr && address < uc->mapped_blocks[i]->end)
        return uc->mapped_blocks[i];

    for(i = 0; i < uc->mapped_block_count; i++) {
        if (address >= uc->mapped_blocks[i]->addr && address < uc->mapped_blocks[i]->end) {
            // cache this index for the next query
            uc->mapped_block_cache_index = i;
            return uc->mapped_blocks[i];
        }
    }

    // not found
    return NULL;
}

static uc_err _hook_mem_invalid(struct uc_struct* uc, uc_cb_eventmem_t callback,
        void *user_data, uc_hook *evh)
{
    size_t i;

    // FIXME: only one event handler at the same time

    i = hook_find_new(uc);
    if (i) {
        uc->hook_callbacks[i].callback = callback;
        uc->hook_callbacks[i].user_data = user_data;
        *evh = i;
        uc->hook_mem_idx = i;
        return UC_ERR_OK;
    } else
        return UC_ERR_NOMEM;
}


static uc_err _hook_intr(struct uc_struct* uc, void *callback,
        void *user_data, uc_hook *evh)
{
    size_t i;

    // FIXME: only one event handler at the same time

    i = hook_find_new(uc);
    if (i) {
        uc->hook_callbacks[i].callback = callback;
        uc->hook_callbacks[i].user_data = user_data;
        *evh = i;
        uc->hook_intr_idx = i;
        return UC_ERR_OK;
    } else
        return UC_ERR_NOMEM;
}


static uc_err _hook_insn(struct uc_struct *uc, unsigned int insn_id, void *callback,
        void *user_data, uc_hook *evh)
{
    size_t i;

    switch(uc->arch) {
        default: break;
        case UC_ARCH_X86:
                 switch(insn_id) {
                     default: break;
                     case UC_X86_INS_OUT:
                              // FIXME: only one event handler at the same time
                              i = hook_find_new(uc);
                              if (i) {
                                  uc->hook_callbacks[i].callback = callback;
                                  uc->hook_callbacks[i].user_data = user_data;
                                  *evh = i;
                                  uc->hook_out_idx = i;
                                  return UC_ERR_OK;
                              } else
                                  return UC_ERR_NOMEM;
                     case UC_X86_INS_IN:
                              // FIXME: only one event handler at the same time
                              i = hook_find_new(uc);
                              if (i) {
                                  uc->hook_callbacks[i].callback = callback;
                                  uc->hook_callbacks[i].user_data = user_data;
                                  *evh = i;
                                  uc->hook_in_idx = i;
                                  return UC_ERR_OK;
                              } else
                                  return UC_ERR_NOMEM;
                     case UC_X86_INS_SYSCALL:
                     case UC_X86_INS_SYSENTER:
                              // FIXME: only one event handler at the same time
                              i = hook_find_new(uc);
                              if (i) {
                                  uc->hook_callbacks[i].callback = callback;
                                  uc->hook_callbacks[i].user_data = user_data;
                                  *evh = i;
                                  uc->hook_syscall_idx = i;
                                  return UC_ERR_OK;
                              } else
                                  return UC_ERR_NOMEM;
                 }
                 break;
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, uc_hook_type type, void *callback, void *user_data, ...)
{
    va_list valist;
    int ret = UC_ERR_OK;
    int id;
    uint64_t begin, end;

    va_start(valist, user_data);

    switch(type) {
        default:
            ret = UC_ERR_HOOK;
            break;
        case UC_HOOK_INTR:
            ret = _hook_intr(uc, callback, user_data, hh);
            break;
        case UC_HOOK_INSN:
            id = va_arg(valist, int);
            ret = _hook_insn(uc, id, callback, user_data, hh);
            break;
        case UC_HOOK_CODE:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_code(uc, UC_HOOK_CODE, begin, end, callback, user_data, hh);
            break;
        case UC_HOOK_BLOCK:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_code(uc, UC_HOOK_BLOCK, begin, end, callback, user_data, hh);
            break;
        case UC_HOOK_MEM_INVALID:
            ret = _hook_mem_invalid(uc, callback, user_data, hh);
            break;
        case UC_HOOK_MEM_READ:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_mem_access(uc, UC_HOOK_MEM_READ, begin, end, callback, user_data, hh);
            break;
        case UC_HOOK_MEM_WRITE:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_mem_access(uc, UC_HOOK_MEM_WRITE, begin, end, callback, user_data, hh);
            break;
        case UC_HOOK_MEM_READ_WRITE:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_mem_access(uc, UC_HOOK_MEM_READ_WRITE, begin, end, callback, user_data, hh);
            break;
    }

    va_end(valist);

    return ret;
}

UNICORN_EXPORT
uc_err uc_hook_del(uc_engine *uc, uc_hook hh)
{
    return hook_del(uc, hh);
}
