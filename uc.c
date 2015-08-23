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

// TODO
static uint64_t map_begin[32], map_end[32];
static int map_count = 0;


static unsigned int all_arch = 0;

static void archs_enable(void)
{
    static bool initialized = false;

    if (initialized)
        return;

#ifdef UNICORN_HAS_ARM
    all_arch = all_arch + (1 << UC_ARCH_ARM);
#endif
#ifdef UNICORN_HAS_ARM64
    all_arch = all_arch + (1 << UC_ARCH_ARM64);
#endif
#ifdef UNICORN_HAS_MIPS
    all_arch = all_arch + (1 << UC_ARCH_MIPS);
#endif
#ifdef UNICORN_HAS_SPARC
    all_arch = all_arch + (1 << UC_ARCH_SPARC);
#endif
#ifdef UNICORN_HAS_M68K
    all_arch = all_arch + (1 << UC_ARCH_M68K);
#endif
#ifdef UNICORN_HAS_X86
    all_arch = all_arch + (1 << UC_ARCH_X86);
#endif

    initialized = true;
}


UNICORN_EXPORT
unsigned int uc_version(unsigned int *major, unsigned int *minor)
{
    archs_enable();

    if (major != NULL && minor != NULL) {
        *major = UC_API_MAJOR;
        *minor = UC_API_MINOR;
    }

    return (UC_API_MAJOR << 8) + UC_API_MINOR;
}


UNICORN_EXPORT
uc_err uc_errno(uch handle)
{
    struct uc_struct *uc;

    if (!handle)
        return UC_ERR_UCH;

    uc = (struct uc_struct *)(uintptr_t)handle;

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
        case UC_ERR_OOM:
            return "Out of memory (UC_ERR_OOM)";
        case UC_ERR_ARCH:
            return "Invalid/unsupported architecture(UC_ERR_ARCH)";
        case UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)";
        case UC_ERR_UCH:
            return "Invalid uch (UC_ERR_UCH)";
        case UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)";
        case UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)";
        case UC_ERR_MEM_READ:
            return "Invalid memory read (UC_ERR_MEM_READ)";
        case UC_ERR_MEM_WRITE:
            return "Invalid memory write (UC_ERR_MEM_WRITE)";
        case UC_ERR_CODE_INVALID:
            return "Invalid code address (UC_ERR_CODE_INVALID)";
        case UC_ERR_INSN_INVALID:
            return "Invalid instruction (UC_ERR_INSN_INVALID)";
        case UC_ERR_HOOK:
            return "Invalid hook type (UC_ERR_HOOK)";
    }
}


UNICORN_EXPORT
bool uc_support(int query)
{
    archs_enable();

    if (query == UC_ARCH_ALL)
        return all_arch == ((1 << UC_ARCH_ARM) | (1 << UC_ARCH_ARM64) |
                (1 << UC_ARCH_MIPS) | (1 << UC_ARCH_X86) |
                (1 << UC_ARCH_M68K) | (1 << UC_ARCH_SPARC));

    if ((unsigned int)query < UC_ARCH_MAX)
        return ((all_arch & (1 << query)) != 0);

    // unsupported query
    return false;
}


UNICORN_EXPORT
uc_err uc_open(uc_arch arch, uc_mode mode, uch *handle)
{
    struct uc_struct *uc;

    archs_enable();

    if (arch < UC_ARCH_MAX) {
        uc = calloc(1, sizeof(*uc));
        if (!uc) {
            // memory insufficient
            return UC_ERR_OOM;
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
            *handle = 0;
            return UC_ERR_ARCH;
        }

        machine_initialize(uc);

        *handle = (uintptr_t)uc;

        if (uc->reg_reset)
            uc->reg_reset(*handle);

        uc->hook_size = HOOK_SIZE;
        uc->hook_callbacks = calloc(1, sizeof(uc->hook_callbacks[0]) * HOOK_SIZE);

        return UC_ERR_OK;
    } else {
        *handle = 0;
        return UC_ERR_ARCH;
    }
}


UNICORN_EXPORT
uc_err uc_close(uch *handle)
{
    struct uc_struct *uc;

    // invalid handle ?
    if (*handle == 0)
        return UC_ERR_UCH;

    uc = (struct uc_struct *)(*handle);
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

    // finally, free uc itself.
    memset(uc, 0, sizeof(*uc));
    free(uc);

    // invalidate this handle by ZERO out its value.
    // this is to make sure it is unusable after uc_close()
    *handle = 0;

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_reg_read(uch handle, int regid, void *value)
{
    struct uc_struct *uc;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    uc = (struct uc_struct *)handle;
    if (uc->reg_read)
        uc->reg_read(handle, regid, value);
    else
        return -1;  // FIXME: need a proper uc_err

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_reg_write(uch handle, int regid, void *value)
{
    struct uc_struct *uc;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    uc = (struct uc_struct *)handle;
    if (uc->reg_write)
        uc->reg_write(handle, regid, value);
    else
        return -1;  // FIXME: need a proper uc_err

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_mem_read(uch handle, uint64_t address, uint8_t *bytes, size_t size)
{
    struct uc_struct *uc = (struct uc_struct *)(uintptr_t)handle;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    if (uc->read_mem(&uc->as, address, bytes, size) == false)
        return UC_ERR_MEM_READ;

    return UC_ERR_OK;
}


UNICORN_EXPORT
uc_err uc_mem_write(uch handle, uint64_t address, uint8_t *bytes, size_t size)
{
    struct uc_struct *uc = (struct uc_struct *)(uintptr_t)handle;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    if (uc->write_mem(&uc->as, address, bytes, size) == false)
        return UC_ERR_MEM_WRITE;

    return UC_ERR_OK;
}

#define TIMEOUT_STEP 2    // microseconds
static void *_timeout_fn(void *arg)
{
    struct uc_struct *uc = (struct uc_struct *)arg;
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
        uc_emu_stop((uch)uc);
    }

    return NULL;
}

static void enable_emu_timer(uch handle, uint64_t timeout)
{
    struct uc_struct *uc = (struct uc_struct *)handle;

    uc->timeout = timeout;
    qemu_thread_create(&uc->timer, "timeout", _timeout_fn,
            uc, QEMU_THREAD_JOINABLE);
}

UNICORN_EXPORT
uc_err uc_emu_start(uch handle, uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
    struct uc_struct* uc = (struct uc_struct *)handle;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    switch(uc->arch) {
        default:
            break;

        case UC_ARCH_M68K:
            uc_reg_write(handle, M68K_REG_PC, &begin);
            break;

        case UC_ARCH_X86:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_16:
                    uc_reg_write(handle, X86_REG_IP, &begin);
                    break;
                case UC_MODE_32:
                    uc_reg_write(handle, X86_REG_EIP, &begin);
                    break;
                case UC_MODE_64:
                    uc_reg_write(handle, X86_REG_RIP, &begin);
                    break;
            }
            break;

        case UC_ARCH_ARM:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_THUMB:
                case UC_MODE_ARM:
                    uc_reg_write(handle, ARM_REG_R15, &begin);
                    break;
            }
            break;

        case UC_ARCH_ARM64:
            uc_reg_write(handle, ARM64_REG_PC, &begin);
            break;

        case UC_ARCH_MIPS:
            // TODO: MIPS32/MIPS64/BIGENDIAN etc
            uc_reg_write(handle, MIPS_REG_PC, &begin);
            break;

        case UC_ARCH_SPARC:
            // TODO: Sparc/Sparc64
            uc_reg_write(handle, SPARC_REG_PC, &begin);
            break;
    }

    uc->emu_count = count;
    if (count > 0) {
        uc->hook_insn = true;
    }

    uc->addr_end = until;

    uc->vm_start(uc);
    if (timeout)
        enable_emu_timer(handle, timeout * 1000);   // microseconds -> nanoseconds
    uc->pause_all_vcpus(uc);
    // emulation is done
    uc->emulation_done = true;

    // reset the counter
    uc->emu_counter = 0;
    uc->stop_request = false;
    uc->invalid_error = UC_ERR_OK;

    return uc->invalid_error;
}


UNICORN_EXPORT
uc_err uc_emu_stop(uch handle)
{
    struct uc_struct* uc = (struct uc_struct *)handle;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    uc->stop_request = true;
    // exit the current TB
    cpu_exit(uc->current_cpu);

    return UC_ERR_OK;
}


static int _hook_code(uch handle, int type, uint64_t begin, uint64_t end,
        void *callback, void *user_data, uch *h2)
{
    int i;

    i = hook_add(handle, type, begin, end, callback, user_data);
    if (i == 0)
        return UC_ERR_OOM;  // FIXME

    *h2 = i;

    return UC_ERR_OK;
}


static uc_err _hook_mem_access(uch handle, uc_mem_type type,
        uint64_t begin, uint64_t end,
        void *callback, void *user_data, uch *h2)
{
    int i;

    i = hook_add(handle, type, begin, end, callback, user_data);
    if (i == 0)
        return UC_ERR_OOM;  // FIXME

    *h2 = i;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_map(uch handle, uint64_t address, size_t size)
{
    struct uc_struct* uc = (struct uc_struct *)handle;
    size_t s;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    // align to 8KB boundary
    map_begin[map_count] = address & (~ (8*1024 - 1));
    s = (size + 8*1024 - 1) & (~ (8*1024));
    map_end[map_count] = s + map_begin[map_count];
    uc->memory_map(uc, map_begin[map_count], s);
    map_count++;

    return UC_ERR_OK;
}

bool memory_mapping(uint64_t address)
{
    unsigned int i;

    for(i = 0; i < map_count; i++) {
        if (address >= map_begin[i] && address <= map_end[i])
            return true;
    }

    // not found
    return false;
}

static uc_err _hook_mem_invalid(struct uc_struct* uc, uc_cb_eventmem_t callback,
        void *user_data, uch *evh)
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
        return UC_ERR_OOM;
}


static uc_err _hook_intr(struct uc_struct* uc, void *callback,
        void *user_data, uch *evh)
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
        return UC_ERR_OOM;
}


static uc_err _hook_insn(struct uc_struct *uc, unsigned int insn_id, void *callback,
        void *user_data, uch *evh)
{
    size_t i;

    switch(uc->arch) {
        default: break;
        case UC_ARCH_X86:
                 switch(insn_id) {
                     default: break;
                     case X86_INS_OUT:
                              // FIXME: only one event handler at the same time
                              i = hook_find_new(uc);
                              if (i) {
                                  uc->hook_callbacks[i].callback = callback;
                                  uc->hook_callbacks[i].user_data = user_data;
                                  *evh = i;
                                  uc->hook_out_idx = i;
                                  return UC_ERR_OK;
                              } else
                                  return UC_ERR_OOM;
                     case X86_INS_IN:
                              // FIXME: only one event handler at the same time
                              i = hook_find_new(uc);
                              if (i) {
                                  uc->hook_callbacks[i].callback = callback;
                                  uc->hook_callbacks[i].user_data = user_data;
                                  *evh = i;
                                  uc->hook_in_idx = i;
                                  return UC_ERR_OK;
                              } else
                                  return UC_ERR_OOM;
                     case X86_INS_SYSCALL:
                     case X86_INS_SYSENTER:
                              // FIXME: only one event handler at the same time
                              i = hook_find_new(uc);
                              if (i) {
                                  uc->hook_callbacks[i].callback = callback;
                                  uc->hook_callbacks[i].user_data = user_data;
                                  *evh = i;
                                  uc->hook_syscall_idx = i;
                                  return UC_ERR_OK;
                              } else
                                  return UC_ERR_OOM;
                 }
                 break;
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_hook_add(uch handle, uch *h2, uc_hook_t type, void *callback, void *user_data, ...)
{
    struct uc_struct* uc = (struct uc_struct *)handle;
    va_list valist;
    int ret = UC_ERR_OK;
    int id;
    uint64_t begin, end;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    va_start(valist, user_data);

    switch(type) {
        default:
            ret = UC_ERR_HOOK;
            break;
        case UC_HOOK_INTR:
            ret = _hook_intr(uc, callback, user_data, h2);
            break;
        case UC_HOOK_INSN:
            id = va_arg(valist, int);
            ret = _hook_insn(uc, id, callback, user_data, h2);
            break;
        case UC_HOOK_CODE:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_code(handle, UC_HOOK_CODE, begin, end, callback, user_data, h2);
            break;
        case UC_HOOK_BLOCK:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_code(handle, UC_HOOK_BLOCK, begin, end, callback, user_data, h2);
            break;
        case UC_HOOK_MEM_INVALID:
            ret = _hook_mem_invalid(uc, callback, user_data, h2);
            break;
        case UC_HOOK_MEM_READ:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_mem_access(handle, UC_MEM_READ, begin, end, callback, user_data, h2);
            break;
        case UC_HOOK_MEM_WRITE:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_mem_access(handle, UC_MEM_WRITE, begin, end, callback, user_data, h2);
        case UC_HOOK_MEM_READ_WRITE:
            begin = va_arg(valist, uint64_t);
            end = va_arg(valist, uint64_t);
            ret = _hook_mem_access(handle, UC_MEM_READ_WRITE, begin, end, callback, user_data, h2);
            break;
    }

    va_end(valist);

    return ret;
}

UNICORN_EXPORT
uc_err uc_hook_del(uch handle, uch *h2)
{
    //struct uc_struct* uc = (struct uc_struct *)handle;

    if (handle == 0)
        // invalid handle
        return UC_ERR_UCH;

    if (*h2 == 0)
        // invalid handle
        return UC_ERR_HANDLE;

    return hook_del(handle, h2);
}

