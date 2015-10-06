/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "uc_priv.h"
#include "hook.h"


// return index for a new hook entry in hook_callbacks[] array.
// this realloc memory if needed.
size_t hook_find_new(struct uc_struct *uc)
{
    size_t i;
    struct hook_struct *new;

    // find the first free slot. skip slot 0, so index > 0
    for(i = 1; i < uc->hook_size; i++) {
        if (uc->hook_callbacks[i].callback == NULL) {
            return i;
        }
    }

    // not found, so the array is full.
    // we have to realloc hook_callbacks[] to contain new hooks
    new = realloc(uc->hook_callbacks,
            (uc->hook_size + HOOK_SIZE) * sizeof(uc->hook_callbacks[0]));
    if (!new)   // OOM ?
        return 0;

    // reset the newly added slots
    memset(new + uc->hook_size, 0, HOOK_SIZE * sizeof(uc->hook_callbacks[0]));

    uc->hook_callbacks = new;
    uc->hook_size += HOOK_SIZE;

    // return the first newly allocated slot
    return uc->hook_size - HOOK_SIZE;
}

// return -1 on failure, index to hook_callbacks[] on success.
size_t hook_add(struct uc_struct *uc, int type, uint64_t begin, uint64_t end, void *callback, void *user_data)
{
    int i;

    // find the first free slot. skip slot 0, so index > 0
    i = hook_find_new(uc);
    if (i) {
        uc->hook_callbacks[i].hook_type = type;
        uc->hook_callbacks[i].begin = begin;
        uc->hook_callbacks[i].end = end;
        uc->hook_callbacks[i].callback = callback;
        uc->hook_callbacks[i].user_data = user_data;

        switch(type) {
            default: break;
            case UC_HOOK_BLOCK:
                     uc->hook_block = true;
                     if (begin > end)
                         uc->hook_block_idx = i;
                     break;
            case UC_HOOK_CODE:
                     uc->hook_insn = true;
                     if (begin > end)
                         uc->hook_insn_idx = i;
                     break;
            case UC_HOOK_MEM_READ:
                     uc->hook_mem_read = true;
                     if (begin > end)
                         uc->hook_read_idx = i;
                     break;
            case UC_HOOK_MEM_WRITE:
                     uc->hook_mem_write = true;
                     if (begin > end)
                         uc->hook_write_idx = i;
                     break;
            case UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE:
                     uc->hook_mem_read = true;
                     uc->hook_mem_write = true;
                     if (begin > end) {
                         uc->hook_read_idx = i;
                         uc->hook_write_idx = i;
                     }
                     break;
        }

        return i;
    }

    // not found
    return 0;
}

// return 0 on success, -1 on failure
uc_err hook_del(struct uc_struct *uc, uc_hook hh)
{
    if (hh == uc->hook_block_idx) {
        uc->hook_block_idx = 0;
    }

    if (hh == uc->hook_insn_idx) {
        uc->hook_insn_idx = 0;
    }

    if (hh == uc->hook_read_idx) {
        uc->hook_read_idx = 0;
    }

    if (hh == uc->hook_write_idx) {
        uc->hook_write_idx = 0;
    }

    if (hh == uc->hook_mem_read_idx) {
        uc->hook_mem_read_idx = 0;
    }

    if (hh == uc->hook_mem_write_idx) {
        uc->hook_mem_write_idx = 0;
    }

    if (hh == uc->hook_mem_fetch_idx) {
        uc->hook_mem_fetch_idx = 0;
    }

    if (hh == uc->hook_mem_read_prot_idx) {
        uc->hook_mem_read_prot_idx = 0;
    }

    if (hh == uc->hook_mem_write_prot_idx) {
        uc->hook_mem_write_prot_idx = 0;
    }

    if (hh == uc->hook_mem_fetch_prot_idx) {
        uc->hook_mem_fetch_prot_idx = 0;
    }

    if (hh == uc->hook_intr_idx) {
        uc->hook_intr_idx = 0;
    }

    if (hh == uc->hook_out_idx) {
        uc->hook_out_idx = 0;
    }

    if (hh == uc->hook_in_idx) {
        uc->hook_in_idx = 0;
    }

    uc->hook_callbacks[hh].callback = NULL;
    uc->hook_callbacks[hh].user_data = NULL;
    uc->hook_callbacks[hh].hook_type = 0;
    uc->hook_callbacks[hh].begin = 0;
    uc->hook_callbacks[hh].end = 0;

    return UC_ERR_OK;
}

// return NULL on failure
static struct hook_struct *_hook_find(struct uc_struct *uc, int type, uint64_t address)
{
    int i;

    switch(type) {
        default: break;
        case UC_HOOK_BLOCK:
            // already hooked all blocks?
            if (uc->hook_block_idx)
                return &uc->hook_callbacks[uc->hook_block_idx];
            break;
        case UC_HOOK_CODE:
            // already hooked all the code?
            if (uc->hook_insn_idx)
                return &uc->hook_callbacks[uc->hook_insn_idx];
            break;
        case UC_HOOK_MEM_READ:
            // already hooked all memory read?
            if (uc->hook_read_idx) {
                return &uc->hook_callbacks[uc->hook_read_idx];
            }
            break;
        case UC_HOOK_MEM_WRITE:
            // already hooked all memory write?
            if (uc->hook_write_idx)
                return &uc->hook_callbacks[uc->hook_write_idx];
            break;
    }

    // no trace-all callback
    for(i = 1; i < uc->hook_size; i++) {
        switch(type) {
            default: break;
            case UC_HOOK_BLOCK:
            case UC_HOOK_CODE:
                     if (uc->hook_callbacks[i].hook_type == type) {
                         if (uc->hook_callbacks[i].begin <= address && address <= uc->hook_callbacks[i].end)
                             return &uc->hook_callbacks[i];
                     }
                     break;
            case UC_HOOK_MEM_READ:
                     if (uc->hook_callbacks[i].hook_type & UC_HOOK_MEM_READ) {
                         if (uc->hook_callbacks[i].begin <= address && address <= uc->hook_callbacks[i].end)
                             return &uc->hook_callbacks[i];
                     }
                     break;
            case UC_HOOK_MEM_WRITE:
                     if (uc->hook_callbacks[i].hook_type & UC_HOOK_MEM_WRITE) {
                         if (uc->hook_callbacks[i].begin <= address && address <= uc->hook_callbacks[i].end)
                             return &uc->hook_callbacks[i];
                     }
                     break;
        }
    }

    // not found
    return NULL;
}


static void hook_count_cb(struct uc_struct *uc, uint64_t address, uint32_t size, void *user_data)
{
    // count this instruction
    uc->emu_counter++;

    if (uc->emu_counter > uc->emu_count)
        uc_emu_stop(uc);
    else if (uc->hook_count_callback)
        uc->hook_count_callback(uc, address, size, user_data);
}

struct hook_struct *hook_find(struct uc_struct *uc, int type, uint64_t address)
{
    // stop executing callbacks if we already got stop request
    if (uc->stop_request)
        return NULL;

    // UC_HOOK_CODE is special because we may need to count instructions
    if (type == UC_HOOK_CODE && uc->emu_count > 0) {
        struct hook_struct *st = _hook_find(uc, type, address);
        if (st) {
            // prepare this struct to pass back to caller
            uc->hook_count.hook_type = UC_HOOK_CODE;
            uc->hook_count.begin = st->begin;
            uc->hook_count.end = st->end;
            uc->hook_count.callback = hook_count_cb;
            uc->hook_count.user_data = st->user_data;
            // save this hook callback so we can call it later
            uc->hook_count_callback = st->callback;
        } else {
            // there is no callback, but we still need to
            // handle instruction count
            uc->hook_count.hook_type = UC_HOOK_CODE;
            uc->hook_count.begin = 1;
            uc->hook_count.end = 0;
            uc->hook_count.callback = hook_count_cb;
            uc->hook_count.user_data = NULL;
            uc->hook_count_callback = NULL; // no callback
        }

        return &(uc->hook_count);
    } else
        return _hook_find(uc, type, address);
}


// TCG helper
void helper_uc_tracecode(int32_t size, void *callback, void *handle, int64_t address, void *user_data);
void helper_uc_tracecode(int32_t size, void *callback, void *handle, int64_t address, void *user_data)
{
    struct uc_struct *uc = handle;

    // sync PC in CPUArchState with address
    if (uc->set_pc) {
        uc->set_pc(uc, address);
    }

    ((uc_cb_hookcode_t)callback)(uc, address, size, user_data);
}
