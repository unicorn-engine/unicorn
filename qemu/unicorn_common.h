#ifndef UNICORN_COMMON_H_
#define UNICORN_COMMON_H_

#include "tcg.h"

// This header define common patterns/codes that will be included in all arch-sepcific
// codes for unicorns purposes.

// return true on success, false on failure
static inline bool cpu_physical_mem_read(AddressSpace *as, hwaddr addr,
                                            uint8_t *buf, int len)
{
    return !cpu_physical_memory_rw(as, addr, (void *)buf, len, 0);
}

static inline bool cpu_physical_mem_write(AddressSpace *as, hwaddr addr,
                                            const uint8_t *buf, int len)
{
    return !cpu_physical_memory_rw(as, addr, (void *)buf, len, 1);
}

static void free_table(gpointer key, gpointer value, gpointer data)
{
    TypeInfo *ti = (TypeInfo*) value;
    g_free((void*) ti->class);
    g_free((void*) ti->name);
    g_free((void*) ti->parent);
    g_free((void*) ti);
}

void tb_cleanup(struct uc_struct *uc);

/** Freeing common resources */
static void release_common(void *t)
{
    TCGContext *s = (TCGContext *)t;
    struct uc_struct* uc = s->uc;

    // Clean TCG.
    TCGOpDef* def = &s->tcg_op_defs[0];
    g_free(def->args_ct);
    g_free(def->sorted_args);
    g_free(s->tcg_op_defs);
    TCGPool *po, *to;
    for (po = s->pool_first; po; po = to) {
        to = po->next;
        g_free(po);
    }
    tcg_pool_reset(s);
    g_hash_table_destroy(s->helpers);

    // Clean memory.
    phys_mem_clean(uc);
    address_space_destroy(&(uc->as));
    memory_free(uc);

    // Clean CPU.
    object_unref(uc, uc->cpu);
    g_hash_table_foreach(uc->type_table, free_table, uc);

    // Clean cache.
    tb_cleanup(uc);
}

static inline void uc_common_init(struct uc_struct* uc)
{
    memory_register_types(uc);
    uc->write_mem = cpu_physical_mem_write;
    uc->read_mem = cpu_physical_mem_read;
    uc->tcg_enabled = tcg_enabled;
    uc->tcg_exec_init = tcg_exec_init;
    uc->cpu_exec_init_all = cpu_exec_init_all;
    uc->pause_all_vcpus = pause_all_vcpus;
    uc->vm_start = vm_start;
    uc->memory_map = memory_map;
    uc->memory_map_ptr = memory_map_ptr;
    uc->memory_unmap = memory_unmap;
    uc->readonly_mem = memory_region_set_readonly;

    uc->target_page_size = TARGET_PAGE_SIZE;
    uc->target_page_align = TARGET_PAGE_SIZE - 1;

    if (!uc->release)
        uc->release = release_common;
}

#endif
