/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */
#ifndef UNICORN_COMMON_H
#define UNICORN_COMMON_H

#include "tcg/tcg.h"
#include "qemu-common.h"
#include "exec/memory.h"

// This header define common patterns/codes that will be included in all arch-sepcific
// codes for unicorns purposes.

void vm_start(struct uc_struct*);
void tcg_exec_init(struct uc_struct *uc, unsigned long tb_size);

// return true on success, false on failure
static inline bool cpu_physical_mem_read(AddressSpace *as, hwaddr addr,
                                            uint8_t *buf, int len)
{
    return cpu_physical_memory_rw(as, addr, (void *)buf, len, 0);
}

static inline bool cpu_physical_mem_write(AddressSpace *as, hwaddr addr,
                                            const uint8_t *buf, int len)
{
    return cpu_physical_memory_rw(as, addr, (void *)buf, len, 1);
}

void tb_cleanup(struct uc_struct *uc);
void free_code_gen_buffer(struct uc_struct *uc);

/** Freeing common resources */
static void release_common(void *t)
{
    TCGPool *po, *to;
    TCGContext *s = (TCGContext *)t;
#if TCG_TARGET_REG_BITS == 32
    int i;
#endif

    // Clean TCG.
    TCGOpDef* def = s->tcg_op_defs;
    g_free(def->args_ct);
    g_free(def->sorted_args);
    g_free(s->tcg_op_defs);

    for (po = s->pool_first; po; po = to) {
        to = po->next;
        g_free(po);
    }
    tcg_pool_reset(s);
    g_hash_table_destroy(s->helper_table);
    g_free(s->indirect_reg_alloc_order);
    /* qemu/tcg/tcg/c:4018: img = g_malloc(img_size); */
    g_free((void *)(s->one_entry->symfile_addr));
    g_free(s->one_entry);
    /* qemu/tcg/tcg/c:574: tcg_ctx->tree = g_tree_new(tb_tc_cmp); */
    g_tree_destroy(s->tree);

    // these function is not available outside qemu
    // so we keep them here instead of outside uc_close.
    address_space_destroy(&s->uc->address_space_memory);
    address_space_destroy(&s->uc->address_space_io);
    memory_free(s->uc);
    /* clean up uc->l1_map. */
    tb_cleanup(s->uc);
    /* clean up tcg_ctx->code_gen_buffer. */
    free_code_gen_buffer(s->uc);
    /* qemu/util/qht.c:264: map = qht_map_create(n_buckets); */
    qht_destroy(&s->tb_ctx.htable);

    cpu_watchpoint_remove_all(CPU(s->uc->cpu), BP_CPU);
    cpu_breakpoint_remove_all(CPU(s->uc->cpu), BP_CPU);

#if TCG_TARGET_REG_BITS == 32
    for(i = 0; i < s->nb_globals; i++) {
        TCGTemp *ts = &s->temps[i];
        if (ts->base_type == TCG_TYPE_I64) {
            if (ts->name && ((strcmp(ts->name+(strlen(ts->name)-2), "_0") == 0) ||
                        (strcmp(ts->name+(strlen(ts->name)-2), "_1") == 0))) {
                free((void *)ts->name);
            }
        }
    }
#endif
}

static inline void target_page_init(struct uc_struct* uc)
{
    uc->target_page_size = TARGET_PAGE_SIZE;
    uc->target_page_align = TARGET_PAGE_SIZE - 1;
}

void softfloat_init(void);
static inline void uc_common_init(struct uc_struct* uc)
{
    uc->write_mem = cpu_physical_mem_write;
    uc->read_mem = cpu_physical_mem_read;
    uc->tcg_exec_init = tcg_exec_init;
    uc->cpu_exec_init_all = cpu_exec_init_all;
    uc->vm_start = vm_start;
    uc->memory_map = memory_map;
    uc->memory_map_ptr = memory_map_ptr;
    uc->memory_unmap = memory_unmap;
    uc->readonly_mem = memory_region_set_readonly;
    uc->target_page = target_page_init;
    uc->softfloat_initialize = softfloat_init;
    uc->tcg_flush_tlb = tcg_flush_softmmu_tlb;
    uc->memory_map_io = memory_map_io;

    if (!uc->release)
        uc->release = release_common;
}
#endif
