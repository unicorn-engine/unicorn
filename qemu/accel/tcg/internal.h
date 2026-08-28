/*
 * Internal execution definitions for TCG.
 *
 * Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ACCEL_TCG_INTERNAL_H
#define ACCEL_TCG_INTERNAL_H

#include "exec/exec-all.h"

/*
 * Translation maintenance is serialized by Unicorn's one-CPU-per-engine
 * execution path. Page lock helpers preserve QEMU's ownership assertions,
 * but do not provide inter-thread synchronization.
 */
#define assert_memory_lock()

#define SMC_BITMAP_USE_THRESHOLD 10

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    uintptr_t first_tb;
    /* Optimize repeated self-modifying-code lookups with a byte bitmap. */
    unsigned long *code_bitmap;
    unsigned int code_write_count;
} PageDesc;

/* Size of the L2 (and L3, etc.) page tables. */
#define V_L2_BITS 10
#define V_L2_SIZE (1 << V_L2_BITS)

/*
 * The bottom level has pointers to PageDesc and is indexed by anything from
 * 4 to (V_L2_BITS + 3) bits, depending on target page size.
 */
#define V_L1_MIN_BITS 4
#define V_L1_MAX_BITS (V_L2_BITS + 3)
#define V_L1_MAX_SIZE (1 << V_L1_MAX_BITS)

PageDesc *page_find_alloc(struct uc_struct *uc, tb_page_addr_t index,
                          int alloc);

static inline PageDesc *page_find(struct uc_struct *uc,
                                  tb_page_addr_t index)
{
    return page_find_alloc(uc, index, 0);
}

/* List iterators for lists of tagged pointers in TranslationBlock. */
#define TB_FOR_EACH_TAGGED(head, tb, n, field)                          \
    for (n = (head) & 1, tb = (TranslationBlock *)((head) & ~1);        \
         tb; tb = (TranslationBlock *)tb->field[n],                     \
             n = (uintptr_t)tb & 1,                                     \
             tb = (TranslationBlock *)((uintptr_t)tb & ~1))

#define PAGE_FOR_EACH_TB(pagedesc, tb, n)                               \
    TB_FOR_EACH_TAGGED((pagedesc)->first_tb, tb, n, page_next)

#define TB_FOR_EACH_JMP(head_tb, tb, n)                                 \
    TB_FOR_EACH_TAGGED((head_tb)->jmp_list_head, tb, n, jmp_list_next)

#ifdef CONFIG_DEBUG_TCG
void do_assert_page_locked(const PageDesc *pd, const char *file, int line);
#define assert_page_locked(pd)                                          \
    do_assert_page_locked(pd, __FILE__, __LINE__)
#else
#define assert_page_locked(pd)
#endif

void page_lock(PageDesc *pd);
void page_unlock(PageDesc *pd);

int cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                              uintptr_t searched_pc, bool reset_icount);
void tb_htable_init(struct uc_struct *uc);
void tb_reset_jump(TranslationBlock *tb, int n);
TranslationBlock *tb_link_page(struct uc_struct *uc, TranslationBlock *tb,
                               tb_page_addr_t phys_pc,
                               tb_page_addr_t phys_page2);

#endif /* ACCEL_TCG_INTERNAL_H */
