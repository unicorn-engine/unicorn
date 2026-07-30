/*
 * Translation block cache maintenance.
 *
 * Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "qemu/osdep.h"
#include "qemu-common.h"

#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "exec/ram_addr.h"
#include "exec/cputlb.h"
#include "exec/tb-hash.h"
#include "translate-all.h"
#include "internal.h"
#include "qemu/bitmap.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "uc_priv.h"

static bool tb_exec_is_locked(struct uc_struct *uc);
static void tb_exec_change(struct uc_struct *uc, bool locked);

static bool tb_cmp(struct uc_struct *uc, const void *ap, const void *bp)
{
    const TranslationBlock *a = ap;
    const TranslationBlock *b = bp;

    return a->pc == b->pc &&
        a->cs_base == b->cs_base &&
        a->flags == b->flags &&
        (tb_cflags(a) & CF_HASH_MASK) == (tb_cflags(b) & CF_HASH_MASK) &&
        a->trace_vcpu_dstate == b->trace_vcpu_dstate &&
        a->page_addr[0] == b->page_addr[0] &&
        a->page_addr[1] == b->page_addr[1];
}

void tb_htable_init(struct uc_struct *uc)
{
    unsigned int mode = QHT_MODE_AUTO_RESIZE;

    qht_init(&uc->tcg_ctx->tb_ctx.htable, tb_cmp, CODE_GEN_HTABLE_SIZE, mode);
}


static void page_lock_pair(struct uc_struct *uc, PageDesc **ret_p1,
                           tb_page_addr_t phys1, PageDesc **ret_p2,
                           tb_page_addr_t phys2, int alloc)
{
    PageDesc *p1, *p2;
    tb_page_addr_t page1;
    tb_page_addr_t page2;

    assert_memory_lock();
    g_assert(phys1 != -1);

    page1 = phys1 >> TARGET_PAGE_BITS;
    page2 = phys2 >> TARGET_PAGE_BITS;

    p1 = page_find_alloc(uc, page1, alloc);
    if (ret_p1) {
        *ret_p1 = p1;
    }
    if (likely(phys2 == -1)) {
        page_lock(p1);
        return;
    } else if (page1 == page2) {
        page_lock(p1);
        if (ret_p2) {
            *ret_p2 = p1;
        }
        return;
    }
    p2 = page_find_alloc(uc, page2, alloc);
    if (ret_p2) {
        *ret_p2 = p2;
    }
    if (page1 < page2) {
        page_lock(p1);
        page_lock(p2);
    } else {
        page_lock(p2);
        page_lock(p1);
    }
}

/* lock the page(s) of a TB in the correct acquisition order */
static inline void page_lock_tb(struct uc_struct *uc,
                                const TranslationBlock *tb)
{
    page_lock_pair(uc, NULL, tb->page_addr[0], NULL, tb->page_addr[1], 0);
}

static inline void page_unlock_tb(struct uc_struct *uc,
                                  const TranslationBlock *tb)
{
    PageDesc *p1 = page_find(uc, tb->page_addr[0] >> TARGET_PAGE_BITS);

    page_unlock(p1);
    if (unlikely(tb->page_addr[1] != -1)) {
        PageDesc *p2 = page_find(uc, tb->page_addr[1] >> TARGET_PAGE_BITS);

        if (p2 != p1) {
            page_unlock(p2);
        }
    }
}

/* call with @p->lock held */
static inline void invalidate_page_bitmap(PageDesc *p)
{
    assert_page_locked(p);

    g_free(p->code_bitmap);
    p->code_bitmap = NULL;
    p->code_write_count = 0;
}

static void tb_clean_internal(void **p, int x)
{
    int i;
    void **q;

    if (x <= 1) {
        for (i = 0; i < V_L2_SIZE; i++) {
            q = p[i];
            if (q) {
                g_free(q);
            }
        }
        g_free(p);
    } else {
        for (i = 0; i < V_L2_SIZE; i++) {
            q = p[i];
            if (q) {
                tb_clean_internal(q, x - 1);
            }
        }
        g_free(p);
    }
}

void tb_cleanup(struct uc_struct *uc)
{
    int i, x;
    void **p;

    if (uc) {
        if (uc->l1_map) {
            x = uc->v_l2_levels;
            if (x <= 0) {
                for (i = 0; i < uc->v_l1_size; i++) {
                    p = uc->l1_map[i];
                    if (p) {
                        g_free(p);
                        uc->l1_map[i] = NULL;
                    }
                }
            } else {
                for (i = 0; i < uc->v_l1_size; i++) {
                    p = uc->l1_map[i];
                    if (p) {
                        tb_clean_internal(p, x);
                        uc->l1_map[i] = NULL;
                    }
                }
            }
        }
    }
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */
static void page_flush_tb_1(struct uc_struct *uc, int level, void **lp)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            page_lock(&pd[i]);
            pd[i].first_tb = (uintptr_t)NULL;
            invalidate_page_bitmap(pd + i);
            page_unlock(&pd[i]);
        }
    } else {
        void **pp = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            page_flush_tb_1(uc, level - 1, pp + i);
        }
    }
}

static void page_flush_tb(struct uc_struct *uc)
{
    int i, l1_sz = uc->v_l1_size;

    for (i = 0; i < l1_sz; i++) {
        page_flush_tb_1(uc, uc->v_l2_levels, uc->l1_map + i);
    }
}

/* flush all the translation blocks */
static void do_tb_flush(CPUState *cpu, run_on_cpu_data tb_flush_count)
{
    mmap_lock();
    /* If it is already been done on request of another CPU,
     * just retry.
     */
    if (cpu->uc->tcg_ctx->tb_ctx.tb_flush_count != tb_flush_count.host_int) {
        goto done;
    }

    cpu_tb_jmp_cache_clear(cpu);

    qht_reset_size(cpu->uc, &cpu->uc->tcg_ctx->tb_ctx.htable,
                   CODE_GEN_HTABLE_SIZE);
    page_flush_tb(cpu->uc);

    tcg_region_reset_all(cpu->uc->tcg_ctx);
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    cpu->uc->tcg_ctx->tb_ctx.tb_flush_count =
        cpu->uc->tcg_ctx->tb_ctx.tb_flush_count + 1;

done:
    mmap_unlock();
}

void tb_flush(CPUState *cpu)
{
    unsigned tb_flush_count = cpu->uc->tcg_ctx->tb_ctx.tb_flush_count;
    do_tb_flush(cpu, RUN_ON_CPU_HOST_INT(tb_flush_count));
}

/*
 * user-mode: call with mmap_lock held
 * !user-mode: call with @pd->lock held
 */
static inline void tb_page_remove(PageDesc *pd, TranslationBlock *tb)
{
    TranslationBlock *tb1;
    uintptr_t *pprev;
    unsigned int n1;

    assert_page_locked(pd);
    pprev = &pd->first_tb;
    PAGE_FOR_EACH_TB(pd, tb1, n1) {
        if (tb1 == tb) {
            *pprev = tb1->page_next[n1];
            return;
        }
        pprev = &tb1->page_next[n1];
    }
    g_assert_not_reached();
}

/* remove @orig from its @n_orig-th jump list */
static inline void tb_remove_from_jmp_list(TranslationBlock *orig, int n_orig)
{
    uintptr_t ptr, ptr_locked;
    TranslationBlock *dest;
    TranslationBlock *tb;
    uintptr_t *pprev;
    int n;

    /* mark the LSB of jmp_dest[] so that no further jumps can be inserted */
    ptr = atomic_or_fetch(&orig->jmp_dest[n_orig], 1);
    dest = (TranslationBlock *)(ptr & ~1);
    if (dest == NULL) {
        return;
    }

    ptr_locked = orig->jmp_dest[n_orig];
    if (ptr_locked != ptr) {
        /*
         * The only possibility is that the jump was unlinked via
         * tb_jump_unlink(dest). Seeing here another destination would be a bug,
         * because we set the LSB above.
         */
        g_assert(ptr_locked == 1 && dest->cflags & CF_INVALID);
        return;
    }
    /*
     * Since the destination pointer still matches, @orig must be in the
     * destination jump list.
     */
    if (dest == orig) {
        /*
         * A self-linked TB is removed from this list before tb_jmp_unlink()
         * can see it, so reset its direct jump now.
         */
        tb_reset_jump(orig, n_orig);
    }
    pprev = &dest->jmp_list_head;
    TB_FOR_EACH_JMP(dest, tb, n) {
        if (tb == orig && n == n_orig) {
            *pprev = tb->jmp_list_next[n];
            /* no need to set orig->jmp_dest[n]; setting the LSB was enough */
            return;
        }
        pprev = &tb->jmp_list_next[n];
    }
    g_assert_not_reached();
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
void tb_reset_jump(TranslationBlock *tb, int n)
{
    uintptr_t addr = (uintptr_t)((char *)tb->tc.ptr + tb->jmp_reset_offset[n]);
    tb_set_jmp_target(tb, n, addr);
}

/* remove any jumps to the TB */
static inline void tb_jmp_unlink(TranslationBlock *dest)
{
    TranslationBlock *tb;
    int n;

    TB_FOR_EACH_JMP(dest, tb, n) {
        tb_reset_jump(tb, n);
#ifdef _MSC_VER
        atomic_and((long *)&tb->jmp_dest[n], (uintptr_t)NULL | 1);
#else
        atomic_and(&tb->jmp_dest[n], (uintptr_t)NULL | 1);
#endif
        /* No need to clear the list entry; setting the dest ptr is enough */
    }
    dest->jmp_list_head = (uintptr_t)NULL;
}

/*
 * If @rm_from_page_list is set, call with logical ownership of the TB pages.
 */
static void do_tb_phys_invalidate(TCGContext *tcg_ctx,
                                  TranslationBlock *tb,
                                  bool rm_from_page_list)
{
    CPUState *cpu = tcg_ctx->uc->cpu;
    struct uc_struct *uc = tcg_ctx->uc;
    PageDesc *p;
    uint32_t h;
    tb_page_addr_t phys_pc;
    bool code_gen_locked;

    assert_memory_lock();
    code_gen_locked = tb_exec_is_locked(uc);
    tb_exec_unlock(uc);

    /* make sure no further incoming jumps will be chained to this TB */
    tb->cflags = tb->cflags | CF_INVALID;

    /* remove the TB from the hash list */
    phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
    h = tb_hash_func(phys_pc, tb->pc, tb->flags, tb_cflags(tb) & CF_HASH_MASK,
                     tb->trace_vcpu_dstate);
    if (!(tb->cflags & CF_NOCACHE) &&
        !qht_remove(&tcg_ctx->tb_ctx.htable, tb, h)) {
        tb_exec_change(uc, code_gen_locked);
        return;
    }

    /* remove the TB from the page list */
    if (rm_from_page_list) {
        p = page_find(tcg_ctx->uc, tb->page_addr[0] >> TARGET_PAGE_BITS);
        tb_page_remove(p, tb);
        invalidate_page_bitmap(p);
        if (tb->page_addr[1] != -1) {
            p = page_find(tcg_ctx->uc, tb->page_addr[1] >> TARGET_PAGE_BITS);
            tb_page_remove(p, tb);
            invalidate_page_bitmap(p);
        }
    }

    /* remove the TB from the hash list */
    h = tb_jmp_cache_hash_func(uc, tb->pc);
    if (cpu->tb_jmp_cache[h] == tb) {
        cpu->tb_jmp_cache[h] = NULL;
    }

    /* suppress this TB from the two jump lists */
    tb_remove_from_jmp_list(tb, 0);
    tb_remove_from_jmp_list(tb, 1);

    /* suppress any remaining jumps to this TB */
    tb_jmp_unlink(tb);

    tcg_ctx->tb_phys_invalidate_count = tcg_ctx->tb_phys_invalidate_count + 1;

    tb_exec_change(uc, code_gen_locked);
}

static void tb_phys_invalidate__locked(TCGContext *tcg_ctx,
                                       TranslationBlock *tb)
{
    do_tb_phys_invalidate(tcg_ctx, tb, true);
}

/* Invalidate one TB. */
void tb_phys_invalidate(TCGContext *tcg_ctx, TranslationBlock *tb,
                        tb_page_addr_t page_addr)
{
    if (page_addr == -1 && tb->page_addr[0] != -1) {
        page_lock_tb(tcg_ctx->uc, tb);
        do_tb_phys_invalidate(tcg_ctx, tb, true);
        page_unlock_tb(tcg_ctx->uc, tb);
    } else {
        do_tb_phys_invalidate(tcg_ctx, tb, false);
    }
}

/* call with @p->lock held */
static void build_page_bitmap(struct uc_struct *uc, PageDesc *p)
{
    int n, tb_start, tb_end;
    TranslationBlock *tb;

    assert_page_locked(p);
    p->code_bitmap = bitmap_new(TARGET_PAGE_SIZE);

    PAGE_FOR_EACH_TB(p, tb, n) {
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->pc & ~TARGET_PAGE_MASK;
            tb_end = tb_start + tb->size;
            if (tb_end > TARGET_PAGE_SIZE) {
                tb_end = TARGET_PAGE_SIZE;
            }
        } else {
            tb_start = 0;
            tb_end = ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        qemu_bitmap_set(p->code_bitmap, tb_start, tb_end - tb_start);
    }
}

/* add the tb in the target page and protect it if necessary
 *
 * Called with logical ownership of @p.
 */
static inline void tb_page_add(struct uc_struct *uc, PageDesc *p,
                               TranslationBlock *tb, unsigned int n,
                               tb_page_addr_t page_addr)
{
    bool page_already_protected;

    assert_page_locked(p);

    tb->page_addr[n] = page_addr;
    tb->page_next[n] = p->first_tb;
    page_already_protected = p->first_tb != (uintptr_t)NULL;
    p->first_tb = (uintptr_t)tb | n;
    invalidate_page_bitmap(p);

    /* if some code is already present, then the pages are already
       protected. So we handle the case where only the first TB is
       allocated in a physical page */
    if (!page_already_protected) {
        tlb_protect_code(uc, page_addr);
    }
}

/* add a new TB and link it to the physical page tables. phys_page2 is
 * (-1) to indicate that only one page contains the TB.
 *
 * Called from the serialized translation path.
 *
 * Returns a pointer @tb, or a pointer to an existing TB that matches @tb.
 * Note that in !user-mode, another thread might have already added a TB
 * for the same block of guest code that @tb corresponds to. In that case,
 * the caller should discard the original @tb, and use instead the returned TB.
 */
TranslationBlock *
tb_link_page(struct uc_struct *uc, TranslationBlock *tb, tb_page_addr_t phys_pc,
             tb_page_addr_t phys_page2)
{
    PageDesc *p;
    PageDesc *p2 = NULL;

    assert_memory_lock();

    if (phys_pc == -1) {
        /*
         * If the TB is not associated with a physical RAM page then
         * it must be a temporary one-insn TB, and we have nothing to do
         * except fill in the page_addr[] fields.
         */
        assert(tb->cflags & CF_NOCACHE);
        tb->page_addr[0] = tb->page_addr[1] = -1;
        return tb;
    }

    /*
     * Add the TB to the page list, acquiring first the pages's locks.
     * We keep the locks held until after inserting the TB in the hash table,
     * so that if the insertion fails we know for sure that the TBs are still
     * in the page descriptors.
     * Note that inserting into the hash table first isn't an option, since
     * we can only insert TBs that are fully initialized.
     */
    page_lock_pair(uc, &p, phys_pc, &p2, phys_page2, 1);
    tb_page_add(uc, p, tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (p2) {
        tb_page_add(uc, p2, tb, 1, phys_page2);
    } else {
        tb->page_addr[1] = -1;
    }

    if (!(tb->cflags & CF_NOCACHE)) {
        void *existing_tb = NULL;
        uint32_t h;

        /* add in the hash table */
        h = tb_hash_func(phys_pc, tb->pc, tb->flags, tb->cflags & CF_HASH_MASK,
                         tb->trace_vcpu_dstate);
        tb->hash = h;   // unicorn needs this so it can remove this tb
        qht_insert(uc, &uc->tcg_ctx->tb_ctx.htable, tb, h, &existing_tb);

        /* remove TB from the page(s) if we couldn't insert it */
        if (unlikely(existing_tb)) {
            tb_page_remove(p, tb);
            invalidate_page_bitmap(p);
            if (p2) {
                tb_page_remove(p2, tb);
                invalidate_page_bitmap(p2);
            }
            tb = existing_tb;
        }
    }

    if (p2 && p2 != p) {
        page_unlock(p2);
    }
    page_unlock(p);

    return tb;
}

/*
 * @p must be non-NULL.
 * user-mode: call with mmap_lock held.
 * !user-mode: call with all @pages locked.
 */
static void tb_invalidate_phys_page_range__locked(
                                      struct uc_struct *uc,
                                      struct page_collection *pages,
                                      PageDesc *p, tb_page_addr_t start,
                                      tb_page_addr_t end,
                                      uintptr_t retaddr)
{
    TranslationBlock *tb;
    tb_page_addr_t tb_start, tb_end;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    CPUState *cpu = uc->cpu;
    CPUArchState *env = NULL;
    bool current_tb_not_found = retaddr != 0;
    bool current_tb_modified = false;
    TranslationBlock *current_tb = NULL;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    uint32_t current_flags = 0;
#endif /* TARGET_HAS_PRECISE_SMC */

    assert_page_locked(p);

#if defined(TARGET_HAS_PRECISE_SMC)
    if (cpu != NULL) {
        env = cpu->env_ptr;
    }
#endif

    /* we remove all the TBs in the range [start, end[ */
    /* XXX: see if in some cases it could be faster to invalidate all
       the code */
    PAGE_FOR_EACH_TB(p, tb, n) {
        assert_page_locked(p);
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
            tb_end = tb_start + tb->size;
        } else {
            tb_start = tb->page_addr[1];
            tb_end = tb_start + ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        /* Unicorn can generate a zero-instruction TB. */
        if (!(tb_end <= start || tb_start >= end) || tb_start == tb_end) {
#ifdef TARGET_HAS_PRECISE_SMC
            if (current_tb_not_found) {
                current_tb_not_found = false;
                /* now we have a real cpu fault */
                current_tb = tcg_tb_lookup(uc->tcg_ctx, retaddr);
            }
            if (current_tb == tb &&
                (tb_cflags(current_tb) & CF_COUNT_MASK) != 1) {
                /*
                 * If we are modifying the current TB, we must stop
                 * its execution. We could be more precise by checking
                 * that the modification is after the current PC, but it
                 * would require a specialized function to partially
                 * restore the CPU state.
                 */
                current_tb_modified = true;
                cpu_restore_state_from_tb(cpu, current_tb, retaddr, true);
                cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
                                     &current_flags);
            }
#endif /* TARGET_HAS_PRECISE_SMC */
            tb_phys_invalidate__locked(uc->tcg_ctx, tb);
        }
    }

    /* if no code remaining, no need to continue to use slow writes */
    if (!p->first_tb) {
        invalidate_page_bitmap(p);
        tlb_unprotect_code(uc, start);
    }

#ifdef TARGET_HAS_PRECISE_SMC
    if (current_tb_modified) {
        page_collection_unlock(pages);
        /* Force execution of one insn next time.  */
        cpu->cflags_next_tb = 1 | curr_cflags();
        mmap_unlock();
        cpu_loop_exit_noexc(cpu);
    }
#endif
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end must refer to the *same* physical page.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 *
 */
void tb_invalidate_phys_page_range(struct uc_struct *uc,
                                   tb_page_addr_t start,
                                   tb_page_addr_t end)
{
    struct page_collection *pages;
    PageDesc *p;

    assert_memory_lock();

    p = page_find(uc, start >> TARGET_PAGE_BITS);
    if (p == NULL) {
        return;
    }
    pages = page_collection_lock(uc, start, end);
    tb_invalidate_phys_page_range__locked(uc, pages, p, start, end, 0);
    page_collection_unlock(pages);
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end may refer to *different* physical pages.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 *
 */
void tb_invalidate_phys_range(struct uc_struct *uc, ram_addr_t start,
                              ram_addr_t end)
{
    struct page_collection *pages;
    tb_page_addr_t next;

    assert_memory_lock();

    pages = page_collection_lock(uc, start, end);
    for (next = (start & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
         //start < end; Unicorn: Fix possible wrap around
         (intptr_t)(end - start) > 0;
         start = next, next += TARGET_PAGE_SIZE) {
        PageDesc *pd = page_find(uc, start >> TARGET_PAGE_BITS);
        tb_page_addr_t bound = MIN(next, end);

        if (pd == NULL) {
            continue;
        }
        tb_invalidate_phys_page_range__locked(uc, pages, pd, start, bound, 0);
    }
    page_collection_unlock(pages);
}

/* len must be <= 8 and start must be a multiple of len.
 * Called via softmmu_template.h when code areas are written to with
 * iothread mutex not held.
 *
 * Call with logical ownership of all @pages in
 * the range [@start, @start + len[.
 */
void tb_invalidate_phys_page_fast(struct uc_struct *uc,
                                  struct page_collection *pages,
                                  tb_page_addr_t start, int len,
                                  uintptr_t retaddr)
{
    PageDesc *p;

    assert_memory_lock();

    p = page_find(uc, start >> TARGET_PAGE_BITS);
    if (!p) {
        return;
    }

    assert_page_locked(p);
    if (!p->code_bitmap &&
        ++p->code_write_count >= SMC_BITMAP_USE_THRESHOLD) {
        build_page_bitmap(uc, p);
    }
    if (p->code_bitmap) {
        unsigned int nr;
        unsigned long b;

        nr = start & ~TARGET_PAGE_MASK;
        b = p->code_bitmap[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1));
        if (b & ((1 << len) - 1)) {
            goto do_invalidate;
        }
    } else {
    do_invalidate:
        tb_invalidate_phys_page_range__locked(uc, pages, p, start, start + len,
                                              retaddr);
    }
}

#if defined(__APPLE__) && defined(HAVE_PTHREAD_JIT_PROTECT) && \
    (defined(__arm__) || defined(__aarch64__))
static bool tb_exec_is_locked(struct uc_struct *uc)
{
    return uc->current_executable;
}

static void tb_exec_change(struct uc_struct *uc, bool executable)
{
    assert_executable(uc->current_executable);
    if (uc->current_executable != executable) {
        jit_write_protect(executable);
        uc->current_executable = executable;
        assert_executable(executable);
    }
}
#else /* not needed on non-Darwin platforms */
static bool tb_exec_is_locked(struct uc_struct *uc)
{
    return false;
}

static void tb_exec_change(struct uc_struct *uc, bool locked)
{
}
#endif

void tb_exec_lock(struct uc_struct *uc)
{
    /* assumes sys_icache_invalidate already called */
    tb_exec_change(uc, true);
}

void tb_exec_unlock(struct uc_struct *uc)
{
    tb_exec_change(uc, false);
}
