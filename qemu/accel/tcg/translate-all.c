/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu-common.h"

#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "exec/ram_addr.h"

#include "exec/cputlb.h"
#include "exec/tb-hash.h"
#include "translate-all.h"
#include "qemu/bitmap.h"
#include "qemu/timer.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "uc_priv.h"

static bool tb_exec_is_locked(TCGContext*);
static void tb_exec_change(TCGContext*, bool locked);

/* #define DEBUG_TB_INVALIDATE */
/* #define DEBUG_TB_FLUSH */
/* make various TB consistency checks */
/* #define DEBUG_TB_CHECK */

#ifdef DEBUG_TB_INVALIDATE
#define DEBUG_TB_INVALIDATE_GATE 1
#else
#define DEBUG_TB_INVALIDATE_GATE 0
#endif

#ifdef DEBUG_TB_FLUSH
#define DEBUG_TB_FLUSH_GATE 1
#else
#define DEBUG_TB_FLUSH_GATE 0
#endif

/* TB consistency checks only implemented for usermode emulation.  */
#undef DEBUG_TB_CHECK

#ifdef DEBUG_TB_CHECK
#define DEBUG_TB_CHECK_GATE 1
#else
#define DEBUG_TB_CHECK_GATE 0
#endif

/* Access to the various translations structures need to be serialised via locks
 * for consistency.
 * In user-mode emulation access to the memory related structures are protected
 * with mmap_lock.
 * In !user-mode we use per-page locks.
 */
#define assert_memory_lock()

#define SMC_BITMAP_USE_THRESHOLD 10

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    uintptr_t first_tb;
    /* in order to optimize self modifying code, we count the number
       of lookups we do to a given page to use a bitmap */
    unsigned long *code_bitmap;
    unsigned int code_write_count;
} PageDesc;

/**
 * struct page_entry - page descriptor entry
 * @pd:     pointer to the &struct PageDesc of the page this entry represents
 * @index:  page index of the page
 * @locked: whether the page is locked
 *
 * This struct helps us keep track of the locked state of a page, without
 * bloating &struct PageDesc.
 *
 * A page lock protects accesses to all fields of &struct PageDesc.
 *
 * See also: &struct page_collection.
 */
struct page_entry {
    PageDesc *pd;
    tb_page_addr_t index;
    bool locked;
};

/**
 * struct page_collection - tracks a set of pages (i.e. &struct page_entry's)
 * @tree:   Binary search tree (BST) of the pages, with key == page index
 * @max:    Pointer to the page in @tree with the highest page index
 *
 * To avoid deadlock we lock pages in ascending order of page index.
 * When operating on a set of pages, we need to keep track of them so that
 * we can lock them in order and also unlock them later. For this we collect
 * pages (i.e. &struct page_entry's) in a binary search @tree. Given that the
 * @tree implementation we use does not provide an O(1) operation to obtain the
 * highest-ranked element, we use @max to keep track of the inserted page
 * with the highest index. This is valuable because if a page is not in
 * the tree and its index is higher than @max's, then we can lock it
 * without breaking the locking order rule.
 *
 * Note on naming: 'struct page_set' would be shorter, but we already have a few
 * page_set_*() helpers, so page_collection is used instead to avoid confusion.
 *
 * See also: page_collection_lock().
 */
struct page_collection {
    GTree *tree;
    struct page_entry *max;
};

/* list iterators for lists of tagged pointers in TranslationBlock */
#define TB_FOR_EACH_TAGGED(head, tb, n, field)                          \
    for (n = (head) & 1, tb = (TranslationBlock *)((head) & ~1);        \
         tb; tb = (TranslationBlock *)tb->field[n], n = (uintptr_t)tb & 1, \
             tb = (TranslationBlock *)((uintptr_t)tb & ~1))

#define PAGE_FOR_EACH_TB(pagedesc, tb, n)                       \
    TB_FOR_EACH_TAGGED((pagedesc)->first_tb, tb, n, page_next)

#define TB_FOR_EACH_JMP(head_tb, tb, n)                                 \
    TB_FOR_EACH_TAGGED((head_tb)->jmp_list_head, tb, n, jmp_list_next)

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
# define L1_MAP_ADDR_SPACE_BITS  HOST_LONG_BITS
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_PHYS_ADDR_SPACE_BITS
#endif

/* Size of the L2 (and L3, etc) page tables.  */
#define V_L2_BITS 10
#define V_L2_SIZE (1 << V_L2_BITS)

/* Make sure all possible CPU event bits fit in tb->trace_vcpu_dstate */
QEMU_BUILD_BUG_ON(CPU_TRACE_DSTATE_MAX_EVENTS >
                  sizeof_field(TranslationBlock, trace_vcpu_dstate)
                  * BITS_PER_BYTE);

/* The bottom level has pointers to PageDesc, and is indexed by
 * anything from 4 to (V_L2_BITS + 3) bits, depending on target page size.
 */
#define V_L1_MIN_BITS 4
#define V_L1_MAX_BITS (V_L2_BITS + 3)
#define V_L1_MAX_SIZE (1 << V_L1_MAX_BITS)

static void page_table_config_init(struct uc_struct *uc)
{
    uint32_t v_l1_bits;

    assert(TARGET_PAGE_BITS);
    /* The bits remaining after N lower levels of page tables.  */
    v_l1_bits = (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % V_L2_BITS;
    if (v_l1_bits < V_L1_MIN_BITS) {
        v_l1_bits += V_L2_BITS;
    }

    uc->v_l1_size = 1 << v_l1_bits;
    uc->v_l1_shift = L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - v_l1_bits;
    uc->v_l2_levels = uc->v_l1_shift / V_L2_BITS - 1;

    assert(v_l1_bits <= V_L1_MAX_BITS);
    assert(uc->v_l1_shift % V_L2_BITS == 0);
    assert(uc->v_l2_levels >= 0);
}

/* Encode VAL as a signed leb128 sequence at P.
   Return P incremented past the encoded value.  */
static uint8_t *encode_sleb128(uint8_t *p, target_long val)
{
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0)
                 || (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

/* Decode a signed leb128 sequence at *PP; increment *PP past the
   decoded value.  Return the decoded value.  */
static target_long decode_sleb128(uint8_t **pp)
{
    uint8_t *p = *pp;
    target_long val = 0;
    int byte, shift = 0;

    do {
        byte = *p++;
        val |= (target_ulong)(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < TARGET_LONG_BITS && (byte & 0x40)) {
#ifdef _MSC_VER
        val |= ((target_ulong)0 - 1) << shift;
#else
        val |= -(target_ulong)1 << shift;
#endif
    }

    *pp = p;
    return val;
}

/* Encode the data collected about the instructions while compiling TB.
   Place the data at BLOCK, and return the number of bytes consumed.

   The logical table consists of TARGET_INSN_START_WORDS target_ulong's,
   which come from the target's insn_start data, followed by a uintptr_t
   which comes from the host pc of the end of the code implementing the insn.

   Each line of the table is encoded as sleb128 deltas from the previous
   line.  The seed for the first line is { tb->pc, 0..., tb->tc.ptr }.
   That is, the first column is seeded with the guest pc, the last column
   with the host pc, and the middle columns with zeros.  */

static int encode_search(struct uc_struct *uc, TranslationBlock *tb, uint8_t *block)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    uint8_t *highwater = tcg_ctx->code_gen_highwater;
    uint8_t *p = block;
    int i, j, n;

    for (i = 0, n = tb->icount; i < n; ++i) {
        target_ulong prev;

        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            if (i == 0) {
                prev = (j == 0 ? tb->pc : 0);
            } else {
                prev = tcg_ctx->gen_insn_data[i - 1][j];
            }
            p = encode_sleb128(p, tcg_ctx->gen_insn_data[i][j] - prev);
        }
        prev = (i == 0 ? 0 : tcg_ctx->gen_insn_end_off[i - 1]);
        p = encode_sleb128(p, tcg_ctx->gen_insn_end_off[i] - prev);

        /* Test for (pending) buffer overflow.  The assumption is that any
           one row beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           encoding a row without having to check during encoding.  */
        if (unlikely(p > highwater)) {
            return -1;
        }
    }

    return p - block;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 * When reset_icount is true, current TB will be interrupted and
 * icount should be recalculated.
 */
static int cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                                     uintptr_t searched_pc, bool reset_icount)
{
    target_ulong data[TARGET_INSN_START_WORDS] = { tb->pc };
    uintptr_t host_pc = (uintptr_t)tb->tc.ptr;
    CPUArchState *env = cpu->env_ptr;
    uint8_t *p = (uint8_t *)tb->tc.ptr + tb->tc.size;
    int i, j, num_insns = tb->icount;

    searched_pc -= GETPC_ADJ;

    if (searched_pc < host_pc) {
        return -1;
    }

    /* Reconstruct the stored insn data while looking for the point at
       which the end of the insn exceeds the searched_pc.  */
    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        host_pc += decode_sleb128(&p);
        if (host_pc > searched_pc) {
            goto found;
        }
    }
    return -1;

 found:
    if (reset_icount && (tb_cflags(tb) & CF_USE_ICOUNT)) {
        /* Reset the cycle counter to the start of the block
           and shift if to the number of actually executed instructions */
        cpu_neg(cpu)->icount_decr.u16.low += num_insns - i;
    }
    restore_state_to_opc(env, tb, data);

    return 0;
}

bool cpu_restore_state(CPUState *cpu, uintptr_t host_pc, bool will_exit)
{
    TCGContext *tcg_ctx = cpu->uc->tcg_ctx;
    TranslationBlock *tb;
    bool r = false;
    uintptr_t check_offset;
    struct uc_struct *uc = cpu->uc;

    /* The host_pc has to be in the region of current code buffer. If
     * it is not we will not be able to resolve it here. The two cases
     * where host_pc will not be correct are:
     *
     *  - fault during translation (instruction fetch)
     *  - fault from helper (not using GETPC() macro)
     *
     * Either way we need return early as we can't resolve it here.
     *
     * We are using unsigned arithmetic so if host_pc <
     * tcg_init_ctx.code_gen_buffer check_offset will wrap to way
     * above the code_gen_buffer_size
     */
    check_offset = host_pc - (uintptr_t) uc->tcg_ctx->code_gen_buffer;

    if (check_offset < uc->tcg_ctx->code_gen_buffer_size) {
        tb = tcg_tb_lookup(tcg_ctx, host_pc);
        if (tb) {
            cpu_restore_state_from_tb(cpu, tb, host_pc, will_exit);
            if (tb_cflags(tb) & CF_NOCACHE) {
                /* one-shot translation, invalidate it immediately */
                tb_phys_invalidate(tcg_ctx, tb, -1);
                tcg_tb_remove(tcg_ctx, tb);
            }
            r = true;
        }
    }

    return r;
}

static void page_init(struct uc_struct *uc)
{
    page_size_init(uc);
    page_table_config_init(uc);
}

static PageDesc *page_find_alloc(struct uc_struct *uc, tb_page_addr_t index, int alloc)
{
    PageDesc *pd;
    void **lp;
    int i;

    /* Level 1.  Always allocated.  */
    lp = uc->l1_map + ((index >> uc->v_l1_shift) & (uc->v_l1_size - 1));

    /* Level 2..N-1.  */
    for (i = uc->v_l2_levels; i > 0; i--) {
        void **p = *lp;

        if (p == NULL) {
            void *existing;

            if (!alloc) {
                return NULL;
            }
            p = g_new0(void *, V_L2_SIZE);
            existing = *lp;
            if (*lp == NULL) {
                *lp = p;
            }
            if (unlikely(existing)) {
                g_free(p);
                p = existing;
            }
        }

        lp = p + ((index >> (i * V_L2_BITS)) & (V_L2_SIZE - 1));
    }

    pd = *lp;
    if (pd == NULL) {
        void *existing;

        if (!alloc) {
            return NULL;
        }
        pd = g_new0(PageDesc, V_L2_SIZE);
        existing = *lp;
        if (*lp == NULL) {
            *lp = pd;
        }
        if (unlikely(existing)) {
            g_free(pd);
            pd = existing;
        }
    }

    return pd + (index & (V_L2_SIZE - 1));
}

static inline PageDesc *page_find(struct uc_struct *uc, tb_page_addr_t index)
{
    return page_find_alloc(uc, index, 0);
}

static void page_lock_pair(struct uc_struct *uc, PageDesc **ret_p1, tb_page_addr_t phys1,
                           PageDesc **ret_p2, tb_page_addr_t phys2, int alloc);

#ifdef CONFIG_DEBUG_TCG

static void ht_pages_locked_debug_init(void)
{
    if (ht_pages_locked_debug) {
        return;
    }
    ht_pages_locked_debug = g_hash_table_new(NULL, NULL);
}

static bool page_is_locked(const PageDesc *pd)
{
    PageDesc *found;

    ht_pages_locked_debug_init();
    found = g_hash_table_lookup(ht_pages_locked_debug, pd);
    return !!found;
}

static void page_lock__debug(PageDesc *pd)
{
    ht_pages_locked_debug_init();
    g_assert(!page_is_locked(pd));
    g_hash_table_insert(ht_pages_locked_debug, pd, pd);
}

static void page_unlock__debug(const PageDesc *pd)
{
    bool removed;

    ht_pages_locked_debug_init();
    g_assert(page_is_locked(pd));
    removed = g_hash_table_remove(ht_pages_locked_debug, pd);
    g_assert(removed);
}

static void
do_assert_page_locked(const PageDesc *pd, const char *file, int line)
{
    if (unlikely(!page_is_locked(pd))) {
        // error_report("assert_page_lock: PageDesc %p not locked @ %s:%d",
        //              pd, file, line);
        abort();    // unreachable in unicorn.
    }
}

#define assert_page_locked(pd) do_assert_page_locked(pd, __FILE__, __LINE__)

void assert_no_pages_locked(void)
{
    ht_pages_locked_debug_init();
    g_assert(g_hash_table_size(ht_pages_locked_debug) == 0);
}

#else /* !CONFIG_DEBUG_TCG */

#define assert_page_locked(pd)

static inline void page_lock__debug(const PageDesc *pd)
{
}

static inline void page_unlock__debug(const PageDesc *pd)
{
}

#endif /* CONFIG_DEBUG_TCG */

static inline void page_lock(PageDesc *pd)
{
    page_lock__debug(pd);
}

static inline void page_unlock(PageDesc *pd)
{
    page_unlock__debug(pd);
}

/* lock the page(s) of a TB in the correct acquisition order */
static inline void page_lock_tb(struct uc_struct *uc, const TranslationBlock *tb)
{
    page_lock_pair(uc, NULL, tb->page_addr[0], NULL, tb->page_addr[1], 0);
}

static inline void page_unlock_tb(struct uc_struct *uc, const TranslationBlock *tb)
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

static inline struct page_entry *
page_entry_new(PageDesc *pd, tb_page_addr_t index)
{
    struct page_entry *pe = g_malloc(sizeof(*pe));

    pe->index = index;
    pe->pd = pd;
    // pe->locked = false;
    return pe;
}

static void page_entry_destroy(gpointer p)
{
    struct page_entry *pe = p;

    // g_assert(pe->locked);
    page_unlock(pe->pd);
    g_free(pe);
}

#if 0
/* returns false on success */
static bool page_entry_trylock(struct page_entry *pe)
{
    bool busy;

    busy = qemu_spin_trylock(&pe->pd->lock);
    if (!busy) {
        g_assert(!pe->locked);
        pe->locked = true;
        page_lock__debug(pe->pd);
    }
    return busy;
}

static void do_page_entry_lock(struct page_entry *pe)
{
    page_lock(pe->pd);
    g_assert(!pe->locked);
    pe->locked = true;
}

static gboolean page_entry_lock(gpointer key, gpointer value, gpointer data)
{
    struct page_entry *pe = value;

    do_page_entry_lock(pe);
    return FALSE;
}

static gboolean page_entry_unlock(gpointer key, gpointer value, gpointer data)
{
    struct page_entry *pe = value;

    if (pe->locked) {
        pe->locked = false;
        page_unlock(pe->pd);
    }
    return FALSE;
}
#endif

/*
 * Trylock a page, and if successful, add the page to a collection.
 * Returns true ("busy") if the page could not be locked; false otherwise.
 */
static bool page_trylock_add(struct uc_struct *uc, struct page_collection *set, tb_page_addr_t addr)
{
    tb_page_addr_t index = addr >> TARGET_PAGE_BITS;
    struct page_entry *pe;
    PageDesc *pd;

    pe = g_tree_lookup(set->tree, &index);
    if (pe) {
        return false;
    }

    pd = page_find(uc, index);
    if (pd == NULL) {
        return false;
    }

    pe = page_entry_new(pd, index);
    g_tree_insert(set->tree, &pe->index, pe);

    /*
     * If this is either (1) the first insertion or (2) a page whose index
     * is higher than any other so far, just lock the page and move on.
     */
    if (set->max == NULL || pe->index > set->max->index) {
        set->max = pe;
#if 0
        do_page_entry_lock(pe);
#endif
        return false;
    }
    /*
     * Try to acquire out-of-order lock; if busy, return busy so that we acquire
     * locks in order.
     */
#if 0
    return page_entry_trylock(pe);
#else
    return 0;
#endif
}

static gint tb_page_addr_cmp(gconstpointer ap, gconstpointer bp, gpointer udata)
{
    tb_page_addr_t a = *(const tb_page_addr_t *)ap;
    tb_page_addr_t b = *(const tb_page_addr_t *)bp;

    if (a == b) {
        return 0;
    } else if (a < b) {
        return -1;
    }
    return 1;
}

/*
 * Lock a range of pages ([@start,@end[) as well as the pages of all
 * intersecting TBs.
 * Locking order: acquire locks in ascending order of page index.
 */
struct page_collection *
page_collection_lock(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end)
{
    struct page_collection *set = g_malloc(sizeof(*set));
    tb_page_addr_t index;
    PageDesc *pd;

    start >>= TARGET_PAGE_BITS;
    end   >>= TARGET_PAGE_BITS;
    g_assert(start <= end);

    set->tree = g_tree_new_full(tb_page_addr_cmp, NULL, NULL,
                                page_entry_destroy);
    set->max = NULL;
    assert_no_pages_locked();

 retry:
#if 0
    g_tree_foreach(set->tree, page_entry_lock, NULL);
#endif

    for (index = start; index <= end; index++) {
        TranslationBlock *tb;
        int n;

        pd = page_find(uc, index);
        if (pd == NULL) {
            continue;
        }
        if (page_trylock_add(uc, set, index << TARGET_PAGE_BITS)) {
#if 0
            g_tree_foreach(set->tree, page_entry_unlock, NULL);
#endif
            goto retry;
        }
        assert_page_locked(pd);
        PAGE_FOR_EACH_TB(pd, tb, n) {
            if (page_trylock_add(uc, set, tb->page_addr[0]) ||
                (tb->page_addr[1] != -1 &&
                 page_trylock_add(uc, set, tb->page_addr[1]))) {
                /* drop all locks, and reacquire in order */
#if 0
                g_tree_foreach(set->tree, page_entry_unlock, NULL);
#endif
                goto retry;
            }
        }
    }
    return set;
}

void page_collection_unlock(struct page_collection *set)
{
    /* entries are unlocked and freed via page_entry_destroy */
    g_tree_destroy(set->tree);
    g_free(set);
}

static void page_lock_pair(struct uc_struct *uc, PageDesc **ret_p1, tb_page_addr_t phys1,
                           PageDesc **ret_p2, tb_page_addr_t phys2, int alloc)
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

/* Minimum size of the code gen buffer.  This number is randomly chosen,
   but not so small that we can't have a fair number of TB's live.  */
#define MIN_CODE_GEN_BUFFER_SIZE     (1 * MiB)

/* Maximum size of the code gen buffer we'd like to use.  Unless otherwise
   indicated, this is constrained by the range of direct branches on the
   host cpu, as used by the TCG implementation of goto_tb.  */
#if defined(__x86_64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2 * GiB)
#elif defined(__sparc__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2 * GiB)
#elif defined(__powerpc64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2 * GiB)
#elif defined(__powerpc__)
# define MAX_CODE_GEN_BUFFER_SIZE  (32 * MiB)
#elif defined(__aarch64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2 * GiB)
#elif defined(__s390x__)
  /* We have a +- 4GB range on the branches; leave some slop.  */
# define MAX_CODE_GEN_BUFFER_SIZE  (3 * GiB)
#elif defined(__mips__)
  /* We have a 256MB branch region, but leave room to make sure the
     main executable is also within that region.  */
# define MAX_CODE_GEN_BUFFER_SIZE  (128 * MiB)
#else
# define MAX_CODE_GEN_BUFFER_SIZE  ((size_t)-1)
#endif

#if TCG_TARGET_REG_BITS == 32
#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (32 * MiB)
#else /* TCG_TARGET_REG_BITS == 64 */
/*
 * We expect most system emulation to run one or two guests per host.
 * Users running large scale system emulation may want to tweak their
 * runtime setup via the tb-size control on the command line.
 */
#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (1 * GiB)
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE \
  (DEFAULT_CODE_GEN_BUFFER_SIZE_1 < MAX_CODE_GEN_BUFFER_SIZE \
   ? DEFAULT_CODE_GEN_BUFFER_SIZE_1 : MAX_CODE_GEN_BUFFER_SIZE)

static inline size_t size_code_gen_buffer(size_t tb_size)
{
    /* Size the buffer.  */
    if (tb_size == 0) {
        tb_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
    }
    if (tb_size < MIN_CODE_GEN_BUFFER_SIZE) {
        tb_size = MIN_CODE_GEN_BUFFER_SIZE;
    }
    if (tb_size > MAX_CODE_GEN_BUFFER_SIZE) {
        tb_size = MAX_CODE_GEN_BUFFER_SIZE;
    }
    return tb_size;
}

#ifdef __mips__
/* In order to use J and JAL within the code_gen_buffer, we require
   that the buffer not cross a 256MB boundary.  */
static inline bool cross_256mb(void *addr, size_t size)
{
    return ((uintptr_t)addr ^ ((uintptr_t)addr + size)) & ~0x0ffffffful;
}

/* We weren't able to allocate a buffer without crossing that boundary,
   so make do with the larger portion of the buffer that doesn't cross.
   Returns the new base of the buffer, and adjusts code_gen_buffer_size.  */
static inline void *split_cross_256mb(TCGContext *tcg_ctx, void *buf1, size_t size1)
{
    void *buf2 = (void *)(((uintptr_t)buf1 + size1) & ~0x0ffffffful);
    size_t size2 = buf1 + size1 - buf2;

    size1 = buf2 - buf1;
    if (size1 < size2) {
        size1 = size2;
        buf1 = buf2;
    }

    tcg_ctx->code_gen_buffer_size = size1;
    return buf1;
}
#endif

#ifdef USE_STATIC_CODE_GEN_BUFFER
static uint8_t static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]
    __attribute__((aligned(CODE_GEN_ALIGN)));

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    void *buf = static_code_gen_buffer;
    void *end = static_code_gen_buffer + sizeof(static_code_gen_buffer);
    size_t size;

    /* page-align the beginning and end of the buffer */
    buf = QEMU_ALIGN_PTR_UP(buf, uc->qemu_real_host_page_size);
    end = QEMU_ALIGN_PTR_DOWN(end, uc->qemu_real_host_page_size);

    size = end - buf;

    /* Honor a command-line option limiting the size of the buffer.  */
    if (size > tcg_ctx->code_gen_buffer_size) {
        size = QEMU_ALIGN_DOWN(tcg_ctx->code_gen_buffer_size,
                               uc->qemu_real_host_page_size);
    }
    tcg_ctx->code_gen_buffer_size = size;

#ifdef __mips__
    if (cross_256mb(buf, size)) {
        buf = split_cross_256mb(tcg_ctx, buf, size);
        size = tcg_ctx->code_gen_buffer_size;
    }
#endif

    if (qemu_mprotect_rwx(buf, size)) {
        abort();
    }
    qemu_madvise(buf, size, QEMU_MADV_HUGEPAGE);

    return buf;
}
#elif defined(_WIN32)
static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    size_t size = tcg_ctx->code_gen_buffer_size;
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT,
                        PAGE_EXECUTE_READWRITE);
}
void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    if (tcg_ctx->code_gen_buffer) {
        VirtualFree(tcg_ctx->code_gen_buffer, 0, MEM_RELEASE);
    }
}
#else
void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    if (tcg_ctx->code_gen_buffer) {
        munmap(tcg_ctx->code_gen_buffer, tcg_ctx->code_gen_buffer_size);
    }
}

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    int prot = PROT_WRITE | PROT_READ | PROT_EXEC;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    size_t size = tcg_ctx->code_gen_buffer_size;
    void *buf;
#ifdef USE_MAP_JIT
    flags |= MAP_JIT;
#endif
    buf = mmap(NULL, size, prot, flags, -1, 0);
    if (buf == MAP_FAILED) {
        return NULL;
    }

#ifdef __mips__
    if (cross_256mb(buf, size)) {
        /*
         * Try again, with the original still mapped, to avoid re-acquiring
         * the same 256mb crossing.
         */
        size_t size2;
        void *buf2 = mmap(NULL, size, prot, flags, -1, 0);
        switch ((int)(buf2 != MAP_FAILED)) {
        case 1:
            if (!cross_256mb(buf2, size)) {
                /* Success!  Use the new buffer.  */
                munmap(buf, size);
                break;
            }
            /* Failure.  Work with what we had.  */
            munmap(buf2, size);
            /* fallthru */
        default:
            /* Split the original buffer.  Free the smaller half.  */
            buf2 = split_cross_256mb(tcg_ctx, buf, size);
            size2 = tcg_ctx->code_gen_buffer_size;
            if (buf == buf2) {
                munmap(buf + size2, size - size2);
            } else {
                munmap(buf, size - size2);
            }
            size = size2;
            break;
        }
        buf = buf2;
    }
#endif

    /* Request large pages for the buffer.  */
    qemu_madvise(buf, size, QEMU_MADV_HUGEPAGE);

    return buf;
}
#endif /* USE_STATIC_CODE_GEN_BUFFER, WIN32, POSIX */

static inline void code_gen_alloc(struct uc_struct *uc, size_t tb_size)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    tcg_ctx->code_gen_buffer_size = size_code_gen_buffer(tb_size);
    tcg_ctx->code_gen_buffer = alloc_code_gen_buffer(uc);
    if (tcg_ctx->code_gen_buffer == NULL) {
        fprintf(stderr, "Could not allocate dynamic translator buffer\n");
        exit(1);
    }
}

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

static void tb_htable_init(struct uc_struct *uc)
{
    unsigned int mode = QHT_MODE_AUTO_RESIZE;

    qht_init(&uc->tcg_ctx->tb_ctx.htable, tb_cmp, CODE_GEN_HTABLE_SIZE, mode);
}


static void uc_invalidate_tb(struct uc_struct *uc, uint64_t start_addr, size_t len) 
{
    tb_page_addr_t start, end;

    // GVA to GPA (GPA -> HVA via page_find, HVA->HPA via host mmu)
    start = get_page_addr_code(uc->cpu->env_ptr, start_addr) & (target_ulong)(-1);
    
    // For 32bit target.
    end = (start + len) & (target_ulong)(-1);

    // We get a wrap?
    if (start > end) {
        return;
    }

    tb_invalidate_phys_range(uc, start, end);
}

static uc_err uc_gen_tb(struct uc_struct *uc, uint64_t addr, uc_tb *out_tb) 
{
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    CPUState *cpu = uc->cpu;
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    uint32_t flags;
    uint32_t hash;
    uint32_t cflags = cpu->cflags_next_tb;

    if (cflags == -1) {
        cflags = curr_cflags();
    }

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    // Unicorn: Our hack here.
    pc = addr;

    hash = tb_jmp_cache_hash_func(env->uc, pc);
    tb = cpu->tb_jmp_cache[hash];

    cflags &= ~CF_CLUSTER_MASK;
    cflags |= cpu->cluster_index << CF_CLUSTER_SHIFT;

    if (unlikely(!(tb &&
                   tb->pc == pc &&
                   tb->cs_base == cs_base &&
                   tb->flags == flags &&
                   tb->trace_vcpu_dstate == *cpu->trace_dstate &&
                   (tb_cflags(tb) & (CF_HASH_MASK | CF_INVALID)) == cflags))) {

        tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
        cpu->tb_jmp_cache[hash] = tb;

        if (tb == NULL) {
            mmap_lock();
            tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
            mmap_unlock();
            /* We add the TB in the virtual pc hash table for the fast lookup */
            cpu->tb_jmp_cache[hash] = tb;
        }
    }

    // If we still couldn't generate a TB, it must be out of memory.
    if (tb == NULL) {
        return UC_ERR_NOMEM;
    }

    if (out_tb != NULL) {
        UC_TB_COPY(out_tb, tb);
    }

    return UC_ERR_OK;
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(struct uc_struct *uc, unsigned long tb_size)
{
    /* remove tcg object. init here. */
    /* tcg class init: tcg-all.c:tcg_accel_class_init(), skip all. */
    /* tcg object init: tcg-all.c:tcg_accel_instance_init(), skip all. */
    /* tcg init: tcg-all.c: tcg_init(), skip all. */
    /* run tcg_exec_init() here. */
    uc->tcg_ctx = g_malloc(sizeof(TCGContext));
    tcg_context_init(uc->tcg_ctx);
    uc->tcg_ctx->uc = uc;
    page_init(uc);
    tb_htable_init(uc);
    code_gen_alloc(uc, tb_size);
    tb_exec_unlock(uc->tcg_ctx);
    tcg_prologue_init(uc->tcg_ctx);
    /* cpu_interrupt_handler is not used in uc1 */
    uc->l1_map = g_malloc0(sizeof(void *) * V_L1_MAX_SIZE);
    /* Invalidate / Cache TBs */
    uc->uc_invalidate_tb = uc_invalidate_tb;
    uc->uc_gen_tb = uc_gen_tb;
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

#if 0
static gboolean tb_host_size_iter(gpointer key, gpointer value, gpointer data)
{
    const TranslationBlock *tb = value;
    size_t *size = data;

    *size += tb->tc.size;
    return false;
}
#endif

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

#if 0
    if (DEBUG_TB_FLUSH_GATE) {
        size_t nb_tbs = tcg_nb_tbs(cpu->uc->tcg_ctx);
        size_t host_size = 0;

        tcg_tb_foreach(cpu->uc->tcg_ctx, tb_host_size_iter, &host_size);
        //printf("qemu: flush code_size=%zu nb_tbs=%zu avg_tb_size=%zu\n",
        //       tcg_code_size(cpu->uc->tcg_ctx), nb_tbs, nb_tbs > 0 ? host_size / nb_tbs : 0);
    }

    CPU_FOREACH(cpu) {
        cpu_tb_jmp_cache_clear(cpu);
    }
#else
    cpu_tb_jmp_cache_clear(cpu);
#endif

    qht_reset_size(cpu->uc, &cpu->uc->tcg_ctx->tb_ctx.htable, CODE_GEN_HTABLE_SIZE);
    page_flush_tb(cpu->uc);

    tcg_region_reset_all(cpu->uc->tcg_ctx);
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    cpu->uc->tcg_ctx->tb_ctx.tb_flush_count = cpu->uc->tcg_ctx->tb_ctx.tb_flush_count + 1;

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
     * We first acquired the lock, and since the destination pointer matches,
     * we know for sure that @orig is in the jmp list.
     */
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
static inline void tb_reset_jump(TranslationBlock *tb, int n)
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
 * In user-mode, call with mmap_lock held.
 * In !user-mode, if @rm_from_page_list is set, call with the TB's pages'
 * locks held.
 */
static void do_tb_phys_invalidate(TCGContext *tcg_ctx, TranslationBlock *tb, bool rm_from_page_list)
{
    CPUState *cpu = tcg_ctx->uc->cpu;
    struct uc_struct *uc = tcg_ctx->uc;
    PageDesc *p;
    uint32_t h;
    tb_page_addr_t phys_pc;
    bool code_gen_locked;

    assert_memory_lock();
    code_gen_locked = tb_exec_is_locked(tcg_ctx);
    tb_exec_unlock(tcg_ctx);

    /* make sure no further incoming jumps will be chained to this TB */
    tb->cflags = tb->cflags | CF_INVALID;

    /* remove the TB from the hash list */
    phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
    h = tb_hash_func(phys_pc, tb->pc, tb->flags, tb_cflags(tb) & CF_HASH_MASK,
                     tb->trace_vcpu_dstate);
    if (!(tb->cflags & CF_NOCACHE) &&
        !qht_remove(&tcg_ctx->tb_ctx.htable, tb, h)) {
        tb_exec_change(tcg_ctx, code_gen_locked);
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

    tb_exec_change(tcg_ctx, code_gen_locked);
}

static void tb_phys_invalidate__locked(TCGContext *tcg_ctx, TranslationBlock *tb)
{
    do_tb_phys_invalidate(tcg_ctx, tb, true);
}

/* invalidate one TB
 *
 * Called with mmap_lock held in user-mode.
 */
void tb_phys_invalidate(TCGContext *tcg_ctx, TranslationBlock *tb, tb_page_addr_t page_addr)
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
 * Called with mmap_lock held for user-mode emulation.
 * Called with @p->lock held in !user-mode.
 */
static inline void tb_page_add(struct uc_struct *uc, PageDesc *p, TranslationBlock *tb,
                               unsigned int n, tb_page_addr_t page_addr)
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
 * Called with mmap_lock held for user-mode emulation.
 *
 * Returns a pointer @tb, or a pointer to an existing TB that matches @tb.
 * Note that in !user-mode, another thread might have already added a TB
 * for the same block of guest code that @tb corresponds to. In that case,
 * the caller should discard the original @tb, and use instead the returned TB.
 */
static TranslationBlock *
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

/* Called with mmap_lock held for user mode emulation.  */
TranslationBlock *tb_gen_code(CPUState *cpu,
                              target_ulong pc, target_ulong cs_base,
                              uint32_t flags, int cflags)
{
#ifdef TARGET_ARM
    struct uc_struct *uc = cpu->uc;
#endif
    TCGContext *tcg_ctx = cpu->uc->tcg_ctx;
    CPUArchState *env = cpu->env_ptr;
    TranslationBlock *tb, *existing_tb;
    tb_page_addr_t phys_pc, phys_page2;
    target_ulong virt_page2;
    tcg_insn_unit *gen_code_buf;
    int gen_code_size, search_size, max_insns;

    assert_memory_lock();
#ifdef HAVE_PTHREAD_JIT_PROTECT
    tb_exec_unlock(false);
#endif
    phys_pc = get_page_addr_code(env, pc);

    if (phys_pc == -1) {
        /* Generate a temporary TB with 1 insn in it */
        cflags &= ~CF_COUNT_MASK;
        cflags |= CF_NOCACHE | 1;
    }

    cflags &= ~CF_CLUSTER_MASK;
    cflags |= cpu->cluster_index << CF_CLUSTER_SHIFT;

    max_insns = cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
    if (cpu->singlestep_enabled) {
        max_insns = 1;
    }

 buffer_overflow:
    tb = tcg_tb_alloc(tcg_ctx);
    if (unlikely(!tb)) {
        /* flush must be done */
        tb_flush(cpu);
        mmap_unlock();
        /* Make the execution loop process the flush as soon as possible.  */
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }

    gen_code_buf = tcg_ctx->code_gen_ptr;
    tb->tc.ptr = gen_code_buf;
    tb->pc = pc;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;
    tb->orig_tb = NULL;
    tb->trace_vcpu_dstate = *cpu->trace_dstate;
    tcg_ctx->tb_cflags = cflags;
 tb_overflow:

    tcg_func_start(tcg_ctx);

    tcg_ctx->cpu = env_cpu(env);
    gen_intermediate_code(cpu, tb, max_insns);
    tcg_ctx->cpu = NULL;

    /* generate machine code */
    tb->jmp_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
    tcg_ctx->tb_jmp_reset_offset = tb->jmp_reset_offset;
    if (TCG_TARGET_HAS_direct_jump) {
        tcg_ctx->tb_jmp_insn_offset = tb->jmp_target_arg;
        tcg_ctx->tb_jmp_target_addr = NULL;
    } else {
        tcg_ctx->tb_jmp_insn_offset = NULL;
        tcg_ctx->tb_jmp_target_addr = tb->jmp_target_arg;
    }

    gen_code_size = tcg_gen_code(tcg_ctx, tb);
    if (unlikely(gen_code_size < 0)) {
        switch (gen_code_size) {
        case -1:
            /*
             * Overflow of code_gen_buffer, or the current slice of it.
             *
             * TODO: We don't need to re-do gen_intermediate_code, nor
             * should we re-do the tcg optimization currently hidden
             * inside tcg_gen_code.  All that should be required is to
             * flush the TBs, allocate a new TB, re-initialize it per
             * above, and re-do the actual code generation.
             */
            goto buffer_overflow;

        case -2:
            /*
             * The code generated for the TranslationBlock is too large.
             * The maximum size allowed by the unwind info is 64k.
             * There may be stricter constraints from relocations
             * in the tcg backend.
             *
             * Try again with half as many insns as we attempted this time.
             * If a single insn overflows, there's a bug somewhere...
             */
            max_insns = tb->icount;
            assert(max_insns > 1);
            max_insns /= 2;
            goto tb_overflow;

        default:
            g_assert_not_reached();
        }
    }
    search_size = encode_search(cpu->uc, tb, (uint8_t *)gen_code_buf + gen_code_size);
    if (unlikely(search_size < 0)) {
        goto buffer_overflow;
    }
    tb->tc.size = gen_code_size;

    tcg_ctx->code_gen_ptr = (void *)
        ROUND_UP((uintptr_t)gen_code_buf + gen_code_size + search_size,
                 CODE_GEN_ALIGN);

    /* init jump list */
    tb->jmp_list_head = (uintptr_t)NULL;
    tb->jmp_list_next[0] = (uintptr_t)NULL;
    tb->jmp_list_next[1] = (uintptr_t)NULL;
    tb->jmp_dest[0] = (uintptr_t)NULL;
    tb->jmp_dest[1] = (uintptr_t)NULL;

    /* init original jump addresses which have been set during tcg_gen_code() */
    if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }

    /* check next page if needed */
    virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
    phys_page2 = -1;
    if ((pc & TARGET_PAGE_MASK) != virt_page2) {
        phys_page2 = get_page_addr_code(env, virt_page2);
    }
    /*
     * No explicit memory barrier is required -- tb_link_page() makes the
     * TB visible in a consistent state.
     */
    existing_tb = tb_link_page(cpu->uc, tb, phys_pc, phys_page2);
    /* if the TB already exists, discard what we just translated */
    if (unlikely(existing_tb != tb)) {
        uintptr_t orig_aligned = (uintptr_t)gen_code_buf;

        orig_aligned -= ROUND_UP(sizeof(*tb), tcg_ctx->uc->qemu_icache_linesize);
        tcg_ctx->code_gen_ptr = (void *)orig_aligned;
        return existing_tb;
    }
    tcg_tb_insert(tcg_ctx, tb);
    return tb;
}

/*
 * @p must be non-NULL.
 * user-mode: call with mmap_lock held.
 * !user-mode: call with all @pages locked.
 */
static void
tb_invalidate_phys_page_range__locked(struct uc_struct *uc, struct page_collection *pages,
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
        // Unicorn: We may indeed generate a TB without any instruction which breaks qemu assumption.
        if ( (!(tb_end <= start || tb_start >= end)) || (tb_start == tb_end) ) {
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
 * Called with mmap_lock held for user-mode emulation
 */
void tb_invalidate_phys_page_range(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end)
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
 * Called with mmap_lock held for user-mode emulation.
 */
void tb_invalidate_phys_range(struct uc_struct *uc, ram_addr_t start, ram_addr_t end)
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
 * Call with all @pages in the range [@start, @start + len[ locked.
 */
void tb_invalidate_phys_page_fast(struct uc_struct *uc, struct page_collection *pages,
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

/* user-mode: call with mmap_lock held */
void tb_check_watchpoint(CPUState *cpu, uintptr_t retaddr)
{
    TCGContext *tcg_ctx = cpu->uc->tcg_ctx;
    TranslationBlock *tb;

    assert_memory_lock();

    tb = tcg_tb_lookup(tcg_ctx, retaddr);
    if (tb) {
        /* We can use retranslation to find the PC.  */
        cpu_restore_state_from_tb(cpu, tb, retaddr, true);
        tb_phys_invalidate(tcg_ctx, tb, -1);
    } else {
        /* The exception probably happened in a helper.  The CPU state should
           have been saved before calling it. Fetch the PC from there.  */
        CPUArchState *env = cpu->env_ptr;
        target_ulong pc, cs_base;
        tb_page_addr_t addr;
        uint32_t flags;

        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        addr = get_page_addr_code(env, pc);
        if (addr != -1) {
            tb_invalidate_phys_range(cpu->uc, addr, addr + 1);
        }
    }
}

/* in deterministic execution mode, instructions doing device I/Os
 * must be at the end of the TB.
 *
 * Called by softmmu_template.h, with iothread mutex not held.
 */
void cpu_io_recompile(CPUState *cpu, uintptr_t retaddr)
{
    TCGContext *tcg_ctx = cpu->uc->tcg_ctx;
#if defined(TARGET_MIPS) || defined(TARGET_SH4)
    CPUArchState *env = cpu->env_ptr;
#endif
    TranslationBlock *tb;
    uint32_t n;

    tb = tcg_tb_lookup(tcg_ctx, retaddr);
    if (!tb) {
        cpu_abort(cpu, "cpu_io_recompile: could not find TB for pc=%p",
                  (void *)retaddr);
    }
    cpu_restore_state_from_tb(cpu, tb, retaddr, true);

    /* On MIPS and SH, delay slot instructions can only be restarted if
       they were already the first instruction in the TB.  If this is not
       the first instruction in a TB then re-execute the preceding
       branch.  */
    n = 1;
#if defined(TARGET_MIPS)
    if ((env->hflags & MIPS_HFLAG_BMASK) != 0
        && env->active_tc.PC != tb->pc) {
        env->active_tc.PC -= (env->hflags & MIPS_HFLAG_B16 ? 2 : 4);
        cpu_neg(cpu)->icount_decr.u16.low++;
        env->hflags &= ~MIPS_HFLAG_BMASK;
        n = 2;
    }
#elif defined(TARGET_SH4)
    if ((env->flags & ((DELAY_SLOT | DELAY_SLOT_CONDITIONAL))) != 0
        && env->pc != tb->pc) {
        env->pc -= 2;
        cpu_neg(cpu)->icount_decr.u16.low++;
        env->flags &= ~(DELAY_SLOT | DELAY_SLOT_CONDITIONAL);
        n = 2;
    }
#endif

    /* Generate a new TB executing the I/O insn.  */
    cpu->cflags_next_tb = curr_cflags() | CF_LAST_IO | n;

    if (tb_cflags(tb) & CF_NOCACHE) {
        if (tb->orig_tb) {
            /* Invalidate original TB if this TB was generated in
             * cpu_exec_nocache() */
            tb_phys_invalidate(tcg_ctx, tb->orig_tb, -1);
        }
        tcg_tb_remove(tcg_ctx, tb);
    }

    /* TODO: If env->pc != tb->pc (i.e. the faulting instruction was not
     * the first in the TB) then we end up generating a whole new TB and
     *  repeating the fault, which is horribly inefficient.
     *  Better would be to execute just this insn uncached, or generate a
     *  second new TB.
     */
    cpu_loop_exit_noexc(cpu);
}

static void tb_jmp_cache_clear_page(CPUState *cpu, target_ulong page_addr)
{
    unsigned int i, i0 = tb_jmp_cache_hash_page(cpu->uc, page_addr);

    for (i = 0; i < TB_JMP_PAGE_SIZE; i++) {
        cpu->tb_jmp_cache[i0 + i] = NULL;
    }
}

void tb_flush_jmp_cache(CPUState *cpu, target_ulong addr)
{
#ifdef TARGET_ARM
    struct uc_struct *uc = cpu->uc;
#endif

    /* Discard jump cache entries for any tb which might potentially
       overlap the flushed page.  */
    tb_jmp_cache_clear_page(cpu, addr - TARGET_PAGE_SIZE);
    tb_jmp_cache_clear_page(cpu, addr);
}

/* This is a wrapper for common code that can not use CONFIG_SOFTMMU */
void tcg_flush_softmmu_tlb(struct uc_struct *uc)
{
    tlb_flush(uc->cpu);
}


#ifdef HAVE_PTHREAD_JIT_PROTECT
static bool tb_exec_is_locked(TCGContext *tcg_ctx)
{
    return tcg_ctx->code_gen_locked;
}

static void tb_exec_change(TCGContext *tcg_ctx, bool locked)
{
    jit_write_protect(locked);
    tcg_ctx->code_gen_locked = locked;
}
#else /* not needed on non-Darwin platforms */
static bool tb_exec_is_locked(TCGContext *tcg_ctx)
{
    return false;
}

static void tb_exec_change(TCGContext *tcg_ctx, bool locked) {}
#endif

void tb_exec_lock(TCGContext *tcg_ctx)
{
    /* assumes sys_icache_invalidate already called */
    tb_exec_change(tcg_ctx, true);
}

void tb_exec_unlock(TCGContext *tcg_ctx)
{
    tb_exec_change(tcg_ctx, false);
}