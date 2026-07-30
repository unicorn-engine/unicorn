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
#include "internal.h"
#include "qemu/timer.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "uc_priv.h"

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

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
# define L1_MAP_ADDR_SPACE_BITS  HOST_LONG_BITS
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_PHYS_ADDR_SPACE_BITS
#endif

/* Make sure all possible CPU event bits fit in tb->trace_vcpu_dstate */
QEMU_BUILD_BUG_ON(CPU_TRACE_DSTATE_MAX_EVENTS >
                  sizeof_field(TranslationBlock, trace_vcpu_dstate)
                  * BITS_PER_BYTE);

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
int cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
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
    check_offset = (uintptr_t)tcg_splitwx_to_rw((void *)host_pc) -
        (uintptr_t)uc->tcg_ctx->code_gen_buffer;

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

PageDesc *page_find_alloc(struct uc_struct *uc, tb_page_addr_t index, int alloc)
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

void
do_assert_page_locked(const PageDesc *pd, const char *file, int line)
{
    if (unlikely(!page_is_locked(pd))) {
        // error_report("assert_page_lock: PageDesc %p not locked @ %s:%d",
        //              pd, file, line);
        abort();    // unreachable in unicorn.
    }
}

void assert_no_pages_locked(void)
{
    ht_pages_locked_debug_init();
    g_assert(g_hash_table_size(ht_pages_locked_debug) == 0);
}

#else /* !CONFIG_DEBUG_TCG */

static inline void page_lock__debug(const PageDesc *pd)
{
}

static inline void page_unlock__debug(const PageDesc *pd)
{
}

#endif /* CONFIG_DEBUG_TCG */

void page_lock(PageDesc *pd)
{
    page_lock__debug(pd);
}

void page_unlock(PageDesc *pd)
{
    page_unlock__debug(pd);
}

#if 0
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
        do_page_entry_lock(pe);
        return false;
    }
    /*
     * Try to acquire out-of-order lock; if busy, return busy so that we acquire
     * locks in order.
     */
    return page_entry_trylock(pe);
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
#endif

/*
 * Lock a range of pages ([@start,@end[) as well as the pages of all
 * intersecting TBs.
 * Locking order: acquire locks in ascending order of page index.
 */
struct page_collection *
page_collection_lock(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end)
{
#if 0
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
    g_tree_foreach(set->tree, page_entry_lock, NULL);

    for (index = start; index <= end; index++) {
        TranslationBlock *tb;
        int n;

        pd = page_find(uc, index);
        if (pd == NULL) {
            continue;
        }
        if (page_trylock_add(uc, set, index << TARGET_PAGE_BITS)) {
            g_tree_foreach(set->tree, page_entry_unlock, NULL);
            goto retry;
        }
        assert_page_locked(pd);
        PAGE_FOR_EACH_TB(pd, tb, n) {
            if (page_trylock_add(uc, set, tb->page_addr[0]) ||
                (tb->page_addr[1] != -1 &&
                 page_trylock_add(uc, set, tb->page_addr[1]))) {
                /* drop all locks, and reacquire in order */
                g_tree_foreach(set->tree, page_entry_unlock, NULL);
                goto retry;
            }
        }
    }
    return set;
#else
    return NULL;
#endif
}

void page_collection_unlock(struct page_collection *set)
{
#if 0
    /* entries are unlocked and freed via page_entry_destroy */
    g_tree_destroy(set->tree);
    g_free(set);
#endif
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
#ifdef WIN32_ENABLE_VEH
#define COMMIT_COUNT (1024) // Commit 4MB per exception
#define CLOSURE_SIZE (4096)

#ifdef _WIN64
static LONG code_gen_buffer_handler(PEXCEPTION_POINTERS ptr, struct uc_struct *uc)
#else
/*
The first two DWORD or smaller arguments that are found in the argument list
from left to right are passed in ECX and EDX registers; all other arguments
are passed on the stack from right to left.
*/
static LONG __fastcall code_gen_buffer_handler(PEXCEPTION_POINTERS ptr, struct uc_struct* uc)
#endif
{
    PEXCEPTION_RECORD record = ptr->ExceptionRecord;
    if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        uint8_t* base = (uint8_t*)(record->ExceptionInformation[1]);
        uint8_t* left = uc->tcg_ctx->initial_buffer;
        uint8_t* right = left + uc->tcg_ctx->initial_buffer_size;
        if (left && base >= left && base < right) {
            // It's our region
            uint8_t* base_end = base + COMMIT_COUNT * 4096;
            uint32_t size = COMMIT_COUNT * 4096;
            if (base_end >= right) {
                size = right - base;
                // whoops, we are almost run out of memory! Commit all instead
            }
            if (VirtualAlloc(base, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
                return EXCEPTION_CONTINUE_EXECUTION;
            } else {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static inline void may_remove_handler(struct uc_struct *uc) {
    if (uc->seh_closure) {
        if (uc->seh_handle) {
            RemoveVectoredExceptionHandler(uc->seh_handle);
        }
        VirtualFree(uc->seh_closure, 0, MEM_RELEASE);
    }
}
#endif // WIN32_ENABLE_VEH

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    size_t size = tcg_ctx->code_gen_buffer_size;
#ifdef WIN32_ENABLE_VEH
    uint8_t *closure, *data;
    uint8_t *ptr;
    void* handler = code_gen_buffer_handler;

    if (uc->prealloc) {
        // Commit the whole buffer upfront so no lazy-commit exception handler
        // is needed. Required for safe concurrent use of multiple uc instances.
        return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    may_remove_handler(uc);

    // Naive trampoline implementation
    closure = VirtualAlloc(NULL, CLOSURE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!closure) {
        return NULL;
    }
    uc->seh_closure = closure;
    data = closure + CLOSURE_SIZE /2;
    
#ifdef _WIN64
    ptr = closure;
    *ptr = 0x48; // REX.w
    ptr += 1;
    *ptr = 0xb8; // mov rax
    ptr += 1;
    memcpy(ptr, &data, 8); // mov rax, &data
    ptr += 8;
    // ; rax = &data
    // mov [rax], rdx ; save rdx
    // mov rdx, [rax+0x8] ; move uc pointer to 2nd arg
    // sub rsp, 0x10; reserve 2 slots as ms fastcall requires
    // call [rax + 0x10] ; go to handler
    const char tramp[] = "\x48\x89\x10\x48\x8b\x50\x08\x48\x83\xec\x10\xff\x50\x10";
    memcpy(ptr, (void*)tramp, sizeof(tramp) - 1); // Note last zero!
    ptr += sizeof(tramp) - 1;
    *ptr = 0x48; // REX.w
    ptr += 1;
    *ptr = 0xba; // mov rdx
    ptr += 1;
    memcpy(ptr, &data, 8); // mov rdx, &data
    ptr += 8;
    // ; rdx = &data
    // add rsp, 0x10 ; clean stack
    // mov rdx, [rdx] ; restore rdx
    // ret
    const char tramp2[] = "\x48\x83\xc4\x10\x48\x8b\x12\xc3";
    memcpy(ptr, (void*)tramp2, sizeof(tramp2) - 1);

    memcpy(data + 0x8,  (void*)&uc, 8);
    memcpy(data + 0x10, (void*)&handler, 8);
#else
    ptr = closure;
    *ptr = 0xb8; // mov eax
    ptr += 1;
    memcpy(ptr, (void*)&data, 4); // mov eax, &data
    ptr += 4;
    // ; eax = &data
    // mov [eax], edx; save edx
    // mov [eax+0x4], ecx; save ecx
    // mov ecx, [esp+4]; get ptr to exception because of cdecl
    // mov edx, [eax+0x8]; get ptr to uc
    // call [eax + 0xC]; get ptr to our handler, it's fastcall so we don't clean stac
    const char tramp[] = "\x89\x10\x89\x48\x04\x8b\x4c\x24\x04\x8b\x50\x08\xff\x50\x0c";
    memcpy(ptr, (void*)tramp, sizeof(tramp) - 1);
    ptr += sizeof(tramp) - 1;
    *ptr = 0xb9; // mov ecx
    ptr += 1;
    memcpy(ptr, (void*)&data, 4); // mov ecx, &data
    ptr += 4;

    // mov edx, [ecx] ; restore edx
    // mov ecx, [ecx+4] ; restore ecx
    // ret 4
    const char tramp2[] = "\x8b\x11\x8b\x49\x04\xc2\x04\x00";
    memcpy(ptr, (void*)tramp2, sizeof(tramp2) - 1);

    memcpy(data + 0x8,  (void*)&uc, 4);
    memcpy(data + 0xC, (void*)&handler, 4);
#endif

    uc->seh_handle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)closure);
    if (!uc->seh_handle) {
        VirtualFree(uc->seh_closure, 0, MEM_RELEASE);
        uc->seh_closure = NULL;
        return NULL;
    }

    return VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    // The VEH lazy-commit path is compiled out: always commit upfront.
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#endif // WIN32_ENABLE_VEH
}
void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    if (tcg_ctx->initial_buffer) {
#ifdef WIN32_ENABLE_VEH
        may_remove_handler(uc);
#endif
        VirtualFree(tcg_ctx->initial_buffer, 0, MEM_RELEASE);
    }
}
#else
void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    if (tcg_ctx->initial_buffer) {
        if (munmap(tcg_ctx->initial_buffer, tcg_ctx->initial_buffer_size)) {
            perror("fail code_gen_buffer");
        }
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
    tcg_ctx->initial_buffer = tcg_ctx->code_gen_buffer;
    tcg_ctx->initial_buffer_size = tcg_ctx->code_gen_buffer_size;
    uc->tcg_buffer_size = tcg_ctx->initial_buffer_size;
    if (tcg_ctx->code_gen_buffer == NULL) {
        fprintf(stderr, "Could not allocate dynamic translator buffer\n");
        exit(1);
    }
}

static void uc_tb_flush(struct uc_struct *uc) {
    tb_exec_unlock(uc);
    tb_flush(uc->cpu);
    tb_exec_lock(uc);
}

static void uc_invalidate_tb(struct uc_struct *uc, uint64_t start_addr, size_t len) 
{
    tb_page_addr_t start, end;

    uc->nested_level++;
    if (sigsetjmp(uc->jmp_bufs[uc->nested_level - 1], 0) != 0) {
        // We a get cpu fault in get_page_addr_code, ignore it.
        uc->nested_level--;
        return;
    }

    // GPA to ram addr
    // https://raw.githubusercontent.com/android/platform_external_qemu/master/docs/QEMU-MEMORY-MANAGEMENT.TXT
    // start_addr : GPA
    // start (returned): ram addr
    // (GPA -> HVA via memory_region_get_ram_addr(mr) + GPA + block->host,
    // GVA -> GPA via tlb & softmmu
    // HVA -> HPA via host mmu)
    start = get_page_addr_code(uc->cpu->env_ptr, start_addr) & (target_ulong)(-1);

    uc->nested_level--;

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
    cflags |= ((uint32_t)cpu->cluster_index) << CF_CLUSTER_SHIFT;

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
void tcg_exec_init(struct uc_struct *uc, uint32_t tb_size)
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
    tb_exec_unlock(uc);
    tcg_prologue_init(uc->tcg_ctx);
    tb_exec_lock(uc);
    /* cpu_interrupt_handler is not used in uc1 */
    uc->l1_map = g_malloc0(sizeof(void *) * V_L1_MAX_SIZE);
    /* Invalidate / Cache TBs */
    uc->uc_invalidate_tb = uc_invalidate_tb;
    uc->uc_gen_tb = uc_gen_tb;
    uc->tb_flush = uc_tb_flush;

    /* Inline hooks optimization */
    uc->add_inline_hook = uc_add_inline_hook;
    uc->del_inline_hook = uc_del_inline_hook;
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
    tb_exec_unlock(cpu->uc);
#endif
    phys_pc = get_page_addr_code(env, pc);

    if (phys_pc == -1) {
        /* Generate a temporary TB; do not cache */
        cflags |= CF_NOCACHE;
    }

    cflags &= ~CF_CLUSTER_MASK;
    cflags |= ((uint32_t)cpu->cluster_index) << CF_CLUSTER_SHIFT;

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
    tb->tc.ptr = (tcg_insn_unit *)tcg_splitwx_to_rx(gen_code_buf);
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
    UC_TRACE_START(UC_TRACE_TB_TRANS);
    gen_intermediate_code(cpu, tb, max_insns);
    UC_TRACE_END(UC_TRACE_TB_TRANS, "[uc] translate tb 0x%" PRIx64 ": ", tb->pc);
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

    /* Undoes tlb_set_dirty in notdirty_write. */
    if (!uc_mem_hook_installed(cpu->uc, tb->pc)) {
        tlb_reset_dirty_by_vaddr(cpu, pc & TARGET_PAGE_MASK,
                                (pc & ~TARGET_PAGE_MASK) + tb->size);
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
