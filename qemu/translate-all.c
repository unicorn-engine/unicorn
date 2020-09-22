/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/mman.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "unicorn/platform.h"

#include "config.h"

#include "qemu-common.h"
#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "tcg.h"
#if defined(CONFIG_USER_ONLY)
#include "qemu.h"
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#include <sys/param.h>
#if __FreeBSD_version >= 700104
#define HAVE_KINFO_GETVMMAP
#define sigqueue sigqueue_freebsd  /* avoid redefinition */
#include <sys/proc.h>
#include <machine/profile.h>
#define _KERNEL
#include <sys/user.h>
#undef _KERNEL
#undef sigqueue
#include <libutil.h>
#endif
#endif
#else
#include "exec/address-spaces.h"
#endif

#include "exec/cputlb.h"
#include "translate-all.h"
#include "qemu/timer.h"

#include "uc_priv.h"

//#define DEBUG_TB_INVALIDATE
//#define DEBUG_FLUSH
/* make various TB consistency checks */
//#define DEBUG_TB_CHECK

#if !defined(CONFIG_USER_ONLY)
/* TB consistency checks only implemented for usermode emulation.  */
#undef DEBUG_TB_CHECK
#endif

#define SMC_BITMAP_USE_THRESHOLD 10

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    TranslationBlock *first_tb;
    /* in order to optimize self modifying code, we count the number
       of lookups we do to a given page to use a bitmap */
    unsigned int code_write_count;
    uint8_t *code_bitmap;
#if defined(CONFIG_USER_ONLY)
    unsigned long flags;
#endif
} PageDesc;

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if !defined(CONFIG_USER_ONLY)
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
# define L1_MAP_ADDR_SPACE_BITS  HOST_LONG_BITS
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_PHYS_ADDR_SPACE_BITS
#endif
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_VIRT_ADDR_SPACE_BITS
#endif

/* Size of the L2 (and L3, etc) page tables.  */
#define V_L2_BITS 10
#define V_L2_SIZE (1 << V_L2_BITS)

/* The bits remaining after N lower levels of page tables.  */
#define V_L1_BITS_REM \
    ((L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % V_L2_BITS)

#if V_L1_BITS_REM < 4
#define V_L1_BITS  (V_L1_BITS_REM + V_L2_BITS)
#else
#define V_L1_BITS  V_L1_BITS_REM
#endif

#define V_L1_SIZE  ((target_ulong)1 << V_L1_BITS)

#define V_L1_SHIFT (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - V_L1_BITS)

static uintptr_t qemu_real_host_page_size;
static uintptr_t qemu_host_page_size;
static uintptr_t qemu_host_page_mask;


static void tb_link_page(struct uc_struct *uc, TranslationBlock *tb,
    tb_page_addr_t phys_pc, tb_page_addr_t phys_page2);
static TranslationBlock *tb_find_pc(struct uc_struct *uc, uintptr_t tc_ptr);

// Unicorn: for cleaning up memory later.
void free_code_gen_buffer(struct uc_struct *uc);

static void cpu_gen_init(struct uc_struct *uc)
{
    uc->tcg_ctx = g_malloc(sizeof(TCGContext));
    tcg_context_init(uc->tcg_ctx);
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
            x = V_L1_SHIFT / V_L2_BITS;
            if (x <= 1) {
                for (i = 0; i < V_L1_SIZE; i++) {
                    p = uc->l1_map[i];
                    if (p) {
                        g_free(p);
                        uc->l1_map[i] = NULL;
                    }
                }
            } else {
                for (i = 0; i < V_L1_SIZE; i++) {
                    p = uc->l1_map[i];
                    if (p) {
                        tb_clean_internal(p, x - 1);
                        uc->l1_map[i] = NULL;
                    }
                }
            }
        }
    }
}

/* return non zero if the very first instruction is invalid so that
   the virtual CPU can trigger an exception.

   '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/
static int cpu_gen_code(CPUArchState *env, TranslationBlock *tb, int *gen_code_size_ptr)    // qq
{
    TCGContext *s = env->uc->tcg_ctx;
    tcg_insn_unit *gen_code_buf;
    int gen_code_size;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count1++; /* includes aborted translations because of
                       exceptions */
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    gen_intermediate_code(env, tb);

    // Unicorn: when tracing block, patch block size operand for callback
    if (env->uc->size_arg != -1 && HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_BLOCK, tb->pc)) {
        if (env->uc->block_full)    // block size is unknown
            *(s->gen_opparam_buf + env->uc->size_arg) = 0;
        else
            *(s->gen_opparam_buf + env->uc->size_arg) = tb->size;
    }

    /* generate machine code */
    gen_code_buf = tb->tc_ptr;
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count++;
    s->interm_time += profile_getclock() - ti;
    s->code_time -= profile_getclock();
#endif
    gen_code_size = tcg_gen_code(s, gen_code_buf);
    if (gen_code_size == -1) {
        return -1;
    }
    //printf(">>> code size = %u: ", gen_code_size);
    //int i;
    //for (i = 0; i < gen_code_size; i++) {
    //    printf(" %02x", gen_code_buf[i]);
    //}
    //printf("\n");
    *gen_code_size_ptr = gen_code_size;
#ifdef CONFIG_PROFILER
    s->code_time += profile_getclock();
    s->code_in_len += tb->size;
    s->code_out_len += gen_code_size;
#endif

    return 0;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 */
static int cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                                     uintptr_t searched_pc)
{
    CPUArchState *env = cpu->env_ptr;
    TCGContext *s = cpu->uc->tcg_ctx;
    int j;
    uintptr_t tc_ptr;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    gen_intermediate_code_pc(env, tb);

    /* find opc index corresponding to search_pc */
    tc_ptr = (uintptr_t)tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif
    j = tcg_gen_code_search_pc(s, (tcg_insn_unit *)tc_ptr,
                               searched_pc - tc_ptr);
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (s->gen_opc_instr_start[j] == 0) {
        j--;
    }
    cpu->icount_decr.u16.low -= s->gen_opc_icount[j];

    restore_state_to_opc(env, tb, j);

#ifdef CONFIG_PROFILER
    s->restore_time += profile_getclock() - ti;
    s->restore_count++;
#endif
    return 0;
}

bool cpu_restore_state(CPUState *cpu, uintptr_t retaddr)
{
    TranslationBlock *tb;
    CPUArchState *env = cpu->env_ptr;

    tb = tb_find_pc(env->uc, retaddr);
    if (tb) {
        cpu_restore_state_from_tb(cpu, tb, retaddr);
        return true;
    }
    return false;
}

#ifdef _WIN32
static inline QEMU_UNUSED_FUNC void map_exec(void *addr, long size)
{
    DWORD old_protect;
    VirtualProtect(addr, size,
                   PAGE_EXECUTE_READWRITE, &old_protect);
}
#else
static inline QEMU_UNUSED_FUNC void map_exec(void *addr, long size)
{
    unsigned long start, end, page_size;

    page_size = getpagesize();
    start = (unsigned long)addr;
    start &= ~(page_size - 1);

    end = (unsigned long)addr + size;
    end += page_size - 1;
    end &= ~(page_size - 1);

    mprotect((void *)start, end - start,
             PROT_READ | PROT_WRITE | PROT_EXEC);
}
#endif

static void page_size_init(void)
{
    /* NOTE: we can always suppose that qemu_host_page_size >=
       TARGET_PAGE_SIZE */
    qemu_real_host_page_size = getpagesize();
    if (qemu_host_page_size == 0) {
        qemu_host_page_size = qemu_real_host_page_size;
    }
    if (qemu_host_page_size < TARGET_PAGE_SIZE) {
        qemu_host_page_size = TARGET_PAGE_SIZE;
    }
    qemu_host_page_mask = ~(qemu_host_page_size - 1);
}

static void page_init(void)
{
    page_size_init();
#if defined(CONFIG_BSD) && defined(CONFIG_USER_ONLY)
    {
#ifdef HAVE_KINFO_GETVMMAP
        struct kinfo_vmentry *freep;
        int i, cnt;

        freep = kinfo_getvmmap(getpid(), &cnt);
        if (freep) {
            mmap_lock();
            for (i = 0; i < cnt; i++) {
                unsigned long startaddr, endaddr;

                startaddr = freep[i].kve_start;
                endaddr = freep[i].kve_end;
                if (h2g_valid(startaddr)) {
                    startaddr = h2g(startaddr) & TARGET_PAGE_MASK;

                    if (h2g_valid(endaddr)) {
                        endaddr = h2g(endaddr);
                        page_set_flags(startaddr, endaddr, PAGE_RESERVED);
                    } else {
#if TARGET_ABI_BITS <= L1_MAP_ADDR_SPACE_BITS
                        endaddr = ~0ul;
                        page_set_flags(startaddr, endaddr, PAGE_RESERVED);
#endif
                    }
                }
            }
            free(freep);
            mmap_unlock();
        }
#else
        FILE *f;

        last_brk = (unsigned long)sbrk(0);

        f = fopen("/compat/linux/proc/self/maps", "r");
        if (f) {
            mmap_lock();

            do {
                unsigned long startaddr, endaddr;
                int n;

                n = fscanf(f, "%lx-%lx %*[^\n]\n", &startaddr, &endaddr);

                if (n == 2 && h2g_valid(startaddr)) {
                    startaddr = h2g(startaddr) & TARGET_PAGE_MASK;

                    if (h2g_valid(endaddr)) {
                        endaddr = h2g(endaddr);
                    } else {
                        endaddr = ~0ul;
                    }
                    page_set_flags(startaddr, endaddr, PAGE_RESERVED);
                }
            } while (!feof(f));

            fclose(f);
            mmap_unlock();
        }
#endif
    }
#endif
}

static PageDesc *page_find_alloc(struct uc_struct *uc, tb_page_addr_t index, int alloc)
{
    PageDesc *pd;
    void **lp;
    int i;

#if defined(CONFIG_USER_ONLY)
    /* We can't use g_malloc because it may recurse into a locked mutex. */
# define ALLOC(P, SIZE)                                 \
    do {                                                \
        P = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,    \
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   \
    } while (0)
#else
# define ALLOC(P, SIZE) \
    do { P = g_malloc0(SIZE); } while (0)
#endif

    if (uc->l1_map == NULL) {
        uc->l1_map_size = V_L1_SIZE * sizeof(uc->l1_map);
        ALLOC(uc->l1_map, uc->l1_map_size);
    }

    /* Level 1.  Always allocated.  */
    lp = uc->l1_map + ((index >> V_L1_SHIFT) & (V_L1_SIZE - 1));

    /* Level 2..N-1.  */
    for (i = V_L1_SHIFT / V_L2_BITS - 1; i > 0; i--) {
        void **p = *lp;

        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            ALLOC(p, sizeof(void *) * V_L2_SIZE);
            *lp = p;
        }

        lp = p + ((index >> (i * V_L2_BITS)) & (V_L2_SIZE - 1));
    }

    pd = *lp;
    if (pd == NULL) {
        if (!alloc) {
            return NULL;
        }
        ALLOC(pd, sizeof(PageDesc) * V_L2_SIZE);
        *lp = pd;
    }

#undef ALLOC

    return pd + (index & (V_L2_SIZE - 1));
}

static inline PageDesc *page_find(struct uc_struct *uc, tb_page_addr_t index)
{
    return page_find_alloc(uc, index, 0);
}

#if !defined(CONFIG_USER_ONLY)
#define mmap_lock() do { } while (0)
#define mmap_unlock() do { } while (0)
#endif

#if defined(CONFIG_USER_ONLY)
/* Currently it is not recommended to allocate big chunks of data in
   user mode. It will change when a dedicated libc will be used.  */
/* ??? 64-bit hosts ought to have no problem mmaping data outside the
   region in which the guest needs to run.  Revisit this.  */
#define USE_STATIC_CODE_GEN_BUFFER
#endif

/* ??? Should configure for this, not list operating systems here.  */
#if (defined(__linux__) \
    || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) \
    || defined(__DragonFly__) || defined(__OpenBSD__) \
    || defined(__NetBSD__))
# define USE_MMAP
#endif

/* Minimum size of the code gen buffer.  This number is randomly chosen,
   but not so small that we can't have a fair number of TB's live.  */
#define MIN_CODE_GEN_BUFFER_SIZE     (1024u * 1024)

/* Maximum size of the code gen buffer we'd like to use.  Unless otherwise
   indicated, this is constrained by the range of direct branches on the
   host cpu, as used by the TCG implementation of goto_tb.  */
#if defined(__x86_64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2ul * 1024 * 1024 * 1024)
#elif defined(__sparc__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2ul * 1024 * 1024 * 1024)
#elif defined(__aarch64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (128ul * 1024 * 1024)
#elif defined(__arm__)
# define MAX_CODE_GEN_BUFFER_SIZE  (16u * 1024 * 1024)
#elif defined(__s390x__)
  /* We have a +- 4GB range on the branches; leave some slop.  */
# define MAX_CODE_GEN_BUFFER_SIZE  (3ul * 1024 * 1024 * 1024)
#elif defined(__mips__)
  /* We have a 256MB branch region, but leave room to make sure the
     main executable is also within that region.  */
# define MAX_CODE_GEN_BUFFER_SIZE  (128ul * 1024 * 1024)
#else
# define MAX_CODE_GEN_BUFFER_SIZE  ((size_t)-1)
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (8 * 1024 * 1024)

#define DEFAULT_CODE_GEN_BUFFER_SIZE \
  (DEFAULT_CODE_GEN_BUFFER_SIZE_1 < MAX_CODE_GEN_BUFFER_SIZE \
   ? DEFAULT_CODE_GEN_BUFFER_SIZE_1 : MAX_CODE_GEN_BUFFER_SIZE)

static inline size_t size_code_gen_buffer(struct uc_struct *uc, size_t tb_size)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;

    /* Size the buffer.  */
    if (tb_size == 0) {
#ifdef USE_STATIC_CODE_GEN_BUFFER
        tb_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
#else
        /* ??? Needs adjustments.  */
        /* ??? If we relax the requirement that CONFIG_USER_ONLY use the
           static buffer, we could size this on RESERVED_VA, on the text
           segment size of the executable, or continue to use the default.  */
        tb_size = (unsigned long)DEFAULT_CODE_GEN_BUFFER_SIZE;
#endif
    }
    if (tb_size < MIN_CODE_GEN_BUFFER_SIZE) {
        tb_size = MIN_CODE_GEN_BUFFER_SIZE;
    }
    if (tb_size > MAX_CODE_GEN_BUFFER_SIZE) {
        tb_size = MAX_CODE_GEN_BUFFER_SIZE;
    }
    tcg_ctx->code_gen_buffer_size = tb_size;
    return tb_size;
}

#ifdef __mips__
/* In order to use J and JAL within the code_gen_buffer, we require
   that the buffer not cross a 256MB boundary.  */
static inline bool cross_256mb(void *addr, size_t size)
{
    return ((uintptr_t)addr ^ ((uintptr_t)addr + size)) & 0xf0000000;
}

/* We weren't able to allocate a buffer without crossing that boundary,
   so make do with the larger portion of the buffer that doesn't cross.
   Returns the new base of the buffer, and adjusts code_gen_buffer_size.  */
static inline void *split_cross_256mb(struct uc_struct *uc, void *buf1, size_t size1)
{
    void *buf2 = (void *)(((uintptr_t)buf1 + size1) & 0xf0000000);
    size_t size2 = buf1 + size1 - buf2;
    TCGContext *tcg_ctx = uc->tcg_ctx;

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
static uint8_t QEMU_ALIGN(CODE_GEN_ALIGN, static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]);

void free_code_gen_buffer(struct uc_struct *uc)
{
    // Do nothing, we use a static buffer.
}

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    void *buf = static_code_gen_buffer;
#ifdef __mips__
    if (cross_256mb(buf, tcg_ctx->code_gen_buffer_size)) {
        buf = split_cross_256mb(buf, tcg_ctx->code_gen_buffer_size);
    }
#endif
    map_exec(buf, tcg_ctx->code_gen_buffer_size);
    return buf;
}
#elif defined(USE_MMAP)
void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    if (tcg_ctx->code_gen_buffer)
        munmap(tcg_ctx->code_gen_buffer, tcg_ctx->code_gen_buffer_size);
}

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    uintptr_t start = 0;
    void *buf;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    /* Constrain the position of the buffer based on the host cpu.
       Note that these addresses are chosen in concert with the
       addresses assigned in the relevant linker script file.  */
# if defined(__PIE__) || defined(__PIC__)
    /* Don't bother setting a preferred location if we're building
       a position-independent executable.  We're more likely to get
       an address near the main executable if we let the kernel
       choose the address.  */
# elif defined(__x86_64__) && defined(MAP_32BIT)
    /* Force the memory down into low memory with the executable.
       Leave the choice of exact location with the kernel.  */
    flags |= MAP_32BIT;
    /* Cannot expect to map more than 800MB in low memory.  */
    if (tcg_ctx->code_gen_buffer_size > 800u * 1024 * 1024) {
        tcg_ctx->code_gen_buffer_size = 800u * 1024 * 1024;
    }
# elif defined(__sparc__)
    start = 0x40000000ul;
# elif defined(__s390x__)
    start = 0x90000000ul;
# elif defined(__mips__)
    /* ??? We ought to more explicitly manage layout for softmmu too.  */
#  ifdef CONFIG_USER_ONLY
    start = 0x68000000ul;
#  elif _MIPS_SIM == _ABI64
    start = 0x128000000ul;
#  else
    start = 0x08000000ul;
#  endif
# endif

    buf = mmap((void *)start, tcg_ctx->code_gen_buffer_size,
               PROT_WRITE | PROT_READ | PROT_EXEC, flags, -1, 0);
    if (buf == MAP_FAILED) {
        return NULL;
    }

#ifdef __mips__
    if (cross_256mb(buf, tcg_ctx->code_gen_buffer_size)) {
        /* Try again, with the original still mapped, to avoid re-acquiring
           that 256mb crossing.  This time don't specify an address.  */
        size_t size2, size1 = tcg_ctx->code_gen_buffer_size;
        void *buf2 = mmap(NULL, size1, PROT_WRITE | PROT_READ | PROT_EXEC,
                          flags, -1, 0);
        if (buf2 != MAP_FAILED) {
            if (!cross_256mb(buf2, size1)) {
                /* Success!  Use the new buffer.  */
                munmap(buf, size1);
                return buf2;
            }
            /* Failure.  Work with what we had.  */
            munmap(buf2, size1);
        }

        /* Split the original buffer.  Free the smaller half.  */
        buf2 = split_cross_256mb(buf, size1);
        size2 = tcg_ctx->code_gen_buffer_size;
        munmap(buf + (buf == buf2 ? size2 : 0), size1 - size2);
        return buf2;
    }
#endif

    return buf;
}
#else
void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    if (tcg_ctx->code_gen_buffer)
        g_free(tcg_ctx->code_gen_buffer);
}

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    void *buf = g_malloc(tcg_ctx->code_gen_buffer_size);

    if (buf == NULL) {
        return NULL;
    }

#ifdef __mips__
    if (cross_256mb(buf, tcg_ctx->code_gen_buffer_size)) {
        void *buf2 = g_malloc(tcg_ctx->code_gen_buffer_size);
        if (buf2 != NULL && !cross_256mb(buf2, size1)) {
            /* Success!  Use the new buffer.  */
            free(buf);
            buf = buf2;
        } else {
            /* Failure.  Work with what we had.  Since this is malloc
               and not mmap, we can't free the other half.  */
            free(buf2);
            buf = split_cross_256mb(buf, tcg_ctx->code_gen_buffer_size);
        }
    }
#endif

    map_exec(buf, tcg_ctx->code_gen_buffer_size);
    return buf;
}
#endif /* USE_STATIC_CODE_GEN_BUFFER, USE_MMAP */

static inline void code_gen_alloc(struct uc_struct *uc, size_t tb_size)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;

    tcg_ctx->code_gen_buffer_size = size_code_gen_buffer(uc, tb_size);
    tcg_ctx->code_gen_buffer = alloc_code_gen_buffer(uc);
    if (tcg_ctx->code_gen_buffer == NULL) {
        fprintf(stderr, "Could not allocate dynamic translator buffer\n");
        exit(1);
    }

    //qemu_madvise(tcg_ctx.code_gen_buffer, tcg_ctx.code_gen_buffer_size,
    //        QEMU_MADV_HUGEPAGE);

    /* Steal room for the prologue at the end of the buffer.  This ensures
       (via the MAX_CODE_GEN_BUFFER_SIZE limits above) that direct branches
       from TB's to the prologue are going to be in range.  It also means
       that we don't need to mark (additional) portions of the data segment
       as executable.  */
    tcg_ctx->code_gen_prologue = (char*)tcg_ctx->code_gen_buffer +
            tcg_ctx->code_gen_buffer_size - 1024;
    tcg_ctx->code_gen_buffer_size -= 1024;

    tcg_ctx->code_gen_buffer_max_size = tcg_ctx->code_gen_buffer_size -
        (TCG_MAX_OP_SIZE * OPC_BUF_SIZE);
    tcg_ctx->code_gen_max_blocks = tcg_ctx->code_gen_buffer_size /
            CODE_GEN_AVG_BLOCK_SIZE;
    tcg_ctx->tb_ctx.tbs =
            g_malloc(tcg_ctx->code_gen_max_blocks * sizeof(TranslationBlock));
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(struct uc_struct *uc, unsigned long tb_size)
{
    TCGContext *tcg_ctx;

    cpu_gen_init(uc);
    code_gen_alloc(uc, tb_size);
    tcg_ctx = uc->tcg_ctx;
    tcg_ctx->code_gen_ptr = tcg_ctx->code_gen_buffer;
    tcg_ctx->uc = uc;
    page_init();
#if !defined(CONFIG_USER_ONLY) || !defined(CONFIG_USE_GUEST_BASE)
    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(tcg_ctx);
#endif
}

bool tcg_enabled(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    return tcg_ctx->code_gen_buffer != NULL;
}

/* Allocate a new translation block. Flush the translation buffer if
   too many translation blocks or too much generated code. */
static TranslationBlock *tb_alloc(struct uc_struct *uc, target_ulong pc)
{
    TranslationBlock *tb;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    if (tcg_ctx->tb_ctx.nb_tbs >= tcg_ctx->code_gen_max_blocks ||
        (size_t)(((char*)tcg_ctx->code_gen_ptr - (char*)tcg_ctx->code_gen_buffer)) >=
         tcg_ctx->code_gen_buffer_max_size) {
        return NULL;
    }
    tb = &tcg_ctx->tb_ctx.tbs[tcg_ctx->tb_ctx.nb_tbs++];
    tb->pc = pc;
    tb->cflags = 0;
    return tb;
}

void tb_free(struct uc_struct *uc, TranslationBlock *tb)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;

    /* In practice this is mostly used for single use temporary TB
       Ignore the hard cases and just back up if this TB happens to
       be the last one generated.  */
    if (tcg_ctx->tb_ctx.nb_tbs > 0 &&
            tb == &tcg_ctx->tb_ctx.tbs[tcg_ctx->tb_ctx.nb_tbs - 1]) {
        tcg_ctx->code_gen_ptr = tb->tc_ptr;
        tcg_ctx->tb_ctx.nb_tbs--;
    }
}

static inline void invalidate_page_bitmap(PageDesc *p)
{
    if (p->code_bitmap) {
        g_free(p->code_bitmap);
        p->code_bitmap = NULL;
    }
    p->code_write_count = 0;
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */
static void page_flush_tb_1(int level, void **lp)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            pd[i].first_tb = NULL;
            invalidate_page_bitmap(pd + i);
        }
    } else {
        void **pp = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            page_flush_tb_1(level - 1, pp + i);
        }
    }
}

static void page_flush_tb(struct uc_struct *uc)
{
    int i;

    if (uc->l1_map == NULL)
        return;

    for (i = 0; i < V_L1_SIZE; i++) {
        page_flush_tb_1(V_L1_SHIFT / V_L2_BITS - 1, uc->l1_map + i);
    }
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUArchState *env1)
{
    CPUState *cpu = ENV_GET_CPU(env1);
    struct uc_struct* uc = cpu->uc;
    TCGContext *tcg_ctx = uc->tcg_ctx;

#if defined(DEBUG_FLUSH)
    printf("qemu: flush code_size=%ld nb_tbs=%d avg_tb_size=%ld\n",
           (unsigned long)(tcg_ctx->code_gen_ptr - tcg_ctx->code_gen_buffer),
           tcg_ctx->tb_ctx.nb_tbs, tcg_ctx->tb_ctx.nb_tbs > 0 ?
           ((unsigned long)(tcg_ctx->code_gen_ptr - tcg_ctx->code_gen_buffer)) /
           tcg_ctx->tb_ctx.nb_tbs : 0);
#endif
    if ((unsigned long)((char*)tcg_ctx->code_gen_ptr - (char*)tcg_ctx->code_gen_buffer)
        > tcg_ctx->code_gen_buffer_size) {
        cpu_abort(cpu, "Internal error: code buffer overflow\n");
    }
    tcg_ctx->tb_ctx.nb_tbs = 0;

    memset(cpu->tb_jmp_cache, 0, sizeof(cpu->tb_jmp_cache));

    memset(tcg_ctx->tb_ctx.tb_phys_hash, 0, sizeof(tcg_ctx->tb_ctx.tb_phys_hash));
    page_flush_tb(uc);

    tcg_ctx->code_gen_ptr = tcg_ctx->code_gen_buffer;
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    tcg_ctx->tb_ctx.tb_flush_count++;
}

#ifdef DEBUG_TB_CHECK

static void tb_invalidate_check(target_ulong address)
{
    TranslationBlock *tb;
    int i;

    address &= TARGET_PAGE_MASK;
    for (i = 0; i < CODE_GEN_PHYS_HASH_SIZE; i++) {
        for (tb = tb_ctx.tb_phys_hash[i]; tb != NULL; tb = tb->phys_hash_next) {
            if (!(address + TARGET_PAGE_SIZE <= tb->pc ||
                  address >= tb->pc + tb->size)) {
                printf("ERROR invalidate: address=" TARGET_FMT_lx
                       " PC=%08lx size=%04x\n",
                       address, (long)tb->pc, tb->size);
            }
        }
    }
}

/* verify that all the pages have correct rights for code */
static void tb_page_check(struct uc_struct *uc)
{
    TranslationBlock *tb;
    int i, flags1, flags2;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    for (i = 0; i < CODE_GEN_PHYS_HASH_SIZE; i++) {
        for (tb = tcg_ctx->tb_ctx.tb_phys_hash[i]; tb != NULL;
                tb = tb->phys_hash_next) {
            flags1 = page_get_flags(tb->pc);
            flags2 = page_get_flags(tb->pc + tb->size - 1);
            if ((flags1 & PAGE_WRITE) || (flags2 & PAGE_WRITE)) {
                printf("ERROR page flags: PC=%08lx size=%04x f1=%x f2=%x\n",
                       (long)tb->pc, tb->size, flags1, flags2);
            }
        }
    }
}

#endif

static inline void tb_hash_remove(TranslationBlock **ptb, TranslationBlock *tb)
{
    TranslationBlock *tb1;

    for (;;) {
        tb1 = *ptb;
        if (tb1 == tb) {
            *ptb = tb1->phys_hash_next;
            break;
        }
        ptb = &tb1->phys_hash_next;
    }
}

static inline void tb_page_remove(TranslationBlock **ptb, TranslationBlock *tb)
{
    TranslationBlock *tb1;
    unsigned int n1;

    for (;;) {
        tb1 = *ptb;
        n1 = (uintptr_t)tb1 & 3;
        tb1 = (TranslationBlock *)((uintptr_t)tb1 & ~3);
        if (tb1 == tb) {
            *ptb = tb1->page_next[n1];
            break;
        }
        ptb = &tb1->page_next[n1];
    }
}

static inline void tb_jmp_remove(TranslationBlock *tb, int n)
{
    TranslationBlock *tb1, **ptb;
    unsigned int n1;

    ptb = &tb->jmp_next[n];
    tb1 = *ptb;
    if (tb1) {
        /* find tb(n) in circular list */
        for (;;) {
            tb1 = *ptb;
            n1 = (uintptr_t)tb1 & 3;
            tb1 = (TranslationBlock *)((uintptr_t)tb1 & ~3);
            if (n1 == n && tb1 == tb) {
                break;
            }
            if (n1 == 2) {
                ptb = &tb1->jmp_first;
            } else {
                ptb = &tb1->jmp_next[n1];
            }
        }
        /* now we can suppress tb(n) from the list */
        *ptb = tb->jmp_next[n];

        tb->jmp_next[n] = NULL;
    }
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
static inline void tb_reset_jump(TranslationBlock *tb, int n)
{
    tb_set_jmp_target(tb, n, (uintptr_t)((char*)tb->tc_ptr + tb->tb_next_offset[n]));
}

/* invalidate one TB */
void tb_phys_invalidate(struct uc_struct *uc,
    TranslationBlock *tb, tb_page_addr_t page_addr)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    CPUState *cpu = uc->cpu;
    PageDesc *p;
    unsigned int h, n1;
    tb_page_addr_t phys_pc;
    TranslationBlock *tb1, *tb2;

    /* remove the TB from the hash list */
    phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
    h = tb_phys_hash_func(phys_pc);
    tb_hash_remove(&tcg_ctx->tb_ctx.tb_phys_hash[h], tb);

    /* remove the TB from the page list */
    if (tb->page_addr[0] != page_addr) {
        p = page_find(uc, tb->page_addr[0] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }
    if (tb->page_addr[1] != -1 && tb->page_addr[1] != page_addr) {
        p = page_find(uc, tb->page_addr[1] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }

    tcg_ctx->tb_ctx.tb_invalidated_flag = 1;

    /* remove the TB from the hash list */
    h = tb_jmp_cache_hash_func(tb->pc);
    if (cpu->tb_jmp_cache[h] == tb) {
        cpu->tb_jmp_cache[h] = NULL;
    }

    /* suppress this TB from the two jump lists */
    tb_jmp_remove(tb, 0);
    tb_jmp_remove(tb, 1);

    /* suppress any remaining jumps to this TB */
    tb1 = tb->jmp_first;
    for (;;) {
        n1 = (uintptr_t)tb1 & 3;
        if (n1 == 2) {
            break;
        }
        tb1 = (TranslationBlock *)((uintptr_t)tb1 & ~3);
        tb2 = tb1->jmp_next[n1];
        tb_reset_jump(tb1, n1);
        tb1->jmp_next[n1] = NULL;
        tb1 = tb2;
    }
    tb->jmp_first = (TranslationBlock *)((uintptr_t)tb | 2); /* fail safe */

    tcg_ctx->tb_ctx.tb_phys_invalidate_count++;
}

static inline void set_bits(uint8_t *tab, int start, int len)
{
    int end, mask, end1;

    end = start + len;
    tab += start >> 3;
    mask = 0xff << (start & 7);
    if ((start & ~7) == (end & ~7)) {
        if (start < end) {
            mask &= ~(0xff << (end & 7));
            *tab |= mask;
        }
    } else {
        *tab++ |= mask;
        start = (start + 8) & ~7;
        end1 = end & ~7;
        while (start < end1) {
            *tab++ = 0xff;
            start += 8;
        }
        if (start < end) {
            mask = ~(0xff << (end & 7));
            *tab |= mask;
        }
    }
}

static void build_page_bitmap(PageDesc *p)
{
    int n, tb_start, tb_end;
    TranslationBlock *tb;

    p->code_bitmap = g_malloc0(TARGET_PAGE_SIZE / 8);

    tb = p->first_tb;
    while (tb != NULL) {
        n = (uintptr_t)tb & 3;
        tb = (TranslationBlock *)((uintptr_t)tb & ~3);
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
        set_bits(p->code_bitmap, tb_start, tb_end - tb_start);
        tb = tb->page_next[n];
    }
}

TranslationBlock *tb_gen_code(CPUState *cpu,
                              target_ulong pc, target_ulong cs_base,
                              int flags, int cflags)    // qq
{
    CPUArchState *env = cpu->env_ptr;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    TranslationBlock *tb;
    tb_page_addr_t phys_pc, phys_page2;
    int code_gen_size;
    int ret;

    phys_pc = get_page_addr_code(env, pc);
    tb = tb_alloc(env->uc, pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(env);
        /* cannot fail at this point */
        tb = tb_alloc(env->uc, pc);
        /* Don't forget to invalidate previous TB info.  */
        tcg_ctx->tb_ctx.tb_invalidated_flag = 1;
    }
    tb->tc_ptr = tcg_ctx->code_gen_ptr;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;
    ret = cpu_gen_code(env, tb, &code_gen_size);  // qq
    if (ret == -1) {
        tb_free(env->uc, tb);
        return NULL;
    }
    tcg_ctx->code_gen_ptr = (void *)(((uintptr_t)tcg_ctx->code_gen_ptr +
            code_gen_size + CODE_GEN_ALIGN - 1) & ~(CODE_GEN_ALIGN - 1));

    phys_page2 = -1;
    /* check next page if needed */
    if (tb->size) {
        target_ulong virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
        if ((pc & TARGET_PAGE_MASK) != virt_page2) {
            phys_page2 = get_page_addr_code(env, virt_page2);
        }
    }
    tb_link_page(cpu->uc, tb, phys_pc, phys_page2);
    return tb;
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end may refer to *different* physical pages.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 */
void tb_invalidate_phys_range(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end,
                              int is_cpu_write_access)
{
    while (start < end) {
        tb_invalidate_phys_page_range(uc, start, end, is_cpu_write_access);
        start &= TARGET_PAGE_MASK;
        start += TARGET_PAGE_SIZE;
    }
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end must refer to the *same* physical page.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 */
void tb_invalidate_phys_page_range(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access)
{
    TranslationBlock *tb, *tb_next, *saved_tb;
    CPUState *cpu = uc->current_cpu;
#if defined(TARGET_HAS_PRECISE_SMC)
    CPUArchState *env = NULL;
#endif
    tb_page_addr_t tb_start, tb_end;
    PageDesc *p;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    int current_tb_not_found = is_cpu_write_access;
    TranslationBlock *current_tb = NULL;
    int current_tb_modified = 0;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    int current_flags = 0;
#endif /* TARGET_HAS_PRECISE_SMC */

    p = page_find(uc, start >> TARGET_PAGE_BITS);
    if (!p) {
        return;
    }
    if (!p->code_bitmap &&
        ++p->code_write_count >= SMC_BITMAP_USE_THRESHOLD &&
        is_cpu_write_access) {
        /* build code bitmap */
        build_page_bitmap(p);
    }
#if defined(TARGET_HAS_PRECISE_SMC)
    if (cpu != NULL) {
        env = cpu->env_ptr;
    }
#endif

    /* we remove all the TBs in the range [start, end[ */
    /* XXX: see if in some cases it could be faster to invalidate all
       the code */
    tb = p->first_tb;
    while (tb != NULL) {
        n = (uintptr_t)tb & 3;
        tb = (TranslationBlock *)((uintptr_t)tb & ~3);
        tb_next = tb->page_next[n];
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
        if (!(tb_end <= start || tb_start >= end)) {
#ifdef TARGET_HAS_PRECISE_SMC
            if (current_tb_not_found) {
                current_tb_not_found = 0;
                current_tb = NULL;
                if (cpu->mem_io_pc) {
                    /* now we have a real cpu fault */
                    current_tb = tb_find_pc(uc, cpu->mem_io_pc);
                }
            }
            if (current_tb == tb &&
                (current_tb->cflags & CF_COUNT_MASK) != 1) {
                /* If we are modifying the current TB, we must stop
                its execution. We could be more precise by checking
                that the modification is after the current PC, but it
                would require a specialized function to partially
                restore the CPU state */

                current_tb_modified = 1;
                // self-modifying code will restore state from TB
                cpu_restore_state_from_tb(cpu, current_tb, cpu->mem_io_pc);
                cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
                                     &current_flags);
            }
#endif /* TARGET_HAS_PRECISE_SMC */
            /* we need to do that to handle the case where a signal
               occurs while doing tb_phys_invalidate() */
            saved_tb = NULL;
            if (cpu != NULL) {
                saved_tb = cpu->current_tb;
                cpu->current_tb = NULL;
            }
            tb_phys_invalidate(uc, tb, -1);
            if (cpu != NULL) {
                cpu->current_tb = saved_tb;
                if (cpu->interrupt_request && cpu->current_tb) {
                    cpu_interrupt(cpu, cpu->interrupt_request);
                }
            }
        }
        tb = tb_next;
    }
#if !defined(CONFIG_USER_ONLY)
    /* if no code remaining, no need to continue to use slow writes */
    if (!p->first_tb) {
        invalidate_page_bitmap(p);
        if (is_cpu_write_access) {
            tlb_unprotect_code_phys(cpu, start, cpu->mem_io_vaddr);
        }
    }
#endif
#ifdef TARGET_HAS_PRECISE_SMC
    if (current_tb_modified) {
        /* we generate a block containing just the instruction
           modifying the memory. It will ensure that it cannot modify
           itself */
        cpu->current_tb = NULL;
        tb_gen_code(cpu, current_pc, current_cs_base, current_flags, 1);
        cpu_resume_from_signal(cpu, NULL);
    }
#endif
}

#if !defined(CONFIG_SOFTMMU)
static void tb_invalidate_phys_page(struct uc_struct *uc, tb_page_addr_t addr,
                                    uintptr_t pc, void *puc,
                                    bool locked)
{
    TranslationBlock *tb;
    PageDesc *p;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    TranslationBlock *current_tb = NULL;
    CPUState *cpu = uc->current_cpu;
    CPUArchState *env = NULL;
    int current_tb_modified = 0;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    int current_flags = 0;
#endif

    addr &= TARGET_PAGE_MASK;
    p = page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        return;
    }
    tb = p->first_tb;
#ifdef TARGET_HAS_PRECISE_SMC
    if (tb && pc != 0) {
        current_tb = tb_find_pc(uc, pc);
    }
    if (cpu != NULL) {
        env = cpu->env_ptr;
    }
#endif
    while (tb != NULL) {
        n = (uintptr_t)tb & 3;
        tb = (TranslationBlock *)((uintptr_t)tb & ~3);
#ifdef TARGET_HAS_PRECISE_SMC
        if (current_tb == tb &&
            (current_tb->cflags & CF_COUNT_MASK) != 1) {
                /* If we are modifying the current TB, we must stop
                   its execution. We could be more precise by checking
                   that the modification is after the current PC, but it
                   would require a specialized function to partially
                   restore the CPU state */

            current_tb_modified = 1;
            cpu_restore_state_from_tb(cpu, current_tb, pc);
            cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
                                 &current_flags);
        }
#endif /* TARGET_HAS_PRECISE_SMC */
        tb_phys_invalidate(uc, tb, addr);
        tb = tb->page_next[n];
    }
    p->first_tb = NULL;
#ifdef TARGET_HAS_PRECISE_SMC
    if (current_tb_modified) {
        /* we generate a block containing just the instruction
           modifying the memory. It will ensure that it cannot modify
           itself */
        cpu->current_tb = NULL;
        tb_gen_code(cpu, current_pc, current_cs_base, current_flags, 1);
        if (locked) {
            mmap_unlock();
        }
        cpu_resume_from_signal(cpu, puc);
    }
#endif
}
#endif

/* add the tb in the target page and protect it if necessary */
static inline void tb_alloc_page(struct uc_struct *uc, TranslationBlock *tb,
                                 unsigned int n, tb_page_addr_t page_addr)
{
    PageDesc *p;
#ifndef CONFIG_USER_ONLY
    bool page_already_protected;
#endif

    tb->page_addr[n] = page_addr;
    p = page_find_alloc(uc, page_addr >> TARGET_PAGE_BITS, 1);
    tb->page_next[n] = p->first_tb;
#ifndef CONFIG_USER_ONLY
    page_already_protected = p->first_tb != NULL;
#endif
    p->first_tb = (TranslationBlock *)((uintptr_t)tb | n);
    invalidate_page_bitmap(p);

#if defined(TARGET_HAS_SMC) || 1

#if defined(CONFIG_USER_ONLY)
    if (p->flags & PAGE_WRITE) {
        target_ulong addr;
        PageDesc *p2;
        int prot;

        /* force the host page as non writable (writes will have a
           page fault + mprotect overhead) */
        page_addr &= qemu_host_page_mask;
        prot = 0;
        for (addr = page_addr; addr < page_addr + qemu_host_page_size;
            addr += TARGET_PAGE_SIZE) {

            p2 = page_find(addr >> TARGET_PAGE_BITS);
            if (!p2) {
                continue;
            }
            prot |= p2->flags;
            p2->flags &= ~PAGE_WRITE;
          }
        mprotect(g2h(page_addr), qemu_host_page_size,
                 (prot & PAGE_BITS) & ~PAGE_WRITE);
#ifdef DEBUG_TB_INVALIDATE
        printf("protecting code page: 0x" TARGET_FMT_lx "\n",
               page_addr);
#endif
    }
#else
    /* if some code is already present, then the pages are already
       protected. So we handle the case where only the first TB is
       allocated in a physical page */
    if (!page_already_protected) {
        tlb_protect_code(uc, page_addr);
    }
#endif

#endif /* TARGET_HAS_SMC */
}

void tb_invalidate_phys_page_fast(struct uc_struct* uc, tb_page_addr_t start, int len)
{
    PageDesc *p;

#if 0
    if (1) {
        qemu_log("modifying code at 0x%x size=%d EIP=%x PC=%08x\n",
                  cpu_single_env->mem_io_vaddr, len,
                  cpu_single_env->eip,
                  cpu_single_env->eip +
                  (intptr_t)cpu_single_env->segs[R_CS].base);
    }
#endif
    p = page_find(uc, start >> TARGET_PAGE_BITS);
    if (!p) {
        return;
    }
    if (p->code_bitmap) {
        unsigned int nr;
        unsigned long b;

        nr = start & ~TARGET_PAGE_MASK;
        b = p->code_bitmap[BIT_WORD(nr)] >> ((nr & (BITS_PER_LONG - 1)) & 0x1f);
        if (b & ((1 << len) - 1)) {
            goto do_invalidate;
        }
    } else {
    do_invalidate:
        tb_invalidate_phys_page_range(uc, start, start + len, 1);
    }
}

/* add a new TB and link it to the physical page tables. phys_page2 is
   (-1) to indicate that only one page contains the TB. */
static void tb_link_page(struct uc_struct *uc,
    TranslationBlock *tb, tb_page_addr_t phys_pc, tb_page_addr_t phys_page2)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    unsigned int h;
    TranslationBlock **ptb;

    /* Grab the mmap lock to stop another thread invalidating this TB
       before we are done.  */
    mmap_lock();
    /* add in the physical hash table */
    h = tb_phys_hash_func(phys_pc);
    ptb = &tcg_ctx->tb_ctx.tb_phys_hash[h];
    tb->phys_hash_next = *ptb;
    *ptb = tb;

    /* add in the page list */
    tb_alloc_page(uc, tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1) {
        tb_alloc_page(uc, tb, 1, phys_page2);
    } else {
        tb->page_addr[1] = -1;
    }

    tb->jmp_first = (TranslationBlock *)((uintptr_t)tb | 2);
    tb->jmp_next[0] = NULL;
    tb->jmp_next[1] = NULL;

    /* init original jump addresses */
    if (tb->tb_next_offset[0] != 0xffff) {
        tb_reset_jump(tb, 0);
    }
    if (tb->tb_next_offset[1] != 0xffff) {
        tb_reset_jump(tb, 1);
    }

#ifdef DEBUG_TB_CHECK
    tb_page_check();
#endif
    mmap_unlock();
}

/* find the TB 'tb' such that tb[0].tc_ptr <= tc_ptr <
   tb[1].tc_ptr. Return NULL if not found */
static TranslationBlock *tb_find_pc(struct uc_struct *uc, uintptr_t tc_ptr)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    int m_min, m_max, m;
    uintptr_t v;
    TranslationBlock *tb;

    if (tcg_ctx->tb_ctx.nb_tbs <= 0) {
        return NULL;
    }
    if (tc_ptr < (uintptr_t)tcg_ctx->code_gen_buffer ||
        tc_ptr >= (uintptr_t)tcg_ctx->code_gen_ptr) {
        return NULL;
    }
    /* binary search (cf Knuth) */
    m_min = 0;
    m_max = tcg_ctx->tb_ctx.nb_tbs - 1;
    while (m_min <= m_max) {
        m = (m_min + m_max) >> 1;
        tb = &tcg_ctx->tb_ctx.tbs[m];
        v = (uintptr_t)tb->tc_ptr;
        if (v == tc_ptr) {
            return tb;
        } else if (tc_ptr < v) {
            m_max = m - 1;
        } else {
            m_min = m + 1;
        }
    }
    return &tcg_ctx->tb_ctx.tbs[m_max];
}

#if defined(TARGET_HAS_ICE) && !defined(CONFIG_USER_ONLY)
void tb_invalidate_phys_addr(AddressSpace *as, hwaddr addr)
{
    ram_addr_t ram_addr;
    MemoryRegion *mr;
    hwaddr l = 1;

    mr = address_space_translate(as, addr, &addr, &l, false);
    if (!(memory_region_is_ram(mr)
          || memory_region_is_romd(mr))) {
        return;
    }
    ram_addr = (ram_addr_t)((memory_region_get_ram_addr(mr) & TARGET_PAGE_MASK)
        + addr);
    tb_invalidate_phys_page_range(as->uc, ram_addr, ram_addr + 1, 0);
}
#endif /* TARGET_HAS_ICE && !defined(CONFIG_USER_ONLY) */

void tb_check_watchpoint(CPUState *cpu)
{
    TranslationBlock *tb;
    CPUArchState *env = cpu->env_ptr;

    tb = tb_find_pc(env->uc, cpu->mem_io_pc);
    if (!tb) {
        cpu_abort(cpu, "check_watchpoint: could not find TB for pc=%p",
                  (void *)cpu->mem_io_pc);
    }
    cpu_restore_state_from_tb(cpu, tb, cpu->mem_io_pc);
    tb_phys_invalidate(cpu->uc, tb, -1);
}

#ifndef CONFIG_USER_ONLY
/* mask must never be zero, except for A20 change call */
static void tcg_handle_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;

    cpu->tcg_exit_req = 1;
}

CPUInterruptHandler cpu_interrupt_handler = tcg_handle_interrupt;

/* in deterministic execution mode, instructions doing device I/Os
   must be at the end of the TB */
void cpu_io_recompile(CPUState *cpu, uintptr_t retaddr)
{
    CPUArchState *env = cpu->env_ptr;
    TranslationBlock *tb;
    uint32_t n, cflags;
    target_ulong pc, cs_base;
    uint64_t flags;

    tb = tb_find_pc(env->uc, retaddr);
    if (!tb) {
        cpu_abort(cpu, "cpu_io_recompile: could not find TB for pc=%p",
                  (void *)retaddr);
    }
    n = cpu->icount_decr.u16.low + tb->icount;
    cpu_restore_state_from_tb(cpu, tb, retaddr);
    /* Calculate how many instructions had been executed before the fault
       occurred.  */
    n = n - cpu->icount_decr.u16.low;
    /* Generate a new TB ending on the I/O insn.  */
    n++;
    /* On MIPS and SH, delay slot instructions can only be restarted if
       they were already the first instruction in the TB.  If this is not
       the first instruction in a TB then re-execute the preceding
       branch.  */
#if defined(TARGET_MIPS)
    if ((env->hflags & MIPS_HFLAG_BMASK) != 0 && n > 1) {
        env->active_tc.PC -= 4;
        cpu->icount_decr.u16.low++;
        env->hflags &= ~MIPS_HFLAG_BMASK;
    }
#elif defined(TARGET_SH4)
    if ((env->flags & ((DELAY_SLOT | DELAY_SLOT_CONDITIONAL))) != 0
            && n > 1) {
        env->pc -= 2;
        cpu->icount_decr.u16.low++;
        env->flags &= ~(DELAY_SLOT | DELAY_SLOT_CONDITIONAL);
    }
#endif
    /* This should never happen.  */
    if (n > CF_COUNT_MASK) {
        cpu_abort(cpu, "TB too big during recompile");
    }

    cflags = n | CF_LAST_IO;
    pc = tb->pc;
    cs_base = tb->cs_base;
    flags = tb->flags;
    tb_phys_invalidate(cpu->uc, tb, -1);
    /* FIXME: In theory this could raise an exception.  In practice
       we have already translated the block once so it's probably ok.  */
    tb_gen_code(cpu, pc, cs_base, (int)flags, cflags);
    /* TODO: If env->pc != tb->pc (i.e. the faulting instruction was not
       the first in the TB) then we end up generating a whole new TB and
       repeating the fault, which is horribly inefficient.
       Better would be to execute just this insn uncached, or generate a
       second new TB.  */
    cpu_resume_from_signal(cpu, NULL);
}

void tb_flush_jmp_cache(CPUState *cpu, target_ulong addr)
{
    unsigned int i;

    /* Discard jump cache entries for any tb which might potentially
       overlap the flushed page.  */
    i = tb_jmp_cache_hash_page(addr - TARGET_PAGE_SIZE);
    memset(&cpu->tb_jmp_cache[i], 0,
           TB_JMP_PAGE_SIZE * sizeof(TranslationBlock *));

    i = tb_jmp_cache_hash_page(addr);
    memset(&cpu->tb_jmp_cache[i], 0,
           TB_JMP_PAGE_SIZE * sizeof(TranslationBlock *));
}

#if 0
void dump_exec_info(FILE *f, fprintf_function cpu_fprintf)
{
    int i, target_code_size, max_target_code_size;
    int direct_jmp_count, direct_jmp2_count, cross_page;
    TranslationBlock *tb;

    target_code_size = 0;
    max_target_code_size = 0;
    cross_page = 0;
    direct_jmp_count = 0;
    direct_jmp2_count = 0;
    for (i = 0; i < tcg_ctx.tb_ctx.nb_tbs; i++) {
        tb = &tcg_ctx.tb_ctx.tbs[i];
        target_code_size += tb->size;
        if (tb->size > max_target_code_size) {
            max_target_code_size = tb->size;
        }
        if (tb->page_addr[1] != -1) {
            cross_page++;
        }
        if (tb->tb_next_offset[0] != 0xffff) {
            direct_jmp_count++;
            if (tb->tb_next_offset[1] != 0xffff) {
                direct_jmp2_count++;
            }
        }
    }
    /* XXX: avoid using doubles ? */
    cpu_fprintf(f, "Translation buffer state:\n");
    cpu_fprintf(f, "gen code size       %td/%zd\n",
                tcg_ctx.code_gen_ptr - tcg_ctx.code_gen_buffer,
                tcg_ctx.code_gen_buffer_max_size);
    cpu_fprintf(f, "TB count            %d/%d\n",
            tcg_ctx.tb_ctx.nb_tbs, tcg_ctx.code_gen_max_blocks);
    cpu_fprintf(f, "TB avg target size  %d max=%d bytes\n",
            tcg_ctx.tb_ctx.nb_tbs ? target_code_size /
                    tcg_ctx.tb_ctx.nb_tbs : 0,
            max_target_code_size);
    cpu_fprintf(f, "TB avg host size    %td bytes (expansion ratio: %0.1f)\n",
            tcg_ctx.tb_ctx.nb_tbs ? (tcg_ctx.code_gen_ptr -
                                     tcg_ctx.code_gen_buffer) /
                                     tcg_ctx.tb_ctx.nb_tbs : 0,
                target_code_size ? (double) (tcg_ctx.code_gen_ptr -
                                             tcg_ctx.code_gen_buffer) /
                                             target_code_size : 0);
    cpu_fprintf(f, "cross page TB count %d (%d%%)\n", cross_page,
            tcg_ctx.tb_ctx.nb_tbs ? (cross_page * 100) /
                                    tcg_ctx.tb_ctx.nb_tbs : 0);
    cpu_fprintf(f, "direct jump count   %d (%d%%) (2 jumps=%d %d%%)\n",
                direct_jmp_count,
                tcg_ctx.tb_ctx.nb_tbs ? (direct_jmp_count * 100) /
                        tcg_ctx.tb_ctx.nb_tbs : 0,
                direct_jmp2_count,
                tcg_ctx.tb_ctx.nb_tbs ? (direct_jmp2_count * 100) /
                        tcg_ctx.tb_ctx.nb_tbs : 0);
    cpu_fprintf(f, "\nStatistics:\n");
    cpu_fprintf(f, "TB flush count      %d\n", tcg_ctx.tb_ctx.tb_flush_count);
    cpu_fprintf(f, "TB invalidate count %d\n",
            tcg_ctx.tb_ctx.tb_phys_invalidate_count);
    //cpu_fprintf(f, "TLB flush count     %d\n", tlb_flush_count);
    tcg_dump_info(f, cpu_fprintf);
}
#endif

#else /* CONFIG_USER_ONLY */

void cpu_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;
    cpu->tcg_exit_req = 1;
}

#if 0
/*
 * Walks guest process memory "regions" one by one
 * and calls callback function 'fn' for each region.
 */
struct walk_memory_regions_data {
    walk_memory_regions_fn fn;
    void *priv;
    target_ulong start;
    int prot;
};

static int walk_memory_regions_end(struct walk_memory_regions_data *data,
                                   target_ulong end, int new_prot)
{
    if (data->start != -1u) {
        int rc = data->fn(data->priv, data->start, end, data->prot);
        if (rc != 0) {
            return rc;
        }
    }

    data->start = (new_prot ? end : -1u);
    data->prot = new_prot;

    return 0;
}

static int walk_memory_regions_1(struct walk_memory_regions_data *data,
                                 target_ulong base, int level, void **lp)
{
    target_ulong pa;
    int i, rc;

    if (*lp == NULL) {
        return walk_memory_regions_end(data, base, 0);
    }

    if (level == 0) {
        PageDesc *pd = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            int prot = pd[i].flags;

            pa = base | (i << TARGET_PAGE_BITS);
            if (prot != data->prot) {
                rc = walk_memory_regions_end(data, pa, prot);
                if (rc != 0) {
                    return rc;
                }
            }
        }
    } else {
        void **pp = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            pa = base | ((target_ulong)i <<
                (TARGET_PAGE_BITS + V_L2_BITS * level));
            rc = walk_memory_regions_1(data, pa, level - 1, pp + i);
            if (rc != 0) {
                return rc;
            }
        }
    }

    return 0;
}

typedef int (*walk_memory_regions_fn)(void *, target_ulong,
        target_ulong, unsigned long);

static int walk_memory_regions(void *priv, walk_memory_regions_fn fn)
{
    struct walk_memory_regions_data data;
    uintptr_t i;

    data.fn = fn;
    data.priv = priv;
    data.start = -1u;
    data.prot = 0;

    for (i = 0; i < V_L1_SIZE; i++) {
        int rc = walk_memory_regions_1(&data, (target_ulong)i << (V_L1_SHIFT + TARGET_PAGE_BITS),
                                       V_L1_SHIFT / V_L2_BITS - 1, l1_map + i);
        if (rc != 0) {
            return rc;
        }
    }

    return walk_memory_regions_end(&data, 0, 0);
}

static int dump_region(void *priv, target_ulong start,
    target_ulong end, unsigned long prot)
{
    FILE *f = (FILE *)priv;

    (void) fprintf(f, TARGET_FMT_lx"-"TARGET_FMT_lx
        " "TARGET_FMT_lx" %c%c%c\n",
        start, end, end - start,
        ((prot & PAGE_READ) ? 'r' : '-'),
        ((prot & PAGE_WRITE) ? 'w' : '-'),
        ((prot & PAGE_EXEC) ? 'x' : '-'));

    return 0;
}

/* dump memory mappings */
void page_dump(FILE *f)
{
    const int length = sizeof(target_ulong) * 2;
    (void) fprintf(f, "%-*s %-*s %-*s %s\n",
            length, "start", length, "end", length, "size", "prot");
    walk_memory_regions(f, dump_region);
}

#endif

int page_get_flags(target_ulong address)
{
    PageDesc *p;

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p) {
        return 0;
    }
    return p->flags;
}

/* Modify the flags of a page and invalidate the code if necessary.
   The flag PAGE_WRITE_ORG is positioned automatically depending
   on PAGE_WRITE.  The mmap_lock should already be held.  */
static void page_set_flags(struct uc_struct *uc, target_ulong start, target_ulong end, int flags)
{
    target_ulong addr, len;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(end < ((target_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif
    assert(start < end);

    start = start & TARGET_PAGE_MASK;
    end = TARGET_PAGE_ALIGN(end);

    if (flags & PAGE_WRITE) {
        flags |= PAGE_WRITE_ORG;
    }

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
        PageDesc *p = page_find_alloc(uc, addr >> TARGET_PAGE_BITS, 1);

        /* If the write protection bit is set, then we invalidate
           the code inside.  */
        if (!(p->flags & PAGE_WRITE) &&
            (flags & PAGE_WRITE) &&
            p->first_tb) {
            tb_invalidate_phys_page(addr, 0, NULL, false);
        }
        p->flags = flags;
    }
}

static int page_check_range(target_ulong start, target_ulong len, int flags)
{
    PageDesc *p;
    target_ulong end;
    target_ulong addr;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(start < ((target_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif

    if (len == 0) {
        return 0;
    }
    if (start + len - 1 < start) {
        /* We've wrapped around.  */
        return -1;
    }

    /* must do before we loose bits in the next step */
    end = TARGET_PAGE_ALIGN(start + len);
    start = start & TARGET_PAGE_MASK;

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
        p = page_find(addr >> TARGET_PAGE_BITS);
        if (!p) {
            return -1;
        }
        if (!(p->flags & PAGE_VALID)) {
            return -1;
        }

        if ((flags & PAGE_READ) && !(p->flags & PAGE_READ)) {
            return -1;
        }
        if (flags & PAGE_WRITE) {
            if (!(p->flags & PAGE_WRITE_ORG)) {
                return -1;
            }
            /* unprotect the page if it was put read-only because it
               contains translated code */
            if (!(p->flags & PAGE_WRITE)) {
                if (!page_unprotect(addr, 0, NULL)) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* called from signal handler: invalidate the code and unprotect the
   page. Return TRUE if the fault was successfully handled. */
static int page_unprotect(target_ulong address, uintptr_t pc, void *puc)
{
    unsigned int prot;
    PageDesc *p;
    target_ulong host_start, host_end, addr;

    /* Technically this isn't safe inside a signal handler.  However we
       know this only ever happens in a synchronous SEGV handler, so in
       practice it seems to be ok.  */
    mmap_lock();

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p) {
        mmap_unlock();
        return 0;
    }

    /* if the page was really writable, then we change its
       protection back to writable */
    if ((p->flags & PAGE_WRITE_ORG) && !(p->flags & PAGE_WRITE)) {
        host_start = address & qemu_host_page_mask;
        host_end = host_start + qemu_host_page_size;

        prot = 0;
        for (addr = host_start ; addr < host_end ; addr += TARGET_PAGE_SIZE) {
            p = page_find(addr >> TARGET_PAGE_BITS);
            p->flags |= PAGE_WRITE;
            prot |= p->flags;

            /* and since the content will be modified, we must invalidate
               the corresponding translated code. */
            tb_invalidate_phys_page(addr, pc, puc, true);
#ifdef DEBUG_TB_CHECK
            tb_invalidate_check(addr);
#endif
        }
        mprotect((void *)g2h(host_start), qemu_host_page_size,
                 prot & PAGE_BITS);

        mmap_unlock();
        return 1;
    }
    mmap_unlock();
    return 0;
}
#endif /* CONFIG_USER_ONLY */
