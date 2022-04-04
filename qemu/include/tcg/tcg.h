/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TCG_H
#define TCG_H

#include "cpu.h"
#include "exec/memop.h"
#include "exec/tb-context.h"
#include "qemu/bitops.h"
#include "qemu/queue.h"
#include "tcg/tcg-mo.h"
#include "tcg-target.h"
#include "tcg-apple-jit.h"
#include "qemu/int128.h"

/* XXX: make safe guess about sizes */
#define MAX_OP_PER_INSTR 266

#if HOST_LONG_BITS == 32
#define MAX_OPC_PARAM_PER_ARG 2
#else
#define MAX_OPC_PARAM_PER_ARG 1
#endif
#define MAX_OPC_PARAM_IARGS 6
#define MAX_OPC_PARAM_OARGS 1
#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)

/* A Call op needs up to 4 + 2N parameters on 32-bit archs,
 * and up to 4 + N parameters on 64-bit archs
 * (N = number of input arguments + output arguments).  */
#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))

#define CPU_TEMP_BUF_NLONGS 128

/* Default target word size to pointer size.  */
#ifndef TCG_TARGET_REG_BITS
# if UINTPTR_MAX == UINT32_MAX
#  define TCG_TARGET_REG_BITS 32
# elif UINTPTR_MAX == UINT64_MAX
#  define TCG_TARGET_REG_BITS 64
# else
#  error Unknown pointer size for tcg target
# endif
#endif

#if TCG_TARGET_REG_BITS == 32
typedef int32_t tcg_target_long;
typedef uint32_t tcg_target_ulong;
#define TCG_PRIlx PRIx32
#define TCG_PRIld PRId32
#elif TCG_TARGET_REG_BITS == 64
typedef int64_t tcg_target_long;
typedef uint64_t tcg_target_ulong;
#define TCG_PRIlx PRIx64
#define TCG_PRIld PRId64
#else
#error unsupported
#endif

/* Oversized TCG guests make things like MTTCG hard
 * as we can't use atomics for cputlb updates.
 */
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
#define TCG_OVERSIZED_GUEST 1
#else
#define TCG_OVERSIZED_GUEST 0
#endif

#if TCG_TARGET_NB_REGS <= 32
typedef uint32_t TCGRegSet;
#elif TCG_TARGET_NB_REGS <= 64
typedef uint64_t TCGRegSet;
#else
#error unsupported
#endif

#if TCG_TARGET_REG_BITS == 32
/* Turn some undef macros into false macros.  */
#define TCG_TARGET_HAS_extrl_i64_i32    0
#define TCG_TARGET_HAS_extrh_i64_i32    0
#define TCG_TARGET_HAS_div_i64          0
#define TCG_TARGET_HAS_rem_i64          0
#define TCG_TARGET_HAS_div2_i64         0
#define TCG_TARGET_HAS_rot_i64          0
#define TCG_TARGET_HAS_ext8s_i64        0
#define TCG_TARGET_HAS_ext16s_i64       0
#define TCG_TARGET_HAS_ext32s_i64       0
#define TCG_TARGET_HAS_ext8u_i64        0
#define TCG_TARGET_HAS_ext16u_i64       0
#define TCG_TARGET_HAS_ext32u_i64       0
#define TCG_TARGET_HAS_bswap16_i64      0
#define TCG_TARGET_HAS_bswap32_i64      0
#define TCG_TARGET_HAS_bswap64_i64      0
#define TCG_TARGET_HAS_neg_i64          0
#define TCG_TARGET_HAS_not_i64          0
#define TCG_TARGET_HAS_andc_i64         0
#define TCG_TARGET_HAS_orc_i64          0
#define TCG_TARGET_HAS_eqv_i64          0
#define TCG_TARGET_HAS_nand_i64         0
#define TCG_TARGET_HAS_nor_i64          0
#define TCG_TARGET_HAS_clz_i64          0
#define TCG_TARGET_HAS_ctz_i64          0
#define TCG_TARGET_HAS_ctpop_i64        0
#define TCG_TARGET_HAS_deposit_i64      0
#define TCG_TARGET_HAS_extract_i64      0
#define TCG_TARGET_HAS_sextract_i64     0
#define TCG_TARGET_HAS_extract2_i64     0
#define TCG_TARGET_HAS_movcond_i64      0
#define TCG_TARGET_HAS_add2_i64         0
#define TCG_TARGET_HAS_sub2_i64         0
#define TCG_TARGET_HAS_mulu2_i64        0
#define TCG_TARGET_HAS_muls2_i64        0
#define TCG_TARGET_HAS_muluh_i64        0
#define TCG_TARGET_HAS_mulsh_i64        0
/* Turn some undef macros into true macros.  */
#define TCG_TARGET_HAS_add2_i32         1
#define TCG_TARGET_HAS_sub2_i32         1
#endif

#ifndef TCG_TARGET_deposit_i32_valid
#define TCG_TARGET_deposit_i32_valid(ofs, len) 1
#endif
#ifndef TCG_TARGET_deposit_i64_valid
#define TCG_TARGET_deposit_i64_valid(ofs, len) 1
#endif
#ifndef TCG_TARGET_extract_i32_valid
#define TCG_TARGET_extract_i32_valid(ofs, len) 1
#endif
#ifndef TCG_TARGET_extract_i64_valid
#define TCG_TARGET_extract_i64_valid(ofs, len) 1
#endif

/* Only one of DIV or DIV2 should be defined.  */
#if defined(TCG_TARGET_HAS_div_i32)
#define TCG_TARGET_HAS_div2_i32         0
#elif defined(TCG_TARGET_HAS_div2_i32)
#define TCG_TARGET_HAS_div_i32          0
#define TCG_TARGET_HAS_rem_i32          0
#endif
#if defined(TCG_TARGET_HAS_div_i64)
#define TCG_TARGET_HAS_div2_i64         0
#elif defined(TCG_TARGET_HAS_div2_i64)
#define TCG_TARGET_HAS_div_i64          0
#define TCG_TARGET_HAS_rem_i64          0
#endif

/* For 32-bit targets, some sort of unsigned widening multiply is required.  */
#if TCG_TARGET_REG_BITS == 32 \
    && !(defined(TCG_TARGET_HAS_mulu2_i32) \
         || defined(TCG_TARGET_HAS_muluh_i32))
# error "Missing unsigned widening multiply"
#endif

#if !defined(TCG_TARGET_HAS_v64) \
    && !defined(TCG_TARGET_HAS_v128) \
    && !defined(TCG_TARGET_HAS_v256)
#define TCG_TARGET_MAYBE_vec            0
#define TCG_TARGET_HAS_abs_vec          0
#define TCG_TARGET_HAS_neg_vec          0
#define TCG_TARGET_HAS_not_vec          0
#define TCG_TARGET_HAS_andc_vec         0
#define TCG_TARGET_HAS_orc_vec          0
#define TCG_TARGET_HAS_shi_vec          0
#define TCG_TARGET_HAS_shs_vec          0
#define TCG_TARGET_HAS_shv_vec          0
#define TCG_TARGET_HAS_mul_vec          0
#define TCG_TARGET_HAS_sat_vec          0
#define TCG_TARGET_HAS_minmax_vec       0
#define TCG_TARGET_HAS_bitsel_vec       0
#define TCG_TARGET_HAS_cmpsel_vec       0
#else
#define TCG_TARGET_MAYBE_vec            1
#endif
#ifndef TCG_TARGET_HAS_v64
#define TCG_TARGET_HAS_v64              0
#endif
#ifndef TCG_TARGET_HAS_v128
#define TCG_TARGET_HAS_v128             0
#endif
#ifndef TCG_TARGET_HAS_v256
#define TCG_TARGET_HAS_v256             0
#endif

#ifndef TARGET_INSN_START_EXTRA_WORDS
# define TARGET_INSN_START_WORDS 1
#else
# define TARGET_INSN_START_WORDS (1 + TARGET_INSN_START_EXTRA_WORDS)
#endif

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
#include "tcg/tcg-opc.h"
#undef DEF
    NB_OPS,
} TCGOpcode;

#define tcg_regset_set_reg(d, r)   ((d) |= (TCGRegSet)1 << (r))
#define tcg_regset_reset_reg(d, r) ((d) &= ~((TCGRegSet)1 << (r)))
#define tcg_regset_test_reg(d, r)  (((d) >> (r)) & 1)

#ifndef TCG_TARGET_INSN_UNIT_SIZE
# error "Missing TCG_TARGET_INSN_UNIT_SIZE"
#elif TCG_TARGET_INSN_UNIT_SIZE == 1
typedef uint8_t tcg_insn_unit;
#elif TCG_TARGET_INSN_UNIT_SIZE == 2
typedef uint16_t tcg_insn_unit;
#elif TCG_TARGET_INSN_UNIT_SIZE == 4
typedef uint32_t tcg_insn_unit;
#elif TCG_TARGET_INSN_UNIT_SIZE == 8
typedef uint64_t tcg_insn_unit;
#else
/* The port better have done this.  */
#endif


#if defined CONFIG_DEBUG_TCG || defined QEMU_STATIC_ANALYSIS
# define tcg_debug_assert(X) do { assert(X); } while (0)
#else
#ifndef _MSC_VER
# define tcg_debug_assert(X) \
    do { if (!(X)) { __builtin_unreachable(); } } while (0)
#else
# define tcg_debug_assert(X)
#endif
#endif

typedef struct TCGRelocation TCGRelocation;
struct TCGRelocation {
    QSIMPLEQ_ENTRY(TCGRelocation) next;
    tcg_insn_unit *ptr;
    intptr_t addend;
    int type;
};

typedef struct TCGLabel TCGLabel;
struct TCGLabel {
    unsigned present : 1;
    unsigned has_value : 1;
    unsigned id : 14;
    unsigned refs : 16;
    union {
        uintptr_t value;
        tcg_insn_unit *value_ptr;
    } u;
    QSIMPLEQ_HEAD(, TCGRelocation) relocs;
    QSIMPLEQ_ENTRY(TCGLabel) next;
};

typedef struct TCGPool {
    struct TCGPool *next;
    int size;
    uint8_t QEMU_ALIGN(8, data[0]);
} TCGPool;

#define TCG_POOL_CHUNK_SIZE 32768

#define TCG_MAX_TEMPS 512
#define TCG_MAX_INSNS 512

/* when the size of the arguments of a called function is smaller than
   this value, they are statically allocated in the TB stack frame */
#define TCG_STATIC_CALL_ARGS_SIZE 128

typedef enum TCGType {
    TCG_TYPE_I32,
    TCG_TYPE_I64,

    TCG_TYPE_V64,
    TCG_TYPE_V128,
    TCG_TYPE_V256,

    TCG_TYPE_COUNT, /* number of different types */

    /* An alias for the size of the host register.  */
#if TCG_TARGET_REG_BITS == 32
    TCG_TYPE_REG = TCG_TYPE_I32,
#else
    TCG_TYPE_REG = TCG_TYPE_I64,
#endif

    /* An alias for the size of the native pointer.  */
#if UINTPTR_MAX == UINT32_MAX
    TCG_TYPE_PTR = TCG_TYPE_I32,
#else
    TCG_TYPE_PTR = TCG_TYPE_I64,
#endif

    /* An alias for the size of the target "long", aka register.  */
#if TARGET_LONG_BITS == 64
    TCG_TYPE_TL = TCG_TYPE_I64,
#else
    TCG_TYPE_TL = TCG_TYPE_I32,
#endif
} TCGType;

/**
 * get_alignment_bits
 * @memop: MemOp value
 *
 * Extract the alignment size from the memop.
 */
static inline unsigned get_alignment_bits(MemOp memop)
{
    unsigned a = memop & MO_AMASK;

    if (a == MO_UNALN) {
        /* No alignment required.  */
        a = 0;
    } else if (a == MO_ALIGN) {
        /* A natural alignment requirement.  */
        a = memop & MO_SIZE;
    } else {
        /* A specific alignment requirement.  */
        a = a >> MO_ASHIFT;
    }

    /* The requested alignment cannot overlap the TLB flags.  */
    tcg_debug_assert((TLB_FLAGS_MASK & ((1 << a) - 1)) == 0);

    return a;
}

typedef tcg_target_ulong TCGArg;

/* Define type and accessor macros for TCG variables.

   TCG variables are the inputs and outputs of TCG ops, as described
   in tcg/README. Target CPU front-end code uses these types to deal
   with TCG variables as it emits TCG code via the tcg_gen_* functions.
   They come in several flavours:
    * TCGv_i32 : 32 bit integer type
    * TCGv_i64 : 64 bit integer type
    * TCGv_ptr : a host pointer type
    * TCGv_vec : a host vector type; the exact size is not exposed
                 to the CPU front-end code.
    * TCGv : an integer type the same size as target_ulong
             (an alias for either TCGv_i32 or TCGv_i64)
   The compiler's type checking will complain if you mix them
   up and pass the wrong sized TCGv to a function.

   Users of tcg_gen_* don't need to know about any of the internal
   details of these, and should treat them as opaque types.
   You won't be able to look inside them in a debugger either.

   Internal implementation details follow:

   Note that there is no definition of the structs TCGv_i32_d etc anywhere.
   This is deliberate, because the values we store in variables of type
   TCGv_i32 are not really pointers-to-structures. They're just small
   integers, but keeping them in pointer types like this means that the
   compiler will complain if you accidentally pass a TCGv_i32 to a
   function which takes a TCGv_i64, and so on. Only the internals of
   TCG need to care about the actual contents of the types.  */

typedef struct TCGv_i32_d *TCGv_i32;
typedef struct TCGv_i64_d *TCGv_i64;
typedef struct TCGv_ptr_d *TCGv_ptr;
typedef struct TCGv_vec_d *TCGv_vec;
typedef TCGv_ptr TCGv_env;
#if TARGET_LONG_BITS == 32
#define TCGv TCGv_i32
#elif TARGET_LONG_BITS == 64
#define TCGv TCGv_i64
#else
#error Unhandled TARGET_LONG_BITS value
#endif

/* call flags */
/* Helper does not read globals (either directly or through an exception). It
   implies TCG_CALL_NO_WRITE_GLOBALS. */
#define TCG_CALL_NO_READ_GLOBALS    0x0001
/* Helper does not write globals */
#define TCG_CALL_NO_WRITE_GLOBALS   0x0002
/* Helper can be safely suppressed if the return value is not used. */
#define TCG_CALL_NO_SIDE_EFFECTS    0x0004
/* Helper is QEMU_NORETURN.  */
#define TCG_CALL_NO_RETURN          0x0008

/* convenience version of most used call flags */
#define TCG_CALL_NO_RWG         TCG_CALL_NO_READ_GLOBALS
#define TCG_CALL_NO_WG          TCG_CALL_NO_WRITE_GLOBALS
#define TCG_CALL_NO_SE          TCG_CALL_NO_SIDE_EFFECTS
#define TCG_CALL_NO_RWG_SE      (TCG_CALL_NO_RWG | TCG_CALL_NO_SE)
#define TCG_CALL_NO_WG_SE       (TCG_CALL_NO_WG | TCG_CALL_NO_SE)

/* Used to align parameters.  See the comment before tcgv_i32_temp.  */
#define TCG_CALL_DUMMY_ARG      ((TCGArg)0)

/* Conditions.  Note that these are laid out for easy manipulation by
   the functions below:
     bit 0 is used for inverting;
     bit 1 is signed,
     bit 2 is unsigned,
     bit 3 is used with bit 0 for swapping signed/unsigned.  */
typedef enum {
    /* non-signed */
    TCG_COND_NEVER  = 0 | 0 | 0 | 0,
    TCG_COND_ALWAYS = 0 | 0 | 0 | 1,
    TCG_COND_EQ     = 8 | 0 | 0 | 0,
    TCG_COND_NE     = 8 | 0 | 0 | 1,
    /* signed */
    TCG_COND_LT     = 0 | 0 | 2 | 0,
    TCG_COND_GE     = 0 | 0 | 2 | 1,
    TCG_COND_LE     = 8 | 0 | 2 | 0,
    TCG_COND_GT     = 8 | 0 | 2 | 1,
    /* unsigned */
    TCG_COND_LTU    = 0 | 4 | 0 | 0,
    TCG_COND_GEU    = 0 | 4 | 0 | 1,
    TCG_COND_LEU    = 8 | 4 | 0 | 0,
    TCG_COND_GTU    = 8 | 4 | 0 | 1,
} TCGCond;

/* Invert the sense of the comparison.  */
static inline TCGCond tcg_invert_cond(TCGCond c)
{
    return (TCGCond)(c ^ 1);
}

/* Swap the operands in a comparison.  */
static inline TCGCond tcg_swap_cond(TCGCond c)
{
    return c & 6 ? (TCGCond)(c ^ 9) : c;
}

/* Create an "unsigned" version of a "signed" comparison.  */
static inline TCGCond tcg_unsigned_cond(TCGCond c)
{
    return c & 2 ? (TCGCond)(c ^ 6) : c;
}

/* Create a "signed" version of an "unsigned" comparison.  */
static inline TCGCond tcg_signed_cond(TCGCond c)
{
    return c & 4 ? (TCGCond)(c ^ 6) : c;
}

/* Must a comparison be considered unsigned?  */
static inline bool is_unsigned_cond(TCGCond c)
{
    return (c & 4) != 0;
}

/* Create a "high" version of a double-word comparison.
   This removes equality from a LTE or GTE comparison.  */
static inline TCGCond tcg_high_cond(TCGCond c)
{
    switch (c) {
    case TCG_COND_GE:
    case TCG_COND_LE:
    case TCG_COND_GEU:
    case TCG_COND_LEU:
        return (TCGCond)(c ^ 8);
    default:
        return c;
    }
}

typedef enum TCGTempVal {
    TEMP_VAL_DEAD,
    TEMP_VAL_REG,
    TEMP_VAL_MEM,
    TEMP_VAL_CONST,
} TCGTempVal;

typedef struct TCGTemp {
    TCGReg reg:8;
    TCGTempVal val_type:8;
    TCGType base_type:8;
    TCGType type:8;
    unsigned int fixed_reg:1;
    unsigned int indirect_reg:1;
    unsigned int indirect_base:1;
    unsigned int mem_coherent:1;
    unsigned int mem_allocated:1;
    /* If true, the temp is saved across both basic blocks and
       translation blocks.  */
    unsigned int temp_global:1;
    /* If true, the temp is saved across basic blocks but dead
       at the end of translation blocks.  If false, the temp is
       dead at the end of basic blocks.  */
    unsigned int temp_local:1;
    unsigned int temp_allocated:1;

    tcg_target_long val;
    struct TCGTemp *mem_base;
    intptr_t mem_offset;
    const char *name;

    /* Pass-specific information that can be stored for a temporary.
       One word worth of integer data, and one pointer to data
       allocated separately.  */
    uintptr_t state;
    void *state_ptr;
} TCGTemp;

typedef struct TCGContext TCGContext;

typedef struct TCGTempSet {
    unsigned long l[BITS_TO_LONGS(TCG_MAX_TEMPS)];
} TCGTempSet;

/* While we limit helpers to 6 arguments, for 32-bit hosts, with padding,
   this imples a max of 6*2 (64-bit in) + 2 (64-bit out) = 14 operands.
   There are never more than 2 outputs, which means that we can store all
   dead + sync data within 16 bits.  */
#define DEAD_ARG  4
#define SYNC_ARG  1
typedef uint16_t TCGLifeData;

/* The layout here is designed to avoid a bitfield crossing of
   a 32-bit boundary, which would cause GCC to add extra padding.  */
typedef struct TCGOp {
#ifdef _MSC_VER
    uint32_t opc   : 8;        /*  8 */
#else
    TCGOpcode opc   : 8;        /*  8 */
#endif

    /* Parameters for this opcode.  See below.  */
    unsigned param1 : 4;        /* 12 */
    unsigned param2 : 4;        /* 16 */

    /* Lifetime data of the operands.  */
    unsigned life   : 16;       /* 32 */

    /* Next and previous opcodes.  */
    QTAILQ_ENTRY(TCGOp) link;

    /* Arguments for the opcode.  */
    TCGArg args[MAX_OPC_PARAM];

    /* Register preferences for the output(s).  */
    TCGRegSet output_pref[2];
} TCGOp;

#define TCGOP_CALLI(X)    (X)->param1
#define TCGOP_CALLO(X)    (X)->param2

#define TCGOP_VECL(X)     (X)->param1
#define TCGOP_VECE(X)     (X)->param2

/* Make sure operands fit in the bitfields above.  */
QEMU_BUILD_BUG_ON(NB_OPS > (1 << 8));

typedef struct TCGProfile {
    int64_t cpu_exec_time;
    int64_t tb_count1;
    int64_t tb_count;
    int64_t op_count; /* total insn count */
    int op_count_max; /* max insn per TB */
    int temp_count_max;
    int64_t temp_count;
    int64_t del_op_count;
    int64_t code_in_len;
    int64_t code_out_len;
    int64_t search_out_len;
    int64_t interm_time;
    int64_t code_time;
    int64_t la_time;
    int64_t opt_time;
    int64_t restore_count;
    int64_t restore_time;
    int64_t table_op_count[NB_OPS];
} TCGProfile;

/*
 * We divide code_gen_buffer into equally-sized "regions" that TCG threads
 * dynamically allocate from as demand dictates. Given appropriate region
 * sizing, this minimizes flushes even when some TCG threads generate a lot
 * more code than others.
 */
typedef struct TCGOpDef TCGOpDef;
struct tcg_region_state {
    /* fields set at init time */
    void *start;
    void *start_aligned;
    void *end;
    size_t n;
    size_t size; /* size of one region */
    size_t stride; /* .size + guard size */

    size_t current; /* current region index */
    size_t agg_size_full; /* aggregate size of full regions */
};

struct TCGContext {
    uint8_t *pool_cur, *pool_end;
    TCGPool *pool_first, *pool_current, *pool_first_large;
    int nb_labels;
    int nb_globals;
    int nb_temps;
    int nb_indirects;
    int nb_ops;

    /* goto_tb support */
    tcg_insn_unit *code_buf;
    uint16_t *tb_jmp_reset_offset; /* tb->jmp_reset_offset */
    uintptr_t *tb_jmp_insn_offset; /* tb->jmp_target_arg if direct_jump */
    uintptr_t *tb_jmp_target_addr; /* tb->jmp_target_arg if !direct_jump */

    TCGRegSet reserved_regs;
    uint32_t tb_cflags; /* cflags of the current TB */
    intptr_t current_frame_offset;
    intptr_t frame_start;
    intptr_t frame_end;
    TCGTemp *frame_temp;

    tcg_insn_unit *code_ptr;

#ifdef CONFIG_DEBUG_TCG
    int temps_in_use;
    int goto_tb_issue_mask;
    const TCGOpcode *vecop_list;
#endif

    /* Code generation.  Note that we specifically do not use tcg_insn_unit
       here, because there's too much arithmetic throughout that relies
       on addition and subtraction working on bytes.  Rely on the GCC
       extension that allows arithmetic on void*.  */
    void *code_gen_prologue;
    void *code_gen_epilogue;
    void *code_gen_buffer;
    void *initial_buffer;
    size_t initial_buffer_size;
    size_t code_gen_buffer_size;
    void *code_gen_ptr;
    void *data_gen_ptr;

    /* Threshold to flush the translated code buffer.  */
    void *code_gen_highwater;

#ifdef HAVE_PTHREAD_JIT_PROTECT
    /*
     * True for X, False for W.
     * 
     * Source: https://developer.apple.com/documentation/apple_silicon/porting_just-in-time_compilers_to_apple_silicon?language=objc
     */
    bool code_gen_locked;
#endif

    size_t tb_phys_invalidate_count;

    /* Track which vCPU triggers events */
    CPUState *cpu;                      /* *_trans */

    /* These structures are private to tcg-target.inc.c.  */
#ifdef TCG_TARGET_NEED_LDST_LABELS
    QSIMPLEQ_HEAD(, TCGLabelQemuLdst) ldst_labels;
#endif
#ifdef TCG_TARGET_NEED_POOL_LABELS
    struct TCGLabelPoolData *pool_labels;
#endif

    TCGLabel *exitreq_label;

    TCGTempSet free_temps[TCG_TYPE_COUNT * 2];
    TCGTemp temps[TCG_MAX_TEMPS]; /* globals first, temps after */

    QTAILQ_HEAD(, TCGOp) ops, free_ops;
    QSIMPLEQ_HEAD(, TCGLabel) labels;

    /* Tells which temporary holds a given register.
       It does not take into account fixed registers */
    TCGTemp *reg_to_temp[TCG_TARGET_NB_REGS];

    uint16_t gen_insn_end_off[TCG_MAX_INSNS];
    target_ulong gen_insn_data[TCG_MAX_INSNS][TARGET_INSN_START_WORDS];

    /* qemu/accel/tcg/translate-all.c */
    TBContext tb_ctx;
    /* qemu/include/exec/gen-icount.h */
    TCGOp *icount_start_insn;
    /* qemu/tcg/tcg.c */
    GHashTable *helper_table;
    GHashTable *custom_helper_infos; // To support inline hooks.
    TCGv_ptr cpu_env;
    struct tcg_region_state region;
    GTree *tree;
    TCGRegSet tcg_target_available_regs[TCG_TYPE_COUNT];
    TCGRegSet tcg_target_call_clobber_regs;
    int *indirect_reg_alloc_order;
    struct jit_code_entry *one_entry;
    /* qemu/tcg/tcg-common.c */
    TCGOpDef *tcg_op_defs;

    // Unicorn engine variables
    struct uc_struct *uc;

    /* qemu/target/i386/translate.c: global register indexes */
    TCGv cpu_cc_dst, cpu_cc_src, cpu_cc_src2;
    TCGv_i32 cpu_cc_op;
    TCGv cpu_regs[56]; // 16 GRP for x64
    /* only x86 need cpu_seg_base[]. */
    TCGv cpu_seg_base[6];
    TCGv_i64 cpu_bndl[4];
    TCGv_i64 cpu_bndu[4];

    /* qemu/tcg/i386/tcg-target.inc.c */
    void *tb_ret_addr;

    /* target/riscv/translate.c */
    TCGv cpu_gpr[32], cpu_pc; // also target/mips/translate.c
    TCGv_i64 cpu_fpr[32]; /* assume F and D extensions */
    TCGv load_res;
    TCGv load_val;

    // target/arm/translate.c
    /* We reuse the same 64-bit temporaries for efficiency.  */
    TCGv_i64 cpu_V0, cpu_V1, cpu_M0;
    TCGv_i32 cpu_R[16];
    TCGv_i32 cpu_CF, cpu_NF, cpu_VF, cpu_ZF;
    TCGv_i64 cpu_exclusive_addr;
    TCGv_i64 cpu_exclusive_val;

    // target/arm/translate-a64.c
    TCGv_i64 cpu_X[32];
    TCGv_i64 cpu_pc_arm64;
    /* Load/store exclusive handling */
    TCGv_i64 cpu_exclusive_high;

    // target/mips/translate.c
    // #define MIPS_DSP_ACC 4
    // TCGv cpu_HI[MIPS_DSP_ACC], cpu_LO[MIPS_DSP_ACC];
    TCGv cpu_HI[4], cpu_LO[4];
    TCGv cpu_dspctrl, btarget, bcond;
    TCGv cpu_lladdr, cpu_llval;
    TCGv_i32 hflags;
    TCGv_i32 fpu_fcr0, fpu_fcr31;
    TCGv_i64 fpu_f64[32];
    TCGv_i64 msa_wr_d[64];
#if defined(TARGET_MIPS64)
    /* Upper halves of R5900's 128-bit registers: MMRs (multimedia registers) */
    TCGv_i64 cpu_mmr[32];
#endif
#if !defined(TARGET_MIPS64)
    /* MXU registers */
    // #define NUMBER_OF_MXU_REGISTERS 16
    // TCGv mxu_gpr[NUMBER_OF_MXU_REGISTERS - 1];
    TCGv mxu_gpr[16 - 1];
    TCGv mxu_CR;
#endif

    // target/sparc/translate.c
    /* global register indexes */
    TCGv_ptr cpu_regwptr;
    // TCGv cpu_cc_src, cpu_cc_src2, cpu_cc_dst;
    // TCGv_i32 cpu_cc_op;
    TCGv_i32 cpu_psr;
    TCGv cpu_fsr, cpu_npc;
    // TCGv cpu_regs[32];
    TCGv cpu_y;
    TCGv cpu_tbr;
    TCGv cpu_cond;
#ifdef TARGET_SPARC64
    TCGv_i32 cpu_xcc, cpu_fprs;
    TCGv cpu_gsr;
    TCGv cpu_tick_cmpr, cpu_stick_cmpr, cpu_hstick_cmpr;
    TCGv cpu_hintp, cpu_htba, cpu_hver, cpu_ssr, cpu_ver;
#else
    TCGv cpu_wim;
#endif
    /* Floating point registers */
    // TCGv_i64 cpu_fpr[TARGET_DPREGS];

    // target/m68k/translate.c
    TCGv_i32 cpu_halted;
    TCGv_i32 cpu_exception_index;
    char cpu_reg_names[2 * 8 * 3 + 5 * 4];
    TCGv cpu_dregs[8];
    TCGv cpu_aregs[8];
    TCGv_i64 cpu_macc[4];
    TCGv NULL_QREG;
    /* Used to distinguish stores from bad addressing modes.  */
    TCGv store_dummy;

    // target/tricore/translate.c
    TCGv_i32 cpu_gpr_a[16];
    TCGv_i32 cpu_gpr_d[16];
    TCGv_i32 cpu_PSW_C, cpu_PSW_V, cpu_PSW_SV, cpu_PSW_AV, cpu_PSW_SAV;
    TCGv_i32 cpu_PC, cpu_PCXI, cpu_PSW, cpu_ICR;
    
    // Used to store the start of current instrution.
    uint64_t pc_start;

    // target/s390x/translate.c
    TCGv_i64 psw_addr;
    TCGv_i64 psw_mask;
    TCGv_i64 gbea;

    TCGv_i32 cc_op;
    TCGv_i64 cc_src;
    TCGv_i64 cc_dst;
    TCGv_i64 cc_vr;

    char s390x_cpu_reg_names[16][4]; // renamed from original cpu_reg_names[][] to avoid name clash with m68k
    TCGv_i64 regs[16];
};

static inline size_t temp_idx(TCGContext *tcg_ctx, TCGTemp *ts)
{
    ptrdiff_t n = ts - tcg_ctx->temps;
    tcg_debug_assert(n >= 0 && n < tcg_ctx->nb_temps);
    return n;
}

static inline TCGArg temp_arg(TCGTemp *ts)
{
    return (uintptr_t)ts;
}

static inline TCGTemp *arg_temp(TCGArg a)
{
    return (TCGTemp *)(uintptr_t)a;
}

/* Using the offset of a temporary, relative to TCGContext, rather than
   its index means that we don't use 0.  That leaves offset 0 free for
   a NULL representation without having to leave index 0 unused.  */
static inline TCGTemp *tcgv_i32_temp(TCGContext *tcg_ctx, TCGv_i32 v)
{
    uintptr_t o = (uintptr_t)v;
    TCGTemp *t = (TCGTemp *)((char *)tcg_ctx + o);
    tcg_debug_assert(offsetof(TCGContext, temps[temp_idx(tcg_ctx, t)]) == o);
    return t;
}

static inline TCGTemp *tcgv_i64_temp(TCGContext *tcg_ctx, TCGv_i64 v)
{
    return tcgv_i32_temp(tcg_ctx, (TCGv_i32)v);
}

static inline TCGTemp *tcgv_ptr_temp(TCGContext *tcg_ctx, TCGv_ptr v)
{
    return tcgv_i32_temp(tcg_ctx, (TCGv_i32)v);
}

static inline TCGTemp *tcgv_vec_temp(TCGContext *tcg_ctx, TCGv_vec v)
{
    return tcgv_i32_temp(tcg_ctx, (TCGv_i32)v);
}

static inline TCGArg tcgv_i32_arg(TCGContext *tcg_ctx, TCGv_i32 v)
{
    return temp_arg(tcgv_i32_temp(tcg_ctx, v));
}

static inline TCGArg tcgv_i64_arg(TCGContext *tcg_ctx, TCGv_i64 v)
{
    return temp_arg(tcgv_i64_temp(tcg_ctx, v));
}

static inline TCGArg tcgv_ptr_arg(TCGContext *tcg_ctx, TCGv_ptr v)
{
    return temp_arg(tcgv_ptr_temp(tcg_ctx, v));
}

static inline TCGArg tcgv_vec_arg(TCGContext *tcg_ctx, TCGv_vec v)
{
    return temp_arg(tcgv_vec_temp(tcg_ctx, v));
}

static inline TCGv_i32 temp_tcgv_i32(TCGContext *tcg_ctx, TCGTemp *t)
{
    (void)temp_idx(tcg_ctx, t); /* trigger embedded assert */
    return (TCGv_i32)((char *)t - (char *)tcg_ctx);
}

static inline TCGv_i64 temp_tcgv_i64(TCGContext *tcg_ctx, TCGTemp *t)
{
    return (TCGv_i64)temp_tcgv_i32(tcg_ctx, t);
}

static inline TCGv_ptr temp_tcgv_ptr(TCGContext *tcg_ctx, TCGTemp *t)
{
    return (TCGv_ptr)temp_tcgv_i32(tcg_ctx, t);
}

static inline TCGv_vec temp_tcgv_vec(TCGContext *tcg_ctx, TCGTemp *t)
{
    return (TCGv_vec)temp_tcgv_i32(tcg_ctx, t);
}

#if TCG_TARGET_REG_BITS == 32
static inline TCGv_i32 TCGV_LOW(TCGContext *tcg_ctx, TCGv_i64 t)
{
    return temp_tcgv_i32(tcg_ctx, tcgv_i64_temp(tcg_ctx, t));
}

static inline TCGv_i32 TCGV_HIGH(TCGContext *tcg_ctx, TCGv_i64 t)
{
    return temp_tcgv_i32(tcg_ctx, tcgv_i64_temp(tcg_ctx, t) + 1);
}
#endif

static inline void tcg_set_insn_param(TCGOp *op, int arg, TCGArg v)
{
    op->args[arg] = v;
}

static inline void tcg_set_insn_start_param(TCGOp *op, int arg, target_ulong v)
{
#if TARGET_LONG_BITS <= TCG_TARGET_REG_BITS
    tcg_set_insn_param(op, arg, v);
#else
    tcg_set_insn_param(op, arg * 2, v);
    tcg_set_insn_param(op, arg * 2 + 1, v >> 32);
#endif
}

/* The last op that was emitted.  */
static inline TCGOp *tcg_last_op(TCGContext *tcg_ctx)
{
    return QTAILQ_LAST(&tcg_ctx->ops);
}

/* Test for whether to terminate the TB for using too many opcodes.  */
static inline bool tcg_op_buf_full(TCGContext *tcg_ctx)
{
    /* This is not a hard limit, it merely stops translation when
     * we have produced "enough" opcodes.  We want to limit TB size
     * such that a RISC host can reasonably use a 16-bit signed
     * branch within the TB.  We also need to be mindful of the
     * 16-bit unsigned offsets, TranslationBlock.jmp_reset_offset[]
     * and TCGContext.gen_insn_end_off[].
     */
    return tcg_ctx->nb_ops >= 4000;
}

/* pool based memory allocation */

/* user-mode: mmap_lock must be held for tcg_malloc_internal. */
void *tcg_malloc_internal(TCGContext *s, int size);
void tcg_pool_reset(TCGContext *s);
TranslationBlock *tcg_tb_alloc(TCGContext *s);

void tcg_region_init(TCGContext *tcg_ctx);
void tcg_region_reset_all(TCGContext *tcg_ctx);

size_t tcg_code_size(TCGContext *tcg_ctx);
size_t tcg_code_capacity(TCGContext *tcg_ctx);

void tcg_tb_insert(TCGContext *tcg_ctx, TranslationBlock *tb);
void tcg_tb_remove(TCGContext *tcg_ctx, TranslationBlock *tb);
size_t tcg_tb_phys_invalidate_count(TCGContext *tcg_ctx);
TranslationBlock *tcg_tb_lookup(TCGContext *tcg_ctx, uintptr_t tc_ptr);
/* glib gtree:
 * gboolean (*GTraverseFunc)  (gpointer key, gpointer value, gpointer data);
*/
typedef int (*GTraverseFunc) (void *key, void *value, void *data);
void tcg_tb_foreach(TCGContext *tcg_ctx, GTraverseFunc func, gpointer user_data);
size_t tcg_nb_tbs(TCGContext *tcg_ctx);

/* user-mode: Called with mmap_lock held.  */
static inline void *tcg_malloc(TCGContext *tcg_ctx, int size)
{
    TCGContext *s = tcg_ctx;
    uint8_t *ptr, *ptr_end;

    /* ??? This is a weak placeholder for minimum malloc alignment.  */
    size = QEMU_ALIGN_UP(size, 8);

    ptr = s->pool_cur;
    ptr_end = ptr + size;
    if (unlikely(ptr_end > s->pool_end)) {
        return tcg_malloc_internal(tcg_ctx, size);
    } else {
        s->pool_cur = ptr_end;
        return ptr;
    }
}

void tcg_context_init(TCGContext *s);
void tcg_register_thread(void);
void tcg_prologue_init(TCGContext *s);
void tcg_func_start(TCGContext *s);

int tcg_gen_code(TCGContext *s, TranslationBlock *tb);

void tcg_set_frame(TCGContext *s, TCGReg reg, intptr_t start, intptr_t size);

TCGTemp *tcg_global_mem_new_internal(TCGContext *tcg_ctx, TCGType, TCGv_ptr,
                                     intptr_t, const char *);
TCGTemp *tcg_temp_new_internal(TCGContext *tcg_ctx, TCGType, bool);
void tcg_temp_free_internal(TCGContext *tcg_ctx, TCGTemp *);
TCGv_vec tcg_temp_new_vec(TCGContext *tcg_ctx, TCGType type);
TCGv_vec tcg_temp_new_vec_matching(TCGContext *tcg_ctx, TCGv_vec match);

static inline void tcg_temp_free_i32(TCGContext *tcg_ctx, TCGv_i32 arg)
{
    tcg_temp_free_internal(tcg_ctx, tcgv_i32_temp(tcg_ctx, arg));
}

static inline void tcg_temp_free_i64(TCGContext *tcg_ctx, TCGv_i64 arg)
{
    tcg_temp_free_internal(tcg_ctx, tcgv_i64_temp(tcg_ctx, arg));
}

static inline void tcg_temp_free_ptr(TCGContext *tcg_ctx, TCGv_ptr arg)
{
    tcg_temp_free_internal(tcg_ctx, tcgv_ptr_temp(tcg_ctx, arg));
}

static inline void tcg_temp_free_vec(TCGContext *tcg_ctx, TCGv_vec arg)
{
    tcg_temp_free_internal(tcg_ctx, tcgv_vec_temp(tcg_ctx, arg));
}

static inline TCGv_i32 tcg_global_mem_new_i32(TCGContext *tcg_ctx, TCGv_ptr reg, intptr_t offset,
                                              const char *name)
{
    TCGTemp *t = tcg_global_mem_new_internal(tcg_ctx, TCG_TYPE_I32, reg, offset, name);
    return temp_tcgv_i32(tcg_ctx, t);
}

static inline TCGv_i32 tcg_temp_new_i32(TCGContext *tcg_ctx)
{
    TCGTemp *t = tcg_temp_new_internal(tcg_ctx, TCG_TYPE_I32, false);
    return temp_tcgv_i32(tcg_ctx, t);
}

static inline TCGv_i32 tcg_temp_local_new_i32(TCGContext *tcg_ctx)
{
    TCGTemp *t = tcg_temp_new_internal(tcg_ctx, TCG_TYPE_I32, true);
    return temp_tcgv_i32(tcg_ctx, t);
}

static inline TCGv_i64 tcg_global_mem_new_i64(TCGContext *tcg_ctx, TCGv_ptr reg, intptr_t offset,
                                              const char *name)
{
    TCGTemp *t = tcg_global_mem_new_internal(tcg_ctx, TCG_TYPE_I64, reg, offset, name);
    return temp_tcgv_i64(tcg_ctx, t);
}

static inline TCGv_i64 tcg_temp_new_i64(TCGContext *tcg_ctx)
{
    TCGTemp *t = tcg_temp_new_internal(tcg_ctx, TCG_TYPE_I64, false);
    return temp_tcgv_i64(tcg_ctx, t);
}

static inline TCGv_i64 tcg_temp_local_new_i64(TCGContext *tcg_ctx)
{
    TCGTemp *t = tcg_temp_new_internal(tcg_ctx, TCG_TYPE_I64, true);
    return temp_tcgv_i64(tcg_ctx, t);
}

static inline TCGv_ptr tcg_global_mem_new_ptr(TCGContext *tcg_ctx, TCGv_ptr reg, intptr_t offset,
                                              const char *name)
{
    TCGTemp *t = tcg_global_mem_new_internal(tcg_ctx, TCG_TYPE_PTR, reg, offset, name);
    return temp_tcgv_ptr(tcg_ctx, t);
}

static inline TCGv_ptr tcg_temp_new_ptr(TCGContext *tcg_ctx)
{
    TCGTemp *t = tcg_temp_new_internal(tcg_ctx, TCG_TYPE_PTR, false);
    return temp_tcgv_ptr(tcg_ctx, t);
}

static inline TCGv_ptr tcg_temp_local_new_ptr(TCGContext *tcg_ctx)
{
    TCGTemp *t = tcg_temp_new_internal(tcg_ctx, TCG_TYPE_PTR, true);
    return temp_tcgv_ptr(tcg_ctx, t);
}

#if defined(CONFIG_DEBUG_TCG)
/* If you call tcg_clear_temp_count() at the start of a section of
 * code which is not supposed to leak any TCG temporaries, then
 * calling tcg_check_temp_count() at the end of the section will
 * return 1 if the section did in fact leak a temporary.
 */
void tcg_clear_temp_count(void);
int tcg_check_temp_count(void);
#else
#define tcg_clear_temp_count() do { } while (0)
#define tcg_check_temp_count() 0
#endif

int64_t tcg_cpu_exec_time(void);

#define TCG_CT_ALIAS  0x80
#define TCG_CT_IALIAS 0x40
#define TCG_CT_NEWREG 0x20 /* output requires a new register */
#define TCG_CT_REG    0x01
#define TCG_CT_CONST  0x02 /* any constant of register size */

typedef struct TCGArgConstraint {
    uint16_t ct;
    uint8_t alias_index;
    union {
        TCGRegSet regs;
    } u;
} TCGArgConstraint;

#define TCG_MAX_OP_ARGS 16

/* Bits for TCGOpDef->flags, 8 bits available.  */
enum {
    /* Instruction exits the translation block.  */
    TCG_OPF_BB_EXIT      = 0x01,
    /* Instruction defines the end of a basic block.  */
    TCG_OPF_BB_END       = 0x02,
    /* Instruction clobbers call registers and potentially update globals.  */
    TCG_OPF_CALL_CLOBBER = 0x04,
    /* Instruction has side effects: it cannot be removed if its outputs
       are not used, and might trigger exceptions.  */
    TCG_OPF_SIDE_EFFECTS = 0x08,
    /* Instruction operands are 64-bits (otherwise 32-bits).  */
    TCG_OPF_64BIT        = 0x10,
    /* Instruction is optional and not implemented by the host, or insn
       is generic and should not be implemened by the host.  */
    TCG_OPF_NOT_PRESENT  = 0x20,
    /* Instruction operands are vectors.  */
    TCG_OPF_VECTOR       = 0x40,
};

typedef struct TCGOpDef {
    const char *name;
    uint8_t nb_oargs, nb_iargs, nb_cargs, nb_args;
    uint8_t flags;
    TCGArgConstraint *args_ct;
    int *sorted_args;
#if defined(CONFIG_DEBUG_TCG)
    int used;
#endif
} TCGOpDef;

typedef struct TCGTargetOpDef {
    TCGOpcode op;
    const char *args_ct_str[TCG_MAX_OP_ARGS];
} TCGTargetOpDef;

#ifndef NDEBUG
#define tcg_abort() \
do {\
    fprintf(stderr, "%s:%d: tcg fatal error\n", __FILE__, __LINE__);\
    abort();\
} while (0)
#else
#define tcg_abort() abort()
#endif

bool tcg_op_supported(TCGOpcode op);

void tcg_gen_callN(TCGContext *tcg_ctx, void *func, TCGTemp *ret, int nargs, TCGTemp **args);

TCGOp *tcg_emit_op(TCGContext *tcg_ctx, TCGOpcode opc);
void tcg_op_remove(TCGContext *s, TCGOp *op);
TCGOp *tcg_op_insert_before(TCGContext *s, TCGOp *op, TCGOpcode opc);
TCGOp *tcg_op_insert_after(TCGContext *s, TCGOp *op, TCGOpcode opc);

void tcg_optimize(TCGContext *s);

TCGv_i32 tcg_const_i32(TCGContext *tcg_ctx, int32_t val);
TCGv_i64 tcg_const_i64(TCGContext *tcg_ctx, int64_t val);
TCGv_i32 tcg_const_local_i32(TCGContext *tcg_ctx, int32_t val);
TCGv_i64 tcg_const_local_i64(TCGContext *tcg_ctx, int64_t val);
TCGv_vec tcg_const_zeros_vec(TCGContext *tcg_ctx, TCGType);
TCGv_vec tcg_const_ones_vec(TCGContext *tcg_ctx, TCGType);
TCGv_vec tcg_const_zeros_vec_matching(TCGContext *tcg_ctx, TCGv_vec);
TCGv_vec tcg_const_ones_vec_matching(TCGContext *tcg_ctx, TCGv_vec);

#if UINTPTR_MAX == UINT32_MAX
# define tcg_const_ptr(tcg_ctx, x)        ((TCGv_ptr)tcg_const_i32(tcg_ctx, (intptr_t)(x)))
# define tcg_const_local_ptr(tcg_ctx, x)  ((TCGv_ptr)tcg_const_local_i32(tcg_ctx, (intptr_t)(x)))
#else
# define tcg_const_ptr(tcg_ctx, x)        ((TCGv_ptr)tcg_const_i64(tcg_ctx, (intptr_t)(x)))
# define tcg_const_local_ptr(tcg_ctx, x)  ((TCGv_ptr)tcg_const_local_i64(tcg_ctx, (intptr_t)(x)))
#endif

TCGLabel *gen_new_label(TCGContext *tcg_ctx);

/**
 * label_arg
 * @l: label
 *
 * Encode a label for storage in the TCG opcode stream.
 */

static inline TCGArg label_arg(TCGLabel *l)
{
    return (uintptr_t)l;
}

/**
 * arg_label
 * @i: value
 *
 * The opposite of label_arg.  Retrieve a label from the
 * encoding of the TCG opcode stream.
 */

static inline TCGLabel *arg_label(TCGArg i)
{
    return (TCGLabel *)(uintptr_t)i;
}

/**
 * tcg_ptr_byte_diff
 * @a, @b: addresses to be differenced
 *
 * There are many places within the TCG backends where we need a byte
 * difference between two pointers.  While this can be accomplished
 * with local casting, it's easy to get wrong -- especially if one is
 * concerned with the signedness of the result.
 *
 * This version relies on GCC's void pointer arithmetic to get the
 * correct result.
 */

static inline ptrdiff_t tcg_ptr_byte_diff(void *a, void *b)
{
    return (char *)a - (char *)b;
}

/**
 * tcg_pcrel_diff
 * @s: the tcg context
 * @target: address of the target
 *
 * Produce a pc-relative difference, from the current code_ptr
 * to the destination address.
 */

static inline ptrdiff_t tcg_pcrel_diff(TCGContext *s, void *target)
{
    return tcg_ptr_byte_diff(target, s->code_ptr);
}

/**
 * tcg_current_code_size
 * @s: the tcg context
 *
 * Compute the current code size within the translation block.
 * This is used to fill in qemu's data structures for goto_tb.
 */

static inline size_t tcg_current_code_size(TCGContext *s)
{
    return tcg_ptr_byte_diff(s->code_ptr, s->code_buf);
}

/* Combine the MemOp and mmu_idx parameters into a single value.  */
typedef uint32_t TCGMemOpIdx;

/**
 * make_memop_idx
 * @op: memory operation
 * @idx: mmu index
 *
 * Encode these values into a single parameter.
 */
static inline TCGMemOpIdx make_memop_idx(MemOp op, unsigned idx)
{
    tcg_debug_assert(idx <= 15);
    return (op << 4) | idx;
}

/**
 * get_memop
 * @oi: combined op/idx parameter
 *
 * Extract the memory operation from the combined value.
 */
static inline MemOp get_memop(TCGMemOpIdx oi)
{
    return oi >> 4;
}

/**
 * get_mmuidx
 * @oi: combined op/idx parameter
 *
 * Extract the mmu index from the combined value.
 */
static inline unsigned get_mmuidx(TCGMemOpIdx oi)
{
    return oi & 15;
}

/**
 * tcg_qemu_tb_exec:
 * @env: pointer to CPUArchState for the CPU
 * @tb_ptr: address of generated code for the TB to execute
 *
 * Start executing code from a given translation block.
 * Where translation blocks have been linked, execution
 * may proceed from the given TB into successive ones.
 * Control eventually returns only when some action is needed
 * from the top-level loop: either control must pass to a TB
 * which has not yet been directly linked, or an asynchronous
 * event such as an interrupt needs handling.
 *
 * Return: The return value is the value passed to the corresponding
 * tcg_gen_exit_tb() at translation time of the last TB attempted to execute.
 * The value is either zero or a 4-byte aligned pointer to that TB combined
 * with additional information in its two least significant bits. The
 * additional information is encoded as follows:
 *  0, 1: the link between this TB and the next is via the specified
 *        TB index (0 or 1). That is, we left the TB via (the equivalent
 *        of) "goto_tb <index>". The main loop uses this to determine
 *        how to link the TB just executed to the next.
 *  2:    we are using instruction counting code generation, and we
 *        did not start executing this TB because the instruction counter
 *        would hit zero midway through it. In this case the pointer
 *        returned is the TB we were about to execute, and the caller must
 *        arrange to execute the remaining count of instructions.
 *  3:    we stopped because the CPU's exit_request flag was set
 *        (usually meaning that there is an interrupt that needs to be
 *        handled). The pointer returned is the TB we were about to execute
 *        when we noticed the pending exit request.
 *
 * If the bottom two bits indicate an exit-via-index then the CPU
 * state is correctly synchronised and ready for execution of the next
 * TB (and in particular the guest PC is the address to execute next).
 * Otherwise, we gave up on execution of this TB before it started, and
 * the caller must fix up the CPU state by calling the CPU's
 * synchronize_from_tb() method with the TB pointer we return (falling
 * back to calling the CPU's set_pc method with tb->pb if no
 * synchronize_from_tb() method exists).
 *
 * Note that TCG targets may use a different definition of tcg_qemu_tb_exec
 * to this default (which just calls the prologue.code emitted by
 * tcg_target_qemu_prologue()).
 */
#define TB_EXIT_MASK      3
#define TB_EXIT_IDX0      0
#define TB_EXIT_IDX1      1
#define TB_EXIT_IDXMAX    1
#define TB_EXIT_REQUESTED 3

#ifdef HAVE_TCG_QEMU_TB_EXEC
uintptr_t tcg_qemu_tb_exec(CPUArchState *env, uint8_t *tb_ptr);
#else
# define tcg_qemu_tb_exec(env, tb_ptr) \
    ((uintptr_t (*)(void *, void *))env->uc->tcg_ctx->code_gen_prologue)(env, tb_ptr)
#endif

void tcg_register_jit(TCGContext *s, void *buf, size_t buf_size);

#if TCG_TARGET_MAYBE_vec
/* Return zero if the tuple (opc, type, vece) is unsupportable;
   return > 0 if it is directly supportable;
   return < 0 if we must call tcg_expand_vec_op.  */
int tcg_can_emit_vec_op(TCGContext *tcg_ctx, TCGOpcode, TCGType, unsigned);
#else
static inline int tcg_can_emit_vec_op(TCGContext *tcg_ctx, TCGOpcode o, TCGType t, unsigned ve)
{
    return 0;
}
#endif

/* Expand the tuple (opc, type, vece) on the given arguments.  */
void tcg_expand_vec_op(TCGContext *tcg_ctx, TCGOpcode, TCGType, unsigned, TCGArg, ...);

/* Replicate a constant C accoring to the log2 of the element size.  */
uint64_t dup_const_func(unsigned vece, uint64_t c);

#ifndef _MSC_VER
#define dup_const(VECE, C)                                         \
    (__builtin_constant_p(VECE)                                    \
     ? (  (VECE) == MO_8  ? 0x0101010101010101ull * (uint8_t)(C)   \
        : (VECE) == MO_16 ? 0x0001000100010001ull * (uint16_t)(C)  \
        : (VECE) == MO_32 ? 0x0000000100000001ull * (uint32_t)(C)  \
        : dup_const_func(VECE, C))                                      \
     : dup_const_func(VECE, C))
#else
#define dup_const(VECE, C) dup_const_func(VECE, C)
#endif


/*
 * Memory helpers that will be used by TCG generated code.
 */
/* Value zero-extended to tcg register size.  */
tcg_target_ulong helper_ret_ldub_mmu(CPUArchState *env, target_ulong addr,
                                     TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_le_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_le_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
uint64_t helper_le_ldq_mmu(CPUArchState *env, target_ulong addr,
                           TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_be_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_be_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
uint64_t helper_be_ldq_mmu(CPUArchState *env, target_ulong addr,
                           TCGMemOpIdx oi, uintptr_t retaddr);

/* Value sign-extended to tcg register size.  */
tcg_target_ulong helper_ret_ldsb_mmu(CPUArchState *env, target_ulong addr,
                                     TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_le_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_le_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_be_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_be_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr);

void helper_ret_stb_mmu(CPUArchState *env, target_ulong addr, uint8_t val,
                        TCGMemOpIdx oi, uintptr_t retaddr);
void helper_le_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr);
void helper_le_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr);
void helper_le_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr);
void helper_be_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr);
void helper_be_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr);
void helper_be_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr);

/* Temporary aliases until backends are converted.  */
#ifdef TARGET_WORDS_BIGENDIAN
# define helper_ret_ldsw_mmu  helper_be_ldsw_mmu
# define helper_ret_lduw_mmu  helper_be_lduw_mmu
# define helper_ret_ldsl_mmu  helper_be_ldsl_mmu
# define helper_ret_ldul_mmu  helper_be_ldul_mmu
# define helper_ret_ldl_mmu   helper_be_ldul_mmu
# define helper_ret_ldq_mmu   helper_be_ldq_mmu
# define helper_ret_stw_mmu   helper_be_stw_mmu
# define helper_ret_stl_mmu   helper_be_stl_mmu
# define helper_ret_stq_mmu   helper_be_stq_mmu
#else
# define helper_ret_ldsw_mmu  helper_le_ldsw_mmu
# define helper_ret_lduw_mmu  helper_le_lduw_mmu
# define helper_ret_ldsl_mmu  helper_le_ldsl_mmu
# define helper_ret_ldul_mmu  helper_le_ldul_mmu
# define helper_ret_ldl_mmu   helper_le_ldul_mmu
# define helper_ret_ldq_mmu   helper_le_ldq_mmu
# define helper_ret_stw_mmu   helper_le_stw_mmu
# define helper_ret_stl_mmu   helper_le_stl_mmu
# define helper_ret_stq_mmu   helper_le_stq_mmu
#endif

uint32_t helper_atomic_cmpxchgb_mmu(CPUArchState *env, target_ulong addr,
                                    uint32_t cmpv, uint32_t newv,
                                    TCGMemOpIdx oi, uintptr_t retaddr);
uint32_t helper_atomic_cmpxchgw_le_mmu(CPUArchState *env, target_ulong addr,
                                       uint32_t cmpv, uint32_t newv,
                                       TCGMemOpIdx oi, uintptr_t retaddr);
uint32_t helper_atomic_cmpxchgl_le_mmu(CPUArchState *env, target_ulong addr,
                                       uint32_t cmpv, uint32_t newv,
                                       TCGMemOpIdx oi, uintptr_t retaddr);
uint64_t helper_atomic_cmpxchgq_le_mmu(CPUArchState *env, target_ulong addr,
                                       uint64_t cmpv, uint64_t newv,
                                       TCGMemOpIdx oi, uintptr_t retaddr);
uint32_t helper_atomic_cmpxchgw_be_mmu(CPUArchState *env, target_ulong addr,
                                       uint32_t cmpv, uint32_t newv,
                                       TCGMemOpIdx oi, uintptr_t retaddr);
uint32_t helper_atomic_cmpxchgl_be_mmu(CPUArchState *env, target_ulong addr,
                                       uint32_t cmpv, uint32_t newv,
                                       TCGMemOpIdx oi, uintptr_t retaddr);
uint64_t helper_atomic_cmpxchgq_be_mmu(CPUArchState *env, target_ulong addr,
                                       uint64_t cmpv, uint64_t newv,
                                       TCGMemOpIdx oi, uintptr_t retaddr);

#define GEN_ATOMIC_HELPER(NAME, TYPE, SUFFIX)         \
TYPE helper_atomic_ ## NAME ## SUFFIX ## _mmu         \
    (CPUArchState *env, target_ulong addr, TYPE val,  \
     TCGMemOpIdx oi, uintptr_t retaddr);

#ifdef CONFIG_ATOMIC64
#define GEN_ATOMIC_HELPER_ALL(NAME)          \
    GEN_ATOMIC_HELPER(NAME, uint32_t, b)     \
    GEN_ATOMIC_HELPER(NAME, uint32_t, w_le)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, w_be)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, l_le)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, l_be)  \
    GEN_ATOMIC_HELPER(NAME, uint64_t, q_le)  \
    GEN_ATOMIC_HELPER(NAME, uint64_t, q_be)
#else
#define GEN_ATOMIC_HELPER_ALL(NAME)          \
    GEN_ATOMIC_HELPER(NAME, uint32_t, b)     \
    GEN_ATOMIC_HELPER(NAME, uint32_t, w_le)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, w_be)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, l_le)  \
    GEN_ATOMIC_HELPER(NAME, uint32_t, l_be)
#endif

GEN_ATOMIC_HELPER_ALL(fetch_add)
GEN_ATOMIC_HELPER_ALL(fetch_sub)
GEN_ATOMIC_HELPER_ALL(fetch_and)
GEN_ATOMIC_HELPER_ALL(fetch_or)
GEN_ATOMIC_HELPER_ALL(fetch_xor)
GEN_ATOMIC_HELPER_ALL(fetch_smin)
GEN_ATOMIC_HELPER_ALL(fetch_umin)
GEN_ATOMIC_HELPER_ALL(fetch_smax)
GEN_ATOMIC_HELPER_ALL(fetch_umax)

GEN_ATOMIC_HELPER_ALL(add_fetch)
GEN_ATOMIC_HELPER_ALL(sub_fetch)
GEN_ATOMIC_HELPER_ALL(and_fetch)
GEN_ATOMIC_HELPER_ALL(or_fetch)
GEN_ATOMIC_HELPER_ALL(xor_fetch)
GEN_ATOMIC_HELPER_ALL(smin_fetch)
GEN_ATOMIC_HELPER_ALL(umin_fetch)
GEN_ATOMIC_HELPER_ALL(smax_fetch)
GEN_ATOMIC_HELPER_ALL(umax_fetch)

GEN_ATOMIC_HELPER_ALL(xchg)

#undef GEN_ATOMIC_HELPER_ALL
#undef GEN_ATOMIC_HELPER

/*
 * These aren't really a "proper" helpers because TCG cannot manage Int128.
 * However, use the same format as the others, for use by the backends.
 *
 * The cmpxchg functions are only defined if HAVE_CMPXCHG128;
 * the ld/st functions are only defined if HAVE_ATOMIC128,
 * as defined by <qemu/atomic128.h>.
 */
Int128 helper_atomic_cmpxchgo_le_mmu(CPUArchState *env, target_ulong addr,
                                     Int128 cmpv, Int128 newv,
                                     TCGMemOpIdx oi, uintptr_t retaddr);
Int128 helper_atomic_cmpxchgo_be_mmu(CPUArchState *env, target_ulong addr,
                                     Int128 cmpv, Int128 newv,
                                     TCGMemOpIdx oi, uintptr_t retaddr);

Int128 helper_atomic_ldo_le_mmu(CPUArchState *env, target_ulong addr,
                                TCGMemOpIdx oi, uintptr_t retaddr);
Int128 helper_atomic_ldo_be_mmu(CPUArchState *env, target_ulong addr,
                                TCGMemOpIdx oi, uintptr_t retaddr);
void helper_atomic_sto_le_mmu(CPUArchState *env, target_ulong addr, Int128 val,
                              TCGMemOpIdx oi, uintptr_t retaddr);
void helper_atomic_sto_be_mmu(CPUArchState *env, target_ulong addr, Int128 val,
                              TCGMemOpIdx oi, uintptr_t retaddr);

#ifdef CONFIG_DEBUG_TCG
void tcg_assert_listed_vecop(TCGOpcode);
#else
static inline void tcg_assert_listed_vecop(TCGOpcode op) { }
#endif

static inline const TCGOpcode *tcg_swap_vecop_list(const TCGOpcode *n)
{
#ifdef CONFIG_DEBUG_TCG
    const TCGOpcode *o = tcg_ctx->vecop_list;
    tcg_ctx->vecop_list = n;
    return o;
#else
    return NULL;
#endif
}

bool tcg_can_emit_vecop_list(TCGContext *tcg_ctx, const TCGOpcode *, TCGType, unsigned);

void check_exit_request(TCGContext *tcg_ctx);

void tcg_dump_ops(TCGContext *s, bool have_prefs, const char *headline);

struct jit_code_entry {
    struct jit_code_entry *next_entry;
    struct jit_code_entry *prev_entry;
    const void *symfile_addr;
    uint64_t symfile_size;
};

void uc_del_inline_hook(uc_engine *uc, struct hook *hk);
void uc_add_inline_hook(uc_engine *uc, struct hook *hk, void** args, int args_len);

#endif /* TCG_H */
