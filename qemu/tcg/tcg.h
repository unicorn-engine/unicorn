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

#include "qemu-common.h"
#include "qemu/bitops.h"
#include "tcg-target.h"
#include "exec/exec-all.h"

#include "uc_priv.h"

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

#if TCG_TARGET_NB_REGS <= 32
typedef uint32_t TCGRegSet;
#elif TCG_TARGET_NB_REGS <= 64
typedef uint64_t TCGRegSet;
#else
#error unsupported
#endif

#if TCG_TARGET_REG_BITS == 32
/* Turn some undef macros into false macros.  */
#define TCG_TARGET_HAS_trunc_shr_i32    0
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
#define TCG_TARGET_HAS_deposit_i64      0
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

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_ ## name,
#include "tcg-opc.h"
#undef DEF
    NB_OPS,
} TCGOpcode;

#define tcg_regset_clear(d) (d) = 0
#define tcg_regset_set(d, s) (d) = (s)
#define tcg_regset_set32(d, reg, val32) (d) |= (val32) << (reg)
#define tcg_regset_set_reg(d, r) (d) |= 1L << (r)
#define tcg_regset_reset_reg(d, r) (d) &= ~(1L << (r))
#define tcg_regset_test_reg(d, r) (((d) >> (r)) & 1)
#define tcg_regset_or(d, a, b) (d) = (a) | (b)
#define tcg_regset_and(d, a, b) (d) = (a) & (b)
#define tcg_regset_andnot(d, a, b) (d) = (a) & ~(b)
#define tcg_regset_not(d, a) (d) = ~(a)

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


typedef struct TCGRelocation {
    struct TCGRelocation *next;
    int type;
    tcg_insn_unit *ptr;
    intptr_t addend;
} TCGRelocation; 

typedef struct TCGLabel {
    int has_value;
    union {
        uintptr_t value;
        tcg_insn_unit *value_ptr;
        TCGRelocation *first_reloc;
    } u;
} TCGLabel;

typedef struct TCGPool {
    struct TCGPool *next;
    int size;
    uint8_t QEMU_ALIGN(8, data[0]);
} TCGPool;

#define TCG_POOL_CHUNK_SIZE 32768

#define TCG_MAX_LABELS 512

#define TCG_MAX_TEMPS 512

/* when the size of the arguments of a called function is smaller than
   this value, they are statically allocated in the TB stack frame */
#define TCG_STATIC_CALL_ARGS_SIZE 128

typedef enum TCGType {
    TCG_TYPE_I32,
    TCG_TYPE_I64,
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

/* Constants for qemu_ld and qemu_st for the Memory Operation field.  */
typedef enum TCGMemOp {
    MO_8     = 0,
    MO_16    = 1,
    MO_32    = 2,
    MO_64    = 3,
    MO_SIZE  = 3,   /* Mask for the above.  */

    MO_SIGN  = 4,   /* Sign-extended, otherwise zero-extended.  */

    MO_BSWAP = 8,   /* Host reverse endian.  */
#ifdef HOST_WORDS_BIGENDIAN
    MO_LE    = MO_BSWAP,
    MO_BE    = 0,
#else
    MO_LE    = 0,
    MO_BE    = MO_BSWAP,
#endif
#ifdef TARGET_WORDS_BIGENDIAN
    MO_TE    = MO_BE,
#else
    MO_TE    = MO_LE,
#endif

    /* Combinations of the above, for ease of use.  */
    MO_UB    = MO_8,
    MO_UW    = MO_16,
    MO_UL    = MO_32,
    MO_SB    = MO_SIGN | MO_8,
    MO_SW    = MO_SIGN | MO_16,
    MO_SL    = MO_SIGN | MO_32,
    MO_Q     = MO_64,

    MO_LEUW  = MO_LE | MO_UW,
    MO_LEUL  = MO_LE | MO_UL,
    MO_LESW  = MO_LE | MO_SW,
    MO_LESL  = MO_LE | MO_SL,
    MO_LEQ   = MO_LE | MO_Q,

    MO_BEUW  = MO_BE | MO_UW,
    MO_BEUL  = MO_BE | MO_UL,
    MO_BESW  = MO_BE | MO_SW,
    MO_BESL  = MO_BE | MO_SL,
    MO_BEQ   = MO_BE | MO_Q,

    MO_TEUW  = MO_TE | MO_UW,
    MO_TEUL  = MO_TE | MO_UL,
    MO_TESW  = MO_TE | MO_SW,
    MO_TESL  = MO_TE | MO_SL,
    MO_TEQ   = MO_TE | MO_Q,

    MO_SSIZE = MO_SIZE | MO_SIGN,
} TCGMemOp;

typedef tcg_target_ulong TCGArg;

/* Define a type and accessor macros for variables.  Using pointer types
   is nice because it gives some level of type safely.  Converting to and
   from intptr_t rather than int reduces the number of sign-extension
   instructions that get implied on 64-bit hosts.  Users of tcg_gen_* don't
   need to know about any of this, and should treat TCGv as an opaque type.
   In addition we do typechecking for different types of variables.  TCGv_i32
   and TCGv_i64 are 32/64-bit variables respectively.  TCGv and TCGv_ptr
   are aliases for target_ulong and host pointer sized values respectively.  */

typedef struct TCGv_i32_d *TCGv_i32;
typedef struct TCGv_i64_d *TCGv_i64;
typedef struct TCGv_ptr_d *TCGv_ptr;

static inline TCGv_i32 QEMU_ARTIFICIAL MAKE_TCGV_I32(intptr_t i)
{
    return (TCGv_i32)i;
}

static inline TCGv_i64 QEMU_ARTIFICIAL MAKE_TCGV_I64(intptr_t i)
{
    return (TCGv_i64)i;
}

static inline TCGv_ptr QEMU_ARTIFICIAL MAKE_TCGV_PTR(intptr_t i)
{
    return (TCGv_ptr)i;
}

static inline intptr_t QEMU_ARTIFICIAL GET_TCGV_I32(TCGv_i32 t)
{
    return (intptr_t)t;
}

static inline intptr_t QEMU_ARTIFICIAL GET_TCGV_I64(TCGv_i64 t)
{
    return (intptr_t)t;
}

static inline intptr_t QEMU_ARTIFICIAL GET_TCGV_PTR(TCGv_ptr t)
{
    return (intptr_t)t;
}

#if TCG_TARGET_REG_BITS == 32
#define TCGV_LOW(t) MAKE_TCGV_I32(GET_TCGV_I64(t))
#define TCGV_HIGH(t) MAKE_TCGV_I32(GET_TCGV_I64(t) + 1)
#endif

#define TCGV_EQUAL_I32(a, b) (GET_TCGV_I32(a) == GET_TCGV_I32(b))
#define TCGV_EQUAL_I64(a, b) (GET_TCGV_I64(a) == GET_TCGV_I64(b))
#define TCGV_EQUAL_PTR(a, b) (GET_TCGV_PTR(a) == GET_TCGV_PTR(b))

/* Dummy definition to avoid compiler warnings.  */
#define TCGV_UNUSED_I32(x) x = MAKE_TCGV_I32(-1)
#define TCGV_UNUSED_I64(x) x = MAKE_TCGV_I64(-1)
#define TCGV_UNUSED_PTR(x) x = MAKE_TCGV_PTR(-1)

#define TCGV_IS_UNUSED_I32(x) (GET_TCGV_I32(x) == -1)
#define TCGV_IS_UNUSED_I64(x) (GET_TCGV_I64(x) == -1)
#define TCGV_IS_UNUSED_PTR(x) (GET_TCGV_PTR(x) == -1)

/* call flags */
/* Helper does not read globals (either directly or through an exception). It
   implies TCG_CALL_NO_WRITE_GLOBALS. */
#define TCG_CALL_NO_READ_GLOBALS    0x0010
/* Helper does not write globals */
#define TCG_CALL_NO_WRITE_GLOBALS   0x0020
/* Helper can be safely suppressed if the return value is not used. */
#define TCG_CALL_NO_SIDE_EFFECTS    0x0040

/* convenience version of most used call flags */
#define TCG_CALL_NO_RWG         TCG_CALL_NO_READ_GLOBALS
#define TCG_CALL_NO_WG          TCG_CALL_NO_WRITE_GLOBALS
#define TCG_CALL_NO_SE          TCG_CALL_NO_SIDE_EFFECTS
#define TCG_CALL_NO_RWG_SE      (TCG_CALL_NO_RWG | TCG_CALL_NO_SE)
#define TCG_CALL_NO_WG_SE       (TCG_CALL_NO_WG | TCG_CALL_NO_SE)

/* used to align parameters */
#define TCG_CALL_DUMMY_TCGV     MAKE_TCGV_I32(-1)
#define TCG_CALL_DUMMY_ARG      ((TCGArg)(-1))

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

#define TEMP_VAL_DEAD  0
#define TEMP_VAL_REG   1
#define TEMP_VAL_MEM   2
#define TEMP_VAL_CONST 3

/* XXX: optimize memory layout */
typedef struct TCGTemp {
    TCGType base_type;
    TCGType type;
    int val_type;
    int reg;
    tcg_target_long val;
    int mem_reg;
    intptr_t mem_offset;
    unsigned int fixed_reg:1;
    unsigned int mem_coherent:1;
    unsigned int mem_allocated:1;
    unsigned int temp_local:1; /* If true, the temp is saved across
                                  basic blocks. Otherwise, it is not
                                  preserved across basic blocks. */
    unsigned int temp_allocated:1; /* never used for code gen */
    const char *name;
} TCGTemp;

typedef struct TCGContext TCGContext;

typedef struct TCGTempSet {
    unsigned long l[BITS_TO_LONGS(TCG_MAX_TEMPS)];
} TCGTempSet;


/* pool based memory allocation */

void *tcg_malloc_internal(TCGContext *s, int size);
void tcg_pool_reset(TCGContext *s);
void tcg_pool_delete(TCGContext *s);

void tcg_context_init(TCGContext *s);
void tcg_context_free(void *s);   // free memory allocated for @s
void tcg_prologue_init(TCGContext *s);
void tcg_func_start(TCGContext *s);

int tcg_gen_code(TCGContext *s, tcg_insn_unit *gen_code_buf);
int tcg_gen_code_search_pc(TCGContext *s, tcg_insn_unit *gen_code_buf,
                           long offset);

void tcg_set_frame(TCGContext *s, int reg, intptr_t start, intptr_t size);

TCGv_i32 tcg_global_reg_new_i32(TCGContext *s, int reg, const char *name);
TCGv_i32 tcg_global_mem_new_i32(TCGContext *s, int reg, intptr_t offset, const char *name);
TCGv_i32 tcg_temp_new_internal_i32(TCGContext *s, int temp_local);
static inline TCGv_i32 tcg_temp_new_i32(TCGContext *s)
{
    return tcg_temp_new_internal_i32(s, 0);
}
static inline TCGv_i32 tcg_temp_local_new_i32(TCGContext *s)
{
    return tcg_temp_new_internal_i32(s, 1);
}
void tcg_temp_free_i32(TCGContext *s, TCGv_i32 arg);
char *tcg_get_arg_str_i32(TCGContext *s, char *buf, int buf_size, TCGv_i32 arg);

TCGv_i64 tcg_global_reg_new_i64(TCGContext *s, int reg, const char *name);
TCGv_i64 tcg_global_mem_new_i64(TCGContext *s, int reg, intptr_t offset, const char *name);
TCGv_i64 tcg_temp_new_internal_i64(TCGContext *s, int temp_local);
static inline TCGv_i64 tcg_temp_new_i64(TCGContext *s)
{
    return tcg_temp_new_internal_i64(s, 0);
}
static inline TCGv_i64 tcg_temp_local_new_i64(TCGContext *s)
{
    return tcg_temp_new_internal_i64(s, 1);
}
void tcg_temp_free_i64(TCGContext *s, TCGv_i64 arg);
char *tcg_get_arg_str_i64(TCGContext *s, char *buf, int buf_size, TCGv_i64 arg);

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

void tcg_dump_info(FILE *f, fprintf_function cpu_fprintf);

#define TCG_CT_ALIAS  0x80
#define TCG_CT_IALIAS 0x40
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
    /* Instruction defines the end of a basic block.  */
    TCG_OPF_BB_END       = 0x01,
    /* Instruction clobbers call registers and potentially update globals.  */
    TCG_OPF_CALL_CLOBBER = 0x02,
    /* Instruction has side effects: it cannot be removed if its outputs
       are not used, and might trigger exceptions.  */
    TCG_OPF_SIDE_EFFECTS = 0x04,
    /* Instruction operands are 64-bits (otherwise 32-bits).  */
    TCG_OPF_64BIT        = 0x08,
    /* Instruction is optional and not implemented by the host, or insn
       is generic and should not be implemened by the host.  */
    TCG_OPF_NOT_PRESENT  = 0x10,
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

typedef enum {
    TCG_TEMP_UNDEF = 0,
    TCG_TEMP_CONST,
    TCG_TEMP_COPY,
} tcg_temp_state;

struct tcg_temp_info {
    tcg_temp_state state;
    uint16_t prev_copy;
    uint16_t next_copy;
    tcg_target_ulong val;
    tcg_target_ulong mask;
};

struct TCGContext {
    uint8_t *pool_cur, *pool_end;
    TCGPool *pool_first, *pool_current, *pool_first_large;
    TCGLabel *labels;
    int nb_labels;
    int nb_globals;
    int nb_temps;

    /* goto_tb support */
    tcg_insn_unit *code_buf;
    uintptr_t *tb_next;
    uint16_t *tb_next_offset;
    uint16_t *tb_jmp_offset; /* != NULL if USE_DIRECT_JUMP */

    /* liveness analysis */
    uint16_t *op_dead_args; /* for each operation, each bit tells if the
                               corresponding argument is dead */
    uint8_t *op_sync_args;  /* for each operation, each bit tells if the
                               corresponding output argument needs to be
                               sync to memory. */
    
    /* tells in which temporary a given register is. It does not take
       into account fixed registers */
    int reg_to_temp[TCG_TARGET_NB_REGS];
    TCGRegSet reserved_regs;
    intptr_t current_frame_offset;
    intptr_t frame_start;
    intptr_t frame_end;
    int frame_reg;

    tcg_insn_unit *code_ptr;
    TCGTemp temps[TCG_MAX_TEMPS]; /* globals first, temps after */
    TCGTempSet free_temps[TCG_TYPE_COUNT * 2];

    GHashTable *helpers;

#ifdef CONFIG_PROFILER
    /* profiling info */
    int64_t tb_count1;
    int64_t tb_count;
    int64_t op_count; /* total insn count */
    int op_count_max; /* max insn per TB */
    int64_t temp_count;
    int temp_count_max;
    int64_t del_op_count;
    int64_t code_in_len;
    int64_t code_out_len;
    int64_t interm_time;
    int64_t code_time;
    int64_t la_time;
    int64_t opt_time;
    int64_t restore_count;
    int64_t restore_time;
#endif

#ifdef CONFIG_DEBUG_TCG
    int temps_in_use;
    int goto_tb_issue_mask;
#endif

    uint16_t gen_opc_buf[OPC_BUF_SIZE];
    TCGArg gen_opparam_buf[OPPARAM_BUF_SIZE];

    uint16_t *gen_opc_ptr;
    TCGArg *gen_opparam_ptr;
    target_ulong gen_opc_pc[OPC_BUF_SIZE];
    uint16_t gen_opc_icount[OPC_BUF_SIZE];
    uint8_t gen_opc_instr_start[OPC_BUF_SIZE];

    /* Code generation.  Note that we specifically do not use tcg_insn_unit
       here, because there's too much arithmetic throughout that relies
       on addition and subtraction working on bytes.  Rely on the GCC
       extension that allows arithmetic on void*.  */
    int code_gen_max_blocks;
    void *code_gen_prologue;
    void *code_gen_buffer;
    size_t code_gen_buffer_size;
    /* threshold to flush the translated code buffer */
    size_t code_gen_buffer_max_size;
    void *code_gen_ptr;

    TBContext tb_ctx;

    /* The TCGBackendData structure is private to tcg-target.c.  */
    struct TCGBackendData *be;

    // Unicorn engine variables
    struct uc_struct *uc;
    /* qemu/target-i386/translate.c: global register indexes */
    TCGv_ptr cpu_env;
    TCGv_i32 cpu_cc_op;
    void *cpu_regs[16]; // 16 GRP for X86-64
    int x86_64_hregs;   // qemu/target-i386/translate.c
    uint8_t gen_opc_cc_op[OPC_BUF_SIZE];    // qemu/target-i386/translate.c

    /* qemu/target-i386/translate.c: global TCGv vars */
    void *cpu_A0;
    void *cpu_cc_dst, *cpu_cc_src, *cpu_cc_src2, *cpu_cc_srcT;

    /* qemu/target-i386/translate.c: local temps */
    void *cpu_T[2];

    /* qemu/target-i386/translate.c: local register indexes (only used inside old micro ops) */
    void *cpu_tmp0, *cpu_tmp4;
    TCGv_ptr cpu_ptr0, cpu_ptr1;
    TCGv_i32 cpu_tmp2_i32, cpu_tmp3_i32;
    TCGv_i64 cpu_tmp1_i64;

    /* qemu/tcg/i386/tcg-target.c */
    void *tb_ret_addr;
    int guest_base_flags;
    /* If bit_MOVBE is defined in cpuid.h (added in GCC version 4.6), we are
       going to attempt to determine at runtime whether movbe is available.  */
    bool have_movbe;

    /* qemu/tcg/tcg.c */
    uint64_t tcg_target_call_clobber_regs;
    uint64_t tcg_target_available_regs[2];
    TCGOpDef *tcg_op_defs;

    /* qemu/tcg/optimize.c */
    struct tcg_temp_info temps2[TCG_MAX_TEMPS];

    /* qemu/target-m68k/translate.c */
    TCGv_i32 cpu_halted;
    char cpu_reg_names[3*8*3 + 5*4];
    void *cpu_dregs[8];
    void *cpu_aregs[8];
    TCGv_i64 cpu_fregs[8];
    TCGv_i64 cpu_macc[4];
    TCGv_i64 QREG_FP_RESULT;
    void *QREG_PC, *QREG_SR, *QREG_CC_OP, *QREG_CC_DEST, *QREG_CC_SRC;
    void *QREG_CC_X, *QREG_DIV1, *QREG_DIV2, *QREG_MACSR, *QREG_MAC_MASK;
    void *NULL_QREG;
    void *opcode_table[65536];
    /* Used to distinguish stores from bad addressing modes.  */
    void *store_dummy;

    /* qemu/target-arm/translate.c */
    uint32_t gen_opc_condexec_bits[OPC_BUF_SIZE];
    TCGv_i64 cpu_V0, cpu_V1, cpu_M0;
    /* We reuse the same 64-bit temporaries for efficiency.  */
    TCGv_i32 cpu_R[16];
    TCGv_i32 cpu_CF, cpu_NF, cpu_VF, cpu_ZF;
    TCGv_i64 cpu_exclusive_addr;
    TCGv_i64 cpu_exclusive_val;
    TCGv_i32 cpu_F0s, cpu_F1s;
    TCGv_i64 cpu_F0d, cpu_F1d;

    /* qemu/target-arm/translate-a64.c */
    TCGv_i64 cpu_pc;
    /* Load/store exclusive handling */
    TCGv_i64 cpu_exclusive_high;
    TCGv_i64 cpu_X[32];

    /* qemu/target-mips/translate.c */
    /* global register indices */
    void *cpu_gpr[32], *cpu_PC;
    void *cpu_HI[4], *cpu_LO[4];    // MIPS_DSP_ACC = 4 in qemu/target-mips/cpu.h
    void *cpu_dspctrl, *btarget, *bcond;
    TCGv_i32 hflags;
    TCGv_i32 fpu_fcr31;
    TCGv_i64 fpu_f64[32];
    TCGv_i64 msa_wr_d[64];

    uint32_t gen_opc_hflags[OPC_BUF_SIZE];
    target_ulong gen_opc_btarget[OPC_BUF_SIZE];

    /* qemu/target-sparc/translate.c */
    /* global register indexes */
    TCGv_ptr cpu_regwptr;
    TCGv_i32 cpu_psr;
    TCGv_i32 cpu_xcc, cpu_asi, cpu_fprs;
    TCGv_i32 cpu_softint;
    /* Floating point registers */
    TCGv_i64 cpu_fpr[32];   // TARGET_DPREGS = 32 for Sparc64, 16 for Sparc

    target_ulong gen_opc_npc[OPC_BUF_SIZE];
    target_ulong gen_opc_jump_pc[2];

    // void *cpu_cc_src, *cpu_cc_src2, *cpu_cc_dst;
    void *cpu_fsr, *sparc_cpu_pc, *cpu_npc, *cpu_gregs[8];
    void *cpu_y;
    void *cpu_tbr;
    void *cpu_cond;
    void *cpu_gsr;
    void *cpu_tick_cmpr, *cpu_stick_cmpr, *cpu_hstick_cmpr;
    void *cpu_hintp, *cpu_htba, *cpu_hver, *cpu_ssr, *cpu_ver;
    void *cpu_wim;

    int exitreq_label;  // gen_tb_start()
};

typedef struct TCGTargetOpDef {
    TCGOpcode op;
    const char *args_ct_str[TCG_MAX_OP_ARGS];
} TCGTargetOpDef;

#define tcg_abort() \
do {\
    fprintf(stderr, "%s:%d: tcg fatal error\n", __FILE__, __LINE__);\
    abort();\
} while (0)

#ifdef CONFIG_DEBUG_TCG
# define tcg_debug_assert(X) do { assert(X); } while (0)
#elif QEMU_GNUC_PREREQ(4, 5)
# define tcg_debug_assert(X) \
    do { if (!(X)) { __builtin_unreachable(); } } while (0)
#else
# define tcg_debug_assert(X) do { (void)(X); } while (0)
#endif

void tcg_add_target_add_op_defs(TCGContext *s, const TCGTargetOpDef *tdefs);

#if UINTPTR_MAX == UINT32_MAX
#define TCGV_NAT_TO_PTR(n) MAKE_TCGV_PTR(GET_TCGV_I32(n))
#define TCGV_PTR_TO_NAT(n) MAKE_TCGV_I32(GET_TCGV_PTR(n))

#define tcg_const_ptr(t, V) TCGV_NAT_TO_PTR(tcg_const_i32(t, (intptr_t)(V)))
#define tcg_global_reg_new_ptr(U, R, N) \
    TCGV_NAT_TO_PTR(tcg_global_reg_new_i32(U, (R), (N)))
#define tcg_global_mem_new_ptr(t, R, O, N) \
    TCGV_NAT_TO_PTR(tcg_global_mem_new_i32(t, (R), (O), (N)))
#define tcg_temp_new_ptr(s) TCGV_NAT_TO_PTR(tcg_temp_new_i32(s))
#define tcg_temp_free_ptr(s, T) tcg_temp_free_i32(s, TCGV_PTR_TO_NAT(T))
#else
#define TCGV_NAT_TO_PTR(n) MAKE_TCGV_PTR(GET_TCGV_I64(n))
#define TCGV_PTR_TO_NAT(n) MAKE_TCGV_I64(GET_TCGV_PTR(n))

#define tcg_const_ptr(t, V) TCGV_NAT_TO_PTR(tcg_const_i64(t, (intptr_t)(V)))
#define tcg_global_reg_new_ptr(U, R, N) \
    TCGV_NAT_TO_PTR(tcg_global_reg_new_i64(U, (R), (N)))
#define tcg_global_mem_new_ptr(t, R, O, N) \
    TCGV_NAT_TO_PTR(tcg_global_mem_new_i64(t, (R), (O), (N)))
#define tcg_temp_new_ptr(s) TCGV_NAT_TO_PTR(tcg_temp_new_i64(s))
#define tcg_temp_free_ptr(s, T) tcg_temp_free_i64(s, TCGV_PTR_TO_NAT(T))
#endif

void tcg_gen_callN(TCGContext *s, void *func,
                   TCGArg ret, int nargs, TCGArg *args);

void tcg_gen_shifti_i64(TCGContext *s, TCGv_i64 ret, TCGv_i64 arg1,
                        int c, int right, int arith);

TCGArg *tcg_optimize(TCGContext *s, uint16_t *tcg_opc_ptr, TCGArg *args,
                     TCGOpDef *tcg_op_def);

static inline void *tcg_malloc(TCGContext *s, int size)
{
    uint8_t *ptr, *ptr_end;
    size = (size + sizeof(long) - 1) & ~(sizeof(long) - 1);
    ptr = s->pool_cur;
    ptr_end = ptr + size;
    if (unlikely(ptr_end > s->pool_end)) {
        return tcg_malloc_internal(s, size);
    } else {
        s->pool_cur = ptr_end;
        return ptr;
    }
}

/* only used for debugging purposes */
void tcg_dump_ops(TCGContext *s);

void dump_ops(const uint16_t *opc_buf, const TCGArg *opparam_buf);
TCGv_i32 tcg_const_i32(TCGContext *s, int32_t val);
TCGv_i64 tcg_const_i64(TCGContext *s, int64_t val);
TCGv_i32 tcg_const_local_i32(TCGContext *s, int32_t val);
TCGv_i64 tcg_const_local_i64(TCGContext *s, int64_t val);

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
    return (char*)a - (char*)b;
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

/**
 * tcg_qemu_tb_exec:
 * @env: CPUArchState * for the CPU
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
 * The return value is a pointer to the next TB to execute
 * (if known; otherwise zero). This pointer is assumed to be
 * 4-aligned, and the bottom two bits are used to return further
 * information:
 *  0, 1: the link between this TB and the next is via the specified
 *        TB index (0 or 1). That is, we left the TB via (the equivalent
 *        of) "goto_tb <index>". The main loop uses this to determine
 *        how to link the TB just executed to the next.
 *  2:    we are using instruction counting code generation, and we
 *        did not start executing this TB because the instruction counter
 *        would hit zero midway through it. In this case the next-TB pointer
 *        returned is the TB we were about to execute, and the caller must
 *        arrange to execute the remaining count of instructions.
 *  3:    we stopped because the CPU's exit_request flag was set
 *        (usually meaning that there is an interrupt that needs to be
 *        handled). The next-TB pointer returned is the TB we were
 *        about to execute when we noticed the pending exit request.
 *
 * If the bottom two bits indicate an exit-via-index then the CPU
 * state is correctly synchronised and ready for execution of the next
 * TB (and in particular the guest PC is the address to execute next).
 * Otherwise, we gave up on execution of this TB before it started, and
 * the caller must fix up the CPU state by calling cpu_pc_from_tb()
 * with the next-TB pointer we return.
 *
 * Note that TCG targets may use a different definition of tcg_qemu_tb_exec
 * to this default (which just calls the prologue.code emitted by
 * tcg_target_qemu_prologue()).
 */
#define TB_EXIT_MASK 3
#define TB_EXIT_IDX0 0
#define TB_EXIT_IDX1 1
#define TB_EXIT_ICOUNT_EXPIRED 2
#define TB_EXIT_REQUESTED 3

#if !defined(tcg_qemu_tb_exec)
# define tcg_qemu_tb_exec(env, tb_ptr) \
    ((uintptr_t (*)(void *, void *))tcg_ctx->code_gen_prologue)(env, tb_ptr)
#endif

/*
 * Memory helpers that will be used by TCG generated code.
 */
#ifdef CONFIG_SOFTMMU
/* Value zero-extended to tcg register size.  */
tcg_target_ulong helper_ret_ldub_mmu(CPUArchState *env, target_ulong addr,
                                     int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_le_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_le_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
uint64_t helper_le_ldq_mmu(CPUArchState *env, target_ulong addr,
                           int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_be_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_be_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
uint64_t helper_be_ldq_mmu(CPUArchState *env, target_ulong addr,
                           int mmu_idx, uintptr_t retaddr);

/* Value sign-extended to tcg register size.  */
tcg_target_ulong helper_ret_ldsb_mmu(CPUArchState *env, target_ulong addr,
                                     int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_le_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_le_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_be_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);
tcg_target_ulong helper_be_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    int mmu_idx, uintptr_t retaddr);

void helper_ret_stb_mmu(CPUArchState *env, target_ulong addr, uint8_t val,
                        int mmu_idx, uintptr_t retaddr);
void helper_le_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       int mmu_idx, uintptr_t retaddr);
void helper_le_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       int mmu_idx, uintptr_t retaddr);
void helper_le_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       int mmu_idx, uintptr_t retaddr);
void helper_be_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       int mmu_idx, uintptr_t retaddr);
void helper_be_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       int mmu_idx, uintptr_t retaddr);
void helper_be_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       int mmu_idx, uintptr_t retaddr);

/* Temporary aliases until backends are converted.  */
#ifdef TARGET_WORDS_BIGENDIAN
# define helper_ret_ldsw_mmu  helper_be_ldsw_mmu
# define helper_ret_lduw_mmu  helper_be_lduw_mmu
# define helper_ret_ldsl_mmu  helper_be_ldsl_mmu
# define helper_ret_ldul_mmu  helper_be_ldul_mmu
# define helper_ret_ldq_mmu   helper_be_ldq_mmu
# define helper_ret_stw_mmu   helper_be_stw_mmu
# define helper_ret_stl_mmu   helper_be_stl_mmu
# define helper_ret_stq_mmu   helper_be_stq_mmu
#else
# define helper_ret_ldsw_mmu  helper_le_ldsw_mmu
# define helper_ret_lduw_mmu  helper_le_lduw_mmu
# define helper_ret_ldsl_mmu  helper_le_ldsl_mmu
# define helper_ret_ldul_mmu  helper_le_ldul_mmu
# define helper_ret_ldq_mmu   helper_le_ldq_mmu
# define helper_ret_stw_mmu   helper_le_stw_mmu
# define helper_ret_stl_mmu   helper_le_stl_mmu
# define helper_ret_stq_mmu   helper_le_stq_mmu
#endif

void check_exit_request(TCGContext *tcg_ctx);

#endif /* CONFIG_SOFTMMU */

#endif /* TCG_H */
