/*
 *  i386 translation
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
#include "qemu/osdep.h"

#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "exec/cpu_ldst.h"
#include "exec/translator.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "qemu/compiler.h"

#include "unicorn/platform.h"
#include "uc_priv.h"

#define PREFIX_REPZ   0x01
#define PREFIX_REPNZ  0x02
#define PREFIX_LOCK   0x04
#define PREFIX_DATA   0x08
#define PREFIX_ADR    0x10
#define PREFIX_VEX    0x20

#ifdef TARGET_X86_64
#define CODE64(s) ((s)->code64)
#define REX_X(s) ((s)->rex_x)
#define REX_B(s) ((s)->rex_b)
#else
#define CODE64(s) 0
#define REX_X(s) 0
#define REX_B(s) 0
#endif

#ifdef TARGET_X86_64
# define ctztl  ctz64
# define clztl  clz64
#else
# define ctztl  ctz32
# define clztl  clz32
#endif

/* For a switch indexed by MODRM, match all memory operands for a given OP.  */
#define CASE_MODRM_MEM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0: \
    case (0 << 6) | (OP << 3) | 1: \
    case (0 << 6) | (OP << 3) | 2: \
    case (0 << 6) | (OP << 3) | 3: \
    case (0 << 6) | (OP << 3) | 4: \
    case (0 << 6) | (OP << 3) | 5: \
    case (0 << 6) | (OP << 3) | 6: \
    case (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0: \
    case (1 << 6) | (OP << 3) | 1: \
    case (1 << 6) | (OP << 3) | 2: \
    case (1 << 6) | (OP << 3) | 3: \
    case (1 << 6) | (OP << 3) | 4: \
    case (1 << 6) | (OP << 3) | 5: \
    case (1 << 6) | (OP << 3) | 6: \
    case (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0: \
    case (2 << 6) | (OP << 3) | 1: \
    case (2 << 6) | (OP << 3) | 2: \
    case (2 << 6) | (OP << 3) | 3: \
    case (2 << 6) | (OP << 3) | 4: \
    case (2 << 6) | (OP << 3) | 5: \
    case (2 << 6) | (OP << 3) | 6: \
    case (2 << 6) | (OP << 3) | 7

#define CASE_MODRM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0: \
    case (0 << 6) | (OP << 3) | 1: \
    case (0 << 6) | (OP << 3) | 2: \
    case (0 << 6) | (OP << 3) | 3: \
    case (0 << 6) | (OP << 3) | 4: \
    case (0 << 6) | (OP << 3) | 5: \
    case (0 << 6) | (OP << 3) | 6: \
    case (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0: \
    case (1 << 6) | (OP << 3) | 1: \
    case (1 << 6) | (OP << 3) | 2: \
    case (1 << 6) | (OP << 3) | 3: \
    case (1 << 6) | (OP << 3) | 4: \
    case (1 << 6) | (OP << 3) | 5: \
    case (1 << 6) | (OP << 3) | 6: \
    case (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0: \
    case (2 << 6) | (OP << 3) | 1: \
    case (2 << 6) | (OP << 3) | 2: \
    case (2 << 6) | (OP << 3) | 3: \
    case (2 << 6) | (OP << 3) | 4: \
    case (2 << 6) | (OP << 3) | 5: \
    case (2 << 6) | (OP << 3) | 6: \
    case (2 << 6) | (OP << 3) | 7: \
    case (3 << 6) | (OP << 3) | 0: \
    case (3 << 6) | (OP << 3) | 1: \
    case (3 << 6) | (OP << 3) | 2: \
    case (3 << 6) | (OP << 3) | 3: \
    case (3 << 6) | (OP << 3) | 4: \
    case (3 << 6) | (OP << 3) | 5: \
    case (3 << 6) | (OP << 3) | 6: \
    case (3 << 6) | (OP << 3) | 7

#include "exec/gen-icount.h"

typedef struct DisasContext {
    DisasContextBase base;

    /* current insn context */
    int override; /* -1 if no override */
    int prefix;
    MemOp aflag;
    MemOp dflag;
    target_ulong pc_start;
    target_ulong pc; /* pc = eip + cs_base */
    /* current block context */
    target_ulong cs_base; /* base of CS segment */
    int pe;     /* protected mode */
    int code32; /* 32 bit code segment */
#ifdef TARGET_X86_64
    int lma;    /* long mode active */
    int code64; /* 64 bit code segment */
    int rex_x, rex_b;
#endif
    int vex_l;  /* vex vector length */
    int vex_v;  /* vex vvvv register, without 1's complement.  */
    int ss32;   /* 32 bit stack segment */
    CCOp cc_op;  /* current CC operation */
    CCOp last_cc_op;  /* Unicorn: last CC operation. Save this to see if cc_op has changed */
    bool cc_op_dirty;
#ifdef TARGET_X86_64
    bool x86_64_hregs;
#endif
    int addseg; /* non zero if either DS/ES/SS have a non zero base */
    int f_st;   /* currently unused */
    int vm86;   /* vm86 mode */
    int cpl;
    int iopl;
    int tf;     /* TF cpu flag */
    int jmp_opt; /* use direct block chaining for direct jumps */
    int repz_opt; /* optimize jumps within repz instructions */
    int mem_index; /* select memory access functions */
    uint64_t flags; /* all execution flags */
    int popl_esp_hack; /* for correct popl with esp base handling */
    int rip_offset; /* only used in x86_64, but left for simplicity */
    int cpuid_features;
    int cpuid_ext_features;
    int cpuid_ext2_features;
    int cpuid_ext3_features;
    int cpuid_7_0_ebx_features;
    int cpuid_xsave_features;

    /* TCG local temps */
    TCGv cc_srcT;
    TCGv A0;
    TCGv T0;
    TCGv T1;

    /* TCG local register indexes (only used inside old micro ops) */
    TCGv tmp0;
    TCGv tmp4;
    TCGv_ptr ptr0;
    TCGv_ptr ptr1;
    TCGv_i32 tmp2_i32;
    TCGv_i32 tmp3_i32;
    TCGv_i64 tmp1_i64;

    sigjmp_buf jmpbuf;

    // Unicorn
    struct uc_struct *uc;
    target_ulong prev_pc; /* save address of the previous instruction */
} DisasContext;

static void gen_eob(DisasContext *s);
static void gen_jr(DisasContext *s, TCGv dest);
static void gen_jmp(DisasContext *s, target_ulong eip);
static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num);
static void gen_op(DisasContext *s, int op, MemOp ot, int d);

/* i386 arith/logic operations */
enum {
    OP_ADDL,
    OP_ORL,
    OP_ADCL,
    OP_SBBL,
    OP_ANDL,
    OP_SUBL,
    OP_XORL,
    OP_CMPL,
};

/* i386 shift ops */
enum {
    OP_ROL,
    OP_ROR,
    OP_RCL,
    OP_RCR,
    OP_SHL,
    OP_SHR,
    OP_SHL1, /* undocumented */
    OP_SAR = 7,
};

enum {
    JCC_O,
    JCC_B,
    JCC_Z,
    JCC_BE,
    JCC_S,
    JCC_P,
    JCC_L,
    JCC_LE,
};

enum {
    /* I386 int registers */
    OR_EAX,   /* MUST be even numbered */
    OR_ECX,
    OR_EDX,
    OR_EBX,
    OR_ESP,
    OR_EBP,
    OR_ESI,
    OR_EDI,

    OR_TMP0 = 16,    /* temporary operand register */
    OR_TMP1,
    OR_A0, /* temporary register used when doing address evaluation */
};

enum {
    USES_CC_DST  = 1,
    USES_CC_SRC  = 2,
    USES_CC_SRC2 = 4,
    USES_CC_SRCT = 8,
};

/* Bit set if the global variable is live after setting CC_OP to X.  */
static const uint8_t cc_op_live[CC_OP_NB] = {
    [CC_OP_DYNAMIC] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_EFLAGS] = USES_CC_SRC,

    [CC_OP_MULB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_MULW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_MULL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_MULQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_ADDB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_ADCB] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCW] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCL] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,

    [CC_OP_SUBB] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SUBW] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SUBL] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SUBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,

    [CC_OP_SBBB] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SBBW] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SBBL] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SBBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,

    [CC_OP_LOGICB] = USES_CC_DST,
    [CC_OP_LOGICW] = USES_CC_DST,
    [CC_OP_LOGICL] = USES_CC_DST,
    [CC_OP_LOGICQ] = USES_CC_DST,

    [CC_OP_INCB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_INCW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_INCL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_INCQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_DECB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_SHLB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_SARB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_BMILGB] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGW] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGL] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGQ] = USES_CC_DST | USES_CC_SRC,

    [CC_OP_ADCX] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADOX] = USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCOX] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_CLR] = 0,
    [CC_OP_POPCNT] = USES_CC_SRC,
};

static inline void gen_jmp_im(DisasContext *s, target_ulong pc);

static void set_cc_op(DisasContext *s, CCOp op)
{
    int dead;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_cc_dst = tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = tcg_ctx->cpu_cc_src2;

    if (s->cc_op == op) {
        return;
    }

    /* Discard CC computation that will no longer be used.  */
    dead = cc_op_live[s->cc_op] & ~cc_op_live[op];
    if (dead & USES_CC_DST) {
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_dst);
    }
    if (dead & USES_CC_SRC) {
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_src);
    }
    if (dead & USES_CC_SRC2) {
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_src2);
    }
    if (dead & USES_CC_SRCT) {
        tcg_gen_discard_tl(tcg_ctx, s->cc_srcT);
    }

    if (op == CC_OP_DYNAMIC) {
        /* The DYNAMIC setting is translator only, and should never be
           stored.  Thus we always consider it clean.  */
        s->cc_op_dirty = false;
    } else {
        /* Discard any computed CC_OP value (see shifts).  */
        if (s->cc_op == CC_OP_DYNAMIC) {
            tcg_gen_discard_i32(tcg_ctx, cpu_cc_op);
        }
        s->cc_op_dirty = true;
    }
    s->cc_op = op;
}

static void gen_update_cc_op(DisasContext *s)
{
    if (s->cc_op_dirty) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;

        tcg_gen_movi_i32(tcg_ctx, cpu_cc_op, s->cc_op);
        s->cc_op_dirty = false;
    }
}

#ifdef TARGET_X86_64

#define NB_OP_SIZES 4

#else /* !TARGET_X86_64 */

#define NB_OP_SIZES 3

#endif /* !TARGET_X86_64 */

#if defined(HOST_WORDS_BIGENDIAN)
#define REG_B_OFFSET (sizeof(target_ulong) - 1)
#define REG_H_OFFSET (sizeof(target_ulong) - 2)
#define REG_W_OFFSET (sizeof(target_ulong) - 2)
#define REG_L_OFFSET (sizeof(target_ulong) - 4)
#define REG_LH_OFFSET (sizeof(target_ulong) - 8)
#else
#define REG_B_OFFSET 0
#define REG_H_OFFSET 1
#define REG_W_OFFSET 0
#define REG_L_OFFSET 0
#define REG_LH_OFFSET 4
#endif

/* In instruction encodings for byte register accesses the
 * register number usually indicates "low 8 bits of register N";
 * however there are some special cases where N 4..7 indicates
 * [AH, CH, DH, BH], ie "bits 15..8 of register N-4". Return
 * true for this special case, false otherwise.
 */
static inline bool byte_reg_is_xH(DisasContext *s, int reg)
{
    if (reg < 4) {
        return false;
    }
#ifdef TARGET_X86_64
    if (reg >= 8 || s->x86_64_hregs) {
        return false;
    }
#endif
    return true;
}

/* Select the size of a push/pop operation.  */
static inline MemOp mo_pushpop(DisasContext *s, MemOp ot)
{
    if (CODE64(s)) {
        return ot == MO_16 ? MO_16 : MO_64;
    } else {
        return ot;
    }
}

/* Select the size of the stack pointer.  */
static inline MemOp mo_stacksize(DisasContext *s)
{
    return CODE64(s) ? MO_64 : s->ss32 ? MO_32 : MO_16;
}

/* Select only size 64 else 32.  Used for SSE operand sizes.  */
static inline MemOp mo_64_32(MemOp ot)
{
#ifdef TARGET_X86_64
    return ot == MO_64 ? MO_64 : MO_32;
#else
    return MO_32;
#endif
}

/* Select size 8 if lsb of B is clear, else OT.  Used for decoding
   byte vs word opcodes.  */
static inline MemOp mo_b_d(int b, MemOp ot)
{
    return b & 1 ? ot : MO_8;
}

/* Select size 8 if lsb of B is clear, else OT capped at 32.
   Used for decoding operand size of port opcodes.  */
static inline MemOp mo_b_d32(int b, MemOp ot)
{
    return b & 1 ? (ot == MO_16 ? MO_16 : MO_32) : MO_8;
}

static void gen_op_mov_reg_v(DisasContext *s, MemOp ot, int reg, TCGv t0)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch(ot) {
    case MO_8:
        if (!byte_reg_is_xH(s, reg)) {
            tcg_gen_deposit_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], tcg_ctx->cpu_regs[reg], t0, 0, 8);
        } else {
            tcg_gen_deposit_tl(tcg_ctx, tcg_ctx->cpu_regs[reg - 4], tcg_ctx->cpu_regs[reg - 4], t0, 8, 8);
        }
        break;
    case MO_16:
        tcg_gen_deposit_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], tcg_ctx->cpu_regs[reg], t0, 0, 16);
        break;
    case MO_32:
        /* For x86_64, this sets the higher half of register to zero.
           For i386, this is equivalent to a mov. */
        tcg_gen_ext32u_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], t0);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], t0);
        break;
#endif
    default:
        tcg_abort();
    }
}

static inline
void gen_op_mov_v_reg(DisasContext *s, MemOp ot, TCGv t0, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (ot == MO_8 && byte_reg_is_xH(s, reg)) {
        tcg_gen_extract_tl(tcg_ctx, t0, tcg_ctx->cpu_regs[reg - 4], 8, 8);
    } else {
        tcg_gen_mov_tl(tcg_ctx, t0, tcg_ctx->cpu_regs[reg]);
    }
}

static void gen_add_A0_im(DisasContext *s, int val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, val);
    if (!CODE64(s)) {
        tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
    }
}

static inline void gen_op_jmp_v(TCGContext *tcg_ctx, TCGv dest)
{
    tcg_gen_st_tl(tcg_ctx, dest, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));
}

static inline
void gen_op_add_reg_im(DisasContext *s, MemOp size, int reg, int32_t val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_addi_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[reg], val);
    gen_op_mov_reg_v(s, size, reg, s->tmp0);
}

static inline void gen_op_add_reg_T0(DisasContext *s, MemOp size, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_add_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[reg], s->T0);
    gen_op_mov_reg_v(s, size, reg, s->tmp0);
}

static inline void gen_op_ld_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (HOOK_EXISTS(s->uc, UC_HOOK_MEM_READ))
        gen_jmp_im(s, s->prev_pc); // Unicorn: sync EIP

    tcg_gen_qemu_ld_tl(tcg_ctx, t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (HOOK_EXISTS(s->uc, UC_HOOK_MEM_WRITE))
        gen_jmp_im(s, s->prev_pc); // Unicorn: sync EIP

    tcg_gen_qemu_st_tl(tcg_ctx, t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_rm_T0_A0(DisasContext *s, int idx, int d)
{
    if (d == OR_TMP0) {
        gen_op_st_v(s, idx, s->T0, s->A0);
    } else {
        gen_op_mov_reg_v(s, idx, d, s->T0);
    }
}

static inline void gen_jmp_im(DisasContext *s, target_ulong pc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_movi_tl(tcg_ctx, s->tmp0, pc);
    gen_op_jmp_v(tcg_ctx, s->tmp0);
}

/* Compute SEG:REG into A0.  SEG is selected from the override segment
   (OVR_SEG) and the default segment (DEF_SEG).  OVR_SEG may be -1 to
   indicate no override.  */
static void gen_lea_v_seg(DisasContext *s, MemOp aflag, TCGv a0,
                          int def_seg, int ovr_seg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        if (ovr_seg < 0) {
            tcg_gen_mov_tl(tcg_ctx, s->A0, a0);
            return;
        }
        break;
#endif
    case MO_32:
        /* 32 bit address */
        if (ovr_seg < 0 && s->addseg) {
            ovr_seg = def_seg;
        }
        if (ovr_seg < 0) {
            tcg_gen_ext32u_tl(tcg_ctx, s->A0, a0);
            return;
        }
        break;
    case MO_16:
        /* 16 bit address */
        tcg_gen_ext16u_tl(tcg_ctx, s->A0, a0);
        a0 = s->A0;
        if (ovr_seg < 0) {
            if (s->addseg) {
                ovr_seg = def_seg;
            } else {
                return;
            }
        }
        break;
    default:
        tcg_abort();
    }

    if (ovr_seg >= 0) {
        TCGv seg = tcg_ctx->cpu_seg_base[ovr_seg];

        if (aflag == MO_64) {
            tcg_gen_add_tl(tcg_ctx, s->A0, a0, seg);
        } else if (CODE64(s)) {
            tcg_gen_ext32u_tl(tcg_ctx, s->A0, a0);
            tcg_gen_add_tl(tcg_ctx, s->A0, s->A0, seg);
        } else {
            tcg_gen_add_tl(tcg_ctx, s->A0, a0, seg);
            tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
        }
    }
}

static inline void gen_string_movl_A0_ESI(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_lea_v_seg(s, s->aflag, tcg_ctx->cpu_regs[R_ESI], R_DS, s->override);
}

static inline void gen_string_movl_A0_EDI(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_lea_v_seg(s, s->aflag, tcg_ctx->cpu_regs[R_EDI], R_ES, -1);
}

static inline void gen_op_movl_T0_Dshift(DisasContext *s, MemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_ld32s_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, df));
    tcg_gen_shli_tl(tcg_ctx, s->T0, s->T0, ot);
};

static TCGv gen_ext_tl(TCGContext *tcg_ctx, TCGv dst, TCGv src, MemOp size, bool sign)
{
    switch (size) {
    case MO_8:
        if (sign) {
            tcg_gen_ext8s_tl(tcg_ctx, dst, src);
        } else {
            tcg_gen_ext8u_tl(tcg_ctx, dst, src);
        }
        return dst;
    case MO_16:
        if (sign) {
            tcg_gen_ext16s_tl(tcg_ctx, dst, src);
        } else {
            tcg_gen_ext16u_tl(tcg_ctx, dst, src);
        }
        return dst;
#ifdef TARGET_X86_64
    case MO_32:
        if (sign) {
            tcg_gen_ext32s_tl(tcg_ctx, dst, src);
        } else {
            tcg_gen_ext32u_tl(tcg_ctx, dst, src);
        }
        return dst;
#endif
    default:
        return src;
    }
}

static void gen_extu(TCGContext *tcg_ctx, MemOp ot, TCGv reg)
{
    gen_ext_tl(tcg_ctx, reg, reg, ot, false);
}

static void gen_exts(TCGContext *tcg_ctx, MemOp ot, TCGv reg)
{
    gen_ext_tl(tcg_ctx, reg, reg, ot, true);
}

static inline
void gen_op_jnz_ecx(DisasContext *s, MemOp size, TCGLabel *label1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[R_ECX]);
    gen_extu(tcg_ctx, size, s->tmp0);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_NE, s->tmp0, 0, label1);
}

static inline
void gen_op_jz_ecx(DisasContext *s, MemOp size, TCGLabel *label1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_regs[R_ECX]);
    gen_extu(tcg_ctx, size, s->tmp0);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, s->tmp0, 0, label1);
}

static void gen_helper_in_func(TCGContext *tcg_ctx, MemOp ot, TCGv v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_inb(tcg_ctx, v, tcg_ctx->cpu_env, n);
        break;
    case MO_16:
        gen_helper_inw(tcg_ctx, v, tcg_ctx->cpu_env, n);
        break;
    case MO_32:
        gen_helper_inl(tcg_ctx, v, tcg_ctx->cpu_env, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_helper_out_func(TCGContext *tcg_ctx, MemOp ot, TCGv_i32 v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_outb(tcg_ctx, tcg_ctx->cpu_env, v, n);
        break;
    case MO_16:
        gen_helper_outw(tcg_ctx, tcg_ctx->cpu_env, v, n);
        break;
    case MO_32:
        gen_helper_outl(tcg_ctx, tcg_ctx->cpu_env, v, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_check_io(DisasContext *s, MemOp ot, target_ulong cur_eip,
                         uint32_t svm_flags)
{
    // Unicorn: allow all I/O instructions
    return;

    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong next_eip;

    if (s->pe && (s->cpl > s->iopl || s->vm86)) {
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        switch (ot) {
        case MO_8:
            gen_helper_check_iob(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;
        case MO_16:
            gen_helper_check_iow(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;
        case MO_32:
            gen_helper_check_iol(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;
        default:
            tcg_abort();
        }
    }
    if(s->flags & HF_GUEST_MASK) {
        gen_update_cc_op(s);
        gen_jmp_im(s, cur_eip);
        svm_flags |= (1 << (4 + ot));
        next_eip = s->pc - s->cs_base;
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        gen_helper_svm_check_io(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32,
                                tcg_const_i32(tcg_ctx, svm_flags),
                                tcg_const_i32(tcg_ctx, next_eip - cur_eip));
    }
}

static inline void gen_movs(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static void gen_op_update1_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
}

static void gen_op_update2_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T1);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
}

static void gen_op_update3_cc(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, reg);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T1);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
}

static inline void gen_op_testl_T0_T1_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_and_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, s->T1);
}

static void gen_op_update_neg_cc(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
    tcg_gen_neg_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
    tcg_gen_movi_tl(tcg_ctx, s->cc_srcT, 0);
}

/* compute all eflags to cc_src */
static void gen_compute_eflags(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv zero, dst, src1, src2;
    int live, dead;

    if (s->cc_op == CC_OP_EFLAGS) {
        return;
    }
    if (s->cc_op == CC_OP_CLR) {
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, CC_Z | CC_P);
        set_cc_op(s, CC_OP_EFLAGS);
        return;
    }

    zero = NULL;
    dst = tcg_ctx->cpu_cc_dst;
    src1 = tcg_ctx->cpu_cc_src;
    src2 = tcg_ctx->cpu_cc_src2;

    /* Take care to not read values that are not live.  */
    live = cc_op_live[s->cc_op] & ~USES_CC_SRCT;
    dead = live ^ (USES_CC_DST | USES_CC_SRC | USES_CC_SRC2);
    if (dead) {
        zero = tcg_const_tl(tcg_ctx, 0);
        if (dead & USES_CC_DST) {
            dst = zero;
        }
        if (dead & USES_CC_SRC) {
            src1 = zero;
        }
        if (dead & USES_CC_SRC2) {
            src2 = zero;
        }
    }

    gen_update_cc_op(s);
    gen_helper_cc_compute_all(tcg_ctx, tcg_ctx->cpu_cc_src, dst, src1, src2, tcg_ctx->cpu_cc_op);
    set_cc_op(s, CC_OP_EFLAGS);

    if (dead) {
        tcg_temp_free(tcg_ctx, zero);
    }
}

typedef struct CCPrepare {
    TCGCond cond;
    TCGv reg;
    TCGv reg2;
    target_ulong imm;
    target_ulong mask;
    bool use_reg2;
    bool no_setcond;
} CCPrepare;

/* compute eflags.C to reg */
static CCPrepare gen_prepare_eflags_c(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv t0, t1;
    int size, shift;

    switch (s->cc_op) {
    case CC_OP_SUBB:
    case CC_OP_SUBW:
    case CC_OP_SUBL:
    case CC_OP_SUBQ:
        /* (DATA_TYPE)CC_SRCT < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_SUBB;
        t1 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, false);
        /* If no temporary was used, be careful not to alias t1 and t0.  */
        t0 = t1 == tcg_ctx->cpu_cc_src ? s->tmp0 : reg;
        tcg_gen_mov_tl(tcg_ctx, t0, s->cc_srcT);
        gen_extu(tcg_ctx, size, t0);
        goto add_sub;

    case CC_OP_ADDB:
    case CC_OP_ADDW:
    case CC_OP_ADDL:
    case CC_OP_ADDQ:
        /* (DATA_TYPE)CC_DST < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_ADDB;
        t1 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, false);
        t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, size, false);
    add_sub:
        return (CCPrepare) { .cond = TCG_COND_LTU, .reg = t0,
                             .reg2 = t1, .mask = -1, .use_reg2 = true };

    case CC_OP_LOGICB:
    case CC_OP_LOGICW:
    case CC_OP_LOGICL:
    case CC_OP_LOGICQ:
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = -1 };

    case CC_OP_INCB:
    case CC_OP_INCW:
    case CC_OP_INCL:
    case CC_OP_INCQ:

    case CC_OP_DECB:
    case CC_OP_DECW:
    case CC_OP_DECL:
    case CC_OP_DECQ:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = -1, .no_setcond = true };

    case CC_OP_SHLB:
    case CC_OP_SHLW:
    case CC_OP_SHLL:
    case CC_OP_SHLQ:
        /* (CC_SRC >> (DATA_BITS - 1)) & 1 */
        size = s->cc_op - CC_OP_SHLB;
        shift = (8 << size) - 1;
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = (target_ulong)1 << shift };

    case CC_OP_MULB:
    case CC_OP_MULW:
    case CC_OP_MULL:
    case CC_OP_MULQ:
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = tcg_ctx->cpu_cc_src, .mask = -1 };

    case CC_OP_BMILGB:
    case CC_OP_BMILGW:
    case CC_OP_BMILGL:
    case CC_OP_BMILGQ:
        size = s->cc_op - CC_OP_BMILGB;
        t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_src, size, false);
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = t0, .mask = -1 };

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_dst,
                             .mask = -1, .no_setcond = true };

    case CC_OP_EFLAGS:
    case CC_OP_SARB:
    case CC_OP_SARW:
    case CC_OP_SARL:
    case CC_OP_SARQ:
        /* CC_SRC & 1 */
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = tcg_ctx->cpu_cc_src, .mask = CC_C };

    default:
       /* The need to compute only C from CC_OP_DYNAMIC is important
          in efficiently implementing e.g. INC at the start of a TB.  */
       gen_update_cc_op(s);
       gen_helper_cc_compute_c(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_cc_src,
                               tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_op);
       return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                            .mask = -1, .no_setcond = true };
    }
}

/* compute eflags.P to reg */
static CCPrepare gen_prepare_eflags_p(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_compute_eflags(s);
    return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                         .mask = CC_P };
}

/* compute eflags.S to reg */
static CCPrepare gen_prepare_eflags_s(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = CC_S };
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = -1 };
    default:
        {
            MemOp size = (s->cc_op - CC_OP_ADDB) & 3;
            TCGv t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, size, true);
            return (CCPrepare) { .cond = TCG_COND_LT, .reg = t0, .mask = -1 };
        }
    }
}

/* compute eflags.O to reg */
static CCPrepare gen_prepare_eflags_o(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (s->cc_op) {
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src2,
                             .mask = -1, .no_setcond = true };
    case CC_OP_CLR:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER, .mask = -1 };
    default:
        gen_compute_eflags(s);
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = CC_O };
    }
}

/* compute eflags.Z to reg */
static CCPrepare gen_prepare_eflags_z(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                             .mask = CC_Z };
    case CC_OP_CLR:
        return (CCPrepare) { .cond = TCG_COND_ALWAYS, .mask = -1 };
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = tcg_ctx->cpu_cc_src,
                             .mask = -1 };
    default:
        {
            MemOp size = (s->cc_op - CC_OP_ADDB) & 3;
            TCGv t0 = gen_ext_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_dst, size, false);
            return (CCPrepare) { .cond = TCG_COND_EQ, .reg = t0, .mask = -1 };
        }
    }
}

/* perform a conditional store into register 'reg' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
static CCPrepare gen_prepare_cc(DisasContext *s, int b, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int inv, jcc_op, cond;
    MemOp size;
    CCPrepare cc;
    TCGv t0;

    inv = b & 1;
    jcc_op = (b >> 1) & 7;

    switch (s->cc_op) {
    case CC_OP_SUBB:
    case CC_OP_SUBW:
    case CC_OP_SUBL:
    case CC_OP_SUBQ:
        /* We optimize relational operators for the cmp/jcc case.  */
        size = s->cc_op - CC_OP_SUBB;
        switch (jcc_op) {
        case JCC_BE:
            tcg_gen_mov_tl(tcg_ctx, s->tmp4, s->cc_srcT);
            gen_extu(tcg_ctx, size, s->tmp4);
            t0 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, false);
            cc = (CCPrepare) { .cond = TCG_COND_LEU, .reg = s->tmp4,
                               .reg2 = t0, .mask = -1, .use_reg2 = true };
            break;

        case JCC_L:
            cond = TCG_COND_LT;
            goto fast_jcc_l;
        case JCC_LE:
            cond = TCG_COND_LE;
        fast_jcc_l:
            tcg_gen_mov_tl(tcg_ctx, s->tmp4, s->cc_srcT);
            gen_exts(tcg_ctx, size, s->tmp4);
            t0 = gen_ext_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, size, true);
            cc = (CCPrepare) { .cond = cond, .reg = s->tmp4,
                               .reg2 = t0, .mask = -1, .use_reg2 = true };
            break;

        default:
            goto slow_jcc;
        }
        break;

    default:
    slow_jcc:
        /* This actually generates good code for JC, JZ and JS.  */
        switch (jcc_op) {
        case JCC_O:
            cc = gen_prepare_eflags_o(s, reg);
            break;
        case JCC_B:
            cc = gen_prepare_eflags_c(s, reg);
            break;
        case JCC_Z:
            cc = gen_prepare_eflags_z(s, reg);
            break;
        case JCC_BE:
            gen_compute_eflags(s);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = tcg_ctx->cpu_cc_src,
                               .mask = CC_Z | CC_C };
            break;
        case JCC_S:
            cc = gen_prepare_eflags_s(s, reg);
            break;
        case JCC_P:
            cc = gen_prepare_eflags_p(s, reg);
            break;
        case JCC_L:
            gen_compute_eflags(s);
            if (reg == tcg_ctx->cpu_cc_src) {
                reg = s->tmp0;
            }
            tcg_gen_shri_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_src, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(tcg_ctx, reg, reg, tcg_ctx->cpu_cc_src);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_S };
            break;
        default:
        case JCC_LE:
            gen_compute_eflags(s);
            if (reg == tcg_ctx->cpu_cc_src) {
                reg = s->tmp0;
            }
            tcg_gen_shri_tl(tcg_ctx, reg, tcg_ctx->cpu_cc_src, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(tcg_ctx, reg, reg, tcg_ctx->cpu_cc_src);
            cc = (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                               .mask = CC_S | CC_Z };
            break;
        }
        break;
    }

    if (inv) {
        cc.cond = tcg_invert_cond(cc.cond);
    }
    return cc;
}

static void gen_setcc1(DisasContext *s, int b, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc = gen_prepare_cc(s, b, reg);

    if (cc.no_setcond) {
        if (cc.cond == TCG_COND_EQ) {
            tcg_gen_xori_tl(tcg_ctx, reg, cc.reg, 1);
        } else {
            tcg_gen_mov_tl(tcg_ctx, reg, cc.reg);
        }
        return;
    }

    if (cc.cond == TCG_COND_NE && !cc.use_reg2 && cc.imm == 0 &&
        cc.mask != 0 && (cc.mask & (cc.mask - 1)) == 0) {
        tcg_gen_shri_tl(tcg_ctx, reg, cc.reg, ctztl(cc.mask));
        tcg_gen_andi_tl(tcg_ctx, reg, reg, 1);
        return;
    }
    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, reg, cc.reg, cc.mask);
        cc.reg = reg;
    }
    if (cc.use_reg2) {
        tcg_gen_setcond_tl(tcg_ctx, cc.cond, reg, cc.reg, cc.reg2);
    } else {
        tcg_gen_setcondi_tl(tcg_ctx, cc.cond, reg, cc.reg, cc.imm);
    }
}

static inline void gen_compute_eflags_c(DisasContext *s, TCGv reg)
{
    gen_setcc1(s, JCC_B << 1, reg);
}

/* generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
static inline void gen_jcc1_noeob(DisasContext *s, int b, TCGLabel *l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc = gen_prepare_cc(s, b, s->T0);

    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, s->T0, cc.reg, cc.mask);
        cc.reg = s->T0;
    }
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(tcg_ctx, cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(tcg_ctx, cc.cond, cc.reg, cc.imm, l1);
    }
}

/* Generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used.
   A translation block must end soon.  */
static inline void gen_jcc1(DisasContext *s, int b, TCGLabel *l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc = gen_prepare_cc(s, b, s->T0);

    gen_update_cc_op(s);
    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, s->T0, cc.reg, cc.mask);
        cc.reg = s->T0;
    }
    set_cc_op(s, CC_OP_DYNAMIC);
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(tcg_ctx, cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(tcg_ctx, cc.cond, cc.reg, cc.imm, l1);
    }
}

/* XXX: does not work with gdbstub "ice" single step - not a
   serious problem */
static TCGLabel *gen_jz_ecx_string(DisasContext *s, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGLabel *l1 = gen_new_label(tcg_ctx);
    TCGLabel *l2 = gen_new_label(tcg_ctx);
    gen_op_jnz_ecx(s, s->aflag, l1);
    gen_set_label(tcg_ctx, l2);
    gen_jmp_tb(s, next_eip, 1);
    gen_set_label(tcg_ctx, l1);
    return l2;
}

static inline void gen_stos(DisasContext *s, MemOp ot)
{
    gen_op_mov_v_reg(s, MO_32, s->T0, R_EAX);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static inline void gen_lods(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_op_mov_reg_v(s, ot, R_EAX, s->T0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
}

static inline void gen_scas(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, s->T1, s->A0);
    gen_op(s, OP_CMPL, ot, R_EAX);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static inline void gen_cmps(DisasContext *s, MemOp ot)
{
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, s->T1, s->A0);
    gen_string_movl_A0_ESI(s);
    gen_op(s, OP_CMPL, ot, OR_TMP0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
}

static void gen_bpt_io(DisasContext *s, TCGv_i32 t_port, int ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (s->flags & HF_IOBPT_MASK) {
        TCGv_i32 t_size = tcg_const_i32(tcg_ctx, 1 << ot);
        TCGv t_next = tcg_const_tl(tcg_ctx, s->pc - s->cs_base);

        gen_helper_bpt_io(tcg_ctx, tcg_ctx->cpu_env, t_port, t_size, t_next);
        tcg_temp_free_i32(tcg_ctx, t_size);
        tcg_temp_free(tcg_ctx, t_next);
    }
}


static inline void gen_ins(DisasContext *s, MemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_string_movl_A0_EDI(s);
    /* Note: we must do this dummy write first to be restartable in
       case of page fault. */
    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
    gen_op_st_v(s, ot, s->T0, s->A0);
    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_EDX]);
    tcg_gen_andi_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 0xffff);
    gen_helper_in_func(tcg_ctx, ot, s->T0, s->tmp2_i32);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_EDI);
    gen_bpt_io(s, s->tmp2_i32, ot);
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
    }
}

static inline void gen_outs(DisasContext *s, MemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_start(tcg_ctx);
    }
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);

    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_EDX]);
    tcg_gen_andi_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 0xffff);
    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T0);
    gen_helper_out_func(tcg_ctx, ot, s->tmp2_i32, s->tmp3_i32);
    gen_op_movl_T0_Dshift(s, ot);
    gen_op_add_reg_T0(s, s->aflag, R_ESI);
    gen_bpt_io(s, s->tmp2_i32, ot);
    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
        gen_io_end(tcg_ctx);
    }
}

/* same method as Valgrind : we generate jumps to current or next
   instruction */
#define GEN_REPZ(op)                                                          \
static inline void gen_repz_ ## op(DisasContext *s, MemOp ot,              \
                                 target_ulong cur_eip, target_ulong next_eip) \
{                                                                             \
    TCGLabel *l2;                                                             \
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s, s->aflag, R_ECX, -1);                                \
    /* a loop would cause two single step exceptions if ECX = 1               \
       before rep string_insn */                                              \
    if (s->repz_opt)                                                          \
        gen_op_jz_ecx(s, s->aflag, l2);                                       \
    gen_jmp(s, cur_eip);                                                      \
}

#define GEN_REPZ2(op)                                                         \
static inline void gen_repz_ ## op(DisasContext *s, MemOp ot,              \
                                   target_ulong cur_eip,                      \
                                   target_ulong next_eip,                     \
                                   int nz)                                    \
{                                                                             \
    TCGLabel *l2;                                                             \
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s, s->aflag, R_ECX, -1);                                \
    gen_update_cc_op(s);                                                      \
    gen_jcc1(s, (JCC_Z << 1) | (nz ^ 1), l2);                                 \
    if (s->repz_opt)                                                          \
        gen_op_jz_ecx(s, s->aflag, l2);                                       \
    gen_jmp(s, cur_eip);                                                      \
}

GEN_REPZ(movs)
GEN_REPZ(stos)
GEN_REPZ(lods)
GEN_REPZ(ins)
GEN_REPZ(outs)
GEN_REPZ2(scas)
GEN_REPZ2(cmps)

static void gen_helper_fp_arith_ST0_FT0(TCGContext *tcg_ctx, int op)
{
    switch (op) {
    case 0:
        gen_helper_fadd_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 1:
        gen_helper_fmul_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 2:
        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 3:
        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 4:
        gen_helper_fsub_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 5:
        gen_helper_fsubr_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 6:
        gen_helper_fdiv_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 7:
        gen_helper_fdivr_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
        break;
    }
}

/* NOTE the exception in "r" op ordering */
static void gen_helper_fp_arith_STN_ST0(TCGContext *tcg_ctx, int op, int opreg)
{
    TCGv_i32 tmp = tcg_const_i32(tcg_ctx, opreg);
    switch (op) {
    case 0:
        gen_helper_fadd_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 1:
        gen_helper_fmul_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 4:
        gen_helper_fsubr_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 5:
        gen_helper_fsub_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 6:
        gen_helper_fdivr_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    case 7:
        gen_helper_fdiv_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tmp);
        break;
    }
}

static void gen_exception(DisasContext *s, int trapno, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, trapno));
    s->base.is_jmp = DISAS_NORETURN;
}

/* Generate #UD for the current instruction.  The assumption here is that
   the instruction is known, but it isn't allowed in the current cpu mode.  */
static void gen_illegal_opcode(DisasContext *s)
{
    gen_exception(s, EXCP06_ILLOP, s->pc_start - s->cs_base);
}

/* if d == OR_TMP0, it means memory operand (address in A0) */
static void gen_op(DisasContext *s1, int op, MemOp ot, int d)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;
    uc_engine *uc = s1->uc;

    if (d != OR_TMP0) {
        if (s1->prefix & PREFIX_LOCK) {
            /* Lock prefix when destination is not memory.  */
            gen_illegal_opcode(s1);
            return;
        }
        gen_op_mov_v_reg(s1, ot, s1->T0, d);
    } else if (!(s1->prefix & PREFIX_LOCK)) {
        gen_op_ld_v(s1, ot, s1->T0, s1->A0);
    }
    switch(op) {
    case OP_ADCL:
        gen_compute_eflags_c(s1, s1->tmp4);
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->tmp4, s1->T1);
            tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T0,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T0, s1->tmp4);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update3_cc(s1, s1->tmp4);
        set_cc_op(s1, CC_OP_ADCB + ot);
        break;
    case OP_SBBL:
        gen_compute_eflags_c(s1, s1->tmp4);
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T1, s1->tmp4);
            tcg_gen_neg_tl(tcg_ctx, s1->T0, s1->T0);
            tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T0,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->T0, s1->tmp4);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update3_cc(s1, s1->tmp4);
        set_cc_op(s1, CC_OP_SBBB + ot);
        break;
    case OP_ADDL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_add_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update2_cc(s1);
        set_cc_op(s1, CC_OP_ADDB + ot);
        break;
    case OP_SUBL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_neg_tl(tcg_ctx, s1->T0, s1->T1);
            tcg_gen_atomic_fetch_add_tl(tcg_ctx, s1->cc_srcT, s1->A0, s1->T0,
                                        s1->mem_index, ot | MO_LE);
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->cc_srcT, s1->T1);
        } else {
            tcg_gen_mov_tl(tcg_ctx, s1->cc_srcT, s1->T0);
            tcg_gen_sub_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        
        if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_TCG_OPCODE, s1->pc_start)) {
            struct hook *hook;
            HOOK_FOREACH_VAR_DECLARE;
            HOOK_FOREACH(uc, hook, UC_HOOK_TCG_OPCODE) {
                if (hook->to_delete)
                    continue;
                if (hook->op == UC_TCG_OP_SUB && (hook->op_flags & UC_TCG_OP_FLAG_DIRECT) ) {
                    // TCGv is just an offset to tcg_ctx so it's safe to do so.
                    gen_uc_traceopcode(tcg_ctx, hook, (TCGv_i64)s1->T0, (TCGv_i64)s1->T1, 1 << ((ot & MO_SIZE) + 3), uc, s1->pc_start);
                }
            }
        }

        gen_op_update2_cc(s1);
        set_cc_op(s1, CC_OP_SUBB + ot);
        break;
    default:
    case OP_ANDL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_and_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_and_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc(s1);
        set_cc_op(s1, CC_OP_LOGICB + ot);
        break;
    case OP_ORL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_or_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                       s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_or_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc(s1);
        set_cc_op(s1, CC_OP_LOGICB + ot);
        break;
    case OP_XORL:
        if (s1->prefix & PREFIX_LOCK) {
            tcg_gen_atomic_xor_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T1,
                                        s1->mem_index, ot | MO_LE);
        } else {
            tcg_gen_xor_tl(tcg_ctx, s1->T0, s1->T0, s1->T1);
            gen_op_st_rm_T0_A0(s1, ot, d);
        }
        gen_op_update1_cc(s1);
        set_cc_op(s1, CC_OP_LOGICB + ot);
        break;
    case OP_CMPL:
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s1->T1);
        tcg_gen_mov_tl(tcg_ctx, s1->cc_srcT, s1->T0);
        tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s1->T0, s1->T1);

        if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_TCG_OPCODE, s1->pc_start)) {
            struct hook *hook;
            HOOK_FOREACH_VAR_DECLARE;
            HOOK_FOREACH(uc, hook, UC_HOOK_TCG_OPCODE) {
                if (hook->to_delete)
                    continue;
                if (hook->op == UC_TCG_OP_SUB && (hook->op_flags & UC_TCG_OP_FLAG_CMP) ) {
                    // TCGv is just an offset to tcg_ctx so it's safe to do so.
                    gen_uc_traceopcode(tcg_ctx, hook, (TCGv_i64)s1->T0, (TCGv_i64)s1->T1, 1 << ((ot & MO_SIZE) + 3), uc, s1->pc_start);
                }
            }
        }

        set_cc_op(s1, CC_OP_SUBB + ot);
        break;
    }
}

/* if d == OR_TMP0, it means memory operand (address in A0) */
static void gen_inc(DisasContext *s1, MemOp ot, int d, int c)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;

    if (s1->prefix & PREFIX_LOCK) {
        if (d != OR_TMP0) {
            /* Lock prefix when destination is not memory */
            gen_illegal_opcode(s1);
            return;
        }
        tcg_gen_movi_tl(tcg_ctx, s1->T0, c > 0 ? 1 : -1);
        tcg_gen_atomic_add_fetch_tl(tcg_ctx, s1->T0, s1->A0, s1->T0,
                                    s1->mem_index, ot | MO_LE);
    } else {
        if (d != OR_TMP0) {
            gen_op_mov_v_reg(s1, ot, s1->T0, d);
        } else {
            gen_op_ld_v(s1, ot, s1->T0, s1->A0);
        }
        tcg_gen_addi_tl(tcg_ctx, s1->T0, s1->T0, (c > 0 ? 1 : -1));
        gen_op_st_rm_T0_A0(s1, ot, d);
    }

    gen_compute_eflags_c(s1, tcg_ctx->cpu_cc_src);
    tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s1->T0);
    set_cc_op(s1, (c > 0 ? CC_OP_INCB : CC_OP_DECB) + ot);
}

static void gen_shift_flags(DisasContext *s, MemOp ot, TCGv result,
                            TCGv shm1, TCGv count, bool is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 z32, s32, oldop;
    TCGv z_tl;

    /* Store the results into the CC variables.  If we know that the
       variable must be dead, store unconditionally.  Otherwise we'll
       need to not disrupt the current contents.  */
    z_tl = tcg_const_tl(tcg_ctx, 0);
    if (cc_op_live[s->cc_op] & USES_CC_DST) {
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_dst, count, z_tl,
                           result, tcg_ctx->cpu_cc_dst);
    } else {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, result);
    }
    if (cc_op_live[s->cc_op] & USES_CC_SRC) {
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_src, count, z_tl,
                           shm1, tcg_ctx->cpu_cc_src);
    } else {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, shm1);
    }
    tcg_temp_free(tcg_ctx, z_tl);

    /* Get the two potential CC_OP values into temporaries.  */
    tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    if (s->cc_op == CC_OP_DYNAMIC) {
        oldop = tcg_ctx->cpu_cc_op;
    } else {
        tcg_gen_movi_i32(tcg_ctx, s->tmp3_i32, s->cc_op);
        oldop = s->tmp3_i32;
    }

    /* Conditionally store the CC_OP value.  */
    z32 = tcg_const_i32(tcg_ctx, 0);
    s32 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, s32, count);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_op, s32, z32, s->tmp2_i32, oldop);
    tcg_temp_free_i32(tcg_ctx, z32);
    tcg_temp_free_i32(tcg_ctx, s32);

    /* The CC_OP value is no longer predictable.  */
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_shift_rm_T1(DisasContext *s, MemOp ot, int op1,
                            int is_right, int is_arith)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    tcg_gen_andi_tl(tcg_ctx, s->T1, s->T1, mask);
    tcg_gen_subi_tl(tcg_ctx, s->tmp0, s->T1, 1);

    if (is_right) {
        if (is_arith) {
            gen_exts(tcg_ctx, ot, s->T0);
            tcg_gen_sar_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_sar_tl(tcg_ctx, s->T0, s->T0, s->T1);
        } else {
            gen_extu(tcg_ctx, ot, s->T0);
            tcg_gen_shr_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, s->T1);
        }
    } else {
        tcg_gen_shl_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
        tcg_gen_shl_tl(tcg_ctx, s->T0, s->T0, s->T1);
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, s->T0, s->tmp0, s->T1, is_right);
}

static void gen_shift_rm_im(DisasContext *s, MemOp ot, int op1, int op2,
                            int is_right, int is_arith)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mask = (ot == MO_64 ? 0x3f : 0x1f);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, s->T0, s->A0);
    else
        gen_op_mov_v_reg(s, ot, s->T0, op1);

    op2 &= mask;
    if (op2 != 0) {
        if (is_right) {
            if (is_arith) {
                gen_exts(tcg_ctx, ot, s->T0);
                tcg_gen_sari_tl(tcg_ctx, s->tmp4, s->T0, op2 - 1);
                tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, op2);
            } else {
                gen_extu(tcg_ctx, ot, s->T0);
                tcg_gen_shri_tl(tcg_ctx, s->tmp4, s->T0, op2 - 1);
                tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, op2);
            }
        } else {
            tcg_gen_shli_tl(tcg_ctx, s->tmp4, s->T0, op2 - 1);
            tcg_gen_shli_tl(tcg_ctx, s->T0, s->T0, op2);
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* update eflags if non zero shift */
    if (op2 != 0) {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp4);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
        set_cc_op(s, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    }
}

static void gen_rot_rm_T1(DisasContext *s, MemOp ot, int op1, int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);
    TCGv_i32 t0, t1;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    tcg_gen_andi_tl(tcg_ctx, s->T1, s->T1, mask);

    switch (ot) {
    case MO_8:
        /* Replicate the 8-bit input so that a 32-bit rotate works.  */
        tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
        tcg_gen_muli_tl(tcg_ctx, s->T0, s->T0, 0x01010101);
        goto do_long;
    case MO_16:
        /* Replicate the 16-bit input so that a 32-bit rotate works.  */
        tcg_gen_deposit_tl(tcg_ctx, s->T0, s->T0, s->T0, 16, 16);
        goto do_long;
    do_long:
#ifdef TARGET_X86_64
    case MO_32:
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
        if (is_right) {
            tcg_gen_rotr_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
        } else {
            tcg_gen_rotl_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
        }
        tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
        break;
#endif
    default:
        if (is_right) {
            tcg_gen_rotr_tl(tcg_ctx, s->T0, s->T0, s->T1);
        } else {
            tcg_gen_rotl_tl(tcg_ctx, s->T0, s->T0, s->T1);
        }
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* We'll need the flags computed into CC_SRC.  */
    gen_compute_eflags(s);

    /* The value that was "rotated out" is now present at the other end
       of the word.  Compute C into CC_DST and O into CC_SRC2.  Note that
       since we've computed the flags into CC_SRC, these variables are
       currently dead.  */
    if (is_right) {
        tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask - 1);
        tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, mask);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_cc_dst, 1);
    } else {
        tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, 1);
    }
    tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, 1);
    tcg_gen_xor_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_dst);

    /* Now conditionally store the new CC_OP value.  If the shift count
       is 0 we keep the CC_OP_EFLAGS setting so that only CC_SRC is live.
       Otherwise reuse CC_OP_ADCOX which have the C and O flags split out
       exactly as we computed above.  */
    t0 = tcg_const_i32(tcg_ctx, 0);
    t1 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, t1, s->T1);
    tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, CC_OP_ADCOX);
    tcg_gen_movi_i32(tcg_ctx, s->tmp3_i32, CC_OP_EFLAGS);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, tcg_ctx->cpu_cc_op, t1, t0,
                        s->tmp2_i32, s->tmp3_i32);
    tcg_temp_free_i32(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);

    /* The CC_OP value is no longer predictable.  */ 
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_rot_rm_im(DisasContext *s, MemOp ot, int op1, int op2,
                          int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mask = (ot == MO_64 ? 0x3f : 0x1f);
    int shift;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    op2 &= mask;
    if (op2 != 0) {
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_32:
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
            if (is_right) {
                tcg_gen_rotri_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, op2);
            } else {
                tcg_gen_rotli_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, op2);
            }
            tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
            break;
#endif
        default:
            if (is_right) {
                tcg_gen_rotri_tl(tcg_ctx, s->T0, s->T0, op2);
            } else {
                tcg_gen_rotli_tl(tcg_ctx, s->T0, s->T0, op2);
            }
            break;
        case MO_8:
            mask = 7;
            goto do_shifts;
        case MO_16:
            mask = 15;
        do_shifts:
            shift = op2 & mask;
            if (is_right) {
                shift = mask + 1 - shift;
            }
            gen_extu(tcg_ctx, ot, s->T0);
            tcg_gen_shli_tl(tcg_ctx, s->tmp0, s->T0, shift);
            tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, mask + 1 - shift);
            tcg_gen_or_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
            break;
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    if (op2 != 0) {
        /* Compute the flags into CC_SRC.  */
        gen_compute_eflags(s);

        /* The value that was "rotated out" is now present at the other end
           of the word.  Compute C into CC_DST and O into CC_SRC2.  Note that
           since we've computed the flags into CC_SRC, these variables are
           currently dead.  */
        if (is_right) {
            tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask - 1);
            tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, mask);
            tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_cc_dst, 1);
        } else {
            tcg_gen_shri_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, s->T0, mask);
            tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0, 1);
        }
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, 1);
        tcg_gen_xor_tl(tcg_ctx, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_src2, tcg_ctx->cpu_cc_dst);
        set_cc_op(s, CC_OP_ADCOX);
    }
}

/* XXX: add faster immediate = 1 case */
static void gen_rotc_rm_T1(DisasContext *s, MemOp ot, int op1,
                           int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_compute_eflags(s);
    // assert(s->cc_op == CC_OP_EFLAGS);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, s->T0, s->A0);
    else
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    
    if (is_right) {
        switch (ot) {
        case MO_8:
            gen_helper_rcrb(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_16:
            gen_helper_rcrw(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_32:
            gen_helper_rcrl(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rcrq(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#endif
        default:
            tcg_abort();
        }
    } else {
        switch (ot) {
        case MO_8:
            gen_helper_rclb(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_16:
            gen_helper_rclw(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
        case MO_32:
            gen_helper_rcll(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rclq(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->T0, s->T1);
            break;
#endif
        default:
            tcg_abort();
        }
    }
    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);
}

/* XXX: add faster immediate case */
static void gen_shiftd_rm_T1(DisasContext *s, MemOp ot, int op1,
                             bool is_right, TCGv count_in)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong mask = (ot == MO_64 ? 63 : 31);
    TCGv count;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, s->T0, s->A0);
    } else {
        gen_op_mov_v_reg(s, ot, s->T0, op1);
    }

    count = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx, count, count_in, mask);

    switch (ot) {
    case MO_16:
        /* Note: we implement the Intel behaviour for shift count > 16.
           This means "shrdw C, B, A" shifts A:B:A >> C.  Build the B:A
           portion by constructing it as a 32-bit value.  */
        if (is_right) {
            tcg_gen_deposit_tl(tcg_ctx, s->tmp0, s->T0, s->T1, 16, 16);
            tcg_gen_mov_tl(tcg_ctx, s->T1, s->T0);
            tcg_gen_mov_tl(tcg_ctx, s->T0, s->tmp0);
        } else {
            tcg_gen_deposit_tl(tcg_ctx, s->T1, s->T0, s->T1, 16, 16);
        }
        /* FALLTHRU */
#ifdef TARGET_X86_64
    case MO_32:
        /* Concatenate the two 32-bit values and use a 64-bit shift.  */
        tcg_gen_subi_tl(tcg_ctx, s->tmp0, count, 1);
        if (is_right) {
            tcg_gen_concat_tl_i64(tcg_ctx, s->T0, s->T0, s->T1);
            tcg_gen_shr_i64(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_shr_i64(tcg_ctx, s->T0, s->T0, count);
        } else {
            tcg_gen_concat_tl_i64(tcg_ctx, s->T0, s->T1, s->T0);
            tcg_gen_shl_i64(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            tcg_gen_shl_i64(tcg_ctx, s->T0, s->T0, count);
            tcg_gen_shri_i64(tcg_ctx, s->tmp0, s->tmp0, 32);
            tcg_gen_shri_i64(tcg_ctx, s->T0, s->T0, 32);
        }
        break;
#endif
    default:
        tcg_gen_subi_tl(tcg_ctx, s->tmp0, count, 1);
        if (is_right) {
            tcg_gen_shr_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);

            tcg_gen_subfi_tl(tcg_ctx, s->tmp4, mask + 1, count);
            tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, count);
            tcg_gen_shl_tl(tcg_ctx, s->T1, s->T1, s->tmp4);
        } else {
            tcg_gen_shl_tl(tcg_ctx, s->tmp0, s->T0, s->tmp0);
            if (ot == MO_16) {
                /* Only needed if count > 16, for Intel behaviour.  */
                tcg_gen_subfi_tl(tcg_ctx, s->tmp4, 33, count);
                tcg_gen_shr_tl(tcg_ctx, s->tmp4, s->T1, s->tmp4);
                tcg_gen_or_tl(tcg_ctx, s->tmp0, s->tmp0, s->tmp4);
            }

            tcg_gen_subfi_tl(tcg_ctx, s->tmp4, mask + 1, count);
            tcg_gen_shl_tl(tcg_ctx, s->T0, s->T0, count);
            tcg_gen_shr_tl(tcg_ctx, s->T1, s->T1, s->tmp4);
        }
        tcg_gen_movi_tl(tcg_ctx, s->tmp4, 0);
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, s->T1, count, s->tmp4,
                           s->tmp4, s->T1);
        tcg_gen_or_tl(tcg_ctx, s->T0, s->T0, s->T1);
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, s->T0, s->tmp0, count, is_right);
    tcg_temp_free(tcg_ctx, count);
}

static void gen_shift(DisasContext *s1, int op, MemOp ot, int d, int s)
{
    if (s != OR_TMP1)
        gen_op_mov_v_reg(s1, ot, s1->T1, s);
    switch(op) {
    case OP_ROL:
        gen_rot_rm_T1(s1, ot, d, 0);
        break;
    case OP_ROR:
        gen_rot_rm_T1(s1, ot, d, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_T1(s1, ot, d, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_T1(s1, ot, d, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_T1(s1, ot, d, 1, 1);
        break;
    case OP_RCL:
        gen_rotc_rm_T1(s1, ot, d, 0);
        break;
    case OP_RCR:
        gen_rotc_rm_T1(s1, ot, d, 1);
        break;
    }
}

static void gen_shifti(DisasContext *s1, int op, MemOp ot, int d, int c)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;

    switch(op) {
    case OP_ROL:
        gen_rot_rm_im(s1, ot, d, c, 0);
        break;
    case OP_ROR:
        gen_rot_rm_im(s1, ot, d, c, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_im(s1, ot, d, c, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_im(s1, ot, d, c, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_im(s1, ot, d, c, 1, 1);
        break;
    default:
        /* currently not optimized */
        tcg_gen_movi_tl(tcg_ctx, s1->T1, c);
        gen_shift(s1, op, ot, d, OR_TMP1);
        break;
    }
}

#define X86_MAX_INSN_LENGTH 15

static uint64_t advance_pc(CPUX86State *env, DisasContext *s, int num_bytes)
{
    uint64_t pc = s->pc;

    s->pc += num_bytes;
    if (unlikely(s->pc - s->pc_start > X86_MAX_INSN_LENGTH)) {
        /* If the instruction's 16th byte is on a different page than the 1st, a
         * page fault on the second page wins over the general protection fault
         * caused by the instruction being too long.
         * This can happen even if the operand is only one byte long!
         */
        if (((s->pc - 1) ^ (pc - 1)) & TARGET_PAGE_MASK) {
            volatile uint8_t unused =
                cpu_ldub_code(env, (s->pc - 1) & TARGET_PAGE_MASK);
            (void) unused;
        }
        siglongjmp(s->jmpbuf, 1);
    }

    return pc;
}

static inline uint8_t x86_ldub_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldub(env->uc->tcg_ctx, env, advance_pc(env, s, 1));
}

static inline int16_t x86_ldsw_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldsw(env->uc->tcg_ctx, env, advance_pc(env, s, 2));
}

static inline uint16_t x86_lduw_code(CPUX86State *env, DisasContext *s)
{
    return translator_lduw(env->uc->tcg_ctx, env, advance_pc(env, s, 2));
}

static inline uint32_t x86_ldl_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldl(env->uc->tcg_ctx, env, advance_pc(env, s, 4));
}

#ifdef TARGET_X86_64
static inline uint64_t x86_ldq_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldq(env->uc->tcg_ctx, env, advance_pc(env, s, 8));
}
#endif

/* Decompose an address.  */

typedef struct AddressParts {
    int def_seg;
    int base;
    int index;
    int scale;
    target_long disp;
} AddressParts;

static AddressParts gen_lea_modrm_0(CPUX86State *env, DisasContext *s,
                                    int modrm)
{
    int def_seg, base, index, scale, mod, rm;
    target_long disp;
    bool havesib;

    def_seg = R_DS;
    index = -1;
    scale = 0;
    disp = 0;

    mod = (modrm >> 6) & 3;
    rm = modrm & 7;
    base = rm | REX_B(s);

    if (mod == 3) {
        /* Normally filtered out earlier, but including this path
           simplifies multi-byte nop, as well as bndcl, bndcu, bndcn.  */
        goto done;
    }

    switch (s->aflag) {
    case MO_64:
    case MO_32:
        havesib = 0;
        if (rm == 4) {
            int code = x86_ldub_code(env, s);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            if (index == 4) {
                index = -1;  /* no index */
            }
            base = (code & 7) | REX_B(s);
            havesib = 1;
        }

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)x86_ldl_code(env, s);
                if (CODE64(s) && !havesib) {
                    base = -2;
                    disp += s->pc + s->rip_offset;
                }
            }
            break;
        case 1:
            disp = (int8_t)x86_ldub_code(env, s);
            break;
        default:
        case 2:
            disp = (int32_t)x86_ldl_code(env, s);
            break;
        }

        /* For correct popl handling with esp.  */
        if (base == R_ESP && s->popl_esp_hack) {
            disp += s->popl_esp_hack;
        }
        if (base == R_EBP || base == R_ESP) {
            def_seg = R_SS;
        }
        break;

    case MO_16:
        if (mod == 0) {
            if (rm == 6) {
                base = -1;
                disp = x86_lduw_code(env, s);
                break;
            }
        } else if (mod == 1) {
            disp = (int8_t)x86_ldub_code(env, s);
        } else {
            disp = (int16_t)x86_lduw_code(env, s);
        }

        switch (rm) {
        case 0:
            base = R_EBX;
            index = R_ESI;
            break;
        case 1:
            base = R_EBX;
            index = R_EDI;
            break;
        case 2:
            base = R_EBP;
            index = R_ESI;
            def_seg = R_SS;
            break;
        case 3:
            base = R_EBP;
            index = R_EDI;
            def_seg = R_SS;
            break;
        case 4:
            base = R_ESI;
            break;
        case 5:
            base = R_EDI;
            break;
        case 6:
            base = R_EBP;
            def_seg = R_SS;
            break;
        default:
        case 7:
            base = R_EBX;
            break;
        }
        break;

    default:
        tcg_abort();
    }

 done:
    return (AddressParts){ def_seg, base, index, scale, disp };
}

/* Compute the address, with a minimum number of TCG ops.  */
static TCGv gen_lea_modrm_1(DisasContext *s, AddressParts a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv ea = NULL;

    if (a.index >= 0) {
        if (a.scale == 0) {
            ea = tcg_ctx->cpu_regs[a.index];
        } else {
            tcg_gen_shli_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[a.index], a.scale);
            ea = s->A0;
        }
        if (a.base >= 0) {
            tcg_gen_add_tl(tcg_ctx, s->A0, ea, tcg_ctx->cpu_regs[a.base]);
            ea = s->A0;
        }
    } else if (a.base >= 0) {
        ea = tcg_ctx->cpu_regs[a.base];
    }
    if (!ea) {
        tcg_gen_movi_tl(tcg_ctx, s->A0, a.disp);
        ea = s->A0;
    } else if (a.disp != 0) {
        tcg_gen_addi_tl(tcg_ctx, s->A0, ea, a.disp);
        ea = s->A0;
    }

    return ea;
}

static void gen_lea_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    AddressParts a = gen_lea_modrm_0(env, s, modrm);
    TCGv ea = gen_lea_modrm_1(s, a);
    gen_lea_v_seg(s, s->aflag, ea, a.def_seg, s->override);
}

static void gen_nop_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    (void)gen_lea_modrm_0(env, s, modrm);
}

/* Used for BNDCL, BNDCU, BNDCN.  */
static void gen_bndck(CPUX86State *env, DisasContext *s, int modrm,
                      TCGCond cond, TCGv_i64 bndv)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv ea = gen_lea_modrm_1(s, gen_lea_modrm_0(env, s, modrm));

    tcg_gen_extu_tl_i64(tcg_ctx, s->tmp1_i64, ea);
    if (!CODE64(s)) {
        tcg_gen_ext32u_i64(tcg_ctx, s->tmp1_i64, s->tmp1_i64);
    }
    tcg_gen_setcond_i64(tcg_ctx, cond, s->tmp1_i64, s->tmp1_i64, bndv);
    tcg_gen_extrl_i64_i32(tcg_ctx, s->tmp2_i32, s->tmp1_i64);
    gen_helper_bndck(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
}

/* used for LEA and MOV AX, mem */
static void gen_add_A0_ds_seg(DisasContext *s)
{
    gen_lea_v_seg(s, s->aflag, s->A0, R_DS, s->override);
}

/* generate modrm memory load or store of 'reg'. TMP0 is used if reg ==
   OR_TMP0 */
static void gen_ldst_modrm(CPUX86State *env, DisasContext *s, int modrm,
                           MemOp ot, int reg, int is_store)
{
    int mod, rm;

    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(s, ot, s->T0, reg);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(s, ot, reg, s->T0);
        }
    } else {
        gen_lea_modrm(env, s, modrm);
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(s, ot, s->T0, reg);
            gen_op_st_v(s, ot, s->T0, s->A0);
        } else {
            gen_op_ld_v(s, ot, s->T0, s->A0);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(s, ot, reg, s->T0);
        }
    }
}

static inline uint32_t insn_get(CPUX86State *env, DisasContext *s, MemOp ot)
{
    uint32_t ret;

    switch (ot) {
    case MO_8:
        ret = x86_ldub_code(env, s);
        break;
    case MO_16:
        ret = x86_lduw_code(env, s);
        break;
    case MO_32:
#ifdef TARGET_X86_64
    case MO_64:
#endif
        ret = x86_ldl_code(env, s);
        break;
    default:
        tcg_abort();
    }
    return ret;
}

static inline int insn_const_size(MemOp ot)
{
    if (ot <= MO_32) {
        return 1 << ot;
    } else {
        return 4;
    }
}

static inline bool use_goto_tb(DisasContext *s, target_ulong pc)
{
    return (pc & TARGET_PAGE_MASK) == (s->base.tb->pc & TARGET_PAGE_MASK) ||
           (pc & TARGET_PAGE_MASK) == (s->pc_start & TARGET_PAGE_MASK);
}

static inline void gen_goto_tb(DisasContext *s, int tb_num, target_ulong eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    target_ulong pc = s->cs_base + eip;

    if (use_goto_tb(s, pc))  {
        /* jump to same page: we can use a direct jump */
        tcg_gen_goto_tb(tcg_ctx, tb_num);
        gen_jmp_im(s, eip);
        tcg_gen_exit_tb(tcg_ctx, s->base.tb, tb_num);
        s->base.is_jmp = DISAS_NORETURN;
    } else {
        /* jump to another page */
        gen_jmp_im(s, eip);
        gen_jr(s, s->tmp0);
    }
}

static inline void gen_jcc(DisasContext *s, int b,
                           target_ulong val, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGLabel *l1, *l2;

    if (s->jmp_opt) {
        l1 = gen_new_label(tcg_ctx);
        gen_jcc1(s, b, l1);

        gen_goto_tb(s, 0, next_eip);

        gen_set_label(tcg_ctx, l1);
        gen_goto_tb(s, 1, val);
    } else {
        l1 = gen_new_label(tcg_ctx);
        l2 = gen_new_label(tcg_ctx);
        gen_jcc1(s, b, l1);

        gen_jmp_im(s, next_eip);
        tcg_gen_br(tcg_ctx, l2);

        gen_set_label(tcg_ctx, l1);
        gen_jmp_im(s, val);
        gen_set_label(tcg_ctx, l2);
        gen_eob(s);
    }
}

static void gen_cmovcc1(CPUX86State *env, DisasContext *s, MemOp ot, int b,
                        int modrm, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCPrepare cc;

    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

    cc = gen_prepare_cc(s, b, s->T1);
    if (cc.mask != -1) {
        TCGv t0 = tcg_temp_new(tcg_ctx);
        tcg_gen_andi_tl(tcg_ctx, t0, cc.reg, cc.mask);
        cc.reg = t0;
    }
    if (!cc.use_reg2) {
        cc.reg2 = tcg_const_tl(tcg_ctx, cc.imm);
    }

    tcg_gen_movcond_tl(tcg_ctx, cc.cond, s->T0, cc.reg, cc.reg2,
                       s->T0, tcg_ctx->cpu_regs[reg]);
    gen_op_mov_reg_v(s, ot, reg, s->T0);

    if (cc.mask != -1) {
        tcg_temp_free(tcg_ctx, cc.reg);
    }
    if (!cc.use_reg2) {
        tcg_temp_free(tcg_ctx, cc.reg2);
    }
}

static inline void gen_op_movl_T0_seg(DisasContext *s, int seg_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                     offsetof(CPUX86State,segs[seg_reg].selector));
}

static inline void gen_op_movl_seg_T0_vm(DisasContext *s, int seg_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
    tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                    offsetof(CPUX86State,segs[seg_reg].selector));
    tcg_gen_shli_tl(tcg_ctx, tcg_ctx->cpu_seg_base[seg_reg], s->T0, 4);
}

/* move T0 to seg_reg and compute if the CPU state may change. Never
   call this function with seg_reg == R_CS */
static void gen_movl_seg_T0(DisasContext *s, int seg_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (s->pe && !s->vm86) {
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        gen_helper_load_seg(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, seg_reg), s->tmp2_i32);
        /* abort translation because the addseg value may change or
           because ss32 may change. For R_SS, translation must always
           stop as a special handling must be done to disable hardware
           interrupts for the next instruction */
        if (seg_reg == R_SS || (s->code32 && seg_reg < R_FS)) {
            s->base.is_jmp = DISAS_TOO_MANY;
        }
    } else {
        gen_op_movl_seg_T0_vm(s, seg_reg);
        if (seg_reg == R_SS) {
            s->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static inline int svm_is_rep(int prefixes)
{
    return ((prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) ? 8 : 0);
}

static inline void
gen_svm_check_intercept_param(DisasContext *s, target_ulong pc_start,
                              uint32_t type, uint64_t param)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    /* no SVM activated; fast case */
    if (likely(!(s->flags & HF_GUEST_MASK)))
        return;
    gen_update_cc_op(s);
    gen_jmp_im(s, pc_start - s->cs_base);
    gen_helper_svm_check_intercept_param(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, type),
                                         tcg_const_i64(tcg_ctx, param));
}

static inline void
gen_svm_check_intercept(DisasContext *s, target_ulong pc_start, uint64_t type)
{
    gen_svm_check_intercept_param(s, pc_start, type, 0);
}

static inline void gen_stack_update(DisasContext *s, int addend)
{
    gen_op_add_reg_im(s, mo_stacksize(s), R_ESP, addend);
}

/* Generate a push. It depends on ss32, addseg and dflag.  */
static void gen_push_v(DisasContext *s, TCGv val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);
    int size = 1 << d_ot;
    TCGv new_esp = s->A0;

    tcg_gen_subi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_ESP], size);

    if (!CODE64(s)) {
        if (s->addseg) {
            new_esp = s->tmp4;
            tcg_gen_mov_tl(tcg_ctx, new_esp, s->A0);
        }
        gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
    }

    gen_op_st_v(s, d_ot, val, s->A0);
    gen_op_mov_reg_v(s, a_ot, R_ESP, new_esp);
}

/* two step pop is necessary for precise exceptions */
static MemOp gen_pop_T0(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    MemOp d_ot = mo_pushpop(s, s->dflag);

    gen_lea_v_seg(s, mo_stacksize(s), tcg_ctx->cpu_regs[R_ESP], R_SS, -1);
    gen_op_ld_v(s, d_ot, s->T0, s->A0);

    return d_ot;
}

static inline void gen_pop_update(DisasContext *s, MemOp ot)
{
    gen_stack_update(s, 1 << ot);
}

static inline void gen_stack_A0(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_lea_v_seg(s, s->ss32 ? MO_32 : MO_16, tcg_ctx->cpu_regs[R_ESP], R_SS, -1);
}

static void gen_pusha(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp s_ot = s->ss32 ? MO_32 : MO_16;
    MemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_ESP], (i - 8) * size);
        gen_lea_v_seg(s, s_ot, s->A0, R_SS, -1);
        gen_op_st_v(s, d_ot, tcg_ctx->cpu_regs[7 - i], s->A0);
    }

    gen_stack_update(s, -8 * size);
}

static void gen_popa(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp s_ot = s->ss32 ? MO_32 : MO_16;
    MemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        /* ESP is not reloaded */
        if (7 - i == R_ESP) {
            continue;
        }
        tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_ESP], i * size);
        gen_lea_v_seg(s, s_ot, s->A0, R_SS, -1);
        gen_op_ld_v(s, d_ot, s->T0, s->A0);
        gen_op_mov_reg_v(s, d_ot, 7 - i, s->T0);
    }

    gen_stack_update(s, 8 * size);
}

static void gen_enter(DisasContext *s, int esp_addend, int level)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = CODE64(s) ? MO_64 : s->ss32 ? MO_32 : MO_16;
    int size = 1 << d_ot;

    /* Push BP; compute FrameTemp into T1.  */
    tcg_gen_subi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[R_ESP], size);
    gen_lea_v_seg(s, a_ot, s->T1, R_SS, -1);
    gen_op_st_v(s, d_ot, tcg_ctx->cpu_regs[R_EBP], s->A0);

    level &= 31;
    if (level != 0) {
        int i;

        /* Copy level-1 pointers from the previous frame.  */
        for (i = 1; i < level; ++i) {
            tcg_gen_subi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EBP], size * i);
            gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
            gen_op_ld_v(s, d_ot, s->tmp0, s->A0);

            tcg_gen_subi_tl(tcg_ctx, s->A0, s->T1, size * i);
            gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
            gen_op_st_v(s, d_ot, s->tmp0, s->A0);
        }

        /* Push the current FrameTemp as the last level.  */
        tcg_gen_subi_tl(tcg_ctx, s->A0, s->T1, size * level);
        gen_lea_v_seg(s, a_ot, s->A0, R_SS, -1);
        gen_op_st_v(s, d_ot, s->T1, s->A0);
    }

    /* Copy the FrameTemp value to EBP.  */
    gen_op_mov_reg_v(s, a_ot, R_EBP, s->T1);

    /* Compute the final value of ESP.  */
    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T1, esp_addend + size * level);
    gen_op_mov_reg_v(s, a_ot, R_ESP, s->T1);
}

static void gen_leave(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);

    gen_lea_v_seg(s, a_ot, tcg_ctx->cpu_regs[R_EBP], R_SS, -1);
    gen_op_ld_v(s, d_ot, s->T0, s->A0);

    tcg_gen_addi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[R_EBP], 1ULL << d_ot);

    gen_op_mov_reg_v(s, d_ot, R_EBP, s->T0);
    gen_op_mov_reg_v(s, a_ot, R_ESP, s->T1);
}

/* Similarly, except that the assumption here is that we don't decode
   the instruction at all -- either a missing opcode, an unimplemented
   feature, or just a bogus instruction stream.  */
static void gen_unknown_opcode(CPUX86State *env, DisasContext *s)
{
    gen_illegal_opcode(s);
}

/* an interrupt is different from an exception because of the
   privilege checks */
static void gen_interrupt(DisasContext *s, int intno,
                          target_ulong cur_eip, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_raise_interrupt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, intno),
                               tcg_const_i32(tcg_ctx, next_eip - cur_eip));
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_debug(DisasContext *s, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_debug(tcg_ctx, tcg_ctx->cpu_env);
    s->base.is_jmp = DISAS_NORETURN;
}

static void gen_set_hflag(DisasContext *s, uint32_t mask)
{
    if ((s->flags & mask) == 0) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;

        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_ld_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_gen_ori_i32(tcg_ctx, t, t, mask);
        tcg_gen_st_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_temp_free_i32(tcg_ctx, t);
        s->flags |= mask;
    }
}

static void gen_reset_hflag(DisasContext *s, uint32_t mask)
{
    if (s->flags & mask) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;

        TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_ld_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_gen_andi_i32(tcg_ctx, t, t, ~mask);
        tcg_gen_st_i32(tcg_ctx, t, tcg_ctx->cpu_env, offsetof(CPUX86State, hflags));
        tcg_temp_free_i32(tcg_ctx, t);
        s->flags &= ~mask;
    }
}

/* Clear BND registers during legacy branches.  */
static void gen_bnd_jmp(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    /* Clear the registers only if BND prefix is missing, MPX is enabled,
       and if the BNDREGs are known to be in use (non-zero) already.
       The helper itself will check BNDPRESERVE at runtime.  */
    if ((s->prefix & PREFIX_REPNZ) == 0
        && (s->flags & HF_MPX_EN_MASK) != 0
        && (s->flags & HF_MPX_IU_MASK) != 0) {
        gen_helper_bnd_jmp(tcg_ctx, tcg_ctx->cpu_env);
    }
}

/* Generate an end of block. Trace exception is also generated if needed.
   If INHIBIT, set HF_INHIBIT_IRQ_MASK if it isn't already set.
   If RECHECK_TF, emit a rechecking helper for #DB, ignoring the state of
   S->TF.  This is used by the syscall/sysret insns.  */
static void
do_gen_eob_worker(DisasContext *s, bool inhibit, bool recheck_tf, bool jr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_update_cc_op(s);

    /* If several instructions disable interrupts, only the first does it.  */
    if (inhibit && !(s->flags & HF_INHIBIT_IRQ_MASK)) {
        gen_set_hflag(s, HF_INHIBIT_IRQ_MASK);
    } else {
        gen_reset_hflag(s, HF_INHIBIT_IRQ_MASK);
    }

    if (s->base.tb->flags & HF_RF_MASK) {
        gen_helper_reset_rf(tcg_ctx, tcg_ctx->cpu_env);
    }
    if (s->base.singlestep_enabled) {
        gen_helper_debug(tcg_ctx, tcg_ctx->cpu_env);
    } else if (recheck_tf) {
        gen_helper_rechecking_single_step(tcg_ctx, tcg_ctx->cpu_env);
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    } else if (s->tf) {
        gen_helper_single_step(tcg_ctx, tcg_ctx->cpu_env);
    } else if (jr) {
        tcg_gen_lookup_and_goto_ptr(tcg_ctx);
    } else {
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    }
    s->base.is_jmp = DISAS_NORETURN;
}

static inline void
gen_eob_worker(DisasContext *s, bool inhibit, bool recheck_tf)
{
    do_gen_eob_worker(s, inhibit, recheck_tf, false);
}

/* End of block.
   If INHIBIT, set HF_INHIBIT_IRQ_MASK if it isn't already set.  */
static void gen_eob_inhibit_irq(DisasContext *s, bool inhibit)
{
    gen_eob_worker(s, inhibit, false);
}

/* End of block, resetting the inhibit irq flag.  */
static void gen_eob(DisasContext *s)
{
    gen_eob_worker(s, false, false);
}

/* Jump to register */
static void gen_jr(DisasContext *s, TCGv dest)
{
    do_gen_eob_worker(s, false, false, true);
}

/* generate a jump to eip. No segment change must happen before as a
   direct call to the next block may occur */
static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num)
{
    gen_update_cc_op(s);
    set_cc_op(s, CC_OP_DYNAMIC);
    if (s->jmp_opt) {
        gen_goto_tb(s, tb_num, eip);
    } else {
        gen_jmp_im(s, eip);
        gen_eob(s);
    }
}

static void gen_jmp(DisasContext *s, target_ulong eip)
{
    gen_jmp_tb(s, eip, 0);
}

static inline void gen_ldq_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset);
}

static inline void gen_stq_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset);
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
}

static inline void gen_ldo_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_sto_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mem_index = s->mem_index;
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, mem_index, MO_LEQ);
    tcg_gen_addi_tl(tcg_ctx, s->tmp0, s->A0, 8);
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->tmp0, mem_index, MO_LEQ);
}

static inline void gen_op_movo(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(0)));
    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset + offsetof(ZMMReg, ZMM_Q(1)));
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset + offsetof(ZMMReg, ZMM_Q(1)));
}

static inline void gen_op_movq(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s_offset);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset);
}

static inline void gen_op_movl(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s_offset);
    tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, d_offset);
}

static inline void gen_op_movq_env_0(DisasContext *s, int d_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_movi_i64(tcg_ctx, s->tmp1_i64, 0);
    tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, d_offset);
}

typedef void (*SSEFunc_i_ep)(TCGContext *s, TCGv_i32 val, TCGv_ptr env, TCGv_ptr reg);
typedef void (*SSEFunc_l_ep)(TCGContext *s, TCGv_i64 val, TCGv_ptr env, TCGv_ptr reg);
typedef void (*SSEFunc_0_epi)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg, TCGv_i32 val);
typedef void (*SSEFunc_0_epl)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg, TCGv_i64 val);
typedef void (*SSEFunc_0_epp)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b);
typedef void (*SSEFunc_0_eppi)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
                               TCGv_i32 val);
typedef void (*SSEFunc_0_ppi)(TCGContext *s, TCGv_ptr reg_a, TCGv_ptr reg_b, TCGv_i32 val);
typedef void (*SSEFunc_0_eppt)(TCGContext *s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
                               TCGv val);

#define SSE_SPECIAL ((void *)1)
#define SSE_DUMMY ((void *)2)

#define MMX_OP2(x) { gen_helper_ ## x ## _mmx, gen_helper_ ## x ## _xmm }
#define SSE_FOP(x) { gen_helper_ ## x ## ps, gen_helper_ ## x ## pd, \
                     gen_helper_ ## x ## ss, gen_helper_ ## x ## sd, }

static const SSEFunc_0_epp sse_op_table1[256][4] = {
    /* 3DNow! extensions */
    [0x0e] = { SSE_DUMMY }, /* femms */
    [0x0f] = { SSE_DUMMY }, /* pf... */
    /* pure SSE operations */
    [0x10] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    [0x11] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    [0x12] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movlps, movlpd, movsldup, movddup */
    [0x13] = { SSE_SPECIAL, SSE_SPECIAL },  /* movlps, movlpd */
    [0x14] = { gen_helper_punpckldq_xmm, gen_helper_punpcklqdq_xmm },
    [0x15] = { gen_helper_punpckhdq_xmm, gen_helper_punpckhqdq_xmm },
    [0x16] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd, movshdup */
    [0x17] = { SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd */

    [0x28] = { SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
    [0x29] = { SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
    [0x2a] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtpi2ps, cvtpi2pd, cvtsi2ss, cvtsi2sd */
    [0x2b] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movntps, movntpd, movntss, movntsd */
    [0x2c] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvttps2pi, cvttpd2pi, cvttsd2si, cvttss2si */
    [0x2d] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtps2pi, cvtpd2pi, cvtsd2si, cvtss2si */
    [0x2e] = { gen_helper_ucomiss, gen_helper_ucomisd },
    [0x2f] = { gen_helper_comiss, gen_helper_comisd },
    [0x50] = { SSE_SPECIAL, SSE_SPECIAL }, /* movmskps, movmskpd */
    [0x51] = SSE_FOP(sqrt),
    [0x52] = { gen_helper_rsqrtps, NULL, gen_helper_rsqrtss, NULL },
    [0x53] = { gen_helper_rcpps, NULL, gen_helper_rcpss, NULL },
    [0x54] = { gen_helper_pand_xmm, gen_helper_pand_xmm }, /* andps, andpd */
    [0x55] = { gen_helper_pandn_xmm, gen_helper_pandn_xmm }, /* andnps, andnpd */
    [0x56] = { gen_helper_por_xmm, gen_helper_por_xmm }, /* orps, orpd */
    [0x57] = { gen_helper_pxor_xmm, gen_helper_pxor_xmm }, /* xorps, xorpd */
    [0x58] = SSE_FOP(add),
    [0x59] = SSE_FOP(mul),
    [0x5a] = { gen_helper_cvtps2pd, gen_helper_cvtpd2ps,
               gen_helper_cvtss2sd, gen_helper_cvtsd2ss },
    [0x5b] = { gen_helper_cvtdq2ps, gen_helper_cvtps2dq, gen_helper_cvttps2dq },
    [0x5c] = SSE_FOP(sub),
    [0x5d] = SSE_FOP(min),
    [0x5e] = SSE_FOP(div),
    [0x5f] = SSE_FOP(max),

    [0xc2] = SSE_FOP(cmpeq),
    [0xc6] = { (SSEFunc_0_epp)gen_helper_shufps,
               (SSEFunc_0_epp)gen_helper_shufpd }, /* XXX: casts */

    /* SSSE3, SSE4, MOVBE, CRC32, BMI1, BMI2, ADX.  */
    [0x38] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
    [0x3a] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },

    /* MMX ops and their SSE extensions */
    [0x60] = MMX_OP2(punpcklbw),
    [0x61] = MMX_OP2(punpcklwd),
    [0x62] = MMX_OP2(punpckldq),
    [0x63] = MMX_OP2(packsswb),
    [0x64] = MMX_OP2(pcmpgtb),
    [0x65] = MMX_OP2(pcmpgtw),
    [0x66] = MMX_OP2(pcmpgtl),
    [0x67] = MMX_OP2(packuswb),
    [0x68] = MMX_OP2(punpckhbw),
    [0x69] = MMX_OP2(punpckhwd),
    [0x6a] = MMX_OP2(punpckhdq),
    [0x6b] = MMX_OP2(packssdw),
    [0x6c] = { NULL, gen_helper_punpcklqdq_xmm },
    [0x6d] = { NULL, gen_helper_punpckhqdq_xmm },
    [0x6e] = { SSE_SPECIAL, SSE_SPECIAL }, /* movd mm, ea */
    [0x6f] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, , movqdu */
    [0x70] = { (SSEFunc_0_epp)gen_helper_pshufw_mmx,
               (SSEFunc_0_epp)gen_helper_pshufd_xmm,
               (SSEFunc_0_epp)gen_helper_pshufhw_xmm,
               (SSEFunc_0_epp)gen_helper_pshuflw_xmm }, /* XXX: casts */
    [0x71] = { SSE_SPECIAL, SSE_SPECIAL }, /* shiftw */
    [0x72] = { SSE_SPECIAL, SSE_SPECIAL }, /* shiftd */
    [0x73] = { SSE_SPECIAL, SSE_SPECIAL }, /* shiftq */
    [0x74] = MMX_OP2(pcmpeqb),
    [0x75] = MMX_OP2(pcmpeqw),
    [0x76] = MMX_OP2(pcmpeql),
    [0x77] = { SSE_DUMMY }, /* emms */
    [0x78] = { NULL, SSE_SPECIAL, NULL, SSE_SPECIAL }, /* extrq_i, insertq_i */
    [0x79] = { NULL, gen_helper_extrq_r, NULL, gen_helper_insertq_r },
    [0x7c] = { NULL, gen_helper_haddpd, NULL, gen_helper_haddps },
    [0x7d] = { NULL, gen_helper_hsubpd, NULL, gen_helper_hsubps },
    [0x7e] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movd, movd, , movq */
    [0x7f] = { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, movdqu */
    [0xc4] = { SSE_SPECIAL, SSE_SPECIAL }, /* pinsrw */
    [0xc5] = { SSE_SPECIAL, SSE_SPECIAL }, /* pextrw */
    [0xd0] = { NULL, gen_helper_addsubpd, NULL, gen_helper_addsubps },
    [0xd1] = MMX_OP2(psrlw),
    [0xd2] = MMX_OP2(psrld),
    [0xd3] = MMX_OP2(psrlq),
    [0xd4] = MMX_OP2(paddq),
    [0xd5] = MMX_OP2(pmullw),
    [0xd6] = { NULL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
    [0xd7] = { SSE_SPECIAL, SSE_SPECIAL }, /* pmovmskb */
    [0xd8] = MMX_OP2(psubusb),
    [0xd9] = MMX_OP2(psubusw),
    [0xda] = MMX_OP2(pminub),
    [0xdb] = MMX_OP2(pand),
    [0xdc] = MMX_OP2(paddusb),
    [0xdd] = MMX_OP2(paddusw),
    [0xde] = MMX_OP2(pmaxub),
    [0xdf] = MMX_OP2(pandn),
    [0xe0] = MMX_OP2(pavgb),
    [0xe1] = MMX_OP2(psraw),
    [0xe2] = MMX_OP2(psrad),
    [0xe3] = MMX_OP2(pavgw),
    [0xe4] = MMX_OP2(pmulhuw),
    [0xe5] = MMX_OP2(pmulhw),
    [0xe6] = { NULL, gen_helper_cvttpd2dq, gen_helper_cvtdq2pd, gen_helper_cvtpd2dq },
    [0xe7] = { SSE_SPECIAL , SSE_SPECIAL },  /* movntq, movntq */
    [0xe8] = MMX_OP2(psubsb),
    [0xe9] = MMX_OP2(psubsw),
    [0xea] = MMX_OP2(pminsw),
    [0xeb] = MMX_OP2(por),
    [0xec] = MMX_OP2(paddsb),
    [0xed] = MMX_OP2(paddsw),
    [0xee] = MMX_OP2(pmaxsw),
    [0xef] = MMX_OP2(pxor),
    [0xf0] = { NULL, NULL, NULL, SSE_SPECIAL }, /* lddqu */
    [0xf1] = MMX_OP2(psllw),
    [0xf2] = MMX_OP2(pslld),
    [0xf3] = MMX_OP2(psllq),
    [0xf4] = MMX_OP2(pmuludq),
    [0xf5] = MMX_OP2(pmaddwd),
    [0xf6] = MMX_OP2(psadbw),
    [0xf7] = { (SSEFunc_0_epp)gen_helper_maskmov_mmx,
               (SSEFunc_0_epp)gen_helper_maskmov_xmm }, /* XXX: casts */
    [0xf8] = MMX_OP2(psubb),
    [0xf9] = MMX_OP2(psubw),
    [0xfa] = MMX_OP2(psubl),
    [0xfb] = MMX_OP2(psubq),
    [0xfc] = MMX_OP2(paddb),
    [0xfd] = MMX_OP2(paddw),
    [0xfe] = MMX_OP2(paddl),
};

static const SSEFunc_0_epp sse_op_table2[3 * 8][2] = {
    [0 + 2] = MMX_OP2(psrlw),
    [0 + 4] = MMX_OP2(psraw),
    [0 + 6] = MMX_OP2(psllw),
    [8 + 2] = MMX_OP2(psrld),
    [8 + 4] = MMX_OP2(psrad),
    [8 + 6] = MMX_OP2(pslld),
    [16 + 2] = MMX_OP2(psrlq),
    [16 + 3] = { NULL, gen_helper_psrldq_xmm },
    [16 + 6] = MMX_OP2(psllq),
    [16 + 7] = { NULL, gen_helper_pslldq_xmm },
};

static const SSEFunc_0_epi sse_op_table3ai[] = {
    gen_helper_cvtsi2ss,
    gen_helper_cvtsi2sd
};

#ifdef TARGET_X86_64
static const SSEFunc_0_epl sse_op_table3aq[] = {
    gen_helper_cvtsq2ss,
    gen_helper_cvtsq2sd
};
#endif

static const SSEFunc_i_ep sse_op_table3bi[] = {
    gen_helper_cvttss2si,
    gen_helper_cvtss2si,
    gen_helper_cvttsd2si,
    gen_helper_cvtsd2si
};

#ifdef TARGET_X86_64
static const SSEFunc_l_ep sse_op_table3bq[] = {
    gen_helper_cvttss2sq,
    gen_helper_cvtss2sq,
    gen_helper_cvttsd2sq,
    gen_helper_cvtsd2sq
};
#endif

static const SSEFunc_0_epp sse_op_table4[8][4] = {
    SSE_FOP(cmpeq),
    SSE_FOP(cmplt),
    SSE_FOP(cmple),
    SSE_FOP(cmpunord),
    SSE_FOP(cmpneq),
    SSE_FOP(cmpnlt),
    SSE_FOP(cmpnle),
    SSE_FOP(cmpord),
};

static const SSEFunc_0_epp sse_op_table5[256] = {
    [0x0c] = gen_helper_pi2fw,
    [0x0d] = gen_helper_pi2fd,
    [0x1c] = gen_helper_pf2iw,
    [0x1d] = gen_helper_pf2id,
    [0x8a] = gen_helper_pfnacc,
    [0x8e] = gen_helper_pfpnacc,
    [0x90] = gen_helper_pfcmpge,
    [0x94] = gen_helper_pfmin,
    [0x96] = gen_helper_pfrcp,
    [0x97] = gen_helper_pfrsqrt,
    [0x9a] = gen_helper_pfsub,
    [0x9e] = gen_helper_pfadd,
    [0xa0] = gen_helper_pfcmpgt,
    [0xa4] = gen_helper_pfmax,
    [0xa6] = gen_helper_movq, /* pfrcpit1; no need to actually increase precision */
    [0xa7] = gen_helper_movq, /* pfrsqit1 */
    [0xaa] = gen_helper_pfsubr,
    [0xae] = gen_helper_pfacc,
    [0xb0] = gen_helper_pfcmpeq,
    [0xb4] = gen_helper_pfmul,
    [0xb6] = gen_helper_movq, /* pfrcpit2 */
    [0xb7] = gen_helper_pmulhrw_mmx,
    [0xbb] = gen_helper_pswapd,
    [0xbf] = gen_helper_pavgb_mmx /* pavgusb */
};

struct SSEOpHelper_epp {
    SSEFunc_0_epp op[2];
    uint32_t ext_mask;
};

struct SSEOpHelper_eppi {
    SSEFunc_0_eppi op[2];
    uint32_t ext_mask;
};

#define SSSE3_OP(x) { MMX_OP2(x), CPUID_EXT_SSSE3 }
#define SSE41_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE41 }
#define SSE42_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE42 }
#define SSE41_SPECIAL { { NULL, SSE_SPECIAL }, CPUID_EXT_SSE41 }
#define PCLMULQDQ_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, \
        CPUID_EXT_PCLMULQDQ }
#define AESNI_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_AES }

static const struct SSEOpHelper_epp sse_op_table6[256] = {
    [0x00] = SSSE3_OP(pshufb),
    [0x01] = SSSE3_OP(phaddw),
    [0x02] = SSSE3_OP(phaddd),
    [0x03] = SSSE3_OP(phaddsw),
    [0x04] = SSSE3_OP(pmaddubsw),
    [0x05] = SSSE3_OP(phsubw),
    [0x06] = SSSE3_OP(phsubd),
    [0x07] = SSSE3_OP(phsubsw),
    [0x08] = SSSE3_OP(psignb),
    [0x09] = SSSE3_OP(psignw),
    [0x0a] = SSSE3_OP(psignd),
    [0x0b] = SSSE3_OP(pmulhrsw),
    [0x10] = SSE41_OP(pblendvb),
    [0x14] = SSE41_OP(blendvps),
    [0x15] = SSE41_OP(blendvpd),
    [0x17] = SSE41_OP(ptest),
    [0x1c] = SSSE3_OP(pabsb),
    [0x1d] = SSSE3_OP(pabsw),
    [0x1e] = SSSE3_OP(pabsd),
    [0x20] = SSE41_OP(pmovsxbw),
    [0x21] = SSE41_OP(pmovsxbd),
    [0x22] = SSE41_OP(pmovsxbq),
    [0x23] = SSE41_OP(pmovsxwd),
    [0x24] = SSE41_OP(pmovsxwq),
    [0x25] = SSE41_OP(pmovsxdq),
    [0x28] = SSE41_OP(pmuldq),
    [0x29] = SSE41_OP(pcmpeqq),
    [0x2a] = SSE41_SPECIAL, /* movntqda */
    [0x2b] = SSE41_OP(packusdw),
    [0x30] = SSE41_OP(pmovzxbw),
    [0x31] = SSE41_OP(pmovzxbd),
    [0x32] = SSE41_OP(pmovzxbq),
    [0x33] = SSE41_OP(pmovzxwd),
    [0x34] = SSE41_OP(pmovzxwq),
    [0x35] = SSE41_OP(pmovzxdq),
    [0x37] = SSE42_OP(pcmpgtq),
    [0x38] = SSE41_OP(pminsb),
    [0x39] = SSE41_OP(pminsd),
    [0x3a] = SSE41_OP(pminuw),
    [0x3b] = SSE41_OP(pminud),
    [0x3c] = SSE41_OP(pmaxsb),
    [0x3d] = SSE41_OP(pmaxsd),
    [0x3e] = SSE41_OP(pmaxuw),
    [0x3f] = SSE41_OP(pmaxud),
    [0x40] = SSE41_OP(pmulld),
    [0x41] = SSE41_OP(phminposuw),
    [0xdb] = AESNI_OP(aesimc),
    [0xdc] = AESNI_OP(aesenc),
    [0xdd] = AESNI_OP(aesenclast),
    [0xde] = AESNI_OP(aesdec),
    [0xdf] = AESNI_OP(aesdeclast),
};

static const struct SSEOpHelper_eppi sse_op_table7[256] = {
    [0x08] = SSE41_OP(roundps),
    [0x09] = SSE41_OP(roundpd),
    [0x0a] = SSE41_OP(roundss),
    [0x0b] = SSE41_OP(roundsd),
    [0x0c] = SSE41_OP(blendps),
    [0x0d] = SSE41_OP(blendpd),
    [0x0e] = SSE41_OP(pblendw),
    [0x0f] = SSSE3_OP(palignr),
    [0x14] = SSE41_SPECIAL, /* pextrb */
    [0x15] = SSE41_SPECIAL, /* pextrw */
    [0x16] = SSE41_SPECIAL, /* pextrd/pextrq */
    [0x17] = SSE41_SPECIAL, /* extractps */
    [0x20] = SSE41_SPECIAL, /* pinsrb */
    [0x21] = SSE41_SPECIAL, /* insertps */
    [0x22] = SSE41_SPECIAL, /* pinsrd/pinsrq */
    [0x40] = SSE41_OP(dpps),
    [0x41] = SSE41_OP(dppd),
    [0x42] = SSE41_OP(mpsadbw),
    [0x44] = PCLMULQDQ_OP(pclmulqdq),
    [0x60] = SSE42_OP(pcmpestrm),
    [0x61] = SSE42_OP(pcmpestri),
    [0x62] = SSE42_OP(pcmpistrm),
    [0x63] = SSE42_OP(pcmpistri),
    [0xdf] = AESNI_OP(aeskeygenassist),
};

static void gen_sse(CPUX86State *env, DisasContext *s, int b,
                    target_ulong pc_start, int rex_r)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    int b1, op1_offset, op2_offset, is_xmm, val;
    int modrm, mod, rm, reg;
    SSEFunc_0_epp sse_fn_epp;
    SSEFunc_0_eppi sse_fn_eppi;
    SSEFunc_0_ppi sse_fn_ppi;
    SSEFunc_0_eppt sse_fn_eppt;
    MemOp ot;

    b &= 0xff;
    if (s->prefix & PREFIX_DATA)
        b1 = 1;
    else if (s->prefix & PREFIX_REPZ)
        b1 = 2;
    else if (s->prefix & PREFIX_REPNZ)
        b1 = 3;
    else
        b1 = 0;
    sse_fn_epp = sse_op_table1[b][b1];
    if (!sse_fn_epp) {
        goto unknown_op;
    }
    if ((b <= 0x5f && b >= 0x10) || b == 0xc6 || b == 0xc2) {
        is_xmm = 1;
    } else {
        if (b1 == 0) {
            /* MMX case */
            is_xmm = 0;
        } else {
            is_xmm = 1;
        }
    }
    /* simple MMX/SSE operation */
    if (s->flags & HF_TS_MASK) {
        gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        return;
    }
    if (s->flags & HF_EM_MASK) {
    illegal_op:
        gen_illegal_opcode(s);
        return;
    }
    if (is_xmm
        && !(s->flags & HF_OSFXSR_MASK)
        && ((b != 0x38 && b != 0x3a) || (s->prefix & PREFIX_DATA))) {
        goto unknown_op;
    }
    if (b == 0x0e) {
        if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW)) {
            /* If we were fully decoding this we might use illegal_op.  */
            goto unknown_op;
        }
        /* femms */
        gen_helper_emms(tcg_ctx, tcg_ctx->cpu_env);
        return;
    }
    if (b == 0x77) {
        /* emms */
        gen_helper_emms(tcg_ctx, tcg_ctx->cpu_env);
        return;
    }
    /* prepare MMX state (XXX: optimize by storing fptt and fptags in
       the static cpu state) */
    if (!is_xmm) {
        gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
    }

    modrm = x86_ldub_code(env, s);
    reg = ((modrm >> 3) & 7);
    if (is_xmm)
        reg |= rex_r;
    mod = (modrm >> 6) & 3;
    if (sse_fn_epp == SSE_SPECIAL) {
        b |= (b1 << 8);
        switch(b) {
        case 0x0e7: /* movntq */
            if (mod == 3) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            break;
        case 0x1e7: /* movntdq */
        case 0x02b: /* movntps */
        case 0x12b: /* movntps */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            gen_sto_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            break;
        case 0x3f0: /* lddqu */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            break;
        case 0x22b: /* movntss */
        case 0x32b: /* movntsd */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            if (b1 & 1) {
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                    xmm_regs[reg].ZMM_L(0)));
                gen_op_st_v(s, MO_32, s->T0, s->A0);
            }
            break;
        case 0x6e: /* movd mm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                              offsetof(CPUX86State, fpregs[reg].mmx));
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx));
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_movl_mm_T0_mmx(tcg_ctx, s->ptr0, s->tmp2_i32);
            }
            break;
        case 0x16e: /* movd xmm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg]));
                gen_helper_movq_mm_T0_xmm(tcg_ctx, s->ptr0, s->T0);
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg]));
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_movl_mm_T0_xmm(tcg_ctx, s->ptr0, s->tmp2_i32);
            }
            break;
        case 0x6f: /* movq mm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,fpregs[rm].mmx));
                tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
            }
            break;
        case 0x010: /* movups */
        case 0x110: /* movupd */
        case 0x028: /* movaps */
        case 0x128: /* movapd */
        case 0x16f: /* movdqa xmm, ea */
        case 0x26f: /* movdqu xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[reg]),
                            offsetof(CPUX86State,xmm_regs[rm]));
            }
            break;
        case 0x210: /* movss xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32, s->T0, s->A0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(1)));
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)));
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)));
            }
            break;
        case 0x310: /* movsd xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)));
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            break;
        case 0x012: /* movlps */
        case 0x112: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                /* movhlps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(1)));
            }
            break;
        case 0x212: /* movsldup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(0)));
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(2)));
            }
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(1)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(2)));
            break;
        case 0x312: /* movddup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
            break;
        case 0x016: /* movhps */
        case 0x116: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(1)));
            } else {
                /* movlhps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            break;
        case 0x216: /* movshdup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(1)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(1)));
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(3)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_L(3)));
            }
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(1)));
            gen_op_movl(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_L(2)),
                        offsetof(CPUX86State,xmm_regs[reg].ZMM_L(3)));
            break;
        case 0x178:
        case 0x378:
            {
                int bit_index, field_length;

                if (b1 == 1 && reg != 0)
                    goto illegal_op;
                field_length = x86_ldub_code(env, s) & 0x3F;
                bit_index = x86_ldub_code(env, s) & 0x3F;
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                    offsetof(CPUX86State,xmm_regs[reg]));
                if (b1 == 1)
                    gen_helper_extrq_i(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                       tcg_const_i32(tcg_ctx, bit_index),
                                       tcg_const_i32(tcg_ctx, field_length));
                else
                    gen_helper_insertq_i(tcg_ctx, tcg_ctx->cpu_env, s->ptr0,
                                         tcg_const_i32(tcg_ctx, bit_index),
                                         tcg_const_i32(tcg_ctx, field_length));
            }
            break;
        case 0x7e: /* movd ea, mm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx.MMX_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x17e: /* movd ea, xmm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                               offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x27e: /* movq xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            }
            gen_op_movq_env_0(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)));
            break;
        case 0x7f: /* movq ea, mm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                gen_op_movq(s, offsetof(CPUX86State, fpregs[rm].mmx),
                            offsetof(CPUX86State,fpregs[reg].mmx));
            }
            break;
        case 0x011: /* movups */
        case 0x111: /* movupd */
        case 0x029: /* movaps */
        case 0x129: /* movapd */
        case 0x17f: /* movdqa ea, xmm */
        case 0x27f: /* movdqu ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_sto_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movo(s, offsetof(CPUX86State, xmm_regs[rm]),
                            offsetof(CPUX86State,xmm_regs[reg]));
            }
            break;
        case 0x211: /* movss ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, xmm_regs[reg].ZMM_L(0)));
                gen_op_st_v(s, MO_32, s->T0, s->A0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(s, offsetof(CPUX86State, xmm_regs[rm].ZMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_L(0)));
            }
            break;
        case 0x311: /* movsd ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[rm].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
            }
            break;
        case 0x013: /* movlps */
        case 0x113: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x017: /* movhps */
        case 0x117: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(1)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x71: /* shift mm, im */
        case 0x72:
        case 0x73:
        case 0x171: /* shift xmm, im */
        case 0x172:
        case 0x173:
            if (b1 >= 2) {
                goto unknown_op;
            }
            val = x86_ldub_code(env, s);
            if (is_xmm) {
                tcg_gen_movi_tl(tcg_ctx, s->T0, val);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_t0.ZMM_L(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, xmm_t0.ZMM_L(1)));
                op1_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                tcg_gen_movi_tl(tcg_ctx, s->T0, val);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, mmx_t0.MMX_L(0)));
                tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, mmx_t0.MMX_L(1)));
                op1_offset = offsetof(CPUX86State,mmx_t0);
            }
            sse_fn_epp = sse_op_table2[((b - 1) & 3) * 8 +
                                       (((modrm >> 3)) & 7)][b1];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (is_xmm) {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op2_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op1_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        case 0x050: /* movmskps */
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskps(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            break;
        case 0x150: /* movmskpd */
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskpd(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            break;
        case 0x02a: /* cvtpi2ps */
        case 0x12a: /* cvtpi2pd */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            switch(b >> 8) {
            case 0x0:
                gen_helper_cvtpi2ps(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            default:
            case 0x1:
                gen_helper_cvtpi2pd(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            }
            break;
        case 0x22a: /* cvtsi2ss */
        case 0x32a: /* cvtsi2sd */
            ot = mo_64_32(s->dflag);
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            if (ot == MO_32) {
                SSEFunc_0_epi sse_fn_epi = sse_op_table3ai[(b >> 8) & 1];
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                sse_fn_epi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_0_epl sse_fn_epl = sse_op_table3aq[(b >> 8) & 1];
                sse_fn_epl(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->T0);
#else
                goto illegal_op;
#endif
            }
            break;
        case 0x02c: /* cvttps2pi */
        case 0x12c: /* cvttpd2pi */
        case 0x02d: /* cvtps2pi */
        case 0x12d: /* cvtpd2pi */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);
                gen_ldo_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            op1_offset = offsetof(CPUX86State,fpregs[reg & 7].mmx);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            switch(b) {
            case 0x02c:
                gen_helper_cvttps2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            case 0x12c:
                gen_helper_cvttpd2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            case 0x02d:
                gen_helper_cvtps2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            case 0x12d:
                gen_helper_cvtpd2pi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
                break;
            }
            break;
        case 0x22c: /* cvttss2si */
        case 0x32c: /* cvttsd2si */
        case 0x22d: /* cvtss2si */
        case 0x32d: /* cvtsd2si */
            ot = mo_64_32(s->dflag);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                if ((b >> 8) & 1) {
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.ZMM_Q(0)));
                } else {
                    gen_op_ld_v(s, MO_32, s->T0, s->A0);
                    tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State, xmm_t0.ZMM_L(0)));
                }
                op2_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op2_offset);
            if (ot == MO_32) {
                SSEFunc_i_ep sse_fn_i_ep =
                    sse_op_table3bi[((b >> 7) & 2) | (b & 1)];
                sse_fn_i_ep(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
                tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_l_ep sse_fn_l_ep =
                    sse_op_table3bq[((b >> 7) & 2) | (b & 1)];
                sse_fn_l_ep(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->ptr0);
#else
                goto illegal_op;
#endif
            }
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            break;
        case 0xc4: /* pinsrw */
        case 0x1c4:
            s->rip_offset = 1;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            val = x86_ldub_code(env, s);
            if (b1) {
                val &= 7;
                tcg_gen_st16_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State,xmm_regs[reg].ZMM_W(val)));
            } else {
                val &= 3;
                tcg_gen_st16_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State,fpregs[reg].mmx.MMX_W(val)));
            }
            break;
        case 0xc5: /* pextrw */
        case 0x1c5:
            if (mod != 3)
                goto illegal_op;
            ot = mo_64_32(s->dflag);
            val = x86_ldub_code(env, s);
            if (b1) {
                val &= 7;
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_ld16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State,xmm_regs[rm].ZMM_W(val)));
            } else {
                val &= 3;
                rm = (modrm & 7);
                tcg_gen_ld16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                offsetof(CPUX86State,fpregs[rm].mmx.MMX_W(val)));
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            break;
        case 0x1d6: /* movq ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].ZMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(s, offsetof(CPUX86State, xmm_regs[rm].ZMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].ZMM_Q(0)));
                gen_op_movq_env_0(s,
                                  offsetof(CPUX86State, xmm_regs[rm].ZMM_Q(1)));
            }
            break;
        case 0x2d6: /* movq2dq */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            rm = (modrm & 7);
            gen_op_movq(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(0)),
                        offsetof(CPUX86State,fpregs[rm].mmx));
            gen_op_movq_env_0(s, offsetof(CPUX86State, xmm_regs[reg].ZMM_Q(1)));
            break;
        case 0x3d6: /* movdq2q */
            gen_helper_enter_mmx(tcg_ctx, tcg_ctx->cpu_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_movq(s, offsetof(CPUX86State, fpregs[reg & 7].mmx),
                        offsetof(CPUX86State,xmm_regs[rm].ZMM_Q(0)));
            break;
        case 0xd7: /* pmovmskb */
        case 0x1d7:
            if (mod != 3)
                goto illegal_op;
            if (b1) {
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, xmm_regs[rm]));
                gen_helper_pmovmskb_xmm(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            } else {
                rm = (modrm & 7);
                tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, fpregs[rm].mmx));
                gen_helper_pmovmskb_mmx(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, s->ptr0);
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            break;

        case 0x138:
        case 0x038:
            b = modrm;
            if ((b & 0xf0) == 0xf0) {
                goto do_0f_38_fx;
            }
            modrm = x86_ldub_code(env, s);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto unknown_op;
            }

            sse_fn_epp = sse_op_table6[b].op[b1];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table6[b].ext_mask))
                goto illegal_op;

            if (b1) {
                op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,xmm_regs[rm | REX_B(s)]);
                } else {
                    op2_offset = offsetof(CPUX86State,xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    switch (b) {
                    case 0x20: case 0x30: /* pmovsxbw, pmovzxbw */
                    case 0x23: case 0x33: /* pmovsxwd, pmovzxwd */
                    case 0x25: case 0x35: /* pmovsxdq, pmovzxdq */
                        gen_ldq_env_A0(s, op2_offset +
                                        offsetof(ZMMReg, ZMM_Q(0)));
                        break;
                    case 0x21: case 0x31: /* pmovsxbd, pmovzxbd */
                    case 0x24: case 0x34: /* pmovsxwq, pmovzxwq */
                        tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, op2_offset +
                                        offsetof(ZMMReg, ZMM_L(0)));
                        break;
                    case 0x22: case 0x32: /* pmovsxbq, pmovzxbq */
                        tcg_gen_qemu_ld_tl(tcg_ctx, s->tmp0, s->A0,
                                           s->mem_index, MO_LEUW);
                        tcg_gen_st16_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_env, op2_offset +
                                        offsetof(ZMMReg, ZMM_W(0)));
                        break;
                    case 0x2a:            /* movntqda */
                        gen_ldo_env_A0(s, op1_offset);
                        return;
                    default:
                        gen_ldo_env_A0(s, op2_offset);
                    }
                }
            } else {
                op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
                } else {
                    op2_offset = offsetof(CPUX86State,mmx_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(s, op2_offset);
                }
            }
            if (sse_fn_epp == SSE_SPECIAL) {
                goto unknown_op;
            }

            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);

            if (b == 0x17) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            break;

        case 0x238:
        case 0x338:
        do_0f_38_fx:
            /* Various integer extensions at 0f 38 f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;

            switch (b) {
            case 0x3f0: /* crc32 Gd,Eb */
            case 0x3f1: /* crc32 Gd,Ey */
            do_crc32:
                if (!(s->cpuid_ext_features & CPUID_EXT_SSE42)) {
                    goto illegal_op;
                }
                if ((b & 0xff) == 0xf0) {
                    ot = MO_8;
                } else if (s->dflag != MO_64) {
                    ot = (s->prefix & PREFIX_DATA ? MO_16 : MO_32);
                } else {
                    ot = MO_64;
                }

                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[reg]);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                gen_helper_crc32(tcg_ctx, s->T0, s->tmp2_i32,
                                 s->T0, tcg_const_i32(tcg_ctx, 8 << ot));

                ot = mo_64_32(s->dflag);
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                break;

            case 0x1f0: /* crc32 or movbe */
            case 0x1f1:
                /* For these insns, the f3 prefix is supposed to have priority
                   over the 66 prefix, but that's not what we implement above
                   setting b1.  */
                if (s->prefix & PREFIX_REPNZ) {
                    goto do_crc32;
                }
                /* FALLTHRU */
            case 0x0f0: /* movbe Gy,My */
            case 0x0f1: /* movbe My,Gy */
                if (!(s->cpuid_ext_features & CPUID_EXT_MOVBE)) {
                    goto illegal_op;
                }
                if (s->dflag != MO_64) {
                    ot = (s->prefix & PREFIX_DATA ? MO_16 : MO_32);
                } else {
                    ot = MO_64;
                }

                gen_lea_modrm(env, s, modrm);
                if ((b & 1) == 0) {
                    tcg_gen_qemu_ld_tl(tcg_ctx, s->T0, s->A0,
                                       s->mem_index, ot | MO_BE);
                    gen_op_mov_reg_v(s, ot, reg, s->T0);
                } else {
                    tcg_gen_qemu_st_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->A0,
                                       s->mem_index, ot | MO_BE);
                }
                break;

            case 0x0f2: /* andn Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                tcg_gen_andc_tl(tcg_ctx, s->T0, s->T0, tcg_ctx->cpu_regs[s->vex_v]);
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                gen_op_update1_cc(s);
                set_cc_op(s, CC_OP_LOGICB + ot);
                break;

            case 0x0f7: /* bextr Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                {
                    TCGv bound, zero;

                    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                    /* Extract START, and shift the operand.
                       Shifts larger than operand size get zeros.  */
                    tcg_gen_ext8u_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[s->vex_v]);
                    tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, s->A0);

                    bound = tcg_const_tl(tcg_ctx, ot == MO_64 ? 63 : 31);
                    zero = tcg_const_tl(tcg_ctx, 0);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_LEU, s->T0, s->A0, bound,
                                       s->T0, zero);
                    tcg_temp_free(tcg_ctx, zero);

                    /* Extract the LEN into a mask.  Lengths larger than
                       operand size get all ones.  */
                    tcg_gen_extract_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[s->vex_v], 8, 8);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_LEU, s->A0, s->A0, bound,
                                       s->A0, bound);
                    tcg_temp_free(tcg_ctx, bound);
                    tcg_gen_movi_tl(tcg_ctx, s->T1, 1);
                    tcg_gen_shl_tl(tcg_ctx, s->T1, s->T1, s->A0);
                    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T1, 1);
                    tcg_gen_and_tl(tcg_ctx, s->T0, s->T0, s->T1);

                    gen_op_mov_reg_v(s, ot, reg, s->T0);
                    gen_op_update1_cc(s);
                    set_cc_op(s, CC_OP_LOGICB + ot);
                }
                break;

            case 0x0f5: /* bzhi Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                tcg_gen_ext8u_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                {
                    TCGv bound = tcg_const_tl(tcg_ctx, ot == MO_64 ? 63 : 31);
                    /* Note that since we're using BMILG (in order to get O
                       cleared) we need to store the inverse into C.  */
                    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_LT, tcg_ctx->cpu_cc_src,
                                       s->T1, bound);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_GT, s->T1, s->T1,
                                       bound, bound, s->T1);
                    tcg_temp_free(tcg_ctx, bound);
                }
                tcg_gen_movi_tl(tcg_ctx, s->A0, -1);
                tcg_gen_shl_tl(tcg_ctx, s->A0, s->A0, s->T1);
                tcg_gen_andc_tl(tcg_ctx, s->T0, s->T0, s->A0);
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                gen_op_update1_cc(s);
                set_cc_op(s, CC_OP_BMILGB + ot);
                break;

            case 0x3f6: /* mulx By, Gy, rdx, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                switch (ot) {
                default:
                    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, tcg_ctx->cpu_regs[R_EDX]);
                    tcg_gen_mulu2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                                      s->tmp2_i32, s->tmp3_i32);
                    tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[s->vex_v], s->tmp2_i32);
                    tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp3_i32);
                    break;
#ifdef TARGET_X86_64
                case MO_64:
                    tcg_gen_mulu2_i64(tcg_ctx, s->T0, s->T1,
                                      s->T0, tcg_ctx->cpu_regs[R_EDX]);
                    tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[s->vex_v], s->T0);
                    tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T1);
                    break;
#endif
                }
                break;

            case 0x3f5: /* pdep Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                /* Note that by zero-extending the mask operand, we
                   automatically handle zero-extending the result.  */
                if (ot == MO_64) {
                    tcg_gen_mov_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                }
                gen_helper_pdep(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T0, s->T1);
                break;

            case 0x2f5: /* pext Gy, By, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                /* Note that by zero-extending the mask operand, we
                   automatically handle zero-extending the result.  */
                if (ot == MO_64) {
                    tcg_gen_mov_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v]);
                }
                gen_helper_pext(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T0, s->T1);
                break;

            case 0x1f6: /* adcx Gy, Ey */
            case 0x2f6: /* adox Gy, Ey */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_ADX)) {
                    goto illegal_op;
                } else {
                    TCGv carry_in, carry_out, zero;
                    int end_op;

                    ot = mo_64_32(s->dflag);
                    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

                    /* Re-use the carry-out from a previous round.  */
                    carry_in = NULL;
                    carry_out = (b == 0x1f6 ? tcg_ctx->cpu_cc_dst : tcg_ctx->cpu_cc_src2);
                    switch (s->cc_op) {
                    case CC_OP_ADCX:
                        if (b == 0x1f6) {
                            carry_in = tcg_ctx->cpu_cc_dst;
                            end_op = CC_OP_ADCX;
                        } else {
                            end_op = CC_OP_ADCOX;
                        }
                        break;
                    case CC_OP_ADOX:
                        if (b == 0x1f6) {
                            end_op = CC_OP_ADCOX;
                        } else {
                            carry_in = tcg_ctx->cpu_cc_src2;
                            end_op = CC_OP_ADOX;
                        }
                        break;
                    case CC_OP_ADCOX:
                        end_op = CC_OP_ADCOX;
                        carry_in = carry_out;
                        break;
                    default:
                        end_op = (b == 0x1f6 ? CC_OP_ADCX : CC_OP_ADOX);
                        break;
                    }
                    /* If we can't reuse carry-out, get it out of EFLAGS.  */
                    if (!carry_in) {
                        if (s->cc_op != CC_OP_ADCX && s->cc_op != CC_OP_ADOX) {
                            gen_compute_eflags(s);
                        }
                        carry_in = s->tmp0;
                        tcg_gen_extract_tl(tcg_ctx, carry_in, tcg_ctx->cpu_cc_src,
                                           ctz32(b == 0x1f6 ? CC_C : CC_O), 1);
                    }

                    switch (ot) {
#ifdef TARGET_X86_64
                    case MO_32:
                        /* If we know TL is 64-bit, and we want a 32-bit
                           result, just do everything in 64-bit arithmetic.  */
                        tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], tcg_ctx->cpu_regs[reg]);
                        tcg_gen_ext32u_i64(tcg_ctx, s->T0, s->T0);
                        tcg_gen_add_i64(tcg_ctx, s->T0, s->T0, tcg_ctx->cpu_regs[reg]);
                        tcg_gen_add_i64(tcg_ctx, s->T0, s->T0, carry_in);
                        tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T0);
                        tcg_gen_shri_i64(tcg_ctx, carry_out, s->T0, 32);
                        break;
#endif
                    default:
                        /* Otherwise compute the carry-out in two steps.  */
                        zero = tcg_const_tl(tcg_ctx, 0);
                        tcg_gen_add2_tl(tcg_ctx, s->T0, carry_out,
                                        s->T0, zero,
                                        carry_in, zero);
                        tcg_gen_add2_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], carry_out,
                                        tcg_ctx->cpu_regs[reg], carry_out,
                                        s->T0, zero);
                        tcg_temp_free(tcg_ctx, zero);
                        break;
                    }
                    set_cc_op(s, end_op);
                }
                break;

            case 0x1f7: /* shlx Gy, Ey, By */
            case 0x2f7: /* sarx Gy, Ey, By */
            case 0x3f7: /* shrx Gy, Ey, By */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                if (ot == MO_64) {
                    tcg_gen_andi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v], 63);
                } else {
                    tcg_gen_andi_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[s->vex_v], 31);
                }
                if (b == 0x1f7) {
                    tcg_gen_shl_tl(tcg_ctx, s->T0, s->T0, s->T1);
                } else if (b == 0x2f7) {
                    if (ot != MO_64) {
                        tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
                    }
                    tcg_gen_sar_tl(tcg_ctx, s->T0, s->T0, s->T1);
                } else {
                    if (ot != MO_64) {
                        tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
                    }
                    tcg_gen_shr_tl(tcg_ctx, s->T0, s->T0, s->T1);
                }
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                break;

            case 0x0f3:
            case 0x1f3:
            case 0x2f3:
            case 0x3f3: /* Group 17 */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
                switch (reg & 7) {
                case 1: /* blsr By,Ey */
                    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T0, 1);
                    tcg_gen_and_tl(tcg_ctx, s->T0, s->T0, s->T1);
                    break;
                case 2: /* blsmsk By,Ey */
                    tcg_gen_subi_tl(tcg_ctx, s->T1, s->T0, 1);
                    tcg_gen_xor_tl(tcg_ctx, s->T0, s->T0, s->T1);
                    break;
                case 3: /* blsi By, Ey */
                    tcg_gen_neg_tl(tcg_ctx, s->T1, s->T0);
                    tcg_gen_and_tl(tcg_ctx, s->T0, s->T0, s->T1);
                    break;
                default:
                    goto unknown_op;
                }
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                gen_op_mov_reg_v(s, ot, s->vex_v, s->T0);
                set_cc_op(s, CC_OP_BMILGB + ot);
                break;

            default:
                goto unknown_op;
            }
            break;

        case 0x03a:
        case 0x13a:
            b = modrm;
            modrm = x86_ldub_code(env, s);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto unknown_op;
            }

            sse_fn_eppi = sse_op_table7[b].op[b1];
            if (!sse_fn_eppi) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table7[b].ext_mask))
                goto illegal_op;

            s->rip_offset = 1;

            if (sse_fn_eppi == SSE_SPECIAL) {
                ot = mo_64_32(s->dflag);
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3)
                    gen_lea_modrm(env, s, modrm);
                reg = ((modrm >> 3) & 7) | rex_r;
                val = x86_ldub_code(env, s);
                switch (b) {
                case 0x14: /* pextrb */
                    tcg_gen_ld8u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_B(val & 15)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(s, ot, rm, s->T0);
                    } else {
                        tcg_gen_qemu_st_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_UB);
                    }
                    break;
                case 0x15: /* pextrw */
                    tcg_gen_ld16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_W(val & 7)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(s, ot, rm, s->T0);
                    } else {
                        tcg_gen_qemu_st_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_LEUW);
                    }
                    break;
                case 0x16:
                    if (ot == MO_32) { /* pextrd */
                        tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(val & 3)));
                        if (mod == 3) {
                            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[rm], s->tmp2_i32);
                        } else {
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                        }
                    } else { /* pextrq */
#ifdef TARGET_X86_64
                        tcg_gen_ld_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_Q(val & 1)));
                        if (mod == 3) {
                            tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_regs[rm], s->tmp1_i64);
                        } else {
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                        }
#else
                        goto illegal_op;
#endif
                    }
                    break;
                case 0x17: /* extractps */
                    tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_L(val & 3)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(s, ot, rm, s->T0);
                    } else {
                        tcg_gen_qemu_st_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_LEUL);
                    }
                    break;
                case 0x20: /* pinsrb */
                    if (mod == 3) {
                        gen_op_mov_v_reg(s, MO_32, s->T0, rm);
                    } else {
                        tcg_gen_qemu_ld_tl(tcg_ctx, s->T0, s->A0,
                                           s->mem_index, MO_UB);
                    }
                    tcg_gen_st8_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].ZMM_B(val & 15)));
                    break;
                case 0x21: /* insertps */
                    if (mod == 3) {
                        tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,xmm_regs[rm]
                                                .ZMM_L((val >> 6) & 3)));
                    } else {
                        tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                    tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State,xmm_regs[reg]
                                            .ZMM_L((val >> 4) & 3)));
                    if ((val >> 0) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(0)));
                    if ((val >> 1) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(1)));
                    if ((val >> 2) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(2)));
                    if ((val >> 3) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        tcg_ctx->cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(3)));
                    break;
                case 0x22:
                    if (ot == MO_32) { /* pinsrd */
                        if (mod == 3) {
                            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[rm]);
                        } else {
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                        }
                        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_L(val & 3)));
                    } else { /* pinsrq */
#ifdef TARGET_X86_64
                        if (mod == 3) {
                            gen_op_mov_v_reg(s, ot, s->tmp1_i64, rm);
                        } else {
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                        }
                        tcg_gen_st_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].ZMM_Q(val & 1)));
#else
                        goto illegal_op;
#endif
                    }
                    break;
                }
                return;
            }

            if (b1) {
                op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,xmm_regs[rm | REX_B(s)]);
                } else {
                    op2_offset = offsetof(CPUX86State,xmm_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldo_env_A0(s, op2_offset);
                }
            } else {
                op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
                if (mod == 3) {
                    op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
                } else {
                    op2_offset = offsetof(CPUX86State,mmx_t0);
                    gen_lea_modrm(env, s, modrm);
                    gen_ldq_env_A0(s, op2_offset);
                }
            }
            val = x86_ldub_code(env, s);

            if ((b & 0xfc) == 0x60) { /* pcmpXstrX */
                set_cc_op(s, CC_OP_EFLAGS);

                if (s->dflag == MO_64) {
                    /* The helper must use entire 64-bit gp registers */
                    val |= 1 << 8;
                }
            }

            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_eppi(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, tcg_const_i32(tcg_ctx, val));
            break;

        case 0x33a:
            /* Various integer extensions at 0f 3a f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;

            switch (b) {
            case 0x3f0: /* rorx Gy,Ey, Ib */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI2)
                    || !(s->prefix & PREFIX_VEX)
                    || s->vex_l != 0) {
                    goto illegal_op;
                }
                ot = mo_64_32(s->dflag);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                b = x86_ldub_code(env, s);
                if (ot == MO_64) {
                    tcg_gen_rotri_tl(tcg_ctx, s->T0, s->T0, b & 63);
                } else {
                    tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                    tcg_gen_rotri_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, b & 31);
                    tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
                }
                gen_op_mov_reg_v(s, ot, reg, s->T0);
                break;

            default:
                goto unknown_op;
            }
            break;

        default:
        unknown_op:
            gen_unknown_opcode(env, s);
            return;
        }
    } else {
        /* generic MMX or SSE operation */
        switch(b) {
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
        case 0xc2: /* compare insns */
            s->rip_offset = 1;
            break;
        default:
            break;
        }
        if (is_xmm) {
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            if (mod != 3) {
                int sz = 4;

                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);

                switch (b) {
                case 0x50:
                case 0x51:
                case 0x52:
                case 0x53:
                case 0x54:
                case 0x55:
                case 0x56:
                case 0x57:
                case 0x58:
                case 0x59:
                case 0x5a:

                case 0x5c:
                case 0x5d:
                case 0x5e:
                case 0x5f:

                case 0xc2:
                    /* Most sse scalar operations.  */
                    if (b1 == 2) {
                        sz = 2;
                    } else if (b1 == 3) {
                        sz = 3;
                    }
                    break;

                case 0x2e:  /* ucomis[sd] */
                case 0x2f:  /* comis[sd] */
                    if (b1 == 0) {
                        sz = 2;
                    } else {
                        sz = 3;
                    }
                    break;
                }

                switch (sz) {
                case 2:
                    /* 32 bit access */
                    gen_op_ld_v(s, MO_32, s->T0, s->A0);
                    tcg_gen_st32_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State,xmm_t0.ZMM_L(0)));
                    break;
                case 3:
                    /* 64 bit access */
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.ZMM_D(0)));
                    break;
                default:
                    /* 128 bit access */
                    gen_ldo_env_A0(s, op2_offset);
                    break;
                }
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
        } else {
            op1_offset = offsetof(CPUX86State,fpregs[reg].mmx);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
        }
        switch(b) {
        case 0x0f: /* 3DNow! data insns */
            val = x86_ldub_code(env, s);
            sse_fn_epp = sse_op_table5[val];
            if (!sse_fn_epp) {
                goto unknown_op;
            }
            if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW)) {
                goto illegal_op;
            }
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
            val = x86_ldub_code(env, s);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_ppi = (SSEFunc_0_ppi)sse_fn_epp;
            sse_fn_ppi(tcg_ctx, s->ptr0, s->ptr1, tcg_const_i32(tcg_ctx, val));
            break;
        case 0xc2:
            /* compare insns */
            val = x86_ldub_code(env, s);
            if (val >= 8)
                goto unknown_op;
            sse_fn_epp = sse_op_table4[val][b1];

            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        case 0xf7:
            /* maskmov : we must prepare A0 */
            if (mod != 3)
                goto illegal_op;
            tcg_gen_mov_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EDI]);
            gen_extu(tcg_ctx, s->aflag, s->A0);
            gen_add_A0_ds_seg(s);

            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_eppt = (SSEFunc_0_eppt)sse_fn_epp;
            sse_fn_eppt(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1, s->A0);
            break;
        default:
            tcg_gen_addi_ptr(tcg_ctx, s->ptr0, tcg_ctx->cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, s->ptr1, tcg_ctx->cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, tcg_ctx->cpu_env, s->ptr0, s->ptr1);
            break;
        }
        if (b == 0x2e || b == 0x2f) {
            set_cc_op(s, CC_OP_EFLAGS);
        }
    }
}

// Unicorn: sync EFLAGS on demand
static void sync_eflags(DisasContext *s, TCGContext *tcg_ctx)
{
    gen_update_cc_op(s);
    gen_helper_read_eflags(tcg_ctx, s->T0, tcg_ctx->cpu_env);
    tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, eflags));
}

/* convert one instruction. s->base.is_jmp is set if the translation must
   be stopped. Return the next pc value */
static target_ulong disas_insn(DisasContext *s, CPUState *cpu)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CPUX86State *env = cpu->env_ptr;
    int b, prefixes;
    int shift;
    MemOp ot, aflag, dflag;
    int modrm, reg, rm, mod, op, opreg, val;
    target_ulong next_eip, tval;
    int rex_w, rex_r;
    target_ulong pc_start = s->base.pc_next;
    TCGOp *tcg_op, *prev_op = NULL;
    bool insn_hook = false;

    s->pc_start = tcg_ctx->pc_start = s->pc = pc_start;
    s->prefix = 0;

    s->uc = env->uc;

    // Unicorn: end address tells us to stop emulation
    if (uc_addr_is_exit(env->uc, s->pc)) {
        // imitate the HLT instruction
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_hlt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        s->base.is_jmp = DISAS_NORETURN;
        return s->pc;
    }

    // Unicorn: callback might need to access to EFLAGS,
    // or want to stop emulation immediately
    if (HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_CODE, pc_start)) {
        if (s->last_cc_op != s->cc_op) {
            sync_eflags(s, tcg_ctx);
            s->last_cc_op = s->cc_op;
        }

        // Sync PC in advance
        gen_jmp_im(s, pc_start);

        // save the last operand
        prev_op = tcg_last_op(tcg_ctx);
        insn_hook = true;
        gen_uc_tracecode(tcg_ctx, 0xf1f1f1f1, UC_HOOK_CODE_IDX, env->uc, pc_start);

        check_exit_request(tcg_ctx);
    }

    s->override = -1;

#ifdef TARGET_X86_64
    s->rex_x = 0;
    s->rex_b = 0;
    s->x86_64_hregs = false;
#endif
    s->rip_offset = 0; /* for relative ip address */
    s->vex_l = 0;
    s->vex_v = 0;
    if (sigsetjmp(s->jmpbuf, 0) != 0) {
        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        return s->pc;
    }

    prefixes = 0;
    rex_w = -1;
    rex_r = 0;

 next_byte:
    b = x86_ldub_code(env, s);
    /* Collect prefixes.  */
    switch (b) {
    case 0xf3:
        prefixes |= PREFIX_REPZ;
        goto next_byte;
    case 0xf2:
        prefixes |= PREFIX_REPNZ;
        goto next_byte;
    case 0xf0:
        prefixes |= PREFIX_LOCK;
        goto next_byte;
    case 0x2e:
        s->override = R_CS;
        goto next_byte;
    case 0x36:
        s->override = R_SS;
        goto next_byte;
    case 0x3e:
        s->override = R_DS;
        goto next_byte;
    case 0x26:
        s->override = R_ES;
        goto next_byte;
    case 0x64:
        s->override = R_FS;
        goto next_byte;
    case 0x65:
        s->override = R_GS;
        goto next_byte;
    case 0x66:
        prefixes |= PREFIX_DATA;
        goto next_byte;
    case 0x67:
        prefixes |= PREFIX_ADR;
        goto next_byte;
#ifdef TARGET_X86_64
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
        if (CODE64(s)) {
            /* REX prefix */
            rex_w = (b >> 3) & 1;
            rex_r = (b & 0x4) << 1;
            s->rex_x = (b & 0x2) << 2;
            REX_B(s) = (b & 0x1) << 3;
            /* select uniform byte register addressing */
            s->x86_64_hregs = true;
            goto next_byte;
        }
        break;
#endif
    case 0xc5: /* 2-byte VEX */
    case 0xc4: /* 3-byte VEX */
        /* VEX prefixes cannot be used except in 32-bit mode.
           Otherwise the instruction is LES or LDS.  */
        if (s->code32 && !s->vm86) {
            static const int pp_prefix[4] = {
                0, PREFIX_DATA, PREFIX_REPZ, PREFIX_REPNZ
            };
            int vex3, vex2 = x86_ldub_code(env, s);

            if (!CODE64(s) && (vex2 & 0xc0) != 0xc0) {
                /* 4.1.4.6: In 32-bit mode, bits [7:6] must be 11b,
                   otherwise the instruction is LES or LDS.  */
                s->pc--; /* rewind the advance_pc() x86_ldub_code() did */
                break;
            }

            /* 4.1.1-4.1.3: No preceding lock, 66, f2, f3, or rex prefixes. */
            if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ
                            | PREFIX_LOCK | PREFIX_DATA)) {
                goto illegal_op;
            }
#ifdef TARGET_X86_64
            if (s->x86_64_hregs) {
                goto illegal_op;
            }
#endif
            rex_r = (~vex2 >> 4) & 8;
            if (b == 0xc5) {
                /* 2-byte VEX prefix: RVVVVlpp, implied 0f leading opcode byte */
                vex3 = vex2;
                b = x86_ldub_code(env, s) | 0x100;
            } else {
                /* 3-byte VEX prefix: RXBmmmmm wVVVVlpp */
#ifdef TARGET_X86_64
                s->rex_x = (~vex2 >> 3) & 8;
                s->rex_b = (~vex2 >> 2) & 8;
#endif
                vex3 = x86_ldub_code(env, s);
                rex_w = (vex3 >> 7) & 1;
                switch (vex2 & 0x1f) {
                case 0x01: /* Implied 0f leading opcode bytes.  */
                    b = x86_ldub_code(env, s) | 0x100;
                    break;
                case 0x02: /* Implied 0f 38 leading opcode bytes.  */
                    b = 0x138;
                    break;
                case 0x03: /* Implied 0f 3a leading opcode bytes.  */
                    b = 0x13a;
                    break;
                default:   /* Reserved for future use.  */
                    goto unknown_op;
                }
            }
            s->vex_v = (~vex3 >> 3) & 0xf;
            s->vex_l = (vex3 >> 2) & 1;
            prefixes |= pp_prefix[vex3 & 3] | PREFIX_VEX;
        }
        break;
    }

    /* Post-process prefixes.  */
    if (CODE64(s)) {
        /* In 64-bit mode, the default data size is 32-bit.  Select 64-bit
           data with rex_w, and 16-bit data with 0x66; rex_w takes precedence
           over 0x66 if both are present.  */
        dflag = (rex_w > 0 ? MO_64 : prefixes & PREFIX_DATA ? MO_16 : MO_32);
        /* In 64-bit mode, 0x67 selects 32-bit addressing.  */
        aflag = (prefixes & PREFIX_ADR ? MO_32 : MO_64);
    } else {
        /* In 16/32-bit mode, 0x66 selects the opposite data size.  */
        if (s->code32 ^ ((prefixes & PREFIX_DATA) != 0)) {
            dflag = MO_32;
        } else {
            dflag = MO_16;
        }
        /* In 16/32-bit mode, 0x67 selects the opposite addressing.  */
        if (s->code32 ^ ((prefixes & PREFIX_ADR) != 0)) {
            aflag = MO_32;
        }  else {
            aflag = MO_16;
        }
    }

    s->prefix = prefixes;
    s->aflag = aflag;
    s->dflag = dflag;

    /* now check op code */
 reswitch:
    switch(b) {
    case 0x0f:
        /**************************/
        /* extended op code */
        b = x86_ldub_code(env, s) | 0x100;
        goto reswitch;

        /**************************/
        /* arith & logic */
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:

    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:

    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:

    case 0x18:
    case 0x19:
    case 0x1a:
    case 0x1b:
    case 0x1c:
    case 0x1d:

    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x24:
    case 0x25:

    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
    case 0x2c:
    case 0x2d:

    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:

    case 0x38:
    case 0x39:
    case 0x3a:
    case 0x3b:
    case 0x3c:
    case 0x3d:
        {
            int op, f, val;
            op = (b >> 3) & 7;
            f = (b >> 1) & 3;

            ot = mo_b_d(b, dflag);

            switch(f) {
            case 0: /* OP Ev, Gv */
                modrm = x86_ldub_code(env, s);
                reg = ((modrm >> 3) & 7) | rex_r;
                mod = (modrm >> 6) & 3;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    opreg = OR_TMP0;
                } else if (op == OP_XORL && rm == reg) {
                xor_zero:
                    /* xor reg, reg optimisation */
                    set_cc_op(s, CC_OP_CLR);
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                    gen_op_mov_reg_v(s, ot, reg, s->T0);
                    break;
                } else {
                    opreg = rm;
                }
                gen_op_mov_v_reg(s, ot, s->T1, reg);
                gen_op(s, op, ot, opreg);
                break;
            case 1: /* OP Gv, Ev */
                modrm = x86_ldub_code(env, s);
                mod = (modrm >> 6) & 3;
                reg = ((modrm >> 3) & 7) | rex_r;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, s->T1, s->A0);
                } else if (op == OP_XORL && rm == reg) {
                    goto xor_zero;
                } else {
                    gen_op_mov_v_reg(s, ot, s->T1, rm);
                }
                gen_op(s, op, ot, reg);
                break;
            case 2: /* OP A, Iv */
                val = insn_get(env, s, ot);
                tcg_gen_movi_tl(tcg_ctx, s->T1, val);
                gen_op(s, op, ot, OR_EAX);
                break;
            }
        }
        break;

    case 0x82:
        if (CODE64(s))
            goto illegal_op;
        /* fall through */
    case 0x80: /* GRP1 */
    case 0x81:
    case 0x83:
        {
            int val;

            ot = mo_b_d(b, dflag);

            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);
            op = (modrm >> 3) & 7;

            if (mod != 3) {
                if (b == 0x83)
                    s->rip_offset = 1;
                else
                    s->rip_offset = insn_const_size(ot);
                gen_lea_modrm(env, s, modrm);
                opreg = OR_TMP0;
            } else {
                opreg = rm;
            }

            switch(b) {
            default:
            case 0x80:
            case 0x81:
            case 0x82:
                val = insn_get(env, s, ot);
                break;
            case 0x83:
                val = (int8_t)insn_get(env, s, MO_8);
                break;
            }
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
            gen_op(s, op, ot, opreg);
        }
        break;

        /**************************/
        /* inc, dec, and other misc arith */
    case 0x40: /* inc Gv */
    case 0x41: /* inc Gv */
    case 0x42: /* inc Gv */
    case 0x43: /* inc Gv */
    case 0x44: /* inc Gv */
    case 0x45: /* inc Gv */
    case 0x46: /* inc Gv */
    case 0x47: /* inc Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), 1);
        break;
    case 0x48: /* dec Gv */
    case 0x49: /* dec Gv */
    case 0x4a: /* dec Gv */
    case 0x4b: /* dec Gv */
    case 0x4c: /* dec Gv */
    case 0x4d: /* dec Gv */
    case 0x4e: /* dec Gv */
    case 0x4f: /* dec Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), -1);
        break;
    case 0xf6: /* GRP3 */
    case 0xf7:
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (mod != 3) {
            if (op == 0) {
                s->rip_offset = insn_const_size(ot);
            }
            gen_lea_modrm(env, s, modrm);
            /* For those below that handle locked memory, don't load here.  */
            if (!(s->prefix & PREFIX_LOCK)
                || op != 2) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
            }
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }

        switch(op) {
        case 0: /* test */
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
            gen_op_testl_T0_T1_cc(s);
            set_cc_op(s, CC_OP_LOGICB + ot);
            break;
        case 2: /* not */
            if (s->prefix & PREFIX_LOCK) {
                if (mod == 3) {
                    goto illegal_op;
                }
                tcg_gen_movi_tl(tcg_ctx, s->T0, ~0);
                tcg_gen_atomic_xor_fetch_tl(tcg_ctx, s->T0, s->A0, s->T0,
                                            s->mem_index, ot | MO_LE);
            } else {
                tcg_gen_not_tl(tcg_ctx, s->T0, s->T0);
                if (mod != 3) {
                    gen_op_st_v(s, ot, s->T0, s->A0);
                } else {
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                }
            }
            break;
        case 3: /* neg */
            if (s->prefix & PREFIX_LOCK) {
                TCGLabel *label1;
                TCGv a0, t0, t1, t2;

                if (mod == 3) {
                    goto illegal_op;
                }
                a0 = tcg_temp_local_new(tcg_ctx);
                t0 = tcg_temp_local_new(tcg_ctx);
                label1 = gen_new_label(tcg_ctx);

                tcg_gen_mov_tl(tcg_ctx, a0, s->A0);
                tcg_gen_mov_tl(tcg_ctx, t0, s->T0);

                gen_set_label(tcg_ctx, label1);
                t1 = tcg_temp_new(tcg_ctx);
                t2 = tcg_temp_new(tcg_ctx);
                tcg_gen_mov_tl(tcg_ctx, t2, t0);
                tcg_gen_neg_tl(tcg_ctx, t1, t0);
                tcg_gen_atomic_cmpxchg_tl(tcg_ctx, t0, a0, t0, t1,
                                          s->mem_index, ot | MO_LE);
                tcg_temp_free(tcg_ctx, t1);
                tcg_gen_brcond_tl(tcg_ctx, TCG_COND_NE, t0, t2, label1);

                tcg_temp_free(tcg_ctx, t2);
                tcg_temp_free(tcg_ctx, a0);
                tcg_gen_mov_tl(tcg_ctx, s->T0, t0);
                tcg_temp_free(tcg_ctx, t0);
            } else {
                tcg_gen_neg_tl(tcg_ctx, s->T0, s->T0);
                if (mod != 3) {
                    gen_op_st_v(s, ot, s->T0, s->A0);
                } else {
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                }
            }
            gen_op_update_neg_cc(s);
            set_cc_op(s, CC_OP_SUBB + ot);
            break;
        case 4: /* mul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(s, MO_8, s->T1, R_EAX);
                tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext8u_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, 0xff00);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(s, MO_16, s->T1, R_EAX);
                tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext16u_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, 16);
                gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mulu2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                                  s->tmp2_i32, s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], s->tmp2_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EDX], s->tmp3_i32);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_mulu2_i64(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX],
                                  s->T0, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 5: /* imul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(s, MO_8, s->T1, R_EAX);
                tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext8s_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_ext8s_tl(tcg_ctx, s->tmp0, s->T0);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, s->tmp0);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(s, MO_16, s->T1, R_EAX);
                tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
                tcg_gen_ext16s_tl(tcg_ctx, s->T1, s->T1);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
                tcg_gen_ext16s_tl(tcg_ctx, s->tmp0, s->T0);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, s->tmp0);
                tcg_gen_shri_tl(tcg_ctx, s->T0, s->T0, 16);
                gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_muls2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                                  s->tmp2_i32, s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], s->tmp2_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EDX], s->tmp3_i32);
                tcg_gen_sari_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 31);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_sub_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp2_i32);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_muls2_i64(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX],
                                  s->T0, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[R_EAX]);
                tcg_gen_sari_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EAX], 63);
                tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 6: /* div */
            switch(ot) {
            case MO_8:
                gen_helper_divb_AL(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            case MO_16:
                gen_helper_divw_AX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            default:
            case MO_32:
                gen_helper_divl_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_helper_divq_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#endif
            }
            break;
        case 7: /* idiv */
            switch(ot) {
            case MO_8:
                gen_helper_idivb_AL(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            case MO_16:
                gen_helper_idivw_AX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
            default:
            case MO_32:
                gen_helper_idivl_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_helper_idivq_EAX(tcg_ctx, tcg_ctx->cpu_env, s->T0);
                break;
#endif
            }
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0xfe: /* GRP4 */
    case 0xff: /* GRP5 */
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (op >= 2 && b == 0xfe) {
            goto unknown_op;
        }
        if (CODE64(s)) {
            if (op == 2 || op == 4) {
                /* operand size for jumps is 64 bit */
                ot = MO_64;
            } else if (op == 3 || op == 5) {
                ot = dflag != MO_16 ? MO_32 + (rex_w == 1) : MO_16;
            } else if (op == 6) {
                /* default push size is 64 bit */
                ot = mo_pushpop(s, dflag);
            }
        }
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            if (op >= 2 && op != 3 && op != 5)
                gen_op_ld_v(s, ot, s->T0, s->A0);
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }

        switch(op) {
        case 0: /* inc Ev */
            if (mod != 3)
                opreg = OR_TMP0;
            else
                opreg = rm;
            gen_inc(s, ot, opreg, 1);
            break;
        case 1: /* dec Ev */
            if (mod != 3)
                opreg = OR_TMP0;
            else
                opreg = rm;
            gen_inc(s, ot, opreg, -1);
            break;
        case 2: /* call Ev */
            /* XXX: optimize if memory (no 'and' is necessary) */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
            }
            next_eip = s->pc - s->cs_base;
            tcg_gen_movi_tl(tcg_ctx, s->T1, next_eip);
            gen_push_v(s, s->T1);
            gen_op_jmp_v(tcg_ctx, s->T0);
            gen_bnd_jmp(s);
            gen_jr(s, s->T0);
            break;
        case 3: /* lcall Ev */
            gen_op_ld_v(s, ot, s->T1, s->A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, s->T0, s->A0);
        do_lcall:
            if (s->pe && !s->vm86) {
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_lcall_protected(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T1,
                                           tcg_const_i32(tcg_ctx, dflag - 1),
                                           tcg_const_tl(tcg_ctx, s->pc - s->cs_base));
            } else {
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_lcall_real(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T1,
                                      tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, s->pc - s->cs_base));
            }
            tcg_gen_ld_tl(tcg_ctx, s->tmp4, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));
            gen_jr(s, s->tmp4);
            break;
        case 4: /* jmp Ev */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
            }
            gen_op_jmp_v(tcg_ctx, s->T0);
            gen_bnd_jmp(s);
            gen_jr(s, s->T0);
            break;
        case 5: /* ljmp Ev */
            gen_op_ld_v(s, ot, s->T1, s->A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, s->T0, s->A0);
        do_ljmp:
            if (s->pe && !s->vm86) {
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_ljmp_protected(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T1,
                                          tcg_const_tl(tcg_ctx, s->pc - s->cs_base));
            } else {
                gen_op_movl_seg_T0_vm(s, R_CS);
                gen_op_jmp_v(tcg_ctx, s->T1);
            }
            tcg_gen_ld_tl(tcg_ctx, s->tmp4, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));
            gen_jr(s, s->tmp4);
            break;
        case 6: /* push Ev */
            gen_push_v(s, s->T0);
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0x84: /* test Ev, Gv */
    case 0x85:
        ot = mo_b_d(b, dflag);

        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_v_reg(s, ot, s->T1, reg);
        gen_op_testl_T0_T1_cc(s);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;

    case 0xa8: /* test eAX, Iv */
    case 0xa9:
        ot = mo_b_d(b, dflag);
        val = insn_get(env, s, ot);

        gen_op_mov_v_reg(s, ot, s->T0, OR_EAX);
        tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        gen_op_testl_T0_T1_cc(s);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;

    case 0x98: /* CWDE/CBW */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(s, MO_32, s->T0, R_EAX);
            tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_64, R_EAX, s->T0);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(s, MO_16, s->T0, R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_32, R_EAX, s->T0);
            break;
        case MO_16:
            gen_op_mov_v_reg(s, MO_8, s->T0, R_EAX);
            tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x99: /* CDQ/CWD */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(s, MO_64, s->T0, R_EAX);
            tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, 63);
            gen_op_mov_reg_v(s, MO_64, R_EDX, s->T0);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(s, MO_32, s->T0, R_EAX);
            tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, 31);
            gen_op_mov_reg_v(s, MO_32, R_EDX, s->T0);
            break;
        case MO_16:
            gen_op_mov_v_reg(s, MO_16, s->T0, R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_sari_tl(tcg_ctx, s->T0, s->T0, 15);
            gen_op_mov_reg_v(s, MO_16, R_EDX, s->T0);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x1af: /* imul Gv, Ev */
    case 0x69: /* imul Gv, Ev, I */
    case 0x6b:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (b == 0x69)
            s->rip_offset = insn_const_size(ot);
        else if (b == 0x6b)
            s->rip_offset = 1;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        if (b == 0x69) {
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        } else if (b == 0x6b) {
            val = (int8_t)insn_get(env, s, MO_8);
            tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        } else {
            gen_op_mov_v_reg(s, ot, s->T1, reg);
        }
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_64:
            tcg_gen_muls2_i64(tcg_ctx, tcg_ctx->cpu_regs[reg], s->T1, s->T0, s->T1);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[reg]);
            tcg_gen_sari_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_dst, 63);
            tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, s->T1);
            break;
#endif
        case MO_32:
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
            tcg_gen_muls2_i32(tcg_ctx, s->tmp2_i32, s->tmp3_i32,
                              s->tmp2_i32, s->tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_regs[reg], s->tmp2_i32);
            tcg_gen_sari_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, 31);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, tcg_ctx->cpu_regs[reg]);
            tcg_gen_sub_i32(tcg_ctx, s->tmp2_i32, s->tmp2_i32, s->tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp2_i32);
            break;
        default:
            tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_ext16s_tl(tcg_ctx, s->T1, s->T1);
            /* XXX: use 32 bit mul which could be faster */
            tcg_gen_mul_tl(tcg_ctx, s->T0, s->T0, s->T1);
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
            tcg_gen_ext16s_tl(tcg_ctx, s->tmp0, s->T0);
            tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0, s->tmp0);
            gen_op_mov_reg_v(s, ot, reg, s->T0);
            break;
        }
        set_cc_op(s, CC_OP_MULB + ot);
        break;
    case 0x1c0:
    case 0x1c1: /* xadd Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        gen_op_mov_v_reg(s, ot, s->T0, reg);
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_v_reg(s, ot, s->T1, rm);
            tcg_gen_add_tl(tcg_ctx, s->T0, s->T0, s->T1);
            gen_op_mov_reg_v(s, ot, reg, s->T1);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
        } else {
            gen_lea_modrm(env, s, modrm);
            if (s->prefix & PREFIX_LOCK) {
                tcg_gen_atomic_fetch_add_tl(tcg_ctx, s->T1, s->A0, s->T0,
                                            s->mem_index, ot | MO_LE);
                tcg_gen_add_tl(tcg_ctx, s->T0, s->T0, s->T1);
            } else {
                gen_op_ld_v(s, ot, s->T1, s->A0);
                tcg_gen_add_tl(tcg_ctx, s->T0, s->T0, s->T1);
                gen_op_st_v(s, ot, s->T0, s->A0);
            }
            gen_op_mov_reg_v(s, ot, reg, s->T1);
        }
        gen_op_update2_cc(s);
        set_cc_op(s, CC_OP_ADDB + ot);
        break;
    case 0x1b0:
    case 0x1b1: /* cmpxchg Ev, Gv */
        {
            TCGv oldv, newv, cmpv;

            ot = mo_b_d(b, dflag);
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            oldv = tcg_temp_new(tcg_ctx);
            newv = tcg_temp_new(tcg_ctx);
            cmpv = tcg_temp_new(tcg_ctx);
            gen_op_mov_v_reg(s, ot, newv, reg);
            tcg_gen_mov_tl(tcg_ctx, cmpv, tcg_ctx->cpu_regs[R_EAX]);

            if (s->prefix & PREFIX_LOCK) {
                if (mod == 3) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                tcg_gen_atomic_cmpxchg_tl(tcg_ctx, oldv, s->A0, cmpv, newv,
                                          s->mem_index, ot | MO_LE);
                gen_op_mov_reg_v(s, ot, R_EAX, oldv);
            } else {
                if (mod == 3) {
                    rm = (modrm & 7) | REX_B(s);
                    gen_op_mov_v_reg(s, ot, oldv, rm);
                } else {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, oldv, s->A0);
                    rm = 0; /* avoid warning */
                }
                gen_extu(tcg_ctx, ot, oldv);
                gen_extu(tcg_ctx, ot, cmpv);
                /* store value = (old == cmp ? new : old);  */
                tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, newv, oldv, cmpv, newv, oldv);
                if (mod == 3) {
                    gen_op_mov_reg_v(s, ot, R_EAX, oldv);
                    gen_op_mov_reg_v(s, ot, rm, newv);
                } else {
                    /* Perform an unconditional store cycle like physical cpu;
                       must be before changing accumulator to ensure
                       idempotency if the store faults and the instruction
                       is restarted */
                    gen_op_st_v(s, ot, newv, s->A0);
                    gen_op_mov_reg_v(s, ot, R_EAX, oldv);
                }
            }
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, oldv);
            tcg_gen_mov_tl(tcg_ctx, s->cc_srcT, cmpv);
            tcg_gen_sub_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, cmpv, oldv);
            set_cc_op(s, CC_OP_SUBB + ot);
            tcg_temp_free(tcg_ctx, oldv);
            tcg_temp_free(tcg_ctx, newv);
            tcg_temp_free(tcg_ctx, cmpv);
        }
        break;
    case 0x1c7: /* cmpxchg8b */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        switch ((modrm >> 3) & 7) {
        case 1: /* CMPXCHG8, CMPXCHG16 */
            if (mod == 3) {
                goto illegal_op;
            }
#ifdef TARGET_X86_64
            if (dflag == MO_64) {
                if (!(s->cpuid_ext_features & CPUID_EXT_CX16)) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                if ((s->prefix & PREFIX_LOCK) &&
                    (tb_cflags(s->base.tb) & CF_PARALLEL)) {
                    gen_helper_cmpxchg16b(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                } else {
                    gen_helper_cmpxchg16b_unlocked(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                }
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            }
#endif        
            if (!(s->cpuid_features & CPUID_CX8)) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            if ((s->prefix & PREFIX_LOCK) &&
                (tb_cflags(s->base.tb) & CF_PARALLEL)) {
                gen_helper_cmpxchg8b(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            } else {
                gen_helper_cmpxchg8b_unlocked(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            }
            set_cc_op(s, CC_OP_EFLAGS);
            break;

        case 7: /* RDSEED */
        case 6: /* RDRAND */
            if (mod != 3 ||
                (s->prefix & (PREFIX_LOCK | PREFIX_REPZ | PREFIX_REPNZ)) ||
                !(s->cpuid_ext_features & CPUID_EXT_RDRAND)) {
                goto illegal_op;
            }
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_io_start(tcg_ctx);
            }
            gen_helper_rdrand(tcg_ctx, s->T0, tcg_ctx->cpu_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(s, dflag, rm, s->T0);
            set_cc_op(s, CC_OP_EFLAGS);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
            break;

        default:
            goto illegal_op;
        }
        break;

        /**************************/
        /* push/pop */
    case 0x50: /* push */
    case 0x51: /* push */
    case 0x52: /* push */
    case 0x53: /* push */
    case 0x54: /* push */
    case 0x55: /* push */
    case 0x56: /* push */
    case 0x57: /* push */
        gen_op_mov_v_reg(s, MO_32, s->T0, (b & 7) | REX_B(s));
        gen_push_v(s, s->T0);
        break;
    case 0x58: /* pop */
    case 0x59: /* pop */
    case 0x5a: /* pop */
    case 0x5b: /* pop */
    case 0x5c: /* pop */
    case 0x5d: /* pop */
    case 0x5e: /* pop */
    case 0x5f: /* pop */
        ot = gen_pop_T0(s);
        /* NOTE: order is important for pop %sp */
        gen_pop_update(s, ot);
        gen_op_mov_reg_v(s, ot, (b & 7) | REX_B(s), s->T0);
        break;
    case 0x60: /* pusha */
        if (CODE64(s))
            goto illegal_op;
        gen_pusha(s);
        break;
    case 0x61: /* popa */
        if (CODE64(s))
            goto illegal_op;
        gen_popa(s);
        break;
    case 0x68: /* push Iv */
    case 0x6a:
        ot = mo_pushpop(s, dflag);
        if (b == 0x68)
            val = insn_get(env, s, ot);
        else
            val = (int8_t)insn_get(env, s, MO_8);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_push_v(s, s->T0);
        break;
    case 0x8f: /* pop Ev */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        ot = gen_pop_T0(s);
        if (mod == 3) {
            /* NOTE: order is important for pop %sp */
            gen_pop_update(s, ot);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
        } else {
            /* NOTE: order is important too for MMU exceptions */
            s->popl_esp_hack = 1 << ot;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            s->popl_esp_hack = 0;
            gen_pop_update(s, ot);
        }
        break;
    case 0xc8: /* enter */
        {
            int level;
            val = x86_lduw_code(env, s);
            level = x86_ldub_code(env, s);
            gen_enter(s, val, level);
        }
        break;
    case 0xc9: /* leave */
        gen_leave(s);
        break;
    case 0x06: /* push es */
    case 0x0e: /* push cs */
    case 0x16: /* push ss */
    case 0x1e: /* push ds */
        if (CODE64(s))
            goto illegal_op;
        gen_op_movl_T0_seg(s, b >> 3);
        gen_push_v(s, s->T0);
        break;
    case 0x1a0: /* push fs */
    case 0x1a8: /* push gs */
        gen_op_movl_T0_seg(s, (b >> 3) & 7);
        gen_push_v(s, s->T0);
        break;
    case 0x07: /* pop es */
    case 0x17: /* pop ss */
    case 0x1f: /* pop ds */
        if (CODE64(s))
            goto illegal_op;
        reg = b >> 3;
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, reg);
        gen_pop_update(s, ot);
        /* Note that reg == R_SS in gen_movl_seg_T0 always sets is_jmp.  */
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            if (reg == R_SS) {
                s->tf = 0;
                gen_eob_inhibit_irq(s, true);
            } else {
                gen_eob(s);
            }
        }
        break;
    case 0x1a1: /* pop fs */
    case 0x1a9: /* pop gs */
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, (b >> 3) & 7);
        gen_pop_update(s, ot);
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /**************************/
        /* mov */
    case 0x88:
    case 0x89: /* mov Gv, Ev */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0xc6:
    case 0xc7: /* mov Ev, Iv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | rex_r;
        if (mod != 3) {
            if (reg != 0)
                goto illegal_op;
            s->rip_offset = insn_const_size(ot);
            gen_lea_modrm(env, s, modrm);
        } else {
            if (reg != 0 && reg != 7)
                goto illegal_op;
        }
        val = insn_get(env, s, ot);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        if (mod != 3) {
            gen_op_st_v(s, ot, s->T0, s->A0);
        } else {
            gen_op_mov_reg_v(s, ot, (modrm & 7) | REX_B(s), s->T0);
        }
        break;
    case 0x8a:
    case 0x8b: /* mov Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_reg_v(s, ot, reg, s->T0);
        break;
    case 0x8e: /* mov seg, Gv */
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        if (reg >= 6 || reg == R_CS)
            goto illegal_op;
        gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
        gen_movl_seg_T0(s, reg);
        /* Note that reg == R_SS in gen_movl_seg_T0 always sets is_jmp.  */
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            if (reg == R_SS) {
                s->tf = 0;
                gen_eob_inhibit_irq(s, true);
            } else {
                gen_eob(s);
            }
        }
        break;
    case 0x8c: /* mov Gv, seg */
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (reg >= 6)
            goto illegal_op;
        gen_op_movl_T0_seg(s, reg);
        ot = mod == 3 ? dflag : MO_16;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
        break;

    case 0x1b6: /* movzbS Gv, Eb */
    case 0x1b7: /* movzwS Gv, Eb */
    case 0x1be: /* movsbS Gv, Eb */
    case 0x1bf: /* movswS Gv, Eb */
        {
            MemOp d_ot;
            MemOp s_ot;

            /* d_ot is the size of destination */
            d_ot = dflag;
            /* ot is the size of source */
            ot = (b & 1) + MO_8;
            /* s_ot is the sign+size of source */
            s_ot = b & 8 ? MO_SIGN | ot : ot;

            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                if (s_ot == MO_SB && byte_reg_is_xH(s, rm)) {
                    tcg_gen_sextract_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[rm - 4], 8, 8);
                } else {
                    gen_op_mov_v_reg(s, ot, s->T0, rm);
                    switch (s_ot) {
                    case MO_UB:
                        tcg_gen_ext8u_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    case MO_SB:
                        tcg_gen_ext8s_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    case MO_UW:
                        tcg_gen_ext16u_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    default:
                    case MO_SW:
                        tcg_gen_ext16s_tl(tcg_ctx, s->T0, s->T0);
                        break;
                    }
                }
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, s_ot, s->T0, s->A0);
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            }
        }
        break;

    case 0x8d: /* lea */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        {
            AddressParts a = gen_lea_modrm_0(env, s, modrm);
            TCGv ea = gen_lea_modrm_1(s, a);
            gen_lea_v_seg(s, s->aflag, ea, -1, -1);
            gen_op_mov_reg_v(s, dflag, reg, s->A0);
        }
        break;

    case 0xa0: /* mov EAX, Ov */
    case 0xa1:
    case 0xa2: /* mov Ov, EAX */
    case 0xa3:
        {
            target_ulong offset_addr;

            ot = mo_b_d(b, dflag);
            switch (s->aflag) {
#ifdef TARGET_X86_64
            case MO_64:
                offset_addr = x86_ldq_code(env, s);
                break;
#endif
            default:
                offset_addr = insn_get(env, s, s->aflag);
                break;
            }
            tcg_gen_movi_tl(tcg_ctx, s->A0, offset_addr);
            gen_add_A0_ds_seg(s);
            if ((b & 2) == 0) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
                gen_op_mov_reg_v(s, ot, R_EAX, s->T0);
            } else {
                gen_op_mov_v_reg(s, ot, s->T0, R_EAX);
                gen_op_st_v(s, ot, s->T0, s->A0);
            }
        }
        break;
    case 0xd7: /* xlat */
        tcg_gen_mov_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EBX]);
        tcg_gen_ext8u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EAX]);
        tcg_gen_add_tl(tcg_ctx, s->A0, s->A0, s->T0);
        gen_extu(tcg_ctx, s->aflag, s->A0);
        gen_add_A0_ds_seg(s);
        gen_op_ld_v(s, MO_8, s->T0, s->A0);
        gen_op_mov_reg_v(s, MO_8, R_EAX, s->T0);
        break;
    case 0xb0: /* mov R, Ib */
    case 0xb1: /* mov R, Ib */
    case 0xb2: /* mov R, Ib */
    case 0xb3: /* mov R, Ib */
    case 0xb4: /* mov R, Ib */
    case 0xb5: /* mov R, Ib */
    case 0xb6: /* mov R, Ib */
    case 0xb7: /* mov R, Ib */
        val = insn_get(env, s, MO_8);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_op_mov_reg_v(s, MO_8, (b & 7) | REX_B(s), s->T0);
        break;
    case 0xb8: /* mov R, Iv */
    case 0xb9: /* mov R, Iv */
    case 0xba: /* mov R, Iv */
    case 0xbb: /* mov R, Iv */
    case 0xbc: /* mov R, Iv */
    case 0xbd: /* mov R, Iv */
    case 0xbe: /* mov R, Iv */
    case 0xbf: /* mov R, Iv */
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            uint64_t tmp;
            /* 64 bit case */
            tmp = x86_ldq_code(env, s);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(tcg_ctx, s->T0, tmp);
            gen_op_mov_reg_v(s, MO_64, reg, s->T0);
        } else
#endif
        {
            ot = dflag;
            val = insn_get(env, s, ot);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(tcg_ctx, s->T0, val);
            gen_op_mov_reg_v(s, ot, reg, s->T0);
        }
        break;

    case 0x91: /* xchg R, EAX */
    case 0x92: /* xchg R, EAX */
    case 0x93: /* xchg R, EAX */
    case 0x94: /* xchg R, EAX */
    case 0x95: /* xchg R, EAX */
    case 0x96: /* xchg R, EAX */
    case 0x97: /* xchg R, EAX */
    do_xchg_reg_eax:
        ot = dflag;
        reg = (b & 7) | REX_B(s);
        rm = R_EAX;
        goto do_xchg_reg;
    case 0x86:
    case 0x87: /* xchg Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
        do_xchg_reg:
            gen_op_mov_v_reg(s, ot, s->T0, reg);
            gen_op_mov_v_reg(s, ot, s->T1, rm);
            gen_op_mov_reg_v(s, ot, rm, s->T0);
            gen_op_mov_reg_v(s, ot, reg, s->T1);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_mov_v_reg(s, ot, s->T0, reg);
            /* for xchg, lock is implicit */
            tcg_gen_atomic_xchg_tl(tcg_ctx, s->T1, s->A0, s->T0,
                                   s->mem_index, ot | MO_LE);
            gen_op_mov_reg_v(s, ot, reg, s->T1);
        }
        break;
    case 0xc4: /* les Gv */
        /* In CODE64 this is VEX3; see above.  */
        op = R_ES;
        goto do_lxx;
    case 0xc5: /* lds Gv */
        /* In CODE64 this is VEX2; see above.  */
        op = R_DS;
        goto do_lxx;
    case 0x1b2: /* lss Gv */
        op = R_SS;
        goto do_lxx;
    case 0x1b4: /* lfs Gv */
        op = R_FS;
        goto do_lxx;
    case 0x1b5: /* lgs Gv */
        op = R_GS;
    do_lxx:
        ot = dflag != MO_16 ? MO_32 : MO_16;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_lea_modrm(env, s, modrm);
        gen_op_ld_v(s, ot, s->T1, s->A0);
        gen_add_A0_im(s, 1 << ot);
        /* load the segment first to handle exceptions properly */
        gen_op_ld_v(s, MO_16, s->T0, s->A0);
        gen_movl_seg_T0(s, op);
        /* then put the data */
        gen_op_mov_reg_v(s, ot, reg, s->T1);
        if (s->base.is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /************************/
        /* shifts */
    case 0xc0:
    case 0xc1:
        /* shift Ev,Ib */
        shift = 2;
    grp2_label:
        {
            ot = mo_b_d(b, dflag);
            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            op = (modrm >> 3) & 7;

            if (mod != 3) {
                if (shift == 2) {
                    s->rip_offset = 1;
                }
                gen_lea_modrm(env, s, modrm);
                opreg = OR_TMP0;
            } else {
                opreg = (modrm & 7) | REX_B(s);
            }

            /* simpler op */
            if (shift == 0) {
                gen_shift(s, op, ot, opreg, OR_ECX);
            } else {
                if (shift == 2) {
                    shift = x86_ldub_code(env, s);
                }
                gen_shifti(s, op, ot, opreg, shift);
            }
        }
        break;
    case 0xd0:
    case 0xd1:
        /* shift Ev,1 */
        shift = 1;
        goto grp2_label;
    case 0xd2:
    case 0xd3:
        /* shift Ev,cl */
        shift = 0;
        goto grp2_label;

    case 0x1a4: /* shld imm */
        op = 0;
        shift = 1;
        goto do_shiftd;
    case 0x1a5: /* shld cl */
        op = 0;
        shift = 0;
        goto do_shiftd;
    case 0x1ac: /* shrd imm */
        op = 1;
        shift = 1;
        goto do_shiftd;
    case 0x1ad: /* shrd cl */
        op = 1;
        shift = 0;
    do_shiftd:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            opreg = OR_TMP0;
        } else {
            opreg = rm;
        }
        gen_op_mov_v_reg(s, ot, s->T1, reg);

        if (shift) {
            TCGv imm = tcg_const_tl(tcg_ctx, x86_ldub_code(env, s));
            gen_shiftd_rm_T1(s, ot, opreg, op, imm);
            tcg_temp_free(tcg_ctx, imm);
        } else {
            gen_shiftd_rm_T1(s, ot, opreg, op, tcg_ctx->cpu_regs[R_ECX]);
        }
        break;

        /************************/
        /* floats */
    case 0xd8:
    case 0xd9:
    case 0xda:
    case 0xdb:
    case 0xdc:
    case 0xdd:
    case 0xde:
    case 0xdf:
        {
            bool update_fip = true;

            if (s->flags & (HF_EM_MASK | HF_TS_MASK)) {
                /* if CR0.EM or CR0.TS are set, generate an FPU exception */
                /* XXX: what to do if illegal op ? */
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            modrm = x86_ldub_code(env, s);
            mod = (modrm >> 6) & 3;
            rm = modrm & 7;
            op = ((b & 7) << 3) | ((modrm >> 3) & 7);
            if (mod != 3) {
                /* memory op */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                TCGv ea = gen_lea_modrm_1(s, a);
                TCGv last_addr = tcg_temp_new(tcg_ctx);
                bool update_fdp = true;

                tcg_gen_mov_tl(tcg_ctx, last_addr, ea);
                gen_lea_v_seg(s, s->aflag, ea, a.def_seg, s->override);
                switch(op) {
                case 0x00: /* fxxxs */
                case 0x01: /* fxxxs */
                case 0x02: /* fxxxs */
                case 0x03: /* fxxxs */
                case 0x04: /* fxxxs */
                case 0x05: /* fxxxs */
                case 0x06: /* fxxxs */
                case 0x07: /* fxxxs */

                case 0x10: /* fixxxl */
                case 0x11: /* fixxxl */
                case 0x12: /* fixxxl */
                case 0x13: /* fixxxl */
                case 0x14: /* fixxxl */
                case 0x15: /* fixxxl */
                case 0x16: /* fixxxl */
                case 0x17: /* fixxxl */

                case 0x20: /* fxxxl */
                case 0x21: /* fxxxl */
                case 0x22: /* fxxxl */
                case 0x23: /* fxxxl */
                case 0x24: /* fxxxl */
                case 0x25: /* fxxxl */
                case 0x26: /* fxxxl */
                case 0x27: /* fxxxl */

                case 0x30: /* fixxx */
                case 0x31: /* fixxx */
                case 0x32: /* fixxx */
                case 0x33: /* fixxx */
                case 0x34: /* fixxx */
                case 0x35: /* fixxx */
                case 0x36: /* fixxx */
                case 0x37: /* fixxx */
                    {
                        int op1;
                        op1 = op & 7;

                        switch(op >> 4) {
                        case 0:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_flds_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 1:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_fildl_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 2:
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            gen_helper_fldl_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp1_i64);
                            break;
                        case 3:
                        default:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LESW);
                            gen_helper_fildl_FT0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        }

                        gen_helper_fp_arith_ST0_FT0(tcg_ctx, op1);
                        if (op1 == 3) {
                            /* fcomp needs pop */
                            gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        }
                    }
                    break;
                case 0x08: /* flds */
                case 0x0a: /* fsts */
                case 0x0b: /* fstps */

                case 0x18: /* fildl, fisttpl, fistl, fistpl */
                case 0x19: /* fildl, fisttpl, fistl, fistpl */
                case 0x1a: /* fildl, fisttpl, fistl, fistpl */
                case 0x1b: /* fildl, fisttpl, fistl, fistpl */

                case 0x28: /* fldl, fisttpll, fstl, fstpl */
                case 0x29: /* fldl, fisttpll, fstl, fstpl */
                case 0x2a: /* fldl, fisttpll, fstl, fstpl */
                case 0x2b: /* fldl, fisttpll, fstl, fstpl */

                case 0x38: /* filds, fisttps, fists, fistps */
                case 0x39: /* filds, fisttps, fists, fistps */
                case 0x3a: /* filds, fisttps, fists, fistps */
                case 0x3b: /* filds, fisttps, fists, fistps */
                    switch(op & 7) {
                    case 0:
                        switch(op >> 4) {
                        case 0:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_flds_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 1:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            gen_helper_fildl_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        case 2:
                            tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            gen_helper_fldl_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp1_i64);
                            break;
                        case 3:
                        default:
                            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LESW);
                            gen_helper_fildl_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                            break;
                        }
                        break;
                    case 1:
                        /* XXX: the corresponding CPUID bit must be tested ! */
                        switch(op >> 4) {
                        case 1:
                            gen_helper_fisttl_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            break;
                        case 2:
                            gen_helper_fisttll_ST0(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            break;
                        case 3:
                        default:
                            gen_helper_fistt_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUW);
                            break;
                        }
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        switch(op >> 4) {
                        case 0:
                            gen_helper_fsts_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            break;
                        case 1:
                            gen_helper_fistl_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUL);
                            break;
                        case 2:
                            gen_helper_fstl_ST0(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0,
                                                s->mem_index, MO_LEQ);
                            break;
                        case 3:
                        default:
                            gen_helper_fist_ST0(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                            tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                                s->mem_index, MO_LEUW);
                            break;
                        }
                        if ((op & 7) == 3)
                            gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    }
                    break;
                case 0x0c: /* fldenv mem */
                    gen_helper_fldenv(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x0d: /* fldcw mem */
                    tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    gen_helper_fldcw(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
                    update_fip = update_fdp = false;
                    break;
                case 0x0e: /* fnstenv mem */
                    gen_helper_fstenv(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x0f: /* fnstcw mem */
                    gen_helper_fnstcw(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                    tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    update_fip = update_fdp = false;
                    break;
                case 0x1d: /* fldt mem */
                    gen_helper_fldt_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    break;
                case 0x1f: /* fstpt mem */
                    gen_helper_fstt_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x2c: /* frstor mem */
                    gen_helper_frstor(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x2e: /* fnsave mem */
                    gen_helper_fsave(tcg_ctx, tcg_ctx->cpu_env, s->A0, tcg_const_i32(tcg_ctx, dflag - 1));
                    update_fip = update_fdp = false;
                    break;
                case 0x2f: /* fnstsw mem */
                    gen_helper_fnstsw(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                    tcg_gen_qemu_st_i32(tcg_ctx, s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    update_fip = update_fdp = false;
                    break;
                case 0x3c: /* fbld */
                    gen_helper_fbld_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    break;
                case 0x3e: /* fbstp */
                    gen_helper_fbst_ST0(tcg_ctx, tcg_ctx->cpu_env, s->A0);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x3d: /* fildll */
                    tcg_gen_qemu_ld_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
                    gen_helper_fildll_ST0(tcg_ctx, tcg_ctx->cpu_env, s->tmp1_i64);
                    break;
                case 0x3f: /* fistpll */
                    gen_helper_fistll_ST0(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env);
                    tcg_gen_qemu_st_i64(tcg_ctx, s->tmp1_i64, s->A0, s->mem_index, MO_LEQ);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                default:
                    goto unknown_op;
                }

                if (update_fdp) {
                    int last_seg = s->override >= 0 ? s->override : a.def_seg;

                    tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State,
                                            segs[last_seg].selector));
                    tcg_gen_st16_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                        offsetof(CPUX86State, fpds));
                    tcg_gen_st_tl(tcg_ctx, last_addr, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State, fpdp));
                }
                tcg_temp_free(tcg_ctx, last_addr);
            } else {
                /* register float ops */
                opreg = rm;

                switch(op) {
                case 0x08: /* fld sti */
                    gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fmov_ST0_STN(tcg_ctx, tcg_ctx->cpu_env,
                                            tcg_const_i32(tcg_ctx, (opreg + 1) & 7));
                    break;
                case 0x09: /* fxchg sti */
                case 0x29: /* fxchg4 sti, undocumented op */
                case 0x39: /* fxchg7 sti, undocumented op */
                    gen_helper_fxchg_ST0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    break;
                case 0x0a: /* grp d9/2 */
                    switch(rm) {
                    case 0: /* fnop */
                        /* check exceptions (FreeBSD FPU probe) */
                        gen_helper_fwait(tcg_ctx, tcg_ctx->cpu_env);
                        update_fip = false;
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x0c: /* grp d9/4 */
                    switch(rm) {
                    case 0: /* fchs */
                        gen_helper_fchs_ST0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 1: /* fabs */
                        gen_helper_fabs_ST0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 4: /* ftst */
                        gen_helper_fldz_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 5: /* fxam */
                        gen_helper_fxam_ST0(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x0d: /* grp d9/5 */
                    {
                        switch(rm) {
                        case 0:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fld1_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 1:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldl2t_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 2:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldl2e_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 3:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldpi_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 4:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldlg2_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 5:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldln2_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        case 6:
                            gen_helper_fpush(tcg_ctx, tcg_ctx->cpu_env);
                            gen_helper_fldz_ST0(tcg_ctx, tcg_ctx->cpu_env);
                            break;
                        default:
                            goto unknown_op;
                        }
                    }
                    break;
                case 0x0e: /* grp d9/6 */
                    switch(rm) {
                    case 0: /* f2xm1 */
                        gen_helper_f2xm1(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 1: /* fyl2x */
                        gen_helper_fyl2x(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 2: /* fptan */
                        gen_helper_fptan(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 3: /* fpatan */
                        gen_helper_fpatan(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 4: /* fxtract */
                        gen_helper_fxtract(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 5: /* fprem1 */
                        gen_helper_fprem1(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 6: /* fdecstp */
                        gen_helper_fdecstp(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                    case 7: /* fincstp */
                        gen_helper_fincstp(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    }
                    break;
                case 0x0f: /* grp d9/7 */
                    switch(rm) {
                    case 0: /* fprem */
                        gen_helper_fprem(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 1: /* fyl2xp1 */
                        gen_helper_fyl2xp1(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 2: /* fsqrt */
                        gen_helper_fsqrt(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 3: /* fsincos */
                        gen_helper_fsincos(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 5: /* fscale */
                        gen_helper_fscale(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 4: /* frndint */
                        gen_helper_frndint(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    case 6: /* fsin */
                        gen_helper_fsin(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                    case 7: /* fcos */
                        gen_helper_fcos(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    }
                    break;
                case 0x00: case 0x01:
                case 0x04: /* fxxx st, sti */
                case 0x05: /* fxxx st, sti */
                case 0x06: /* fxxx st, sti */
                case 0x07: /* fxxx st, sti */

                case 0x20: case 0x21:
                case 0x24: /* fxxx sti, st */
                case 0x25: /* fxxx sti, st */
                case 0x26: /* fxxx sti, st */
                case 0x27: /* fxxx sti, st */

                case 0x30: case 0x31:
                case 0x34: /* fxxxp sti, st */
                case 0x35: /* fxxxp sti, st */
                case 0x36: /* fxxxp sti, st */
                case 0x37: /* fxxxp sti, st */
                    {
                        int op1;

                        op1 = op & 7;
                        if (op >= 0x20) {
                            gen_helper_fp_arith_STN_ST0(tcg_ctx, op1, opreg);
                            if (op >= 0x30)
                                gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        } else {
                            gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                            gen_helper_fp_arith_ST0_FT0(tcg_ctx, op1);
                        }
                    }
                    break;
                case 0x02: /* fcom */
                case 0x22: /* fcom2, undocumented op */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x03: /* fcomp */
                case 0x23: /* fcomp3, undocumented op */
                case 0x32: /* fcomp5, undocumented op */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x15: /* da/5 */
                    switch(rm) {
                    case 1: /* fucompp */
                        gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, 1));
                        gen_helper_fucom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x1c:
                    switch(rm) {
                    case 0: /* feni (287 only, just do nop here) */
                        break;
                    case 1: /* fdisi (287 only, just do nop here) */
                        break;
                    case 2: /* fclex */
                        gen_helper_fclex(tcg_ctx, tcg_ctx->cpu_env);
                        update_fip = false;
                        break;
                    case 3: /* fninit */
                        gen_helper_fninit(tcg_ctx, tcg_ctx->cpu_env);
                        update_fip = false;
                        break;
                    case 4: /* fsetpm (287 only, just do nop here) */
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x1d: /* fucomi */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x1e: /* fcomi */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x28: /* ffree sti */
                    gen_helper_ffree_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    break;
                case 0x2a: /* fst sti */
                    gen_helper_fmov_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    break;
                case 0x2b: /* fstp sti */
                case 0x0b: /* fstp1 sti, undocumented op */
                case 0x3a: /* fstp8 sti, undocumented op */
                case 0x3b: /* fstp9 sti, undocumented op */
                    gen_helper_fmov_STN_ST0(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x2c: /* fucom st(i) */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x2d: /* fucomp st(i) */
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x33: /* de/3 */
                    switch(rm) {
                    case 1: /* fcompp */
                        gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, 1));
                        gen_helper_fcom_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x38: /* ffreep sti, undocumented op */
                    gen_helper_ffree_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    break;
                case 0x3c: /* df/4 */
                    switch(rm) {
                    case 0:
                        gen_helper_fnstsw(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env);
                        tcg_gen_extu_i32_tl(tcg_ctx, s->T0, s->tmp2_i32);
                        gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                        break;
                    default:
                        goto unknown_op;
                    }
                    break;
                case 0x3d: /* fucomip */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fucomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x3e: /* fcomip */
                    if (!(s->cpuid_features & CPUID_CMOV)) {
                        goto illegal_op;
                    }
                    gen_update_cc_op(s);
                    gen_helper_fmov_FT0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_helper_fcomi_ST0_FT0(tcg_ctx, tcg_ctx->cpu_env);
                    gen_helper_fpop(tcg_ctx, tcg_ctx->cpu_env);
                    set_cc_op(s, CC_OP_EFLAGS);
                    break;
                case 0x10: /* fcmovxx */
                case 0x11: /* fcmovxx */
                case 0x12: /* fcmovxx */
                case 0x13: /* fcmovxx */

                case 0x18:
                case 0x19:
                case 0x1a:
                case 0x1b:
                    {
                        int op1;
                        TCGLabel *l1;
                        static const uint8_t fcmov_cc[8] = {
                            (JCC_B << 1),
                            (JCC_Z << 1),
                            (JCC_BE << 1),
                            (JCC_P << 1),
                        };

                        if (!(s->cpuid_features & CPUID_CMOV)) {
                            goto illegal_op;
                        }
                        op1 = fcmov_cc[op & 3] | (((op >> 3) & 1) ^ 1);
                        l1 = gen_new_label(tcg_ctx);
                        gen_jcc1_noeob(s, op1, l1);
                        gen_helper_fmov_ST0_STN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, opreg));
                        gen_set_label(tcg_ctx, l1);
                    }
                    break;
                default:
                    goto unknown_op;
                }
            }

            if (update_fip) {
                tcg_gen_ld_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                offsetof(CPUX86State, segs[R_CS].selector));
                tcg_gen_st16_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env,
                                    offsetof(CPUX86State, fpcs));
                tcg_gen_st_tl(tcg_ctx, tcg_const_tl(tcg_ctx, pc_start - s->cs_base),
                                tcg_ctx->cpu_env, offsetof(CPUX86State, fpip));
            }
        }
        break;
        /************************/
        /* string ops */

    case 0xa4: /* movsS */
    case 0xa5:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_movs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_movs(s, ot);
        }
        break;

    case 0xaa: /* stosS */
    case 0xab:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_stos(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_stos(s, ot);
        }
        break;
    case 0xac: /* lodsS */
    case 0xad:
        ot = mo_b_d(b, dflag);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_lods(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_lods(s, ot);
        }
        break;
    case 0xae: /* scasS */
    case 0xaf:
        ot = mo_b_d(b, dflag);
        if (prefixes & PREFIX_REPNZ) {
            gen_repz_scas(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 1);
        } else if (prefixes & PREFIX_REPZ) {
            gen_repz_scas(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 0);
        } else {
            gen_scas(s, ot);
        }
        break;

    case 0xa6: /* cmpsS */
    case 0xa7:
        ot = mo_b_d(b, dflag);
        if (prefixes & PREFIX_REPNZ) {
            gen_repz_cmps(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 1);
        } else if (prefixes & PREFIX_REPZ) {
            gen_repz_cmps(s, ot, pc_start - s->cs_base, s->pc - s->cs_base, 0);
        } else {
            gen_cmps(s, ot);
        }
        break;
    case 0x6c: /* insS */
    case 0x6d:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base, 
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_ins(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_ins(s, ot);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
        }
        break;
    case 0x6e: /* outsS */
    case 0x6f:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_outs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_outs(s, ot);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
        }
        break;

        /************************/
        /* port I/O */

    case 0xe4:
    case 0xe5:
        ot = mo_b_d32(b, dflag);
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, val);
        gen_helper_in_func(tcg_ctx, ot, s->T1, s->tmp2_i32);
        gen_op_mov_reg_v(s, ot, R_EAX, s->T1);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xe6:
    case 0xe7:
        ot = mo_b_d32(b, dflag);
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T0, val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(s, ot, s->T1, R_EAX);

        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, val);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
        gen_helper_out_func(tcg_ctx, ot, s->tmp2_i32, s->tmp3_i32);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xec:
    case 0xed:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        gen_helper_in_func(tcg_ctx, ot, s->T1, s->tmp2_i32);
        gen_op_mov_reg_v(s, ot, R_EAX, s->T1);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0xee:
    case 0xef:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(s, ot, s->T1, R_EAX);

        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp3_i32, s->T1);
        gen_helper_out_func(tcg_ctx, ot, s->tmp2_i32, s->tmp3_i32);
        gen_bpt_io(s, s->tmp2_i32, ot);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;

        /************************/
        /* control */
    case 0xc2: /* ret im */
        val = x86_ldsw_code(env, s);
        ot = gen_pop_T0(s);
        gen_stack_update(s, val + (1 << ot));
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(tcg_ctx, s->T0);
        gen_bnd_jmp(s);
        gen_jr(s, s->T0);
        break;
    case 0xc3: /* ret */
        ot = gen_pop_T0(s);
        gen_pop_update(s, ot);
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(tcg_ctx, s->T0);
        gen_bnd_jmp(s);
        gen_jr(s, s->T0);
        break;
    case 0xca: /* lret im */
        val = x86_ldsw_code(env, s);
    do_lret:
        if (s->pe && !s->vm86) {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_lret_protected(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, val));
        } else {
            gen_stack_A0(s);
            /* pop offset */
            gen_op_ld_v(s, dflag, s->T0, s->A0);
            /* NOTE: keeping EIP updated is not a problem in case of
               exception */
            gen_op_jmp_v(tcg_ctx, s->T0);
            /* pop selector */
            gen_add_A0_im(s, 1 << dflag);
            gen_op_ld_v(s, dflag, s->T0, s->A0);
            gen_op_movl_seg_T0_vm(s, R_CS);
            /* add stack offset */
            gen_stack_update(s, val + (2 << dflag));
        }
        gen_eob(s);
        break;
    case 0xcb: /* lret */
        val = 0;
        goto do_lret;
    case 0xcf: /* iret */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_IRET);
        if (!s->pe) {
            /* real mode */
            gen_helper_iret_real(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            set_cc_op(s, CC_OP_EFLAGS);
        } else if (s->vm86) {
            if (s->iopl != 3) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_helper_iret_real(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
                set_cc_op(s, CC_OP_EFLAGS);
            }
        } else {
            gen_helper_iret_protected(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, s->pc - s->cs_base));
            set_cc_op(s, CC_OP_EFLAGS);
        }
        gen_eob(s);
        break;
    case 0xe8: /* call im */
        {
            if (dflag != MO_16) {
                tval = (int32_t)insn_get(env, s, MO_32);
            } else {
                tval = (int16_t)insn_get(env, s, MO_16);
            }
            next_eip = s->pc - s->cs_base;
            tval += next_eip;
            if (dflag == MO_16) {
                tval &= 0xffff;
            } else if (!CODE64(s)) {
                tval &= 0xffffffff;
            }
            tcg_gen_movi_tl(tcg_ctx, s->T0, next_eip);
            gen_push_v(s, s->T0);
            gen_bnd_jmp(s);
            gen_jmp(s, tval);
        }
        break;
    case 0x9a: /* lcall im */
        {
            unsigned int selector, offset;

            if (CODE64(s))
                goto illegal_op;
            ot = dflag;
            offset = insn_get(env, s, ot);
            selector = insn_get(env, s, MO_16);

            tcg_gen_movi_tl(tcg_ctx, s->T0, selector);
            tcg_gen_movi_tl(tcg_ctx, s->T1, offset);
        }
        goto do_lcall;
    case 0xe9: /* jmp im */
        if (dflag != MO_16) {
            tval = (int32_t)insn_get(env, s, MO_32);
        } else {
            tval = (int16_t)insn_get(env, s, MO_16);
        }
        tval += s->pc - s->cs_base;
        if (dflag == MO_16) {
            tval &= 0xffff;
        } else if (!CODE64(s)) {
            tval &= 0xffffffff;
        }
        gen_bnd_jmp(s);
        gen_jmp(s, tval);
        break;
    case 0xea: /* ljmp im */
        {
            unsigned int selector, offset;

            if (CODE64(s))
                goto illegal_op;
            ot = dflag;
            offset = insn_get(env, s, ot);
            selector = insn_get(env, s, MO_16);

            tcg_gen_movi_tl(tcg_ctx, s->T0, selector);
            tcg_gen_movi_tl(tcg_ctx, s->T1, offset);
        }
        goto do_ljmp;
    case 0xeb: /* jmp Jb */
        tval = (int8_t)insn_get(env, s, MO_8);
        tval += s->pc - s->cs_base;
        if (dflag == MO_16) {
            tval &= 0xffff;
        }
        gen_jmp(s, tval);
        break;
    case 0x70: /* jcc Jb */
    case 0x71: /* jcc Jb */
    case 0x72: /* jcc Jb */
    case 0x73: /* jcc Jb */
    case 0x74: /* jcc Jb */
    case 0x75: /* jcc Jb */
    case 0x76: /* jcc Jb */
    case 0x77: /* jcc Jb */
    case 0x78: /* jcc Jb */
    case 0x79: /* jcc Jb */
    case 0x7a: /* jcc Jb */
    case 0x7b: /* jcc Jb */
    case 0x7c: /* jcc Jb */
    case 0x7d: /* jcc Jb */
    case 0x7e: /* jcc Jb */
    case 0x7f: /* jcc Jb */
        tval = (int8_t)insn_get(env, s, MO_8);
        goto do_jcc;
    case 0x180: /* jcc Jv */
    case 0x181: /* jcc Jv */
    case 0x182: /* jcc Jv */
    case 0x183: /* jcc Jv */
    case 0x184: /* jcc Jv */
    case 0x185: /* jcc Jv */
    case 0x186: /* jcc Jv */
    case 0x187: /* jcc Jv */
    case 0x188: /* jcc Jv */
    case 0x189: /* jcc Jv */
    case 0x18a: /* jcc Jv */
    case 0x18b: /* jcc Jv */
    case 0x18c: /* jcc Jv */
    case 0x18d: /* jcc Jv */
    case 0x18e: /* jcc Jv */
    case 0x18f: /* jcc Jv */
        if (dflag != MO_16) {
            tval = (int32_t)insn_get(env, s, MO_32);
        } else {
            tval = (int16_t)insn_get(env, s, MO_16);
        }
    do_jcc:
        next_eip = s->pc - s->cs_base;
        tval += next_eip;
        if (dflag == MO_16) {
            tval &= 0xffff;
        }
        gen_bnd_jmp(s);
        gen_jcc(s, b, tval, next_eip);
        break;

    case 0x190: /* setcc Gv */
    case 0x191: /* setcc Gv */
    case 0x192: /* setcc Gv */
    case 0x193: /* setcc Gv */
    case 0x194: /* setcc Gv */
    case 0x195: /* setcc Gv */
    case 0x196: /* setcc Gv */
    case 0x197: /* setcc Gv */
    case 0x198: /* setcc Gv */
    case 0x199: /* setcc Gv */
    case 0x19a: /* setcc Gv */
    case 0x19b: /* setcc Gv */
    case 0x19c: /* setcc Gv */
    case 0x19d: /* setcc Gv */
    case 0x19e: /* setcc Gv */
    case 0x19f: /* setcc Gv */
        modrm = x86_ldub_code(env, s);
        gen_setcc1(s, b, s->T0);
        gen_ldst_modrm(env, s, modrm, MO_8, OR_TMP0, 1);
        break;
    case 0x140: /* cmov Gv, Ev */
    case 0x141: /* cmov Gv, Ev */
    case 0x142: /* cmov Gv, Ev */
    case 0x143: /* cmov Gv, Ev */
    case 0x144: /* cmov Gv, Ev */
    case 0x145: /* cmov Gv, Ev */
    case 0x146: /* cmov Gv, Ev */
    case 0x147: /* cmov Gv, Ev */
    case 0x148: /* cmov Gv, Ev */
    case 0x149: /* cmov Gv, Ev */
    case 0x14a: /* cmov Gv, Ev */
    case 0x14b: /* cmov Gv, Ev */
    case 0x14c: /* cmov Gv, Ev */
    case 0x14d: /* cmov Gv, Ev */
    case 0x14e: /* cmov Gv, Ev */
    case 0x14f: /* cmov Gv, Ev */
        if (!(s->cpuid_features & CPUID_CMOV)) {
            goto illegal_op;
        }
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_cmovcc1(env, s, ot, b, modrm, reg);
        break;

        /************************/
        /* flags */
    case 0x9c: /* pushf */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_PUSHF);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_helper_read_eflags(tcg_ctx, s->T0, tcg_ctx->cpu_env);
            gen_push_v(s, s->T0);
        }
        break;
    case 0x9d: /* popf */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_POPF);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            ot = gen_pop_T0(s);
            if (s->cpl == 0) {
                if (dflag != MO_16) {
                    gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK |
                                                           IOPL_MASK)));
                } else {
                    gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK | IOPL_MASK)
                                                          & 0xffff));
                }
            } else {
                if (s->cpl <= s->iopl) {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                                tcg_const_i32(tcg_ctx, (TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)));
                    } else {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                                tcg_const_i32(tcg_ctx, (TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)
                                                              & 0xffff));
                    }
                } else {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                           tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)));
                    } else {
                        gen_helper_write_eflags(tcg_ctx, tcg_ctx->cpu_env, s->T0,
                                           tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)
                                                         & 0xffff));
                    }
                }
            }
            gen_pop_update(s, ot);
            set_cc_op(s, CC_OP_EFLAGS);
            /* abort translation because TF/AC flag may change */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    case 0x9e: /* sahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_op_mov_v_reg(s, MO_8, s->T0, R_AH);
        gen_compute_eflags(s);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, CC_O);
        tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, CC_S | CC_Z | CC_A | CC_P | CC_C);
        tcg_gen_or_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, s->T0);
        break;
    case 0x9f: /* lahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_compute_eflags(s);
        /* Note: gen_compute_eflags() only gives the condition codes */
        tcg_gen_ori_tl(tcg_ctx, s->T0, tcg_ctx->cpu_cc_src, 0x02);
        gen_op_mov_reg_v(s, MO_8, R_AH, s->T0);
        break;
    case 0xf5: /* cmc */
        gen_compute_eflags(s);
        tcg_gen_xori_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, CC_C);
        break;
    case 0xf8: /* clc */
        gen_compute_eflags(s);
        tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, ~CC_C);
        break;
    case 0xf9: /* stc */
        gen_compute_eflags(s);
        tcg_gen_ori_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, CC_C);
        break;
    case 0xfc: /* cld */
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, 1);
        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, offsetof(CPUX86State, df));
        break;
    case 0xfd: /* std */
        tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, -1);
        tcg_gen_st_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_env, offsetof(CPUX86State, df));
        break;

        /************************/
        /* bit operations */
    case 0x1ba: /* bt/bts/btr/btc Gv, im */
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        op = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        if (mod != 3) {
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            if (!(s->prefix & PREFIX_LOCK)) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
            }
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }
        /* load shift */
        val = x86_ldub_code(env, s);
        tcg_gen_movi_tl(tcg_ctx, s->T1, val);
        if (op < 4)
            goto unknown_op;
        op -= 4;
        goto bt_op;
    case 0x1a3: /* bt Gv, Ev */
        op = 0;
        goto do_btx;
    case 0x1ab: /* bts */
        op = 1;
        goto do_btx;
    case 0x1b3: /* btr */
        op = 2;
        goto do_btx;
    case 0x1bb: /* btc */
        op = 3;
    do_btx:
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        gen_op_mov_v_reg(s, MO_32, s->T1, reg);
        if (mod != 3) {
            AddressParts a = gen_lea_modrm_0(env, s, modrm);
            /* specific case: we need to add a displacement */
            gen_exts(tcg_ctx, ot, s->T1);
            tcg_gen_sari_tl(tcg_ctx, s->tmp0, s->T1, 3 + ot);
            tcg_gen_shli_tl(tcg_ctx, s->tmp0, s->tmp0, ot);
            tcg_gen_add_tl(tcg_ctx, s->A0, gen_lea_modrm_1(s, a), s->tmp0);
            gen_lea_v_seg(s, s->aflag, s->A0, a.def_seg, s->override);
            if (!(s->prefix & PREFIX_LOCK)) {
                gen_op_ld_v(s, ot, s->T0, s->A0);
            }
        } else {
            gen_op_mov_v_reg(s, ot, s->T0, rm);
        }
    bt_op:
        tcg_gen_andi_tl(tcg_ctx, s->T1, s->T1, (1 << (3 + ot)) - 1);
        tcg_gen_movi_tl(tcg_ctx, s->tmp0, 1);
        tcg_gen_shl_tl(tcg_ctx, s->tmp0, s->tmp0, s->T1);
        if (s->prefix & PREFIX_LOCK) {
            switch (op) {
            case 0: /* bt */
                /* Needs no atomic ops; we surpressed the normal
                   memory load for LOCK above so do it now.  */
                gen_op_ld_v(s, ot, s->T0, s->A0);
                break;
            case 1: /* bts */
                tcg_gen_atomic_fetch_or_tl(tcg_ctx, s->T0, s->A0, s->tmp0,
                                           s->mem_index, ot | MO_LE);
                break;
            case 2: /* btr */
                tcg_gen_not_tl(tcg_ctx, s->tmp0, s->tmp0);
                tcg_gen_atomic_fetch_and_tl(tcg_ctx, s->T0, s->A0, s->tmp0,
                                            s->mem_index, ot | MO_LE);
                break;
            default:
            case 3: /* btc */
                tcg_gen_atomic_fetch_xor_tl(tcg_ctx, s->T0, s->A0, s->tmp0,
                                            s->mem_index, ot | MO_LE);
                break;
            }
            tcg_gen_shr_tl(tcg_ctx, s->tmp4, s->T0, s->T1);
        } else {
            tcg_gen_shr_tl(tcg_ctx, s->tmp4, s->T0, s->T1);
            switch (op) {
            case 0: /* bt */
                /* Data already loaded; nothing to do.  */
                break;
            case 1: /* bts */
                tcg_gen_or_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
                break;
            case 2: /* btr */
                tcg_gen_andc_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
                break;
            default:
            case 3: /* btc */
                tcg_gen_xor_tl(tcg_ctx, s->T0, s->T0, s->tmp0);
                break;
            }
            if (op != 0) {
                if (mod != 3) {
                    gen_op_st_v(s, ot, s->T0, s->A0);
                } else {
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                }
            }
        }

        /* Delay all CC updates until after the store above.  Note that
           C is the result of the test, Z is unchanged, and the others
           are all undefined.  */
        switch (s->cc_op) {
        case CC_OP_MULB:
        case CC_OP_MULW:
        case CC_OP_MULL:
        case CC_OP_MULQ:

        case CC_OP_ADDB:
        case CC_OP_ADDW:
        case CC_OP_ADDL:
        case CC_OP_ADDQ:

        case CC_OP_ADCB:
        case CC_OP_ADCW:
        case CC_OP_ADCL:
        case CC_OP_ADCQ:

        case CC_OP_SUBB:
        case CC_OP_SUBW:
        case CC_OP_SUBL:
        case CC_OP_SUBQ:

        case CC_OP_SBBB:
        case CC_OP_SBBW:
        case CC_OP_SBBL:
        case CC_OP_SBBQ:

        case CC_OP_LOGICB:
        case CC_OP_LOGICW:
        case CC_OP_LOGICL:
        case CC_OP_LOGICQ:

        case CC_OP_INCB:
        case CC_OP_INCW:
        case CC_OP_INCL:
        case CC_OP_INCQ:

        case CC_OP_DECB:
        case CC_OP_DECW:
        case CC_OP_DECL:
        case CC_OP_DECQ:

        case CC_OP_SHLB:
        case CC_OP_SHLW:
        case CC_OP_SHLL:
        case CC_OP_SHLQ:

        case CC_OP_SARB:
        case CC_OP_SARW:
        case CC_OP_SARL:
        case CC_OP_SARQ:

        case CC_OP_BMILGB:
        case CC_OP_BMILGW:
        case CC_OP_BMILGL:
        case CC_OP_BMILGQ:
            /* Z was going to be computed from the non-zero status of CC_DST.
               We can get that same Z value (and the new C value) by leaving
               CC_DST alone, setting CC_SRC, and using a CC_OP_SAR of the
               same width.  */
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->tmp4);
            set_cc_op(s, ((s->cc_op - CC_OP_MULB) & 3) + CC_OP_SARB);
            break;
        default:
            /* Otherwise, generate EFLAGS and replace the C bit.  */
            gen_compute_eflags(s);
            tcg_gen_deposit_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, s->tmp4,
                               ctz32(CC_C), 1);
            break;
        }
        break;
    case 0x1bc: /* bsf / tzcnt */
    case 0x1bd: /* bsr / lzcnt */
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(tcg_ctx, ot, s->T0);

        /* Note that lzcnt and tzcnt are in different extensions.  */
        if ((prefixes & PREFIX_REPZ)
            && (b & 1
                ? s->cpuid_ext3_features & CPUID_EXT3_ABM
                : s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)) {
            int size = 8 << ot;
            /* For lzcnt/tzcnt, C bit is defined related to the input. */
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
            if (b & 1) {
                /* For lzcnt, reduce the target_ulong result by the
                   number of zeros that we expect to find at the top.  */
                tcg_gen_clzi_tl(tcg_ctx, s->T0, s->T0, TARGET_LONG_BITS);
                tcg_gen_subi_tl(tcg_ctx, s->T0, s->T0, TARGET_LONG_BITS - size);
            } else {
                /* For tzcnt, a zero input must return the operand size.  */
                tcg_gen_ctzi_tl(tcg_ctx, s->T0, s->T0, size);
            }
            /* For lzcnt/tzcnt, Z bit is defined related to the result.  */
            gen_op_update1_cc(s);
            set_cc_op(s, CC_OP_BMILGB + ot);
        } else {
            /* For bsr/bsf, only the Z bit is defined and it is related
               to the input and not the result.  */
            tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_dst, s->T0);
            set_cc_op(s, CC_OP_LOGICB + ot);

            /* ??? The manual says that the output is undefined when the
               input is zero, but real hardware leaves it unchanged, and
               real programs appear to depend on that.  Accomplish this
               by passing the output as the value to return upon zero.  */
            if (b & 1) {
                /* For bsr, return the bit index of the first 1 bit,
                   not the count of leading zeros.  */
                tcg_gen_xori_tl(tcg_ctx, s->T1, tcg_ctx->cpu_regs[reg], TARGET_LONG_BITS - 1);
                tcg_gen_clz_tl(tcg_ctx, s->T0, s->T0, s->T1);
                tcg_gen_xori_tl(tcg_ctx, s->T0, s->T0, TARGET_LONG_BITS - 1);
            } else {
                tcg_gen_ctz_tl(tcg_ctx, s->T0, s->T0, tcg_ctx->cpu_regs[reg]);
            }
        }
        gen_op_mov_reg_v(s, ot, reg, s->T0);
        break;
        /************************/
        /* bcd */
    case 0x27: /* daa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_daa(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x2f: /* das */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_das(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x37: /* aaa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aaa(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x3f: /* aas */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aas(tcg_ctx, tcg_ctx->cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0xd4: /* aam */
        if (CODE64(s))
            goto illegal_op;
        val = x86_ldub_code(env, s);
        if (val == 0) {
            gen_exception(s, EXCP00_DIVZ, pc_start - s->cs_base);
        } else {
            gen_helper_aam(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, val));
            set_cc_op(s, CC_OP_LOGICB);
        }
        break;
    case 0xd5: /* aad */
        if (CODE64(s))
            goto illegal_op;
        val = x86_ldub_code(env, s);
        gen_helper_aad(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, val));
        set_cc_op(s, CC_OP_LOGICB);
        break;
        /************************/
        /* misc */
    case 0x90: /* nop */
        /* XXX: correct lock test for all insn */
        if (prefixes & PREFIX_LOCK) {
            goto illegal_op;
        }
        /* If REX_B is set, then this is xchg eax, r8d, not a nop.  */
        if (REX_B(s)) {
            goto do_xchg_reg_eax;
        }
        if (prefixes & PREFIX_REPZ) {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_pause(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            s->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x9b: /* fwait */
        if ((s->flags & (HF_MP_MASK | HF_TS_MASK)) ==
            (HF_MP_MASK | HF_TS_MASK)) {
            gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        } else {
            gen_helper_fwait(tcg_ctx, tcg_ctx->cpu_env);
        }
        break;
    case 0xcc: /* int3 */
        gen_interrupt(s, EXCP03_INT3, pc_start - s->cs_base, s->pc - s->cs_base);
        break;
    case 0xcd: /* int N */
        val = x86_ldub_code(env, s);
        if (s->vm86 && s->iopl != 3) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_interrupt(s, val, pc_start - s->cs_base, s->pc - s->cs_base);
        }
        break;
    case 0xce: /* into */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_into(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        break;
#ifdef WANT_ICEBP
    case 0xf1: /* icebp (undocumented, exits to external debugger) */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_ICEBP);
        gen_debug(s, pc_start - s->cs_base);
        break;
#endif
    case 0xfa: /* cli */
        if (!s->vm86) {
            if (s->cpl <= s->iopl) {
                gen_helper_cli(tcg_ctx, tcg_ctx->cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        } else {
            if (s->iopl == 3) {
                gen_helper_cli(tcg_ctx, tcg_ctx->cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        }
        break;
    case 0xfb: /* sti */
        if (s->vm86 ? s->iopl == 3 : s->cpl <= s->iopl) {
            gen_helper_sti(tcg_ctx, tcg_ctx->cpu_env);
            /* interruptions are enabled only the first insn after sti */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob_inhibit_irq(s, true);
        } else {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        }
        break;
    case 0x62: /* bound */
        if (CODE64(s))
            goto illegal_op;
        ot = dflag;
        modrm = x86_ldub_code(env, s);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_op_mov_v_reg(s, ot, s->T0, reg);
        gen_lea_modrm(env, s, modrm);
        tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
        if (ot == MO_16) {
            gen_helper_boundw(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp2_i32);
        } else {
            gen_helper_boundl(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp2_i32);
        }
        break;
    case 0x1c8: /* bswap reg */
    case 0x1c9: /* bswap reg */
    case 0x1ca: /* bswap reg */
    case 0x1cb: /* bswap reg */
    case 0x1cc: /* bswap reg */
    case 0x1cd: /* bswap reg */
    case 0x1ce: /* bswap reg */
    case 0x1cf: /* bswap reg */
        reg = (b & 7) | REX_B(s);
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            gen_op_mov_v_reg(s, MO_64, s->T0, reg);
            tcg_gen_bswap64_i64(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_64, reg, s->T0);
        } else
#endif
        {
            gen_op_mov_v_reg(s, MO_32, s->T0, reg);
            tcg_gen_ext32u_tl(tcg_ctx, s->T0, s->T0);
            tcg_gen_bswap32_tl(tcg_ctx, s->T0, s->T0);
            gen_op_mov_reg_v(s, MO_32, reg, s->T0);
        }
        break;
    case 0xd6: /* salc */
        if (CODE64(s))
            goto illegal_op;
        gen_compute_eflags_c(s, s->T0);
        tcg_gen_neg_tl(tcg_ctx, s->T0, s->T0);
        gen_op_mov_reg_v(s, MO_8, R_EAX, s->T0);
        break;
    case 0xe0: /* loopnz */
    case 0xe1: /* loopz */
    case 0xe2: /* loop */
    case 0xe3: /* jecxz */
        {
            TCGLabel *l1, *l2, *l3;

            tval = (int8_t)insn_get(env, s, MO_8);
            next_eip = s->pc - s->cs_base;
            tval += next_eip;
            if (dflag == MO_16) {
                tval &= 0xffff;
            }

            l1 = gen_new_label(tcg_ctx);
            l2 = gen_new_label(tcg_ctx);
            l3 = gen_new_label(tcg_ctx);
            b &= 3;
            switch(b) {
            case 0: /* loopnz */
            case 1: /* loopz */
                gen_op_add_reg_im(s, s->aflag, R_ECX, -1);
                gen_op_jz_ecx(s, s->aflag, l3);
                gen_jcc1(s, (JCC_Z << 1) | (b ^ 1), l1);
                break;
            case 2: /* loop */
                gen_op_add_reg_im(s, s->aflag, R_ECX, -1);
                gen_op_jnz_ecx(s, s->aflag, l1);
                break;
            default:
            case 3: /* jcxz */
                gen_op_jz_ecx(s, s->aflag, l1);
                break;
            }

            gen_set_label(tcg_ctx, l3);
            gen_jmp_im(s, next_eip);
            tcg_gen_br(tcg_ctx, l2);

            gen_set_label(tcg_ctx, l1);
            gen_jmp_im(s, tval);
            gen_set_label(tcg_ctx, l2);
            gen_eob(s);
        }
        break;
    case 0x130: /* wrmsr */
    case 0x132: /* rdmsr */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            if (b & 2) {
                gen_helper_rdmsr(tcg_ctx, tcg_ctx->cpu_env);
            } else {
                gen_helper_wrmsr(tcg_ctx, tcg_ctx->cpu_env);
            }
        }
        break;
    case 0x131: /* rdtsc */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_io_start(tcg_ctx);
        }
        gen_helper_rdtsc(tcg_ctx, tcg_ctx->cpu_env);
        if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
            gen_jmp(s, s->pc - s->cs_base);
        }
        break;
    case 0x133: /* rdpmc */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_rdpmc(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 0x134: /* sysenter */
        /* For Intel SYSENTER is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            TCGv_i32 addend = tcg_const_i32(tcg_ctx, s->pc - pc_start);
            gen_helper_sysenter(tcg_ctx, tcg_ctx->cpu_env, addend);
            gen_eob(s);
            tcg_temp_free_i32(tcg_ctx, addend);
        }
        break;
    case 0x135: /* sysexit */
        /* For Intel SYSEXIT is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysexit(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            gen_eob(s);
        }
        break;
#ifdef TARGET_X86_64
    case 0x105: /* syscall */
        /* XXX: is it usable in real mode ? */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_syscall(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        /* TF handling for the syscall insn is different. The TF bit is  checked
           after the syscall insn completes. This allows #DB to not be
           generated after one has entered CPL0 if TF is set in FMASK.  */
        gen_eob_worker(s, false, true);
        break;
    case 0x107: /* sysret */
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_helper_sysret(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            /* condition codes are modified only in long mode */
            if (s->lma) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            /* TF handling for the sysret insn is different. The TF bit is
               checked after the sysret insn completes. This allows #DB to be
               generated "as if" the syscall insn in userspace has just
               completed.  */
            gen_eob_worker(s, false, true);
        }
        break;
#endif
    case 0x1a2: /* cpuid */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_cpuid(tcg_ctx, tcg_ctx->cpu_env);
        break;
    case 0xf4: /* hlt */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_hlt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            s->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x100:
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* sldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_READ);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State, ldt.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 2: /* lldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_WRITE);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_lldt(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            }
            break;
        case 1: /* str */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_READ);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                             offsetof(CPUX86State, tr.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 3: /* ltr */
            if (!s->pe || s->vm86)
                goto illegal_op;
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_WRITE);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, s->T0);
                gen_helper_ltr(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            }
            break;
        case 4: /* verr */
        case 5: /* verw */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_update_cc_op(s);
            if (op == 4) {
                gen_helper_verr(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            } else {
                gen_helper_verw(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            }
            set_cc_op(s, CC_OP_EFLAGS);
            break;
        default:
            goto unknown_op;
        }
        break;

    case 0x101:
        modrm = x86_ldub_code(env, s);
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* sgdt */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0,
                             tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.limit));
            gen_op_st_v(s, MO_16, s->T0, s->A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            break;

        case 0xc8: /* monitor */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || s->cpl != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            tcg_gen_mov_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[R_EAX]);
            gen_extu(tcg_ctx, s->aflag, s->A0);
            gen_add_A0_ds_seg(s);
            gen_helper_monitor(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            break;

        case 0xc9: /* mwait */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || s->cpl != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_mwait(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            gen_eob(s);
            break;

        case 0xca: /* clac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || s->cpl != 0) {
                goto illegal_op;
            }
            gen_helper_clac(tcg_ctx, tcg_ctx->cpu_env);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xcb: /* stac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || s->cpl != 0) {
                goto illegal_op;
            }
            gen_helper_stac(tcg_ctx, tcg_ctx->cpu_env);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(1): /* sidt */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.limit));
            gen_op_st_v(s, MO_16, s->T0, s->A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            break;

        case 0xd0: /* xgetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_LOCK | PREFIX_DATA
                                 | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_xgetbv(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s->tmp2_i32);
            tcg_gen_extr_i64_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX], s->tmp1_i64);
            break;

        case 0xd1: /* xsetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_LOCK | PREFIX_DATA
                                 | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_xsetbv(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->tmp1_i64);
            /* End TB because translation flags may change.  */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xd8: /* VMRUN */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmrun(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1),
                             tcg_const_i32(tcg_ctx, s->pc - pc_start));
            tcg_gen_exit_tb(tcg_ctx, NULL, 0);
            s->base.is_jmp = DISAS_NORETURN;
            break;

        case 0xd9: /* VMMCALL */
            if (!(s->flags & HF_SVME_MASK)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmmcall(tcg_ctx, tcg_ctx->cpu_env);
            break;

        case 0xda: /* VMLOAD */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmload(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
            break;

        case 0xdb: /* VMSAVE */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_vmsave(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
            break;

        case 0xdc: /* STGI */
            if ((!(s->flags & HF_SVME_MASK)
                   && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_helper_stgi(tcg_ctx, tcg_ctx->cpu_env);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xdd: /* CLGI */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_clgi(tcg_ctx, tcg_ctx->cpu_env);
            break;

        case 0xde: /* SKINIT */
            if ((!(s->flags & HF_SVME_MASK)
                 && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !s->pe) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_skinit(tcg_ctx, tcg_ctx->cpu_env);
            break;

        case 0xdf: /* INVLPGA */
            if (!(s->flags & HF_SVME_MASK) || !s->pe) {
                goto illegal_op;
            }
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_invlpga(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
            break;

        CASE_MODRM_MEM_OP(2): /* lgdt */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_WRITE);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_16, s->T1, s->A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.base));
            tcg_gen_st32_tl(tcg_ctx, s->T1, tcg_ctx->cpu_env, offsetof(CPUX86State, gdt.limit));
            break;

        CASE_MODRM_MEM_OP(3): /* lidt */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_WRITE);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_16, s->T1, s->A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, s->T0, s->T0, 0xffffff);
            }
            tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.base));
            tcg_gen_st32_tl(tcg_ctx, s->T1, tcg_ctx->cpu_env, offsetof(CPUX86State, idt.limit));
            break;

        CASE_MODRM_OP(4): /* smsw */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_CR0);
            tcg_gen_ld_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, cr[0]));
            if (CODE64(s)) {
                mod = (modrm >> 6) & 3;
                ot = (mod != 3 ? MO_16 : s->dflag);
            } else {
                ot = MO_16;
            }
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
            break;
        case 0xee: /* rdpkru */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_rdpkru(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_env, s->tmp2_i32);
            tcg_gen_extr_i64_tl(tcg_ctx, tcg_ctx->cpu_regs[R_EAX], tcg_ctx->cpu_regs[R_EDX], s->tmp1_i64);
            break;
        case 0xef: /* wrpkru */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(tcg_ctx, s->tmp2_i32, tcg_ctx->cpu_regs[R_ECX]);
            gen_helper_wrpkru(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->tmp1_i64);
            break;
        CASE_MODRM_OP(6): /* lmsw */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_helper_lmsw(tcg_ctx, tcg_ctx->cpu_env, s->T0);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(7): /* invlpg */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                break;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_lea_modrm(env, s, modrm);
            gen_helper_invlpg(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        case 0xf8: /* swapgs */
#ifdef TARGET_X86_64
            if (CODE64(s)) {
                if (s->cpl != 0) {
                    gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                } else {
                    tcg_gen_mov_tl(tcg_ctx, s->T0, tcg_ctx->cpu_seg_base[R_GS]);
                    tcg_gen_ld_tl(tcg_ctx, tcg_ctx->cpu_seg_base[R_GS], tcg_ctx->cpu_env,
                                  offsetof(CPUX86State, kernelgsbase));
                    tcg_gen_st_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env,
                                  offsetof(CPUX86State, kernelgsbase));
                }
                break;
            }
#endif
            goto illegal_op;

        case 0xf9: /* rdtscp */
            if (!(s->cpuid_ext2_features & CPUID_EXT2_RDTSCP)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_io_start(tcg_ctx);
            }
            gen_helper_rdtscp(tcg_ctx, tcg_ctx->cpu_env);
            if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                gen_jmp(s, s->pc - s->cs_base);
            }
            break;

        default:
            goto unknown_op;
        }
        break;

    case 0x108: /* invd */
    case 0x109: /* wbinvd */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, (b & 2) ? SVM_EXIT_INVD : SVM_EXIT_WBINVD);
            /* nothing to do */
        }
        break;
    case 0x63: /* arpl or movslS (x86_64) */
#ifdef TARGET_X86_64
        if (CODE64(s)) {
            int d_ot;
            /* d_ot is the size of destination */
            d_ot = dflag;

            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                gen_op_mov_v_reg(s, MO_32, s->T0, rm);
                /* sign extend */
                if (d_ot == MO_64) {
                    tcg_gen_ext32s_tl(tcg_ctx, s->T0, s->T0);
                }
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32 | MO_SIGN, s->T0, s->A0);
                gen_op_mov_reg_v(s, d_ot, reg, s->T0);
            }
        } else
#endif
        {
            TCGLabel *label1;
            TCGv t0, t1, t2, a0;

            if (!s->pe || s->vm86)
                goto illegal_op;
            t0 = tcg_temp_local_new(tcg_ctx);
            t1 = tcg_temp_local_new(tcg_ctx);
            t2 = tcg_temp_local_new(tcg_ctx);
            ot = MO_16;
            modrm = x86_ldub_code(env, s);
            reg = (modrm >> 3) & 7;
            mod = (modrm >> 6) & 3;
            rm = modrm & 7;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, ot, t0, s->A0);
                a0 = tcg_temp_local_new(tcg_ctx);
                tcg_gen_mov_tl(tcg_ctx, a0, s->A0);
            } else {
                gen_op_mov_v_reg(s, ot, t0, rm);
                a0 = NULL;
            }
            gen_op_mov_v_reg(s, ot, t1, reg);
            tcg_gen_andi_tl(tcg_ctx, s->tmp0, t0, 3);
            tcg_gen_andi_tl(tcg_ctx, t1, t1, 3);
            tcg_gen_movi_tl(tcg_ctx, t2, 0);
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GE, s->tmp0, t1, label1);
            tcg_gen_andi_tl(tcg_ctx, t0, t0, ~3);
            tcg_gen_or_tl(tcg_ctx, t0, t0, t1);
            tcg_gen_movi_tl(tcg_ctx, t2, CC_Z);
            gen_set_label(tcg_ctx, label1);
            if (mod != 3) {
                gen_op_st_v(s, ot, t0, a0);
                tcg_temp_free(tcg_ctx, a0);
           } else {
                gen_op_mov_reg_v(s, ot, rm, t0);
            }
            gen_compute_eflags(s);
            tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, ~CC_Z);
            tcg_gen_or_tl(tcg_ctx, tcg_ctx->cpu_cc_src, tcg_ctx->cpu_cc_src, t2);
            tcg_temp_free(tcg_ctx, t0);
            tcg_temp_free(tcg_ctx, t1);
            tcg_temp_free(tcg_ctx, t2);
        }
        break;
    case 0x102: /* lar */
    case 0x103: /* lsl */
        {
            TCGLabel *label1;
            TCGv t0;
            if (!s->pe || s->vm86)
                goto illegal_op;
            ot = dflag != MO_16 ? MO_32 : MO_16;
            modrm = x86_ldub_code(env, s);
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            t0 = tcg_temp_local_new(tcg_ctx);
            gen_update_cc_op(s);
            if (b == 0x102) {
                gen_helper_lar(tcg_ctx, t0, tcg_ctx->cpu_env, s->T0);
            } else {
                gen_helper_lsl(tcg_ctx, t0, tcg_ctx->cpu_env, s->T0);
            }
            tcg_gen_andi_tl(tcg_ctx, s->tmp0, tcg_ctx->cpu_cc_src, CC_Z);
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, s->tmp0, 0, label1);
            gen_op_mov_reg_v(s, ot, reg, t0);
            gen_set_label(tcg_ctx, label1);
            set_cc_op(s, CC_OP_EFLAGS);
            tcg_temp_free(tcg_ctx, t0);
        }
        break;
    case 0x118:
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* prefetchnta */
        case 1: /* prefetchnt0 */
        case 2: /* prefetchnt0 */
        case 3: /* prefetchnt0 */
            if (mod == 3)
                goto illegal_op;
            gen_nop_modrm(env, s, modrm);
            /* nothing more to do */
            break;
        default: /* nop (multi byte) */
            gen_nop_modrm(env, s, modrm);
            break;
        }
        break;
    case 0x11a:
        modrm = x86_ldub_code(env, s);
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | rex_r;
            if (prefixes & PREFIX_REPZ) {
                /* bndcl */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(env, s, modrm, TCG_COND_LTU, tcg_ctx->cpu_bndl[reg]);
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcu */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                TCGv_i64 notu = tcg_temp_new_i64(tcg_ctx);
                tcg_gen_not_i64(tcg_ctx, notu, tcg_ctx->cpu_bndu[reg]);
                gen_bndck(env, s, modrm, TCG_COND_GTU, notu);
                tcg_temp_free_i64(tcg_ctx, notu);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- from reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4 || (prefixes & PREFIX_LOCK)) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndl[reg2]);
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_bndu[reg2]);
                    }
                } else {
                    gen_lea_modrm(env, s, modrm);
                    if (CODE64(s)) {
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 8);
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                    } else {
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 4);
                        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                    /* bnd registers are now in-use */
                    gen_set_hflag(s, HF_MPX_IU_MASK);
                }
            } else if (mod != 3) {
                /* bndldx */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->A0, 0);
                }
                gen_lea_v_seg(s, s->aflag, s->A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndldx64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_env, s->A0, s->T0);
                    tcg_gen_ld_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_env,
                                   offsetof(CPUX86State, mmx_t0.MMX_Q(0)));
                } else {
                    gen_helper_bndldx32(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_env, s->A0, s->T0);
                    tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndu[reg]);
                    tcg_gen_shri_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], tcg_ctx->cpu_bndu[reg], 32);
                }
                gen_set_hflag(s, HF_MPX_IU_MASK);
            }
        }
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x11b:
        modrm = x86_ldub_code(env, s);
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | rex_r;
            if (mod != 3 && (prefixes & PREFIX_REPZ)) {
                /* bndmk */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (a.base >= 0) {
                    tcg_gen_extu_tl_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_regs[a.base]);
                    if (!CODE64(s)) {
                        tcg_gen_ext32u_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndl[reg]);
                    }
                } else if (a.base == -1) {
                    /* no base register has lower bound of 0 */
                    tcg_gen_movi_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], 0);
                } else {
                    /* rip-relative generates #ud */
                    goto illegal_op;
                }
                tcg_gen_not_tl(tcg_ctx, s->A0, gen_lea_modrm_1(s, a));
                if (!CODE64(s)) {
                    tcg_gen_ext32u_tl(tcg_ctx, s->A0, s->A0);
                }
                tcg_gen_extu_tl_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0);
                /* bnd registers are now in-use */
                gen_set_hflag(s, HF_MPX_IU_MASK);
                break;
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcn */
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(env, s, modrm, TCG_COND_GTU, tcg_ctx->cpu_bndu[reg]);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- to reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4 || (prefixes & PREFIX_LOCK)) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg2], tcg_ctx->cpu_bndl[reg]);
                        tcg_gen_mov_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg2], tcg_ctx->cpu_bndu[reg]);
                    }
                } else {
                    gen_lea_modrm(env, s, modrm);
                    if (CODE64(s)) {
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 8);
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEQ);
                    } else {
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(tcg_ctx, s->A0, s->A0, 4);
                        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                }
            } else if (mod != 3) {
                /* bndstx */
                AddressParts a = gen_lea_modrm_0(env, s, modrm);
                if (reg >= 4
                    || (prefixes & PREFIX_LOCK)
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(tcg_ctx, s->A0, tcg_ctx->cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->A0, 0);
                }
                gen_lea_v_seg(s, s->aflag, s->A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(tcg_ctx, s->T0, tcg_ctx->cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(tcg_ctx, s->T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndstx64(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->T0,
                                        tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndu[reg]);
                } else {
                    gen_helper_bndstx32(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->T0,
                                        tcg_ctx->cpu_bndl[reg], tcg_ctx->cpu_bndu[reg]);
                }
            }
        }
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x119:
    case 0x11c: /* nop (multi byte) */
    case 0x11d: /* nop (multi byte) */
    case 0x11e: /* nop (multi byte) */
    case 0x11f: /* nop (multi byte) */
        modrm = x86_ldub_code(env, s);
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x120: /* mov reg, crN */
    case 0x122: /* mov crN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = x86_ldub_code(env, s);
            /* Ignore the mod bits (assume (modrm&0xc0)==0xc0).
             * AMD documentation (24594.pdf) and testing of
             * intel 386 and 486 processors all show that the mod bits
             * are assumed to be 1's, regardless of actual values.
             */
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | rex_r;
            if (CODE64(s))
                ot = MO_64;
            else
                ot = MO_32;
            if ((prefixes & PREFIX_LOCK) && (reg == 0) &&
                (s->cpuid_ext3_features & CPUID_EXT3_CR8LEG)) {
                reg = 8;
            }
            switch(reg) {
            case 0:
            case 2:
            case 3:
            case 4:
            case 8:
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                if (b & 2) {
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_start(tcg_ctx);
                    }
                    gen_op_mov_v_reg(s, ot, s->T0, rm);
                    gen_helper_write_crN(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, reg),
                                         s->T0);
                    gen_jmp_im(s, s->pc - s->cs_base);
                    gen_eob(s);
                } else {
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_start(tcg_ctx);
                    }
                    gen_helper_read_crN(tcg_ctx, s->T0, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, reg));
                    gen_op_mov_reg_v(s, ot, rm, s->T0);
                    if (tb_cflags(s->base.tb) & CF_USE_ICOUNT) {
                        gen_io_end(tcg_ctx);
                    }
                }
                break;
            default:
                goto unknown_op;
            }
        }
        break;
    case 0x121: /* mov reg, drN */
    case 0x123: /* mov drN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = x86_ldub_code(env, s);
            /* Ignore the mod bits (assume (modrm&0xc0)==0xc0).
             * AMD documentation (24594.pdf) and testing of
             * intel 386 and 486 processors all show that the mod bits
             * are assumed to be 1's, regardless of actual values.
             */
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | rex_r;
            if (CODE64(s))
                ot = MO_64;
            else
                ot = MO_32;
            if (reg >= 8) {
                goto illegal_op;
            }
            if (b & 2) {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_DR0 + reg);
                gen_op_mov_v_reg(s, ot, s->T0, rm);
                tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, reg);
                gen_helper_set_dr(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32, s->T0);
                gen_jmp_im(s, s->pc - s->cs_base);
                gen_eob(s);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_DR0 + reg);
                tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, reg);
                gen_helper_get_dr(tcg_ctx, s->T0, tcg_ctx->cpu_env, s->tmp2_i32);
                gen_op_mov_reg_v(s, ot, rm, s->T0);
            }
        }
        break;
    case 0x106: /* clts */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_helper_clts(tcg_ctx, tcg_ctx->cpu_env);
            /* abort block because static cpu state changed */
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    /* MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4 support */
    case 0x1c3: /* MOVNTI reg, mem */
        if (!(s->cpuid_features & CPUID_SSE2))
            goto illegal_op;
        ot = mo_64_32(dflag);
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0x1ae:
        modrm = x86_ldub_code(env, s);
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* fxsave */
            if (!(s->cpuid_features & CPUID_FXSR)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_fxsave(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            break;

        CASE_MODRM_MEM_OP(1): /* fxrstor */
            if (!(s->cpuid_features & CPUID_FXSR)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_helper_fxrstor(tcg_ctx, tcg_ctx->cpu_env, s->A0);
            break;

        CASE_MODRM_MEM_OP(2): /* ldmxcsr */
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK)) {
                goto illegal_op;
            }
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_qemu_ld_i32(tcg_ctx, s->tmp2_i32, s->A0, s->mem_index, MO_LEUL);
            gen_helper_ldmxcsr(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);
            break;

        CASE_MODRM_MEM_OP(3): /* stmxcsr */
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK)) {
                goto illegal_op;
            }
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(tcg_ctx, s->T0, tcg_ctx->cpu_env, offsetof(CPUX86State, mxcsr));
            gen_op_st_v(s, MO_32, s->T0, s->A0);
            break;

        CASE_MODRM_MEM_OP(4): /* xsave */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (prefixes & (PREFIX_LOCK | PREFIX_DATA
                                | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            gen_helper_xsave(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp1_i64);
            break;

        CASE_MODRM_MEM_OP(5): /* xrstor */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (prefixes & (PREFIX_LOCK | PREFIX_DATA
                                | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_lea_modrm(env, s, modrm);
            tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                  tcg_ctx->cpu_regs[R_EDX]);
            gen_helper_xrstor(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp1_i64);
            /* XRSTOR is how MPX is enabled, which changes how
               we translate.  Thus we need to end the TB.  */
            gen_update_cc_op(s);
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
            break;

        CASE_MODRM_MEM_OP(6): /* xsaveopt / clwb */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            if (prefixes & PREFIX_DATA) {
                /* clwb */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_CLWB)) {
                    goto illegal_op;
                }
                gen_nop_modrm(env, s, modrm);
            } else {
                /* xsaveopt */
                if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                    || (s->cpuid_xsave_features & CPUID_XSAVE_XSAVEOPT) == 0
                    || (prefixes & (PREFIX_REPZ | PREFIX_REPNZ))) {
                    goto illegal_op;
                }
                gen_lea_modrm(env, s, modrm);
                tcg_gen_concat_tl_i64(tcg_ctx, s->tmp1_i64, tcg_ctx->cpu_regs[R_EAX],
                                      tcg_ctx->cpu_regs[R_EDX]);
                gen_helper_xsaveopt(tcg_ctx, tcg_ctx->cpu_env, s->A0, s->tmp1_i64);
            }
            break;

        CASE_MODRM_MEM_OP(7): /* clflush / clflushopt */
            if (prefixes & PREFIX_LOCK) {
                goto illegal_op;
            }
            if (prefixes & PREFIX_DATA) {
                /* clflushopt */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_CLFLUSHOPT)) {
                    goto illegal_op;
                }
            } else {
                /* clflush */
                if ((s->prefix & (PREFIX_REPZ | PREFIX_REPNZ))
                    || !(s->cpuid_features & CPUID_CLFLUSH)) {
                    goto illegal_op;
                }
            }
            gen_nop_modrm(env, s, modrm);
            break;

        case 0xc0: /* rdfsbase (f3 0f ae /0) */
        case 0xc1: /* rdfsbase (f3 0f ae /0) */
        case 0xc2: /* rdfsbase (f3 0f ae /0) */
        case 0xc3: /* rdfsbase (f3 0f ae /0) */
        case 0xc4: /* rdfsbase (f3 0f ae /0) */
        case 0xc5: /* rdfsbase (f3 0f ae /0) */
        case 0xc6: /* rdfsbase (f3 0f ae /0) */
        case 0xc7: /* rdfsbase (f3 0f ae /0) */

        case 0xc8: /* rdgsbase (f3 0f ae /1) */
        case 0xc9: /* rdgsbase (f3 0f ae /1) */
        case 0xca: /* rdgsbase (f3 0f ae /1) */
        case 0xcb: /* rdgsbase (f3 0f ae /1) */
        case 0xcc: /* rdgsbase (f3 0f ae /1) */
        case 0xcd: /* rdgsbase (f3 0f ae /1) */
        case 0xce: /* rdgsbase (f3 0f ae /1) */
        case 0xcf: /* rdgsbase (f3 0f ae /1) */

        case 0xd0: /* wrfsbase (f3 0f ae /2) */
        case 0xd1: /* wrfsbase (f3 0f ae /2) */
        case 0xd2: /* wrfsbase (f3 0f ae /2) */
        case 0xd3: /* wrfsbase (f3 0f ae /2) */
        case 0xd4: /* wrfsbase (f3 0f ae /2) */
        case 0xd5: /* wrfsbase (f3 0f ae /2) */
        case 0xd6: /* wrfsbase (f3 0f ae /2) */
        case 0xd7: /* wrfsbase (f3 0f ae /2) */

        case 0xd8: /* wrgsbase (f3 0f ae /3) */
        case 0xd9: /* wrgsbase (f3 0f ae /3) */
        case 0xda: /* wrgsbase (f3 0f ae /3) */
        case 0xdb: /* wrgsbase (f3 0f ae /3) */
        case 0xdc: /* wrgsbase (f3 0f ae /3) */
        case 0xdd: /* wrgsbase (f3 0f ae /3) */
        case 0xde: /* wrgsbase (f3 0f ae /3) */
        case 0xdf: /* wrgsbase (f3 0f ae /3) */
            if (CODE64(s)
                && (prefixes & PREFIX_REPZ)
                && !(prefixes & PREFIX_LOCK)
                && (s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_FSGSBASE)) {
                TCGv base, treg, src, dst;

                /* Preserve hflags bits by testing CR4 at runtime.  */
                tcg_gen_movi_i32(tcg_ctx, s->tmp2_i32, CR4_FSGSBASE_MASK);
                gen_helper_cr4_testbit(tcg_ctx, tcg_ctx->cpu_env, s->tmp2_i32);

                base = tcg_ctx->cpu_seg_base[modrm & 8 ? R_GS : R_FS];
                treg = tcg_ctx->cpu_regs[(modrm & 7) | REX_B(s)];

                if (modrm & 0x10) {
                    /* wr*base */
                    dst = base, src = treg;
                } else {
                    /* rd*base */
                    dst = treg, src = base;
                }

                if (s->dflag == MO_32) {
                    tcg_gen_ext32u_tl(tcg_ctx, dst, src);
                } else {
                    tcg_gen_mov_tl(tcg_ctx, dst, src);
                }
                break;
            }
            goto unknown_op;

        case 0xf8: /* sfence / pcommit */
            if (prefixes & PREFIX_DATA) {
                /* pcommit */
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_PCOMMIT)
                    || (prefixes & PREFIX_LOCK)) {
                    goto illegal_op;
                }
                break;
            }
            /* fallthru */
        case 0xf9: /* sfence */
        case 0xfa: /* sfence */
        case 0xfb: /* sfence */
        case 0xfc: /* sfence */
        case 0xfd: /* sfence */
        case 0xfe: /* sfence */
        case 0xff: /* sfence */
            if (!(s->cpuid_features & CPUID_SSE)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb(tcg_ctx, TCG_MO_ST_ST | TCG_BAR_SC);
            break;
        case 0xe8: /* lfence */
        case 0xe9: /* lfence */
        case 0xea: /* lfence */
        case 0xeb: /* lfence */
        case 0xec: /* lfence */
        case 0xed: /* lfence */
        case 0xee: /* lfence */
        case 0xef: /* lfence */
            if (!(s->cpuid_features & CPUID_SSE)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb(tcg_ctx, TCG_MO_LD_LD | TCG_BAR_SC);
            break;
        case 0xf0: /* mfence */
        case 0xf1: /* mfence */
        case 0xf2: /* mfence */
        case 0xf3: /* mfence */
        case 0xf4: /* mfence */
        case 0xf5: /* mfence */
        case 0xf6: /* mfence */
        case 0xf7: /* mfence */
            if (!(s->cpuid_features & CPUID_SSE2)
                || (prefixes & PREFIX_LOCK)) {
                goto illegal_op;
            }
            tcg_gen_mb(tcg_ctx, TCG_MO_ALL | TCG_BAR_SC);
            break;

        default:
            goto unknown_op;
        }
        break;

    case 0x10d: /* 3DNow! prefetch(w) */
        modrm = x86_ldub_code(env, s);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x1aa: /* rsm */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_RSM);
        if (!(s->flags & HF_SMM_MASK))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(s, s->pc - s->cs_base);
        gen_helper_rsm(tcg_ctx, tcg_ctx->cpu_env);
        gen_eob(s);
        break;
    case 0x1b8: /* SSE4.2 popcnt */
        if ((prefixes & (PREFIX_REPZ | PREFIX_LOCK | PREFIX_REPNZ)) !=
             PREFIX_REPZ)
            goto illegal_op;
        if (!(s->cpuid_ext_features & CPUID_EXT_POPCNT))
            goto illegal_op;

        modrm = x86_ldub_code(env, s);
        reg = ((modrm >> 3) & 7) | rex_r;

        if (s->prefix & PREFIX_DATA) {
            ot = MO_16;
        } else {
            ot = mo_64_32(dflag);
        }

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(tcg_ctx, ot, s->T0);
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_cc_src, s->T0);
        tcg_gen_ctpop_tl(tcg_ctx, s->T0, s->T0);
        gen_op_mov_reg_v(s, ot, reg, s->T0);

        set_cc_op(s, CC_OP_POPCNT);
        break;
    case 0x10e:
    case 0x10f:
        /* 3DNow! instructions, ignore prefixes */
        s->prefix &= ~(PREFIX_REPZ | PREFIX_REPNZ | PREFIX_DATA);
        /* fall through */
    case 0x110:
    case 0x111:
    case 0x112:
    case 0x113:
    case 0x114:
    case 0x115:
    case 0x116:
    case 0x117:

    case 0x128:
    case 0x129:
    case 0x12a:
    case 0x12b:
    case 0x12c:
    case 0x12d:
    case 0x12e:
    case 0x12f:

    case 0x138:
    case 0x139:
    case 0x13a:

    // case 0x150 ... 0x179:

    case 0x17c:
    case 0x17d:
    case 0x17e:
    case 0x17f:
    case 0x1c2:
    case 0x1c4:
    case 0x1c5:
    case 0x1c6:
    // case 0x1d0 ... 0x1fe:
        gen_sse(env, s, b, pc_start, rex_r);
        break;
    default:
        if (b >= 0x150 && b <= 0x179) {
            gen_sse(env, s, b, pc_start, rex_r);
            break;
        }

        if (b >= 0x1d0 && b <= 0x1fe) {
            gen_sse(env, s, b, pc_start, rex_r);
            break;
        }

        goto unknown_op;
    }

    if (insn_hook) {
        // Unicorn: patch the callback to have the proper instruction size.
        if (prev_op) {
            // As explained further up in the function where prev_op is
            // assigned, we move forward in the tail queue, so we're modifying the
            // move instruction generated by gen_uc_tracecode() that contains
            // the instruction size to assign the proper size (replacing 0xF1F1F1F1).
            tcg_op = QTAILQ_NEXT(prev_op, link);
        } else {
            // this instruction is the first emulated code ever,
            // so the operand is the first operand
            tcg_op = QTAILQ_FIRST(&tcg_ctx->ops);
        }
        tcg_op->args[1] = s->pc - pc_start;
    }

    return s->pc;

 illegal_op:
    gen_illegal_opcode(s);
    return s->pc;

 unknown_op:
    gen_unknown_opcode(env, s);
    return s->pc;
}

void tcg_x86_init(struct uc_struct *uc)
{
    static const char reg_names[CPU_NB_REGS][4] = {
#ifdef TARGET_X86_64
        [R_EAX] = "rax",
        [R_EBX] = "rbx",
        [R_ECX] = "rcx",
        [R_EDX] = "rdx",
        [R_ESI] = "rsi",
        [R_EDI] = "rdi",
        [R_EBP] = "rbp",
        [R_ESP] = "rsp",
        [8]  = "r8",
        [9]  = "r9",
        [10] = "r10",
        [11] = "r11",
        [12] = "r12",
        [13] = "r13",
        [14] = "r14",
        [15] = "r15",
#else
        [R_EAX] = "eax",
        [R_EBX] = "ebx",
        [R_ECX] = "ecx",
        [R_EDX] = "edx",
        [R_ESI] = "esi",
        [R_EDI] = "edi",
        [R_EBP] = "ebp",
        [R_ESP] = "esp",
#endif
    };
    static const char seg_base_names[6][8] = {
        [R_CS] = "cs_base",
        [R_DS] = "ds_base",
        [R_ES] = "es_base",
        [R_FS] = "fs_base",
        [R_GS] = "gs_base",
        [R_SS] = "ss_base",
    };
    static const char bnd_regl_names[4][8] = {
        "bnd0_lb", "bnd1_lb", "bnd2_lb", "bnd3_lb"
    };
    static const char bnd_regu_names[4][8] = {
        "bnd0_ub", "bnd1_ub", "bnd2_ub", "bnd3_ub"
    };
    int i;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    tcg_ctx->cpu_cc_op = tcg_global_mem_new_i32(tcg_ctx, tcg_ctx->cpu_env,
                                       offsetof(CPUX86State, cc_op), "cc_op");
    tcg_ctx->cpu_cc_dst = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPUX86State, cc_dst),
                                    "cc_dst");
    tcg_ctx->cpu_cc_src = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPUX86State, cc_src),
                                    "cc_src");
    tcg_ctx->cpu_cc_src2 = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPUX86State, cc_src2),
                                     "cc_src2");

    for (i = 0; i < CPU_NB_REGS; ++i) {
        tcg_ctx->cpu_regs[i] = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
                                         offsetof(CPUX86State, regs[i]),
                                         reg_names[i]);
    }

    for (i = 0; i < 6; ++i) {
        tcg_ctx->cpu_seg_base[i]
            = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
                                 offsetof(CPUX86State, segs[i].base),
                                 seg_base_names[i]);
    }

    for (i = 0; i < 4; ++i) {
        tcg_ctx->cpu_bndl[i]
            = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env,
                                     offsetof(CPUX86State, bnd_regs[i].lb),
                                     bnd_regl_names[i]);
        tcg_ctx->cpu_bndu[i]
            = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env,
                                     offsetof(CPUX86State, bnd_regs[i].ub),
                                     bnd_regu_names[i]);
    }
}

static void i386_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = cpu->uc->tcg_ctx;
    CPUX86State *env = cpu->env_ptr;
    uint32_t flags = dc->base.tb->flags;
    target_ulong cs_base = dc->base.tb->cs_base;

    // unicorn setup
    dc->uc = cpu->uc;
    dc->pe = (flags >> HF_PE_SHIFT) & 1;
    dc->code32 = (flags >> HF_CS32_SHIFT) & 1;
    dc->ss32 = (flags >> HF_SS32_SHIFT) & 1;
    dc->addseg = (flags >> HF_ADDSEG_SHIFT) & 1;
    dc->f_st = 0;
    dc->vm86 = (flags >> VM_SHIFT) & 1;
    dc->cpl = (flags >> HF_CPL_SHIFT) & 3;
    dc->iopl = (flags >> IOPL_SHIFT) & 3;
    dc->tf = (flags >> TF_SHIFT) & 1;
    dc->cc_op = CC_OP_DYNAMIC;
    dc->cc_op_dirty = false;
    dc->cs_base = cs_base;
    dc->popl_esp_hack = 0;
    /* select memory access functions */
    dc->mem_index = 0;
    dc->mem_index = cpu_mmu_index(env, false);
    dc->cpuid_features = env->features[FEAT_1_EDX];
    dc->cpuid_ext_features = env->features[FEAT_1_ECX];
    dc->cpuid_ext2_features = env->features[FEAT_8000_0001_EDX];
    dc->cpuid_ext3_features = env->features[FEAT_8000_0001_ECX];
    dc->cpuid_7_0_ebx_features = env->features[FEAT_7_0_EBX];
    dc->cpuid_xsave_features = env->features[FEAT_XSAVE];
#ifdef TARGET_X86_64
    dc->lma = (flags >> HF_LMA_SHIFT) & 1;
    dc->code64 = (flags >> HF_CS64_SHIFT) & 1;
#endif
    dc->flags = flags;
    dc->jmp_opt = !(dc->tf || dc->base.singlestep_enabled ||
                    (flags & HF_INHIBIT_IRQ_MASK));
    /* Do not optimize repz jumps at all in icount mode, because
       rep movsS instructions are execured with different paths
       in !repz_opt and repz_opt modes. The first one was used
       always except single step mode. And this setting
       disables jumps optimization and control paths become
       equivalent in run and single step modes.
       Now there will be no jump optimization for repz in
       record/replay modes and there will always be an
       additional step for ecx=0 when icount is enabled.
     */
    dc->repz_opt = !dc->jmp_opt && !(tb_cflags(dc->base.tb) & CF_USE_ICOUNT);
#if 0
    /* check addseg logic */
    if (!dc->addseg && (dc->vm86 || !dc->pe || !dc->code32))
        printf("ERROR addseg\n");
#endif

    dc->T0 = tcg_temp_new(tcg_ctx);
    dc->T1 = tcg_temp_new(tcg_ctx);
    dc->A0 = tcg_temp_new(tcg_ctx);

    dc->tmp0 = tcg_temp_new(tcg_ctx);
    dc->tmp1_i64 = tcg_temp_new_i64(tcg_ctx);
    dc->tmp2_i32 = tcg_temp_new_i32(tcg_ctx);
    dc->tmp3_i32 = tcg_temp_new_i32(tcg_ctx);
    dc->tmp4 = tcg_temp_new(tcg_ctx);
    dc->ptr0 = tcg_temp_new_ptr(tcg_ctx);
    dc->ptr1 = tcg_temp_new_ptr(tcg_ctx);
    dc->cc_srcT = tcg_temp_local_new(tcg_ctx);
}

static void i386_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void i386_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = dc->uc->tcg_ctx;

    dc->prev_pc = dc->base.pc_next;
    tcg_gen_insn_start(tcg_ctx, dc->base.pc_next, dc->cc_op);
}

static bool i386_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                     const CPUBreakpoint *bp)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    /* If RF is set, suppress an internally generated breakpoint.  */
    int flags = dc->base.tb->flags & HF_RF_MASK ? BP_GDB : BP_ANY;
    if (bp->flags & flags) {
        gen_debug(dc, dc->base.pc_next - dc->cs_base);
        dc->base.is_jmp = DISAS_NORETURN;
        /* The address covered by the breakpoint must be included in
           [tb->pc, tb->pc + tb->size) in order to for it to be
           properly cleared -- thus we increment the PC here so that
           the generic logic setting tb->size later does the right thing.  */
        dc->base.pc_next += 1;
        return true;
    } else {
        return false;
    }
}

static void i386_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    target_ulong pc_next;

    pc_next = disas_insn(dc, cpu);

    if (dc->tf || (dc->base.tb->flags & HF_INHIBIT_IRQ_MASK)) {
        /* if single step mode, we generate only one instruction and
           generate an exception */
        /* if irq were inhibited with HF_INHIBIT_IRQ_MASK, we clear
           the flag and abort the translation to give the irqs a
           chance to happen */
        dc->base.is_jmp = DISAS_TOO_MANY;
    } else if ((tb_cflags(dc->base.tb) & CF_USE_ICOUNT)
               && ((pc_next & TARGET_PAGE_MASK)
                   != ((pc_next + TARGET_MAX_INSN_SIZE - 1)
                       & TARGET_PAGE_MASK)
                   || (pc_next & ~TARGET_PAGE_MASK) == 0)) {
        /* Do not cross the boundary of the pages in icount mode,
           it can cause an exception. Do it only when boundary is
           crossed by the first instruction in the block.
           If current instruction already crossed the bound - it's ok,
           because an exception hasn't stopped this code.
         */
        dc->base.is_jmp = DISAS_TOO_MANY;
    } else if ((pc_next - dc->base.pc_first) >= (TARGET_PAGE_SIZE - 32)) {
        dc->base.is_jmp = DISAS_TOO_MANY;
    }

    dc->base.pc_next = pc_next;
}

static void i386_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    if (dc->base.is_jmp == DISAS_TOO_MANY) {
        gen_jmp_im(dc, dc->base.pc_next - dc->cs_base);
        gen_eob(dc);
    }
}

static const TranslatorOps i386_tr_ops = {
    .init_disas_context = i386_tr_init_disas_context,
    .tb_start           = i386_tr_tb_start,
    .insn_start         = i386_tr_insn_start,
    .breakpoint_check   = i386_tr_breakpoint_check,
    .translate_insn     = i386_tr_translate_insn,
    .tb_stop            = i386_tr_tb_stop,
};

/* generate intermediate code for basic block 'tb'.  */
void gen_intermediate_code(CPUState *cpu, TranslationBlock *tb, int max_insns)
{
    DisasContext dc;

    memset(&dc, 0, sizeof(dc));
    translator_loop(&i386_tr_ops, &dc.base, cpu, tb, max_insns);
}

void restore_state_to_opc(CPUX86State *env, TranslationBlock *tb,
                          target_ulong *data)
{
    int cc_op = data[1];
    env->eip = data[0] - tb->cs_base;
    if (cc_op != CC_OP_DYNAMIC) {
        env->cc_op = cc_op;
    }
}
