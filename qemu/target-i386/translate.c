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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "unicorn/platform.h"
#include <signal.h>

#include "qemu/host-utils.h"
#include "cpu.h"
#include "tcg-op.h"
#include "exec/cpu_ldst.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

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

#include "exec/gen-icount.h"

typedef struct DisasContext {
    /* current insn context */
    int override; /* -1 if no override */
    int prefix;
    TCGMemOp aflag;
    TCGMemOp dflag;
    target_ulong pc; /* pc = eip + cs_base */
    int is_jmp; /* 1 = means jump (stop translation), 2 means CPU
                   static state change (stop translation) */
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
    int vex_v;  /* vex vvvv register, without 1's compliment.  */
    int ss32;   /* 32 bit stack segment */
    CCOp cc_op;  /* current CC operation */
    CCOp last_cc_op;  /* Unicorn: last CC operation. Save this to see if cc_op has changed */
    bool cc_op_dirty;
    int addseg; /* non zero if either DS/ES/SS have a non zero base */
    int f_st;   /* currently unused */
    int vm86;   /* vm86 mode */
    int cpl;
    int iopl;
    int tf;     /* TF cpu flag */
    int singlestep_enabled; /* "hardware" single step enabled */
    int jmp_opt; /* use direct block chaining for direct jumps */
    int mem_index; /* select memory access functions */
    uint64_t flags; /* all execution flags */
    struct TranslationBlock *tb;
    int popl_esp_hack; /* for correct popl with esp base handling */
    int rip_offset; /* only used in x86_64, but left for simplicity */
    int cpuid_features;
    int cpuid_ext_features;
    int cpuid_ext2_features;
    int cpuid_ext3_features;
    int cpuid_7_0_ebx_features;
    struct uc_struct *uc;

    // Unicorn
    target_ulong prev_pc; /* save address of the previous instruction */
} DisasContext;

static void gen_eob(DisasContext *s);
static void gen_jmp(DisasContext *s, target_ulong eip);
static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num);
static void gen_op(DisasContext *s, int op, TCGMemOp ot, int d);

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
#ifdef _MSC_VER
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_DYNAMIC, /* must use dynamic code to get cc_op */
    USES_CC_SRC, // CC_OP_EFLAGS,  /* all cc are explicitly computed, CC_SRC = flags */

    USES_CC_DST | USES_CC_SRC, // CC_OP_MULB, /* modify all flags, C, O = (CC_SRC != 0) */
    USES_CC_DST | USES_CC_SRC, // CC_OP_MULW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_MULL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_MULQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_ADDB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    USES_CC_DST | USES_CC_SRC, // CC_OP_ADDW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_ADDL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_ADDQ,

    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCW,
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCL,
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCQ,

    USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBW,
    USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBL,
    USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBQ,

    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBW,
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBL,
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBQ,

    USES_CC_DST, // CC_OP_LOGICB, /* modify all flags, CC_DST = res */
    USES_CC_DST, // CC_OP_LOGICW,
    USES_CC_DST, // CC_OP_LOGICL,
    USES_CC_DST, // CC_OP_LOGICQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_INCB, /* modify all flags except, CC_DST = res, CC_SRC = C */
    USES_CC_DST | USES_CC_SRC, // CC_OP_INCW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_INCL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_INCQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_DECB, /* modify all flags except, CC_DST = res, CC_SRC = C  */
    USES_CC_DST | USES_CC_SRC, // CC_OP_DECW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_DECL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_DECQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_SHLB, /* modify all flags, CC_DST = res, CC_SRC.msb = C */
    USES_CC_DST | USES_CC_SRC, // CC_OP_SHLW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_SHLL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_SHLQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_SARB, /* modify all flags, CC_DST = res, CC_SRC.lsb = C */
    USES_CC_DST | USES_CC_SRC, // CC_OP_SARW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_SARL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_SARQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGB, /* Z,S via CC_DST, C = SRC==0; O=0; P,A undefined */
    USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGW,
    USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGL,
    USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGQ,

    USES_CC_DST | USES_CC_SRC, // CC_OP_ADCX, /* CC_DST = C, CC_SRC = rest.  */
    USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADOX, /* CC_DST = O, CC_SRC = rest.  */
    USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCOX, /* CC_DST = C, CC_SRC2 = O, CC_SRC = rest.  */

    0, // CC_OP_CLR, /* Z set, all other flags clear.  */
#else
    [CC_OP_DYNAMIC] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_EFLAGS] = USES_CC_SRC,
    [CC_OP_MULB ... CC_OP_MULQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDB ... CC_OP_ADDQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADCB ... CC_OP_ADCQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SUBB ... CC_OP_SUBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SBBB ... CC_OP_SBBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_LOGICB ... CC_OP_LOGICQ] = USES_CC_DST,
    [CC_OP_INCB ... CC_OP_INCQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECB ... CC_OP_DECQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLB ... CC_OP_SHLQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARB ... CC_OP_SARQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGB ... CC_OP_BMILGQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADCX] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADOX] = USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCOX] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_CLR] = 0,
#endif
};

static inline void gen_jmp_im(DisasContext *s, target_ulong pc);

static void set_cc_op(DisasContext *s, CCOp op)
{
    int dead;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;
    TCGv cpu_cc_srcT = *(TCGv *)tcg_ctx->cpu_cc_srcT;

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
        tcg_gen_discard_tl(tcg_ctx, cpu_cc_srcT);
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
static inline bool byte_reg_is_xH(int x86_64_hregs, int reg)
{
    if (reg < 4) {
        return false;
    }
#ifdef TARGET_X86_64
    if (reg >= 8 || x86_64_hregs) {
        return false;
    }
#endif
    return true;
}

/* Select the size of a push/pop operation.  */
static inline TCGMemOp mo_pushpop(DisasContext *s, TCGMemOp ot)
{
    if (CODE64(s)) {
        return ot == MO_16 ? MO_16 : MO_64;
    } else {
        return ot;
    }
}

/* Select only size 64 else 32.  Used for SSE operand sizes.  */
static inline TCGMemOp mo_64_32(TCGMemOp ot)
{
#ifdef TARGET_X86_64
    return ot == MO_64 ? MO_64 : MO_32;
#else
    return MO_32;
#endif
}

/* Select size 8 if lsb of B is clear, else OT.  Used for decoding
   byte vs word opcodes.  */
static inline TCGMemOp mo_b_d(int b, TCGMemOp ot)
{
    return b & 1 ? ot : MO_8;
}

/* Select size 8 if lsb of B is clear, else OT capped at 32.
   Used for decoding operand size of port opcodes.  */
static inline TCGMemOp mo_b_d32(int b, TCGMemOp ot)
{
    return b & 1 ? (ot == MO_16 ? MO_16 : MO_32) : MO_8;
}

static void gen_op_mov_reg_v(TCGContext *s, TCGMemOp ot, int reg, TCGv t0)
{
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    switch(ot) {
    case MO_8:
        if (!byte_reg_is_xH(s->x86_64_hregs, reg)) {
            tcg_gen_deposit_tl(s, *cpu_regs[reg], *cpu_regs[reg], t0, 0, 8);
        } else {
            tcg_gen_deposit_tl(s, *cpu_regs[reg - 4], *cpu_regs[reg - 4], t0, 8, 8);
        }
        break;
    case MO_16:
        tcg_gen_deposit_tl(s, *cpu_regs[reg], *cpu_regs[reg], t0, 0, 16);
        break;
    case MO_32:
        /* For x86_64, this sets the higher half of register to zero.
           For i386, this is equivalent to a mov. */
        tcg_gen_ext32u_tl(s, *cpu_regs[reg], t0);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        tcg_gen_mov_tl(s, *cpu_regs[reg], t0);
        break;
#endif
    default:
        tcg_abort();
    }
}

static inline void gen_op_mov_v_reg(TCGContext *s, TCGMemOp ot, TCGv t0, int reg)
{
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    if (ot == MO_8 && byte_reg_is_xH(s->x86_64_hregs, reg)) {
        tcg_gen_shri_tl(s, t0, *cpu_regs[reg - 4], 8);
        tcg_gen_ext8u_tl(s, t0, t0);
    } else {
        tcg_gen_mov_tl(s, t0, *cpu_regs[reg]);
    }
}

static inline void gen_op_movl_A0_reg(TCGContext *s, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_mov_tl(s, cpu_A0, *cpu_regs[reg]);
}

static inline void gen_op_addl_A0_im(TCGContext *s, int32_t val)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;

    tcg_gen_addi_tl(s, cpu_A0, cpu_A0, val);
#ifdef TARGET_X86_64
    tcg_gen_andi_tl(s, cpu_A0, cpu_A0, 0xffffffff);
#endif
}

#ifdef TARGET_X86_64
static inline void gen_op_addq_A0_im(TCGContext *s, int64_t val)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;

    tcg_gen_addi_tl(s, cpu_A0, cpu_A0, val);
}
#endif

static void gen_add_A0_im(DisasContext *s, int val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
#ifdef TARGET_X86_64
    if (CODE64(s))
        gen_op_addq_A0_im(tcg_ctx, val);
    else
#endif
        gen_op_addl_A0_im(tcg_ctx, val);
}

static inline void gen_op_jmp_v(TCGContext *s, TCGv dest)
{
    tcg_gen_st_tl(s, dest, s->cpu_env, offsetof(CPUX86State, eip));
}

static inline void gen_op_add_reg_im(TCGContext *s, TCGMemOp size, int reg, int32_t val)
{
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_addi_tl(s, cpu_tmp0, *cpu_regs[reg], val);
    gen_op_mov_reg_v(s, size, reg, cpu_tmp0);
}

static inline void gen_op_add_reg_T0(TCGContext *s, TCGMemOp size, int reg)
{
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;
    TCGv **cpu_T = (TCGv **)s->cpu_T;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_add_tl(s, cpu_tmp0, *cpu_regs[reg], *cpu_T[0]);
    gen_op_mov_reg_v(s, size, reg, cpu_tmp0);
}

static inline void gen_op_addl_A0_reg_sN(TCGContext *s, int shift, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_mov_tl(s, cpu_tmp0, *cpu_regs[reg]);
    if (shift != 0)
        tcg_gen_shli_tl(s, cpu_tmp0, cpu_tmp0, shift);
    tcg_gen_add_tl(s, cpu_A0, cpu_A0, cpu_tmp0);
    /* For x86_64, this sets the higher half of register to zero.
       For i386, this is equivalent to a nop. */
    tcg_gen_ext32u_tl(s, cpu_A0, cpu_A0);
}

static inline void gen_op_movl_A0_seg(TCGContext *s, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;

    tcg_gen_ld32u_tl(s, cpu_A0, s->cpu_env, offsetof(CPUX86State, segs[reg].base) + REG_L_OFFSET);
}

static inline void gen_op_addl_A0_seg(DisasContext *s, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;

    tcg_gen_ld_tl(tcg_ctx, cpu_tmp0, tcg_ctx->cpu_env, offsetof(CPUX86State, segs[reg].base));
#ifdef TARGET_X86_64
    if (CODE64(s)) {
        tcg_gen_andi_tl(tcg_ctx, cpu_A0, cpu_A0, 0xffffffff);
        tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, cpu_tmp0);
    } else {
        tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, cpu_tmp0);
        tcg_gen_andi_tl(tcg_ctx, cpu_A0, cpu_A0, 0xffffffff);
    }
#else
    tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, cpu_tmp0);
#endif
}

#ifdef TARGET_X86_64
static inline void gen_op_movq_A0_seg(TCGContext *s, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;

    tcg_gen_ld_tl(s, cpu_A0, s->cpu_env, offsetof(CPUX86State, segs[reg].base));
}

static inline void gen_op_addq_A0_seg(TCGContext *s, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;

    tcg_gen_ld_tl(s, cpu_tmp0, s->cpu_env, offsetof(CPUX86State, segs[reg].base));
    tcg_gen_add_tl(s, cpu_A0, cpu_A0, cpu_tmp0);
}

static inline void gen_op_movq_A0_reg(TCGContext *s, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_mov_tl(s, cpu_A0, *cpu_regs[reg]);
}

static inline void gen_op_addq_A0_reg_sN(TCGContext *s, int shift, int reg)
{
    TCGv cpu_A0 = *(TCGv *)s->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_mov_tl(s, cpu_tmp0, *cpu_regs[reg]);
    if (shift != 0)
        tcg_gen_shli_tl(s, cpu_tmp0, cpu_tmp0, shift);
    tcg_gen_add_tl(s, cpu_A0, cpu_A0, cpu_tmp0);
}
#endif

static inline void gen_op_ld_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    if (HOOK_EXISTS(s->uc, UC_HOOK_MEM_READ))
        gen_jmp_im(s, s->prev_pc); // Unicorn: sync EIP
    tcg_gen_qemu_ld_tl(s->uc, t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    if (HOOK_EXISTS(s->uc, UC_HOOK_MEM_WRITE))
        gen_jmp_im(s, s->prev_pc); // Unicorn: sync EIP
    tcg_gen_qemu_st_tl(s->uc, t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_rm_T0_A0(DisasContext *s, int idx, int d)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    if (d == OR_TMP0) {
        gen_op_st_v(s, idx, *cpu_T[0], cpu_A0);
    } else {
        gen_op_mov_reg_v(tcg_ctx, idx, d, *cpu_T[0]);
    }
}

static inline void gen_jmp_im(DisasContext *s, target_ulong pc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;

    tcg_gen_movi_tl(tcg_ctx, cpu_tmp0, pc);
    gen_op_jmp_v(tcg_ctx, cpu_tmp0);
}

static inline void gen_string_movl_A0_ESI(DisasContext *s)
{
    int override;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    override = s->override;
    switch (s->aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        if (override >= 0) {
            gen_op_movq_A0_seg(tcg_ctx, override);
            gen_op_addq_A0_reg_sN(tcg_ctx, 0, R_ESI);
        } else {
            gen_op_movq_A0_reg(tcg_ctx, R_ESI);
        }
        break;
#endif
    case MO_32:
        /* 32 bit address */
        if (s->addseg && override < 0)
            override = R_DS;
        if (override >= 0) {
            gen_op_movl_A0_seg(tcg_ctx, override);
            gen_op_addl_A0_reg_sN(tcg_ctx, 0, R_ESI);
        } else {
            gen_op_movl_A0_reg(tcg_ctx, R_ESI);
        }
        break;
    case MO_16:
        /* 16 address, always override */
        if (override < 0)
            override = R_DS;
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, *cpu_regs[R_ESI]);
        gen_op_addl_A0_seg(s, override);
        break;
    default:
        tcg_abort();
    }
}

static inline void gen_string_movl_A0_EDI(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    switch (s->aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        gen_op_movq_A0_reg(tcg_ctx, R_EDI);
        break;
#endif
    case MO_32:
        if (s->addseg) {
            gen_op_movl_A0_seg(tcg_ctx, R_ES);
            gen_op_addl_A0_reg_sN(tcg_ctx, 0, R_EDI);
        } else {
            gen_op_movl_A0_reg(tcg_ctx, R_EDI);
        }
        break;
    case MO_16:
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EDI]);
        gen_op_addl_A0_seg(s, R_ES);
        break;
    default:
        tcg_abort();
    }
}

static inline void gen_op_movl_T0_Dshift(TCGContext *s, TCGMemOp ot)
{
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_ld32s_tl(s, *cpu_T[0], s->cpu_env, offsetof(CPUX86State, df));
    tcg_gen_shli_tl(s, *cpu_T[0], *cpu_T[0], ot);
};

static TCGv gen_ext_tl(TCGContext *s, TCGv dst, TCGv src, TCGMemOp size, bool sign)
{
    switch (size) {
    case MO_8:
        if (sign) {
            tcg_gen_ext8s_tl(s, dst, src);
        } else {
            tcg_gen_ext8u_tl(s, dst, src);
        }
        return dst;
    case MO_16:
        if (sign) {
            tcg_gen_ext16s_tl(s, dst, src);
        } else {
            tcg_gen_ext16u_tl(s, dst, src);
        }
        return dst;
#ifdef TARGET_X86_64
    case MO_32:
        if (sign) {
            tcg_gen_ext32s_tl(s, dst, src);
        } else {
            tcg_gen_ext32u_tl(s, dst, src);
        }
        return dst;
#endif
    default:
        return src;
    }
}

static void gen_extu(TCGContext *s, TCGMemOp ot, TCGv reg)
{
    gen_ext_tl(s, reg, reg, ot, false);
}

static void gen_exts(TCGContext *s, TCGMemOp ot, TCGv reg)
{
    gen_ext_tl(s, reg, reg, ot, true);
}

static inline void gen_op_jnz_ecx(TCGContext *s, TCGMemOp size, int label1)
{
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_mov_tl(s, cpu_tmp0, *cpu_regs[R_ECX]);
    gen_extu(s, size, cpu_tmp0);
    tcg_gen_brcondi_tl(s, TCG_COND_NE, cpu_tmp0, 0, label1);
}

static inline void gen_op_jz_ecx(TCGContext *s, TCGMemOp size, int label1)
{
    TCGv cpu_tmp0 = *(TCGv *)s->cpu_tmp0;
    TCGv **cpu_regs = (TCGv **)s->cpu_regs;

    tcg_gen_mov_tl(s, cpu_tmp0, *cpu_regs[R_ECX]);
    gen_extu(s, size, cpu_tmp0);
    tcg_gen_brcondi_tl(s, TCG_COND_EQ, cpu_tmp0, 0, label1);
}

static void gen_helper_in_func(TCGContext *s, TCGMemOp ot, TCGv v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_inb(s, v, tcg_const_ptr(s, s->uc), n);
        break;
    case MO_16:
        gen_helper_inw(s, v, tcg_const_ptr(s, s->uc), n);
        break;
    case MO_32:
        gen_helper_inl(s, v, tcg_const_ptr(s, s->uc), n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_helper_out_func(TCGContext *s, TCGMemOp ot, TCGv_i32 v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_outb(s, tcg_const_ptr(s, s->uc), v, n);
        break;
    case MO_16:
        gen_helper_outw(s, tcg_const_ptr(s, s->uc), v, n);
        break;
    case MO_32:
        gen_helper_outl(s, tcg_const_ptr(s, s->uc), v, n);
        break;
    default:
        tcg_abort();
    }
}

static void gen_check_io(DisasContext *s, TCGMemOp ot, target_ulong cur_eip,
                         uint32_t svm_flags)
{
    int state_saved;
    target_ulong next_eip;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    // Unicorn: allow all I/O instructions
    return;

    state_saved = 0;
    if (s->pe && (s->cpl > s->iopl || s->vm86)) {
        gen_update_cc_op(s);
        gen_jmp_im(s, cur_eip);
        state_saved = 1;
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        switch (ot) {
        case MO_8:
            gen_helper_check_iob(tcg_ctx, tcg_ctx->cpu_env, cpu_tmp2_i32);
            break;
        case MO_16:
            gen_helper_check_iow(tcg_ctx, tcg_ctx->cpu_env, cpu_tmp2_i32);
            break;
        case MO_32:
            gen_helper_check_iol(tcg_ctx, tcg_ctx->cpu_env, cpu_tmp2_i32);
            break;
        default:
            tcg_abort();
        }
    }
    if(s->flags & HF_SVMI_MASK) {
        if (!state_saved) {
            gen_update_cc_op(s);
            gen_jmp_im(s, cur_eip);
        }
        svm_flags |= (1 << (4 + ot));
        next_eip = s->pc - s->cs_base;
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        gen_helper_svm_check_io(tcg_ctx, tcg_ctx->cpu_env, cpu_tmp2_i32,
                                tcg_const_i32(tcg_ctx, svm_flags),
                                tcg_const_i32(tcg_ctx, next_eip - cur_eip));
    }
}

static inline void gen_movs(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_ESI);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_EDI);
}

static void gen_op_update1_cc(TCGContext *s)
{
    TCGv cpu_cc_dst = *(TCGv *)s->cpu_cc_dst;
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_mov_tl(s, cpu_cc_dst, *cpu_T[0]);
}

static void gen_op_update2_cc(TCGContext *s)
{
    TCGv cpu_cc_dst = *(TCGv *)s->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)s->cpu_cc_src;
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_mov_tl(s, cpu_cc_src, *cpu_T[1]);
    tcg_gen_mov_tl(s, cpu_cc_dst, *cpu_T[0]);
}

static void gen_op_update3_cc(TCGContext *s, TCGv reg)
{
    TCGv cpu_cc_dst = *(TCGv *)s->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)s->cpu_cc_src;
    TCGv cpu_cc_src2 = *(TCGv *)s->cpu_cc_src2;
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_mov_tl(s, cpu_cc_src2, reg);
    tcg_gen_mov_tl(s, cpu_cc_src, *cpu_T[1]);
    tcg_gen_mov_tl(s, cpu_cc_dst, *cpu_T[0]);
}

static inline void gen_op_testl_T0_T1_cc(TCGContext *s)
{
    TCGv cpu_cc_dst = *(TCGv *)s->cpu_cc_dst;
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_and_tl(s, cpu_cc_dst, *cpu_T[0], *cpu_T[1]);
}

static void gen_op_update_neg_cc(TCGContext *s)
{
    TCGv cpu_cc_dst = *(TCGv *)s->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)s->cpu_cc_src;
    TCGv cpu_cc_srcT = *(TCGv *)s->cpu_cc_srcT;
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_mov_tl(s, cpu_cc_dst, *cpu_T[0]);
    tcg_gen_neg_tl(s, cpu_cc_src, *cpu_T[0]);
    tcg_gen_movi_tl(s, cpu_cc_srcT, 0);
}

/* compute all eflags to cc_src */
static void gen_compute_eflags(DisasContext *s)
{
    TCGv zero, dst, src1, src2;
    int live, dead;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;

    if (s->cc_op == CC_OP_EFLAGS) {
        return;
    }
    if (s->cc_op == CC_OP_CLR) {
        tcg_gen_movi_tl(tcg_ctx, cpu_cc_src, CC_Z | CC_P);
        set_cc_op(s, CC_OP_EFLAGS);
        return;
    }

    TCGV_UNUSED(zero);
    dst = cpu_cc_dst;
    src1 = cpu_cc_src;
    src2 = cpu_cc_src2;

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
    gen_helper_cc_compute_all(tcg_ctx, cpu_cc_src, dst, src1, src2, cpu_cc_op);
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

static inline CCPrepare ccprepare_make(TCGCond cond,
                          TCGv reg, TCGv reg2,
                          target_ulong imm, target_ulong mask,
                          bool use_reg2, bool no_setcond)
{
    CCPrepare cc = { cond, reg, reg2, imm, mask, use_reg2, no_setcond };
    return cc;
}

/* compute eflags.C to reg */
static CCPrepare gen_prepare_eflags_c(DisasContext *s, TCGv reg)
{
    TCGv t0, t1;
    int size, shift;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;
    TCGv cpu_cc_srcT = *(TCGv *)tcg_ctx->cpu_cc_srcT;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;

    switch (s->cc_op) {
    case CC_OP_SUBB: case CC_OP_SUBW: case CC_OP_SUBL: case CC_OP_SUBQ:
        /* (DATA_TYPE)CC_SRCT < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_SUBB;
        t1 = gen_ext_tl(tcg_ctx, cpu_tmp0, cpu_cc_src, size, false);
        /* If no temporary was used, be careful not to alias t1 and t0.  */
        t0 = TCGV_EQUAL(t1, cpu_cc_src) ? cpu_tmp0 : reg;
        tcg_gen_mov_tl(tcg_ctx, t0, cpu_cc_srcT);
        gen_extu(tcg_ctx, size, t0);
        goto add_sub;

    case CC_OP_ADDB: case CC_OP_ADDW: case CC_OP_ADDL: case CC_OP_ADDQ:
        /* (DATA_TYPE)CC_DST < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_ADDB;
        t1 = gen_ext_tl(tcg_ctx, cpu_tmp0, cpu_cc_src, size, false);
        t0 = gen_ext_tl(tcg_ctx, reg, cpu_cc_dst, size, false);
    add_sub:
        return ccprepare_make(TCG_COND_LTU, t0, t1, 0, -1, true, false);

    case CC_OP_LOGICB: case CC_OP_LOGICW: case CC_OP_LOGICL: case CC_OP_LOGICQ:
    case CC_OP_CLR:
        return ccprepare_make(TCG_COND_NEVER, 0, 0, 0, -1, false, false);

    case CC_OP_INCB: case CC_OP_INCW: case CC_OP_INCL: case CC_OP_INCQ:
    case CC_OP_DECB: case CC_OP_DECW: case CC_OP_DECL: case CC_OP_DECQ:
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, -1, false, true);

    case CC_OP_SHLB: case CC_OP_SHLW: case CC_OP_SHLL: case CC_OP_SHLQ:
        /* (CC_SRC >> (DATA_BITS - 1)) & 1 */
            size = s->cc_op - CC_OP_SHLB;
        shift = (8 << size) - 1;
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, (target_ulong)(1ULL << shift), false, false);

    case CC_OP_MULB: case CC_OP_MULW: case CC_OP_MULL: case CC_OP_MULQ:
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, -1, false, false);

    case CC_OP_BMILGB: case CC_OP_BMILGW: case CC_OP_BMILGL: case CC_OP_BMILGQ:
        size = s->cc_op - CC_OP_BMILGB;
        t0 = gen_ext_tl(tcg_ctx, reg, cpu_cc_src, size, false);
        return ccprepare_make(TCG_COND_EQ, t0, 0, 0, -1, false, false);

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return ccprepare_make(TCG_COND_NE, cpu_cc_dst, 0, 0, -1, false, true);

    case CC_OP_EFLAGS:
    case CC_OP_SARB: case CC_OP_SARW: case CC_OP_SARL: case CC_OP_SARQ:
        /* CC_SRC & 1 */
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, CC_C, false, false);

    default:
        /* The need to compute only C from CC_OP_DYNAMIC is important
            in efficiently implementing e.g. INC at the start of a TB.  */
        gen_update_cc_op(s);
        gen_helper_cc_compute_c(tcg_ctx, reg, cpu_cc_dst, cpu_cc_src,
                                cpu_cc_src2, cpu_cc_op);
        return ccprepare_make(TCG_COND_NE, reg, 0, 0, -1, false, true);
    }
}

/* compute eflags.P to reg */
static CCPrepare gen_prepare_eflags_p(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;

    gen_compute_eflags(s);
    return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, CC_P, false, false);
}

/* compute eflags.S to reg */
static CCPrepare gen_prepare_eflags_s(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;

    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, CC_S, false, false);
    case CC_OP_CLR:
        return ccprepare_make(TCG_COND_NEVER, 0, 0, 0, -1, false, false);
    default:
        {
            TCGMemOp size = (s->cc_op - CC_OP_ADDB) & 3;
            TCGv t0 = gen_ext_tl(tcg_ctx, reg, cpu_cc_dst, size, true);
            return ccprepare_make(TCG_COND_LT, t0, 0, 0, -1, false, false);
        }
    }
}

/* compute eflags.O to reg */
static CCPrepare gen_prepare_eflags_o(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;

    switch (s->cc_op) {
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return ccprepare_make(TCG_COND_NE, cpu_cc_src2, 0, 0, -1, false, true);
    case CC_OP_CLR:
        return ccprepare_make(TCG_COND_NEVER, 0, 0, 0, -1, false, false);
    default:
        gen_compute_eflags(s);
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, CC_O, false, false);
    }
}

/* compute eflags.Z to reg */
static CCPrepare gen_prepare_eflags_z(DisasContext *s, TCGv reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;

    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, CC_Z, false, false);
    case CC_OP_CLR:
        return ccprepare_make(TCG_COND_ALWAYS, 0, 0, 0, -1, false, false);
    default:
        {
            TCGMemOp size = (s->cc_op - CC_OP_ADDB) & 3;
            TCGv t0 = gen_ext_tl(tcg_ctx, reg, cpu_cc_dst, size, false);
            return ccprepare_make(TCG_COND_EQ, t0, 0, 0, -1, false, false);
        }
    }
}

/* perform a conditional store into register 'reg' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
static CCPrepare gen_prepare_cc(DisasContext *s, int b, TCGv reg)
{
    int inv, jcc_op, cond;
    TCGMemOp size;
    CCPrepare cc;
    TCGv t0;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_srcT = *(TCGv *)tcg_ctx->cpu_cc_srcT;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv cpu_tmp4 = *(TCGv *)tcg_ctx->cpu_tmp4;

    inv = b & 1;
    jcc_op = (b >> 1) & 7;

    switch (s->cc_op) {
    case CC_OP_SUBB: case CC_OP_SUBW: case CC_OP_SUBL: case CC_OP_SUBQ:
        /* We optimize relational operators for the cmp/jcc case.  */
        size = s->cc_op - CC_OP_SUBB;
        switch (jcc_op) {
        case JCC_BE:
            tcg_gen_mov_tl(tcg_ctx, cpu_tmp4, cpu_cc_srcT);
            gen_extu(tcg_ctx, size, cpu_tmp4);
            t0 = gen_ext_tl(tcg_ctx, cpu_tmp0, cpu_cc_src, size, false);
            cc = ccprepare_make(TCG_COND_LEU, cpu_tmp4, t0, 0, -1, true, false);
            break;

        case JCC_L:
            cond = TCG_COND_LT;
            goto fast_jcc_l;
        case JCC_LE:
            cond = TCG_COND_LE;
        fast_jcc_l:
            tcg_gen_mov_tl(tcg_ctx, cpu_tmp4, cpu_cc_srcT);
            gen_exts(tcg_ctx, size, cpu_tmp4);
            t0 = gen_ext_tl(tcg_ctx, cpu_tmp0, cpu_cc_src, size, true);
            cc = ccprepare_make(cond, cpu_tmp4, t0, 0, -1, true, false);
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
            cc = ccprepare_make(TCG_COND_NE, cpu_cc_src, 0, 0, CC_Z | CC_C, false, false);
            break;
        case JCC_S:
            cc = gen_prepare_eflags_s(s, reg);
            break;
        case JCC_P:
            cc = gen_prepare_eflags_p(s, reg);
            break;
        case JCC_L:
            gen_compute_eflags(s);
            if (TCGV_EQUAL(reg, cpu_cc_src)) {
                reg = cpu_tmp0;
            }
            tcg_gen_shri_tl(tcg_ctx, reg, cpu_cc_src, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(tcg_ctx, reg, reg, cpu_cc_src);
            cc = ccprepare_make(TCG_COND_NE, reg, 0, 0, CC_S, false, false);
            break;
        default:
        case JCC_LE:
            gen_compute_eflags(s);
            if (TCGV_EQUAL(reg, cpu_cc_src)) {
                reg = cpu_tmp0;
            }
            tcg_gen_shri_tl(tcg_ctx, reg, cpu_cc_src, 4); /* CC_O -> CC_S */
            tcg_gen_xor_tl(tcg_ctx, reg, reg, cpu_cc_src);
            cc = ccprepare_make(TCG_COND_NE, reg, 0, 0, CC_S | CC_Z, false, false);
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
    CCPrepare cc = gen_prepare_cc(s, b, reg);
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

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
static inline void gen_jcc1_noeob(DisasContext *s, int b, int l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    CCPrepare cc = gen_prepare_cc(s, b, *cpu_T[0]);

    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, *cpu_T[0], cc.reg, cc.mask);
        cc.reg = *cpu_T[0];
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
static inline void gen_jcc1(DisasContext *s, int b, int l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    CCPrepare cc = gen_prepare_cc(s, b, *cpu_T[0]);

    gen_update_cc_op(s);
    if (cc.mask != -1) {
        tcg_gen_andi_tl(tcg_ctx, *cpu_T[0], cc.reg, cc.mask);
        cc.reg = *cpu_T[0];
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
static int gen_jz_ecx_string(DisasContext *s, target_ulong next_eip)
{
    int l1, l2;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    l1 = gen_new_label(tcg_ctx);
    l2 = gen_new_label(tcg_ctx);
    gen_op_jnz_ecx(tcg_ctx, s->aflag, l1);
    gen_set_label(tcg_ctx, l2);
    gen_jmp_tb(s, next_eip, 1);
    gen_set_label(tcg_ctx, l1);
    return l2;
}

static inline void gen_stos(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], R_EAX);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_EDI);
}

static inline void gen_lods(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    gen_op_mov_reg_v(tcg_ctx, ot, R_EAX, *cpu_T[0]);
    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_ESI);
}

static inline void gen_scas(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
    gen_op(s, OP_CMPL, ot, R_EAX);
    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_EDI);
}

static inline void gen_cmps(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
    gen_string_movl_A0_ESI(s);
    gen_op(s, OP_CMPL, ot, OR_TMP0);
    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_ESI);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_EDI);
}

static inline void gen_ins(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    gen_string_movl_A0_EDI(s);
    /* Note: we must do this dummy write first to be restartable in
       case of page fault. */
    tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], 0);
    gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
    tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_regs[R_EDX]);
    tcg_gen_andi_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, 0xffff);
    gen_helper_in_func(tcg_ctx, ot, *cpu_T[0], cpu_tmp2_i32);
    gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_EDI);
}

static inline void gen_outs(DisasContext *s, TCGMemOp ot)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv_i32 cpu_tmp3_i32 = tcg_ctx->cpu_tmp3_i32;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);

    tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_regs[R_EDX]);
    tcg_gen_andi_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, 0xffff);
    tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_T[0]);
    gen_helper_out_func(tcg_ctx, ot, cpu_tmp2_i32, cpu_tmp3_i32);

    gen_op_movl_T0_Dshift(tcg_ctx, ot);
    gen_op_add_reg_T0(tcg_ctx, s->aflag, R_ESI);
}

/* same method as Valgrind : we generate jumps to current or next
   instruction */
#define GEN_REPZ(op)                                                          \
static inline void gen_repz_ ## op(DisasContext *s, TCGMemOp ot,              \
                                 target_ulong cur_eip, target_ulong next_eip) \
{                                                                             \
    int l2;\
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s->uc->tcg_ctx, s->aflag, R_ECX, -1);                                   \
    /* a loop would cause two single step exceptions if ECX = 1               \
       before rep string_insn */                                              \
    if (!s->jmp_opt)                                                          \
        gen_op_jz_ecx(s->uc->tcg_ctx, s->aflag, l2);                                          \
    gen_jmp(s, cur_eip);                                                      \
}

#define GEN_REPZ2(op)                                                         \
static inline void gen_repz_ ## op(DisasContext *s, TCGMemOp ot,              \
                                   target_ulong cur_eip,                      \
                                   target_ulong next_eip,                     \
                                   int nz)                                    \
{                                                                             \
    int l2;\
    gen_update_cc_op(s);                                                      \
    l2 = gen_jz_ecx_string(s, next_eip);                                      \
    gen_ ## op(s, ot);                                                        \
    gen_op_add_reg_im(s->uc->tcg_ctx, s->aflag, R_ECX, -1);                                   \
    gen_update_cc_op(s);                                                      \
    gen_jcc1(s, (JCC_Z << 1) | (nz ^ 1), l2);                                 \
    if (!s->jmp_opt)                                                          \
        gen_op_jz_ecx(s->uc->tcg_ctx, s->aflag, l2);                                          \
    gen_jmp(s, cur_eip);                                                      \
}

GEN_REPZ(movs)
GEN_REPZ(stos)
GEN_REPZ(lods)
GEN_REPZ(ins)
GEN_REPZ(outs)
GEN_REPZ2(scas)
GEN_REPZ2(cmps)

static void gen_helper_fp_arith_ST0_FT0(TCGContext *s, int op)
{
    switch (op) {
    case 0:
        gen_helper_fadd_ST0_FT0(s, s->cpu_env);
        break;
    case 1:
        gen_helper_fmul_ST0_FT0(s, s->cpu_env);
        break;
    case 2:
        gen_helper_fcom_ST0_FT0(s, s->cpu_env);
        break;
    case 3:
        gen_helper_fcom_ST0_FT0(s, s->cpu_env);
        break;
    case 4:
        gen_helper_fsub_ST0_FT0(s, s->cpu_env);
        break;
    case 5:
        gen_helper_fsubr_ST0_FT0(s, s->cpu_env);
        break;
    case 6:
        gen_helper_fdiv_ST0_FT0(s, s->cpu_env);
        break;
    case 7:
        gen_helper_fdivr_ST0_FT0(s, s->cpu_env);
        break;
    }
}

/* NOTE the exception in "r" op ordering */
static void gen_helper_fp_arith_STN_ST0(TCGContext *s, int op, int opreg)
{
    TCGv_i32 tmp = tcg_const_i32(s, opreg);
    switch (op) {
    case 0:
        gen_helper_fadd_STN_ST0(s, s->cpu_env, tmp);
        break;
    case 1:
        gen_helper_fmul_STN_ST0(s, s->cpu_env, tmp);
        break;
    case 4:
        gen_helper_fsubr_STN_ST0(s, s->cpu_env, tmp);
        break;
    case 5:
        gen_helper_fsub_STN_ST0(s, s->cpu_env, tmp);
        break;
    case 6:
        gen_helper_fdivr_STN_ST0(s, s->cpu_env, tmp);
        break;
    case 7:
        gen_helper_fdiv_STN_ST0(s, s->cpu_env, tmp);
        break;
    }
}

/* if d == OR_TMP0, it means memory operand (address in A0) */
static void gen_op(DisasContext *s, int op, TCGMemOp ot, int d)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_srcT = *(TCGv *)tcg_ctx->cpu_cc_srcT;
    TCGv cpu_tmp4 = *(TCGv *)tcg_ctx->cpu_tmp4;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    if (d != OR_TMP0) {
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], d);
    } else {
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    }
    switch(op) {
    case OP_ADCL:
        gen_compute_eflags_c(s, cpu_tmp4);
        tcg_gen_add_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        tcg_gen_add_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_tmp4);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update3_cc(tcg_ctx, cpu_tmp4);
        set_cc_op(s, CC_OP_ADCB + ot);
        break;
    case OP_SBBL:
        gen_compute_eflags_c(s, cpu_tmp4);
        tcg_gen_sub_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        tcg_gen_sub_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_tmp4);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update3_cc(tcg_ctx, cpu_tmp4);
        set_cc_op(s, CC_OP_SBBB + ot);
        break;
    case OP_ADDL:
        tcg_gen_add_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update2_cc(tcg_ctx);
        set_cc_op(s, CC_OP_ADDB + ot);
        break;
    case OP_SUBL:
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_srcT, *cpu_T[0]);
        tcg_gen_sub_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update2_cc(tcg_ctx);
        set_cc_op(s, CC_OP_SUBB + ot);
        break;
    default:
    case OP_ANDL:
        tcg_gen_and_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update1_cc(tcg_ctx);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;
    case OP_ORL:
        tcg_gen_or_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update1_cc(tcg_ctx);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;
    case OP_XORL:
        tcg_gen_xor_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        gen_op_st_rm_T0_A0(s, ot, d);
        gen_op_update1_cc(tcg_ctx);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;
    case OP_CMPL:
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_T[1]);
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_srcT, *cpu_T[0]);
        tcg_gen_sub_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0], *cpu_T[1]);
        set_cc_op(s, CC_OP_SUBB + ot);
        break;
    }
}

/* if d == OR_TMP0, it means memory operand (address in A0) */
static void gen_inc(DisasContext *s, TCGMemOp ot, int d, int c)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    if (d != OR_TMP0) {
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], d);
    } else {
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    }
    gen_compute_eflags_c(s, cpu_cc_src);
    if (c > 0) {
        tcg_gen_addi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 1);
        set_cc_op(s, CC_OP_INCB + ot);
    } else {
        tcg_gen_addi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], -1);
        set_cc_op(s, CC_OP_DECB + ot);
    }
    gen_op_st_rm_T0_A0(s, ot, d);
    tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
}

static void gen_shift_flags(DisasContext *s, TCGMemOp ot, TCGv result,
                            TCGv shm1, TCGv count, bool is_right)
{
    TCGv_i32 z32, s32, oldop;
    TCGv z_tl;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv_i32 cpu_tmp3_i32 = tcg_ctx->cpu_tmp3_i32;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;

    /* Store the results into the CC variables.  If we know that the
       variable must be dead, store unconditionally.  Otherwise we'll
       need to not disrupt the current contents.  */
    z_tl = tcg_const_tl(tcg_ctx, 0);
    if (cc_op_live[s->cc_op] & USES_CC_DST) {
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, cpu_cc_dst, count, z_tl,
                           result, cpu_cc_dst);
    } else {
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, result);
    }
    if (cc_op_live[s->cc_op] & USES_CC_SRC) {
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_NE, cpu_cc_src, count, z_tl,
                           shm1, cpu_cc_src);
    } else {
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, shm1);
    }
    tcg_temp_free(tcg_ctx, z_tl);

    /* Get the two potential CC_OP values into temporaries.  */
    tcg_gen_movi_i32(tcg_ctx, cpu_tmp2_i32, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    if (s->cc_op == CC_OP_DYNAMIC) {
        oldop = cpu_cc_op;
    } else {
        tcg_gen_movi_i32(tcg_ctx, cpu_tmp3_i32, s->cc_op);
        oldop = cpu_tmp3_i32;
    }

    /* Conditionally store the CC_OP value.  */
    z32 = tcg_const_i32(tcg_ctx, 0);
    s32 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, s32, count);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, cpu_cc_op, s32, z32, cpu_tmp2_i32, oldop);
    tcg_temp_free_i32(tcg_ctx, z32);
    tcg_temp_free_i32(tcg_ctx, s32);

    /* The CC_OP value is no longer predictable.  */
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_shift_rm_T1(DisasContext *s, TCGMemOp ot, int op1,
                            int is_right, int is_arith)
{
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    } else {
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], op1);
    }

    tcg_gen_andi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], mask);
    tcg_gen_subi_tl(tcg_ctx, cpu_tmp0, *cpu_T[1], 1);

    if (is_right) {
        if (is_arith) {
            gen_exts(tcg_ctx, ot, *cpu_T[0]);
            tcg_gen_sar_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);
            tcg_gen_sar_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        } else {
            gen_extu(tcg_ctx, ot, *cpu_T[0]);
            tcg_gen_shr_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);
            tcg_gen_shr_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        }
    } else {
        tcg_gen_shl_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);
        tcg_gen_shl_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, *cpu_T[0], cpu_tmp0, *cpu_T[1], is_right);
}

static void gen_shift_rm_im(DisasContext *s, TCGMemOp ot, int op1, int op2,
                            int is_right, int is_arith)
{
    int mask = (ot == MO_64 ? 0x3f : 0x1f);
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_tmp4 = *(TCGv *)tcg_ctx->cpu_tmp4;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    else
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], op1);

    op2 &= mask;
    if (op2 != 0) {
        if (is_right) {
            if (is_arith) {
                gen_exts(tcg_ctx, ot, *cpu_T[0]);
                tcg_gen_sari_tl(tcg_ctx, cpu_tmp4, *cpu_T[0], op2 - 1);
                tcg_gen_sari_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], op2);
            } else {
                gen_extu(tcg_ctx, ot, *cpu_T[0]);
                tcg_gen_shri_tl(tcg_ctx, cpu_tmp4, *cpu_T[0], op2 - 1);
                tcg_gen_shri_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], op2);
            }
        } else {
            tcg_gen_shli_tl(tcg_ctx, cpu_tmp4, *cpu_T[0], op2 - 1);
            tcg_gen_shli_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], op2);
        }
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    /* update eflags if non zero shift */
    if (op2 != 0) {
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, cpu_tmp4);
        tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
        set_cc_op(s, (is_right ? CC_OP_SARB : CC_OP_SHLB) + ot);
    }
}

static void gen_rot_rm_T1(DisasContext *s, TCGMemOp ot, int op1, int is_right)
{
    target_ulong mask = (ot == MO_64 ? 0x3f : 0x1f);
    TCGv_i32 t0, t1;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv_i32 cpu_tmp3_i32 = tcg_ctx->cpu_tmp3_i32;
    TCGv_i32 cpu_cc_op = tcg_ctx->cpu_cc_op;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    } else {
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], op1);
    }

    tcg_gen_andi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], mask);

    switch (ot) {
    case MO_8:
        /* Replicate the 8-bit input so that a 32-bit rotate works.  */
        tcg_gen_ext8u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
        tcg_gen_muli_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 0x01010101);
        goto do_long;
    case MO_16:
        /* Replicate the 16-bit input so that a 32-bit rotate works.  */
        tcg_gen_deposit_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[0], 16, 16);
        goto do_long;
    do_long:
#ifdef TARGET_X86_64
    case MO_32:
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_T[1]);
        if (is_right) {
            tcg_gen_rotr_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
        } else {
            tcg_gen_rotl_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
        }
        tcg_gen_extu_i32_tl(tcg_ctx, *cpu_T[0], cpu_tmp2_i32);
        break;
#endif
    default:
        if (is_right) {
            tcg_gen_rotr_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        } else {
            tcg_gen_rotl_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
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
        tcg_gen_shri_tl(tcg_ctx, cpu_cc_src2, *cpu_T[0], mask - 1);
        tcg_gen_shri_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0], mask);
        tcg_gen_andi_tl(tcg_ctx, cpu_cc_dst, cpu_cc_dst, 1);
    } else {
        tcg_gen_shri_tl(tcg_ctx, cpu_cc_src2, *cpu_T[0], mask);
        tcg_gen_andi_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0], 1);
    }
    tcg_gen_andi_tl(tcg_ctx, cpu_cc_src2, cpu_cc_src2, 1);
    tcg_gen_xor_tl(tcg_ctx, cpu_cc_src2, cpu_cc_src2, cpu_cc_dst);

    /* Now conditionally store the new CC_OP value.  If the shift count
       is 0 we keep the CC_OP_EFLAGS setting so that only CC_SRC is live.
       Otherwise reuse CC_OP_ADCOX which have the C and O flags split out
       exactly as we computed above.  */
    t0 = tcg_const_i32(tcg_ctx, 0);
    t1 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_trunc_tl_i32(tcg_ctx, t1, *cpu_T[1]);
    tcg_gen_movi_i32(tcg_ctx, cpu_tmp2_i32, CC_OP_ADCOX);
    tcg_gen_movi_i32(tcg_ctx, cpu_tmp3_i32, CC_OP_EFLAGS);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, cpu_cc_op, t1, t0,
                        cpu_tmp2_i32, cpu_tmp3_i32);
    tcg_temp_free_i32(tcg_ctx, t0);
    tcg_temp_free_i32(tcg_ctx, t1);

    /* The CC_OP value is no longer predictable.  */
    set_cc_op(s, CC_OP_DYNAMIC);
}

static void gen_rot_rm_im(DisasContext *s, TCGMemOp ot, int op1, int op2,
                          int is_right)
{
    int mask = (ot == MO_64 ? 0x3f : 0x1f);
    int shift;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

#ifdef TARGET_X86_64
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
#endif

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    } else {
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], op1);
    }

    op2 &= mask;
    if (op2 != 0) {
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_32:
            tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
            if (is_right) {
                tcg_gen_rotri_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, op2);
            } else {
                tcg_gen_rotli_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, op2);
            }
            tcg_gen_extu_i32_tl(tcg_ctx, *cpu_T[0], cpu_tmp2_i32);
            break;
#endif
        default:
            if (is_right) {
                tcg_gen_rotri_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], op2);
            } else {
                tcg_gen_rotli_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], op2);
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
            gen_extu(tcg_ctx, ot, *cpu_T[0]);
            tcg_gen_shli_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], shift);
            tcg_gen_shri_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], mask + 1 - shift);
            tcg_gen_or_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_tmp0);
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
            tcg_gen_shri_tl(tcg_ctx, cpu_cc_src2, *cpu_T[0], mask - 1);
            tcg_gen_shri_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0], mask);
            tcg_gen_andi_tl(tcg_ctx, cpu_cc_dst, cpu_cc_dst, 1);
        } else {
            tcg_gen_shri_tl(tcg_ctx, cpu_cc_src2, *cpu_T[0], mask);
            tcg_gen_andi_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0], 1);
        }
        tcg_gen_andi_tl(tcg_ctx, cpu_cc_src2, cpu_cc_src2, 1);
        tcg_gen_xor_tl(tcg_ctx, cpu_cc_src2, cpu_cc_src2, cpu_cc_dst);
        set_cc_op(s, CC_OP_ADCOX);
    }
}

/* XXX: add faster immediate = 1 case */
static void gen_rotc_rm_T1(DisasContext *s, TCGMemOp ot, int op1,
                           int is_right)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_compute_eflags(s);
    assert(s->cc_op == CC_OP_EFLAGS);

    /* load */
    if (op1 == OR_TMP0)
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    else
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], op1);

    if (is_right) {
        switch (ot) {
        case MO_8:
            gen_helper_rcrb(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
        case MO_16:
            gen_helper_rcrw(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
        case MO_32:
            gen_helper_rcrl(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rcrq(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
#endif
        default:
            tcg_abort();
        }
    } else {
        switch (ot) {
        case MO_8:
            gen_helper_rclb(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
        case MO_16:
            gen_helper_rclw(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
        case MO_32:
            gen_helper_rcll(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
            break;
#ifdef TARGET_X86_64
        case MO_64:
            gen_helper_rclq(tcg_ctx, *cpu_T[0], tcg_ctx->cpu_env, *cpu_T[0], *cpu_T[1]);
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
static void gen_shiftd_rm_T1(DisasContext *s, TCGMemOp ot, int op1,
                             bool is_right, TCGv count_in)
{
    target_ulong mask = (ot == MO_64 ? 63 : 31);
    TCGv count;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv cpu_tmp4 = *(TCGv *)tcg_ctx->cpu_tmp4;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    /* load */
    if (op1 == OR_TMP0) {
        gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
    } else {
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], op1);
    }

    count = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_tl(tcg_ctx, count, count_in, mask);

    switch (ot) {
    case MO_16:
        /* Note: we implement the Intel behaviour for shift count > 16.
           This means "shrdw C, B, A" shifts A:B:A >> C.  Build the B:A
           portion by constructing it as a 32-bit value.  */
        if (is_right) {
            tcg_gen_deposit_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], *cpu_T[1], 16, 16);
            tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], *cpu_T[0]);
            tcg_gen_mov_tl(tcg_ctx, *cpu_T[0], cpu_tmp0);
        } else {
            tcg_gen_deposit_tl(tcg_ctx, *cpu_T[1], *cpu_T[0], *cpu_T[1], 16, 16);
        }
        /* FALLTHRU */
#ifdef TARGET_X86_64
    case MO_32:
        /* Concatenate the two 32-bit values and use a 64-bit shift.  */
        tcg_gen_subi_tl(tcg_ctx, cpu_tmp0, count, 1);
        if (is_right) {
            tcg_gen_concat_tl_i64(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
            tcg_gen_shr_i64(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);
            tcg_gen_shr_i64(tcg_ctx, *cpu_T[0], *cpu_T[0], count);
        } else {
            tcg_gen_concat_tl_i64(tcg_ctx, *cpu_T[0], *cpu_T[1], *cpu_T[0]);
            tcg_gen_shl_i64(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);
            tcg_gen_shl_i64(tcg_ctx, *cpu_T[0], *cpu_T[0], count);
            tcg_gen_shri_i64(tcg_ctx, cpu_tmp0, cpu_tmp0, 32);
            tcg_gen_shri_i64(tcg_ctx, *cpu_T[0], *cpu_T[0], 32);
        }
        break;
#endif
    default:
        tcg_gen_subi_tl(tcg_ctx, cpu_tmp0, count, 1);
        if (is_right) {
            tcg_gen_shr_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);

            tcg_gen_subfi_tl(tcg_ctx, cpu_tmp4, mask + 1, count);
            tcg_gen_shr_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], count);
            tcg_gen_shl_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], cpu_tmp4);
        } else {
            tcg_gen_shl_tl(tcg_ctx, cpu_tmp0, *cpu_T[0], cpu_tmp0);
            if (ot == MO_16) {
                /* Only needed if count > 16, for Intel behaviour.  */
                tcg_gen_subfi_tl(tcg_ctx, cpu_tmp4, 33, count);
                tcg_gen_shr_tl(tcg_ctx, cpu_tmp4, *cpu_T[1], cpu_tmp4);
                tcg_gen_or_tl(tcg_ctx, cpu_tmp0, cpu_tmp0, cpu_tmp4);
            }

            tcg_gen_subfi_tl(tcg_ctx, cpu_tmp4, mask + 1, count);
            tcg_gen_shl_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], count);
            tcg_gen_shr_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], cpu_tmp4);
        }
        tcg_gen_movi_tl(tcg_ctx, cpu_tmp4, 0);
        tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, *cpu_T[1], count, cpu_tmp4,
                           cpu_tmp4, *cpu_T[1]);
        tcg_gen_or_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
        break;
    }

    /* store */
    gen_op_st_rm_T0_A0(s, ot, op1);

    gen_shift_flags(s, ot, *cpu_T[0], cpu_tmp0, count, is_right);
    tcg_temp_free(tcg_ctx, count);
}

static void gen_shift(DisasContext *s1, int op, TCGMemOp ot, int d, int s)
{
    TCGContext *tcg_ctx = s1->uc->tcg_ctx;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    if (s != OR_TMP1)
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], s);
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

static void gen_shifti(DisasContext *s, int op, TCGMemOp ot, int d, int c)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    switch(op) {
    case OP_ROL:
        gen_rot_rm_im(s, ot, d, c, 0);
        break;
    case OP_ROR:
        gen_rot_rm_im(s, ot, d, c, 1);
        break;
    case OP_SHL:
    case OP_SHL1:
        gen_shift_rm_im(s, ot, d, c, 0, 0);
        break;
    case OP_SHR:
        gen_shift_rm_im(s, ot, d, c, 1, 0);
        break;
    case OP_SAR:
        gen_shift_rm_im(s, ot, d, c, 1, 1);
        break;
    default:
        /* currently not optimized */
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], c);
        gen_shift(s, op, ot, d, OR_TMP1);
        break;
    }
}

static void gen_lea_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    target_long disp;
    int havesib;
    int base;
    int index;
    int scale;
    int mod, rm, code, override, must_add_seg;
    TCGv sum;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    override = s->override;
    must_add_seg = s->addseg;
    if (override >= 0)
        must_add_seg = 1;
    mod = (modrm >> 6) & 3;
    rm = modrm & 7;

    switch (s->aflag) {
    case MO_64:
    case MO_32:
        havesib = 0;
        base = rm;
        index = -1;
        scale = 0;

        if (base == 4) {
            havesib = 1;
            code = cpu_ldub_code(env, s->pc++);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            if (index == 4) {
                index = -1;  /* no index */
            }
            base = (code & 7);
        }
        base |= REX_B(s);

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)cpu_ldl_code(env, s->pc);
                s->pc += 4;
                if (CODE64(s) && !havesib) {
                    disp += s->pc + s->rip_offset;
                }
            } else {
                disp = 0;
            }
            break;
        case 1:
            disp = (int8_t)cpu_ldub_code(env, s->pc++);
            break;
        default:
        case 2:
            disp = (int32_t)cpu_ldl_code(env, s->pc);
            s->pc += 4;
            break;
        }

        /* For correct popl handling with esp.  */
        if (base == R_ESP && s->popl_esp_hack) {
            disp += s->popl_esp_hack;
        }

        /* Compute the address, with a minimum number of TCG ops.  */
        TCGV_UNUSED(sum);
        if (index >= 0) {
            if (scale == 0) {
                sum = *cpu_regs[index];
            } else {
                tcg_gen_shli_tl(tcg_ctx, cpu_A0, *cpu_regs[index], scale);
                sum = cpu_A0;
            }
            if (base >= 0) {
                tcg_gen_add_tl(tcg_ctx, cpu_A0, sum, *cpu_regs[base]);
                sum = cpu_A0;
            }
        } else if (base >= 0) {
            sum = *cpu_regs[base];
        }
        if (TCGV_IS_UNUSED(sum)) {
            tcg_gen_movi_tl(tcg_ctx, cpu_A0, disp);
        } else {
            tcg_gen_addi_tl(tcg_ctx, cpu_A0, sum, disp);
        }

        if (must_add_seg) {
            if (override < 0) {
                if (base == R_EBP || base == R_ESP) {
                    override = R_SS;
                } else {
                    override = R_DS;
                }
            }

            tcg_gen_ld_tl(tcg_ctx, cpu_tmp0, tcg_ctx->cpu_env,
                          offsetof(CPUX86State, segs[override].base));
            if (CODE64(s)) {
                if (s->aflag == MO_32) {
                    tcg_gen_ext32u_tl(tcg_ctx, cpu_A0, cpu_A0);
                }
                tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, cpu_tmp0);
                return;
            }

            tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, cpu_tmp0);
        }

        if (s->aflag == MO_32) {
            tcg_gen_ext32u_tl(tcg_ctx, cpu_A0, cpu_A0);
        }
        break;

    case MO_16:
        switch (mod) {
        case 0:
            if (rm == 6) {
                disp = cpu_lduw_code(env, s->pc);
                s->pc += 2;
                tcg_gen_movi_tl(tcg_ctx, cpu_A0, disp);
                rm = 0; /* avoid SS override */
                goto no_rm;
            } else {
                disp = 0;
            }
            break;
        case 1:
            disp = (int8_t)cpu_ldub_code(env, s->pc++);
            break;
        default:
        case 2:
            disp = (int16_t)cpu_lduw_code(env, s->pc);
            s->pc += 2;
            break;
        }

        sum = cpu_A0;
        switch (rm) {
        case 0:
            tcg_gen_add_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EBX], *cpu_regs[R_ESI]);
            break;
        case 1:
            tcg_gen_add_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EBX], *cpu_regs[R_EDI]);
            break;
        case 2:
            tcg_gen_add_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EBP], *cpu_regs[R_ESI]);
            break;
        case 3:
            tcg_gen_add_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EBP], *cpu_regs[R_EDI]);
            break;
        case 4:
            sum = *cpu_regs[R_ESI];
            break;
        case 5:
            sum = *cpu_regs[R_EDI];
            break;
        case 6:
            sum = *cpu_regs[R_EBP];
            break;
        default:
        case 7:
            sum = *cpu_regs[R_EBX];
            break;
        }
        tcg_gen_addi_tl(tcg_ctx, cpu_A0, sum, disp);
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, cpu_A0);
    no_rm:
        if (must_add_seg) {
            if (override < 0) {
                if (rm == 2 || rm == 3 || rm == 6) {
                    override = R_SS;
                } else {
                    override = R_DS;
                }
            }
            gen_op_addl_A0_seg(s, override);
        }
        break;

    default:
        tcg_abort();
    }
}

static void gen_nop_modrm(CPUX86State *env, DisasContext *s, int modrm)
{
    int mod, rm, base, code;

    mod = (modrm >> 6) & 3;
    if (mod == 3)
        return;
    rm = modrm & 7;

    switch (s->aflag) {
    case MO_64:
    case MO_32:
        base = rm;

        if (base == 4) {
            code = cpu_ldub_code(env, s->pc++);
            base = (code & 7);
        }

        switch (mod) {
        case 0:
            if (base == 5) {
                s->pc += 4;
            }
            break;
        case 1:
            s->pc++;
            break;
        default:
        case 2:
            s->pc += 4;
            break;
        }
        break;

    case MO_16:
        switch (mod) {
        case 0:
            if (rm == 6) {
                s->pc += 2;
            }
            break;
        case 1:
            s->pc++;
            break;
        default:
        case 2:
            s->pc += 2;
            break;
        }
        break;

    default:
        tcg_abort();
    }
}

/* used for LEA and MOV AX, mem */
static void gen_add_A0_ds_seg(DisasContext *s)
{
    int override, must_add_seg;
    must_add_seg = s->addseg;
    override = R_DS;
    if (s->override >= 0) {
        override = s->override;
        must_add_seg = 1;
    }
    if (must_add_seg) {
#ifdef TARGET_X86_64
        if (CODE64(s)) {
            gen_op_addq_A0_seg(s->uc->tcg_ctx, override);
        } else
#endif
        {
            gen_op_addl_A0_seg(s, override);
        }
    }
}

/* generate modrm memory load or store of 'reg'. TMP0 is used if reg ==
   OR_TMP0 */
static void gen_ldst_modrm(CPUX86State *env, DisasContext *s, int modrm,
                           TCGMemOp ot, int reg, int is_store)
{
    int mod, rm;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;


    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
            gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
        } else {
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
        }
    } else {
        gen_lea_modrm(env, s, modrm);
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
            gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
        } else {
            gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
            if (reg != OR_TMP0)
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
        }
    }
}

static inline uint32_t insn_get(CPUX86State *env, DisasContext *s, TCGMemOp ot)
{
    uint32_t ret;

    switch (ot) {
    case MO_8:
        ret = cpu_ldub_code(env, s->pc);
        s->pc++;
        break;
    case MO_16:
        ret = cpu_lduw_code(env, s->pc);
        s->pc += 2;
        break;
    case MO_32:
#ifdef TARGET_X86_64
    case MO_64:
#endif
        ret = cpu_ldl_code(env, s->pc);
        s->pc += 4;
        break;
    default:
        tcg_abort();
    }
    return ret;
}

static inline int insn_const_size(TCGMemOp ot)
{
    if (ot <= MO_32) {
        return 1 << ot;
    } else {
        return 4;
    }
}

static inline void gen_goto_tb(DisasContext *s, int tb_num, target_ulong eip)
{
    TranslationBlock *tb;
    target_ulong pc;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    pc = s->cs_base + eip;
    tb = s->tb;
    /* NOTE: we handle the case where the TB spans two pages here */
    if ((pc & TARGET_PAGE_MASK) == (tb->pc & TARGET_PAGE_MASK) ||
        (pc & TARGET_PAGE_MASK) == ((s->pc - 1) & TARGET_PAGE_MASK))  {
        /* jump to same page: we can use a direct jump */
        tcg_gen_goto_tb(tcg_ctx, tb_num);
        gen_jmp_im(s, eip);
        tcg_gen_exit_tb(tcg_ctx, (uintptr_t)tb + tb_num);
    } else {
        /* jump to another page: currently not optimized */
        gen_jmp_im(s, eip);
        gen_eob(s);
    }
}

static inline void gen_jcc(DisasContext *s, int b,
                           target_ulong val, target_ulong next_eip)
{
    int l1, l2;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (s->jmp_opt) {
        l1 = gen_new_label(tcg_ctx);
        gen_jcc1(s, b, l1);

        gen_goto_tb(s, 0, next_eip);

        gen_set_label(tcg_ctx, l1);
        gen_goto_tb(s, 1, val);
        s->is_jmp = DISAS_TB_JUMP;
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

static void gen_cmovcc1(CPUX86State *env, DisasContext *s, TCGMemOp ot, int b,
                        int modrm, int reg)
{
    CCPrepare cc;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);

    cc = gen_prepare_cc(s, b, *cpu_T[1]);
    if (cc.mask != -1) {
        TCGv t0 = tcg_temp_new(tcg_ctx);
        tcg_gen_andi_tl(tcg_ctx, t0, cc.reg, cc.mask);
        cc.reg = t0;
    }
    if (!cc.use_reg2) {
        cc.reg2 = tcg_const_tl(tcg_ctx, cc.imm);
    }

    tcg_gen_movcond_tl(tcg_ctx, cc.cond, *cpu_T[0], cc.reg, cc.reg2,
                       *cpu_T[0], *cpu_regs[reg]);
    gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);

    if (cc.mask != -1) {
        tcg_temp_free(tcg_ctx, cc.reg);
    }
    if (!cc.use_reg2) {
        tcg_temp_free(tcg_ctx, cc.reg2);
    }
}

static inline void gen_op_movl_T0_seg(TCGContext *s, int seg_reg)
{
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_ld32u_tl(s, *cpu_T[0], s->cpu_env,
                     offsetof(CPUX86State,segs[seg_reg].selector));
}

static inline void gen_op_movl_seg_T0_vm(TCGContext *s, int seg_reg)
{
    TCGv **cpu_T = (TCGv **)s->cpu_T;

    tcg_gen_andi_tl(s, *cpu_T[0], *cpu_T[0], 0xffff);
    tcg_gen_st32_tl(s, *cpu_T[0], s->cpu_env,
                    offsetof(CPUX86State,segs[seg_reg].selector));
    tcg_gen_shli_tl(s, *cpu_T[0], *cpu_T[0], 4);
    tcg_gen_st_tl(s, *cpu_T[0], s->cpu_env,
                  offsetof(CPUX86State,segs[seg_reg].base));
}

/* move T0 to seg_reg and compute if the CPU state may change. Never
   call this function with seg_reg == R_CS */
static void gen_movl_seg_T0(DisasContext *s, int seg_reg, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    if (s->pe && !s->vm86) {
        /* XXX: optimize by finding processor state dynamically */
        gen_update_cc_op(s);
        gen_jmp_im(s, cur_eip);
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        gen_helper_load_seg(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, seg_reg), cpu_tmp2_i32);
        /* abort translation because the addseg value may change or
           because ss32 may change. For R_SS, translation must always
           stop as a special handling must be done to disable hardware
           interrupts for the next instruction */
        if (seg_reg == R_SS || (s->code32 && seg_reg < R_FS))
            s->is_jmp = DISAS_TB_JUMP;
    } else {
        gen_op_movl_seg_T0_vm(tcg_ctx, seg_reg);
        if (seg_reg == R_SS)
            s->is_jmp = DISAS_TB_JUMP;
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
    if (likely(!(s->flags & HF_SVMI_MASK)))
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
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

#ifdef TARGET_X86_64
    if (CODE64(s)) {
        gen_op_add_reg_im(tcg_ctx, MO_64, R_ESP, addend);
    } else
#endif
    if (s->ss32) {
        gen_op_add_reg_im(tcg_ctx, MO_32, R_ESP, addend);
    } else {
        gen_op_add_reg_im(tcg_ctx, MO_16, R_ESP, addend);
    }
}

/* Generate a push. It depends on ss32, addseg and dflag.  */
static void gen_push_v(DisasContext *s, TCGv val)
{
    TCGMemOp a_ot, d_ot = mo_pushpop(s, s->dflag);
    int size = 1 << d_ot;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp4 = *(TCGv *)tcg_ctx->cpu_tmp4;
    TCGv new_esp = cpu_A0;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    tcg_gen_subi_tl(tcg_ctx, cpu_A0, *cpu_regs[R_ESP], size);

    if (CODE64(s)) {
        a_ot = MO_64;
    } else if (s->ss32) {
        a_ot = MO_32;
        if (s->addseg) {
            new_esp = cpu_tmp4;
            tcg_gen_mov_tl(tcg_ctx, new_esp, cpu_A0);
            gen_op_addl_A0_seg(s, R_SS);
        } else {
            tcg_gen_ext32u_tl(tcg_ctx, cpu_A0, cpu_A0);
        }
    } else {
        a_ot = MO_16;
        new_esp = cpu_tmp4;
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, cpu_A0);
        tcg_gen_mov_tl(tcg_ctx, new_esp, cpu_A0);
        gen_op_addl_A0_seg(s, R_SS);
    }

    gen_op_st_v(s, d_ot, val, cpu_A0);
    gen_op_mov_reg_v(tcg_ctx, a_ot, R_ESP, new_esp);
}

/* two step pop is necessary for precise exceptions */
static TCGMemOp gen_pop_T0(DisasContext *s)
{
    TCGMemOp d_ot = mo_pushpop(s, s->dflag);
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv addr = cpu_A0;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

    if (CODE64(s)) {
        addr = *cpu_regs[R_ESP];
    } else if (!s->ss32) {
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, *cpu_regs[R_ESP]);
        gen_op_addl_A0_seg(s, R_SS);
    } else if (s->addseg) {
        tcg_gen_mov_tl(tcg_ctx, cpu_A0, *cpu_regs[R_ESP]);
        gen_op_addl_A0_seg(s, R_SS);
    } else {
        tcg_gen_ext32u_tl(tcg_ctx, cpu_A0, *cpu_regs[R_ESP]);
    }

    gen_op_ld_v(s, d_ot, *cpu_T[0], addr);
    return d_ot;
}

static void gen_pop_update(DisasContext *s, TCGMemOp ot)
{
    gen_stack_update(s, 1 << ot);
}

static void gen_stack_A0(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_op_movl_A0_reg(tcg_ctx, R_ESP);
    if (!s->ss32)
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, cpu_A0);
    tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], cpu_A0);
    if (s->addseg)
        gen_op_addl_A0_seg(s, R_SS);
}

/* NOTE: wrap around in 16 bit not fully handled */
static void gen_pusha(DisasContext *s)
{
    int i;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_op_movl_A0_reg(tcg_ctx, R_ESP);
    gen_op_addl_A0_im(tcg_ctx, ((unsigned int)(-8)) << s->dflag);
    if (!s->ss32)
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, cpu_A0);
    tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], cpu_A0);
    if (s->addseg)
        gen_op_addl_A0_seg(s, R_SS);
    for(i = 0;i < 8; i++) {
        gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], 7 - i);
        gen_op_st_v(s, s->dflag, *cpu_T[0], cpu_A0);
        gen_op_addl_A0_im(tcg_ctx, 1 << s->dflag);
    }
    gen_op_mov_reg_v(tcg_ctx, MO_16 + s->ss32, R_ESP, *cpu_T[1]);
}

/* NOTE: wrap around in 16 bit not fully handled */
static void gen_popa(DisasContext *s)
{
    int i;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    gen_op_movl_A0_reg(tcg_ctx, R_ESP);
    if (!s->ss32)
        tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, cpu_A0);
    tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], cpu_A0);
    tcg_gen_addi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], 8 << s->dflag);
    if (s->addseg)
        gen_op_addl_A0_seg(s, R_SS);
    for(i = 0;i < 8; i++) {
        /* ESP is not reloaded */
        if (i != 3) {
            gen_op_ld_v(s, s->dflag, *cpu_T[0], cpu_A0);
            gen_op_mov_reg_v(tcg_ctx, s->dflag, 7 - i, *cpu_T[0]);
        }
        gen_op_addl_A0_im(tcg_ctx, 1 << s->dflag);
    }
    gen_op_mov_reg_v(tcg_ctx, MO_16 + s->ss32, R_ESP, *cpu_T[1]);
}

static void gen_enter(DisasContext *s, int esp_addend, int level)
{
    TCGMemOp ot = mo_pushpop(s, s->dflag);
    int opsize = 1 << ot;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;

    level &= 0x1f;
#ifdef TARGET_X86_64
    if (CODE64(s)) {
        gen_op_movl_A0_reg(tcg_ctx, R_ESP);
        gen_op_addq_A0_im(tcg_ctx, -opsize);
        tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], cpu_A0);

        /* push bp */
        gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], R_EBP);
        gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
        if (level) {
            /* XXX: must save state */
            gen_helper_enter64_level(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, level),
                                     tcg_const_i32(tcg_ctx, (ot == MO_64)),
                                     *cpu_T[1]);
        }
        gen_op_mov_reg_v(tcg_ctx, ot, R_EBP, *cpu_T[1]);
        tcg_gen_addi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], -esp_addend + (-opsize * level));
        gen_op_mov_reg_v(tcg_ctx, MO_64, R_ESP, *cpu_T[1]);
    } else
#endif
    {
        gen_op_movl_A0_reg(tcg_ctx, R_ESP);
        gen_op_addl_A0_im(tcg_ctx, -opsize);
        if (!s->ss32)
            tcg_gen_ext16u_tl(tcg_ctx, cpu_A0, cpu_A0);
        tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], cpu_A0);
        if (s->addseg)
            gen_op_addl_A0_seg(s, R_SS);
        /* push bp */
        gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], R_EBP);
        gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
        if (level) {
            /* XXX: must save state */
            gen_helper_enter_level(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, level),
                                   tcg_const_i32(tcg_ctx, s->dflag - 1),
                                   *cpu_T[1]);
        }
        gen_op_mov_reg_v(tcg_ctx, ot, R_EBP, *cpu_T[1]);
        tcg_gen_addi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], -esp_addend + (-opsize * level));
        gen_op_mov_reg_v(tcg_ctx, MO_16 + s->ss32, R_ESP, *cpu_T[1]);
    }
}

static void gen_exception(DisasContext *s, int trapno, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, trapno));
    s->is_jmp = DISAS_TB_JUMP;
}

/* an interrupt is different from an exception because of the
   privilege checks */
static void gen_interrupt(DisasContext *s, int intno,
                          target_ulong cur_eip, target_ulong next_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    // Unicorn: skip to the next instruction after our interrupt callback
    gen_jmp_im(s, cur_eip);
    gen_helper_raise_interrupt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, intno),
                               tcg_const_i32(tcg_ctx, next_eip - cur_eip));
    s->is_jmp = DISAS_TB_JUMP;
}

static void gen_debug(DisasContext *s, target_ulong cur_eip)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);
    gen_jmp_im(s, cur_eip);
    gen_helper_debug(tcg_ctx, tcg_ctx->cpu_env);
    s->is_jmp = DISAS_TB_JUMP;
}

/* generate a generic end of block. Trace exception is also generated
   if needed */
static void gen_eob(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    gen_update_cc_op(s);    // qq
    if (s->tb->flags & HF_INHIBIT_IRQ_MASK) {
        gen_helper_reset_inhibit_irq(tcg_ctx, tcg_ctx->cpu_env);
    }
    if (s->tb->flags & HF_RF_MASK) {
        gen_helper_reset_rf(tcg_ctx, tcg_ctx->cpu_env);
    }
    if (s->singlestep_enabled) {
        gen_helper_debug(tcg_ctx, tcg_ctx->cpu_env);
    } else if (s->tf) {
        gen_helper_single_step(tcg_ctx, tcg_ctx->cpu_env);
    } else {
        tcg_gen_exit_tb(s->uc->tcg_ctx, 0);
    }
    s->is_jmp = DISAS_TB_JUMP;
}

/* generate a jump to eip. No segment change must happen before as a
   direct call to the next block may occur */
static void gen_jmp_tb(DisasContext *s, target_ulong eip, int tb_num)
{
    gen_update_cc_op(s);
    set_cc_op(s, CC_OP_DYNAMIC);
    if (s->jmp_opt) {
        gen_goto_tb(s, tb_num, eip);
        s->is_jmp = DISAS_TB_JUMP;
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
    TCGv_i64 cpu_tmp1_i64 = tcg_ctx->cpu_tmp1_i64;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;

    tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, cpu_tmp1_i64, tcg_ctx->cpu_env, offset);
}

static inline void gen_stq_env_A0(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 cpu_tmp1_i64 = tcg_ctx->cpu_tmp1_i64;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;

    tcg_gen_ld_i64(tcg_ctx, cpu_tmp1_i64, tcg_ctx->cpu_env, offset);
    tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
}

static inline void gen_ldo_env_A0(DisasContext *s, int offset)
{
    int mem_index = s->mem_index;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 cpu_tmp1_i64 = tcg_ctx->cpu_tmp1_i64;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;

    tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_A0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, cpu_tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(XMMReg, XMM_Q(0)));
    tcg_gen_addi_tl(tcg_ctx, cpu_tmp0, cpu_A0, 8);
    tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_tmp0, mem_index, MO_LEQ);
    tcg_gen_st_i64(tcg_ctx, cpu_tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(XMMReg, XMM_Q(1)));
}

static inline void gen_sto_env_A0(DisasContext *s, int offset)
{
    int mem_index = s->mem_index;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 cpu_tmp1_i64 = tcg_ctx->cpu_tmp1_i64;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;

    tcg_gen_ld_i64(tcg_ctx, cpu_tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(XMMReg, XMM_Q(0)));
    tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_A0, mem_index, MO_LEQ);
    tcg_gen_addi_tl(tcg_ctx, cpu_tmp0, cpu_A0, 8);
    tcg_gen_ld_i64(tcg_ctx, cpu_tmp1_i64, tcg_ctx->cpu_env, offset + offsetof(XMMReg, XMM_Q(1)));
    tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_tmp0, mem_index, MO_LEQ);
}

static inline void gen_op_movo(TCGContext *s, int d_offset, int s_offset)
{
    TCGv_i64 cpu_tmp1_i64 = s->cpu_tmp1_i64;

    tcg_gen_ld_i64(s, cpu_tmp1_i64, s->cpu_env, s_offset);
    tcg_gen_st_i64(s, cpu_tmp1_i64, s->cpu_env, d_offset);
    tcg_gen_ld_i64(s, cpu_tmp1_i64, s->cpu_env, s_offset + 8);
    tcg_gen_st_i64(s, cpu_tmp1_i64, s->cpu_env, d_offset + 8);
}

static inline void gen_op_movq(TCGContext *s, int d_offset, int s_offset)
{
    TCGv_i64 cpu_tmp1_i64 = s->cpu_tmp1_i64;

    tcg_gen_ld_i64(s, cpu_tmp1_i64, s->cpu_env, s_offset);
    tcg_gen_st_i64(s, cpu_tmp1_i64, s->cpu_env, d_offset);
}

static inline void gen_op_movl(TCGContext *s, int d_offset, int s_offset)
{
    tcg_gen_ld_i32(s, s->cpu_tmp2_i32, s->cpu_env, s_offset);
    tcg_gen_st_i32(s, s->cpu_tmp2_i32, s->cpu_env, d_offset);
}

static inline void gen_op_movq_env_0(TCGContext *s, int d_offset)
{
    TCGv_i64 cpu_tmp1_i64 = s->cpu_tmp1_i64;

    tcg_gen_movi_i64(s, cpu_tmp1_i64, 0);
    tcg_gen_st_i64(s, cpu_tmp1_i64, s->cpu_env, d_offset);
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
    // filler: 0x00 - 0x0e
    {0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},

    /* 3DNow! extensions */
    { SSE_DUMMY }, /* femms */
    { SSE_DUMMY }, /* pf. . . */

    /* pure SSE operations */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movlps, movlpd, movsldup, movddup */
    { SSE_SPECIAL, SSE_SPECIAL },  /* movlps, movlpd */
    { gen_helper_punpckldq_xmm, gen_helper_punpcklqdq_xmm },
    { gen_helper_punpckhdq_xmm, gen_helper_punpckhqdq_xmm },
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd, movshdup */
    { SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd */

    // filler: 0x18 - 0x27
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},

    /* pure SSE operations */
    { SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
    { SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtpi2ps, cvtpi2pd, cvtsi2ss, cvtsi2sd */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movntps, movntpd, movntss, movntsd */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvttps2pi, cvttpd2pi, cvttsd2si, cvttss2si */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtps2pi, cvtpd2pi, cvtsd2si, cvtss2si */
    { gen_helper_ucomiss, gen_helper_ucomisd },
    { gen_helper_comiss, gen_helper_comisd },

    // filler: 0x30 - 0x37
    {0},{0},{0},{0},{0},{0},{0},{0},

    /* SSSE3, SSE4, MOVBE, CRC32, BMI1, BMI2, ADX.  */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
    {0},	// filler: 0x39
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },

    // filler: 0x3b - 0x4f
    {0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},

    /* pure SSE operations */
    { SSE_SPECIAL, SSE_SPECIAL }, /* movmskps, movmskpd */
    SSE_FOP(sqrt),
    { gen_helper_rsqrtps, NULL, gen_helper_rsqrtss, NULL },
    { gen_helper_rcpps, NULL, gen_helper_rcpss, NULL },
    { gen_helper_pand_xmm, gen_helper_pand_xmm }, /* andps, andpd */
    { gen_helper_pandn_xmm, gen_helper_pandn_xmm }, /* andnps, andnpd */
    { gen_helper_por_xmm, gen_helper_por_xmm }, /* orps, orpd */
    { gen_helper_pxor_xmm, gen_helper_pxor_xmm }, /* xorps, xorpd */
    SSE_FOP(add),
    SSE_FOP(mul),
    { gen_helper_cvtps2pd, gen_helper_cvtpd2ps,
      gen_helper_cvtss2sd, gen_helper_cvtsd2ss },
    { gen_helper_cvtdq2ps, gen_helper_cvtps2dq, gen_helper_cvttps2dq },
    SSE_FOP(sub),
    SSE_FOP(min),
    SSE_FOP(div),
    SSE_FOP(max),

    /* MMX ops and their SSE extensions */
    MMX_OP2(punpcklbw),
    MMX_OP2(punpcklwd),
    MMX_OP2(punpckldq),
    MMX_OP2(packsswb),
    MMX_OP2(pcmpgtb),
    MMX_OP2(pcmpgtw),
    MMX_OP2(pcmpgtl),
    MMX_OP2(packuswb),
    MMX_OP2(punpckhbw),
    MMX_OP2(punpckhwd),
    MMX_OP2(punpckhdq),
    MMX_OP2(packssdw),
    { NULL, gen_helper_punpcklqdq_xmm },
    { NULL, gen_helper_punpckhqdq_xmm },
    { SSE_SPECIAL, SSE_SPECIAL }, /* movd mm, ea */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, , movqdu */
    { (SSEFunc_0_epp)gen_helper_pshufw_mmx,
      (SSEFunc_0_epp)gen_helper_pshufd_xmm,
      (SSEFunc_0_epp)gen_helper_pshufhw_xmm,
      (SSEFunc_0_epp)gen_helper_pshuflw_xmm }, /* XXX: casts */
    { SSE_SPECIAL, SSE_SPECIAL }, /* shiftw */
    { SSE_SPECIAL, SSE_SPECIAL }, /* shiftd */
    { SSE_SPECIAL, SSE_SPECIAL }, /* shiftq */
    MMX_OP2(pcmpeqb),
    MMX_OP2(pcmpeqw),
    MMX_OP2(pcmpeql),
    { SSE_DUMMY }, /* emms */
    { NULL, SSE_SPECIAL, NULL, SSE_SPECIAL }, /* extrq_i, insertq_i */
    { NULL, gen_helper_extrq_r, NULL, gen_helper_insertq_r },
    {0},{0}, // filler: 0x7a - 0x7b
    { NULL, gen_helper_haddpd, NULL, gen_helper_haddps },
    { NULL, gen_helper_hsubpd, NULL, gen_helper_hsubps },
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movd, movd, , movq */
    { SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, movdqu */

    // filler: 0x80 - 0xc1
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},

    SSE_FOP(cmpeq),

    // filler: 0xc3
    {0},

    /* MMX ops and their SSE extensions */
    { SSE_SPECIAL, SSE_SPECIAL }, /* pinsrw */
    { SSE_SPECIAL, SSE_SPECIAL }, /* pextrw */

    { (SSEFunc_0_epp)gen_helper_shufps,
      (SSEFunc_0_epp)gen_helper_shufpd }, /* XXX: casts */

    // filler: 0xc7 - 0xcf
    {0}, {0},{0},{0},{0},{0},{0},{0},{0},

    /* MMX ops and their SSE extensions */
    { NULL, gen_helper_addsubpd, NULL, gen_helper_addsubps },
    MMX_OP2(psrlw),
    MMX_OP2(psrld),
    MMX_OP2(psrlq),
    MMX_OP2(paddq),
    MMX_OP2(pmullw),
    { NULL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
    { SSE_SPECIAL, SSE_SPECIAL }, /* pmovmskb */
    MMX_OP2(psubusb),
    MMX_OP2(psubusw),
    MMX_OP2(pminub),
    MMX_OP2(pand),
    MMX_OP2(paddusb),
    MMX_OP2(paddusw),
    MMX_OP2(pmaxub),
    MMX_OP2(pandn),
    MMX_OP2(pavgb),
    MMX_OP2(psraw),
    MMX_OP2(psrad),
    MMX_OP2(pavgw),
    MMX_OP2(pmulhuw),
    MMX_OP2(pmulhw),
    { NULL, gen_helper_cvttpd2dq, gen_helper_cvtdq2pd, gen_helper_cvtpd2dq },
    { SSE_SPECIAL , SSE_SPECIAL },  /* movntq, movntq */
    MMX_OP2(psubsb),
    MMX_OP2(psubsw),
    MMX_OP2(pminsw),
    MMX_OP2(por),
    MMX_OP2(paddsb),
    MMX_OP2(paddsw),
    MMX_OP2(pmaxsw),
    MMX_OP2(pxor),
    { NULL, NULL, NULL, SSE_SPECIAL }, /* lddqu */
    MMX_OP2(psllw),
    MMX_OP2(pslld),
    MMX_OP2(psllq),
    MMX_OP2(pmuludq),
    MMX_OP2(pmaddwd),
    MMX_OP2(psadbw),
    { (SSEFunc_0_epp)gen_helper_maskmov_mmx,
      (SSEFunc_0_epp)gen_helper_maskmov_xmm }, /* XXX: casts */
    MMX_OP2(psubb),
    MMX_OP2(psubw),
    MMX_OP2(psubl),
    MMX_OP2(psubq),
    MMX_OP2(paddb),
    MMX_OP2(paddw),
    MMX_OP2(paddl),

    // filler: 0xff
    {0},
};

static const SSEFunc_0_epp sse_op_table2[3 * 8][2] = {
#ifdef _MSC_VER
    {0},{0},
    MMX_OP2(psrlw),
    {0},
    MMX_OP2(psraw),
    {0},
    MMX_OP2(psllw),
    {0},{0},{0},
    MMX_OP2(psrld),
    {0},
    MMX_OP2(psrad),
    {0},
    MMX_OP2(pslld),
    {0},{0},{0},
    MMX_OP2(psrlq),
    { NULL, gen_helper_psrldq_xmm },
    {0},{0},
    MMX_OP2(psllq),
    { NULL, gen_helper_pslldq_xmm },
#else
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
#endif
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
#ifdef _MSC_VER
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},      // filler: 0x00 - 0x0b
    gen_helper_pi2fw,
    gen_helper_pi2fd,
    {0},{0}, {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0}, // filler: 0x0e - 0x01b
    gen_helper_pf2iw,
    gen_helper_pf2id,
    // filler: 0x1e - 0x89
    {0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},
    gen_helper_pfnacc,
    {0},{0},{0},    // filler: 0x8b - 0x8d
    gen_helper_pfpnacc,
    {0},            // filler: 0x8f
    gen_helper_pfcmpge,
    {0},{0},{0},    // filler: 0x91 - 0x93
    gen_helper_pfmin,
    {0},            // filler: 0x95
    gen_helper_pfrcp,
    gen_helper_pfrsqrt,
    {0},{0},        // filler: 0x98 - 0x99
    gen_helper_pfsub,
    {0},{0},{0},    // filler: 0x9b - 0x9d
    gen_helper_pfadd,
    {0},            // filler: 0x9f
    gen_helper_pfcmpgt,
    {0},{0},{0},    // filler: 0xa1 - 0xa3
    gen_helper_pfmax,
    {0},            // filler: 0xa5
    gen_helper_movq, /* pfrcpit1; no need to actually increase precision */
    gen_helper_movq, /* pfrsqit1 */
    {0},{0},        // filler: 0xa8 - 0xa9
    gen_helper_pfsubr,
    {0},{0},{0},    // filler: 0xab - 0xad
    gen_helper_pfacc,
    {0},            // filler: 0xaf
    gen_helper_pfcmpeq,
    {0},{0},{0},    // filler: 0xb1 - 0xb3
    gen_helper_pfmul,
    {0},            // filler: 0xb5
    gen_helper_movq, /* pfrcpit2 */
    gen_helper_pmulhrw_mmx,
    {0},{0},{0},    // filler: 0xb8 - 0xba
    gen_helper_pswapd,
    {0},{0},{0},    // filler: 0xbc - 0xbe
    gen_helper_pavgb_mmx, /* pavgusb */
    // filler: 0xc0 - 0xff
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
    {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
#else
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
#endif
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
    SSSE3_OP(pshufb),
    SSSE3_OP(phaddw),
    SSSE3_OP(phaddd),
    SSSE3_OP(phaddsw),
    SSSE3_OP(pmaddubsw),
    SSSE3_OP(phsubw),
    SSSE3_OP(phsubd),
    SSSE3_OP(phsubsw),
    SSSE3_OP(psignb),
    SSSE3_OP(psignw),
    SSSE3_OP(psignd),
    SSSE3_OP(pmulhrsw),
    {{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x0c - 0x0f
    SSE41_OP(pblendvb),
    {{0},0},{{0},0},{{0},0},     // filler: 0x11 - 0x13
    SSE41_OP(blendvps),
    SSE41_OP(blendvpd),
    {{0},0},             // filler: 0x16
    SSE41_OP(ptest),
    {{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x18 - 0x1b
    SSSE3_OP(pabsb),
    SSSE3_OP(pabsw),
    SSSE3_OP(pabsd),
    {{0},0},             // filler: 0x1f
    SSE41_OP(pmovsxbw),
    SSE41_OP(pmovsxbd),
    SSE41_OP(pmovsxbq),
    SSE41_OP(pmovsxwd),
    SSE41_OP(pmovsxwq),
    SSE41_OP(pmovsxdq),
    {{0},0},{{0},0},         // filler: 0x26 - 0x27
    SSE41_OP(pmuldq),
    SSE41_OP(pcmpeqq),
    SSE41_SPECIAL, /* movntqda */
    SSE41_OP(packusdw),
    {{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x2c - 0x2f
    SSE41_OP(pmovzxbw),
    SSE41_OP(pmovzxbd),
    SSE41_OP(pmovzxbq),
    SSE41_OP(pmovzxwd),
    SSE41_OP(pmovzxwq),
    SSE41_OP(pmovzxdq),
    {{0},0},             // filler: 0x36
    SSE42_OP(pcmpgtq),
    SSE41_OP(pminsb),
    SSE41_OP(pminsd),
    SSE41_OP(pminuw),
    SSE41_OP(pminud),
    SSE41_OP(pmaxsb),
    SSE41_OP(pmaxsd),
    SSE41_OP(pmaxuw),
    SSE41_OP(pmaxud),
    SSE41_OP(pmulld),
    SSE41_OP(phminposuw),
    // filler: 0x42 - 0xda
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},
    AESNI_OP(aesimc),
    AESNI_OP(aesenc),
    AESNI_OP(aesenclast),
    AESNI_OP(aesdec),
    AESNI_OP(aesdeclast),
    // filler: 0xe0 - 0xff
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
};

static const struct SSEOpHelper_eppi sse_op_table7[256] = {
#ifdef _MSC_VER
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x00 - 0x07
    SSE41_OP(roundps),
    SSE41_OP(roundpd),
    SSE41_OP(roundss),
    SSE41_OP(roundsd),
    SSE41_OP(blendps),
    SSE41_OP(blendpd),
    SSE41_OP(pblendw),
    SSSE3_OP(palignr),
    {{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x10 - 0x13
    SSE41_SPECIAL, /* pextrb */
    SSE41_SPECIAL, /* pextrw */
    SSE41_SPECIAL, /* pextrd/pextrq */
    SSE41_SPECIAL, /* extractps */
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x18 - 0x1f
    SSE41_SPECIAL, /* pinsrb */
    SSE41_SPECIAL, /* insertps */
    SSE41_SPECIAL, /* pinsrd/pinsrq */
    // filler: 0x23 - 0x3f
                            {{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    SSE41_OP(dpps),
    SSE41_OP(dppd),
    SSE41_OP(mpsadbw),
    {{0},0}, // filler: 0x43
    PCLMULQDQ_OP(pclmulqdq),
    // filler: 0x45 - 0x5f
                                            {{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    SSE42_OP(pcmpestrm),
    SSE42_OP(pcmpestri),
    SSE42_OP(pcmpistrm),
    SSE42_OP(pcmpistri),
    // filler: 0x64 - 0xde
                                    {{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    AESNI_OP(aeskeygenassist),
    // filler: 0xe0 - 0xff
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
    {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
#else
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
#endif
};

static void gen_sse(CPUX86State *env, DisasContext *s, int b,
                    target_ulong pc_start, int rex_r)
{
    int b1, op1_offset, op2_offset, is_xmm, val;
    int modrm, mod, rm, reg;
    SSEFunc_0_epp sse_fn_epp;
    SSEFunc_0_eppi sse_fn_eppi;
    SSEFunc_0_ppi sse_fn_ppi;
    SSEFunc_0_eppt sse_fn_eppt;
    TCGMemOp ot;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr cpu_env = tcg_ctx->cpu_env;
    TCGv_ptr cpu_ptr0 = tcg_ctx->cpu_ptr0;
    TCGv_ptr cpu_ptr1 = tcg_ctx->cpu_ptr1;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv_i32 cpu_tmp3_i32 = tcg_ctx->cpu_tmp3_i32;
    TCGv_i64 cpu_tmp1_i64 = tcg_ctx->cpu_tmp1_i64;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_src2 = *(TCGv *)tcg_ctx->cpu_cc_src2;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;

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
        goto illegal_op;
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
        gen_exception(s, EXCP06_ILLOP, pc_start - s->cs_base);
        return;
    }
    if (is_xmm && !(s->flags & HF_OSFXSR_MASK))
        if ((b != 0x38 && b != 0x3a) || (s->prefix & PREFIX_DATA))
            goto illegal_op;
    if (b == 0x0e) {
        if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW))
            goto illegal_op;
        /* femms */
        gen_helper_emms(tcg_ctx, cpu_env);
        return;
    }
    if (b == 0x77) {
        /* emms */
        gen_helper_emms(tcg_ctx, cpu_env);
        return;
    }
    /* prepare MMX state (XXX: optimize by storing fptt and fptags in
       the static cpu state) */
    if (!is_xmm) {
        gen_helper_enter_mmx(tcg_ctx, cpu_env);
    }

    modrm = cpu_ldub_code(env, s->pc++);
    reg = ((modrm >> 3) & 7);
    if (is_xmm)
        reg |= rex_r;
    mod = (modrm >> 6) & 3;
    if (sse_fn_epp == SSE_SPECIAL) {
        b |= (b1 << 8);
        switch(b) {
        case 0x0e7: /* movntq */
            if (mod == 3)
                goto illegal_op;
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
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,
                    xmm_regs[reg].XMM_L(0)));
                gen_op_st_v(s, MO_32, *cpu_T[0], cpu_A0);
            }
            break;
        case 0x6e: /* movd mm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_st_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,fpregs[reg].mmx));
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx));
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_movl_mm_T0_mmx(tcg_ctx, cpu_ptr0, cpu_tmp2_i32);
            }
            break;
        case 0x16e: /* movd xmm, ea */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg]));
                gen_helper_movq_mm_T0_xmm(tcg_ctx, cpu_ptr0, *cpu_T[0]);
            } else
#endif
            {
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 0);
                tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg]));
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_movl_mm_T0_xmm(tcg_ctx, cpu_ptr0, cpu_tmp2_i32);
            }
            break;
        case 0x6f: /* movq mm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                tcg_gen_ld_i64(tcg_ctx, cpu_tmp1_i64, cpu_env,
                               offsetof(CPUX86State,fpregs[rm].mmx));
                tcg_gen_st_i64(tcg_ctx, cpu_tmp1_i64, cpu_env,
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
                gen_op_movo(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg]),
                            offsetof(CPUX86State,xmm_regs[rm]));
            }
            break;
        case 0x210: /* movss xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32, *cpu_T[0], cpu_A0);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)));
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], 0);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(1)));
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(2)));
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_L(0)));
            }
            break;
        case 0x310: /* movsd xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], 0);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(2)));
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(3)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)));
            }
            break;
        case 0x012: /* movlps */
        case 0x112: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                /* movhlps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_Q(1)));
            }
            break;
        case 0x212: /* movsldup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_L(0)));
                gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(2)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_L(2)));
            }
            gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(1)),
                        offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)));
            gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(3)),
                        offsetof(CPUX86State,xmm_regs[reg].XMM_L(2)));
            break;
        case 0x312: /* movddup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)));
            }
            gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(1)),
                        offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)));
            break;
        case 0x016: /* movhps */
        case 0x116: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(1)));
            } else {
                /* movlhps */
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(1)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)));
            }
            break;
        case 0x216: /* movshdup */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldo_env_A0(s, offsetof(CPUX86State, xmm_regs[reg]));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(1)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_L(1)));
                gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(3)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_L(3)));
            }
            gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)),
                        offsetof(CPUX86State,xmm_regs[reg].XMM_L(1)));
            gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_L(2)),
                        offsetof(CPUX86State,xmm_regs[reg].XMM_L(3)));
            break;
        case 0x178:
        case 0x378:
            {
                int bit_index, field_length;

                if (b1 == 1 && reg != 0)
                    goto illegal_op;
                field_length = cpu_ldub_code(env, s->pc++) & 0x3F;
                bit_index = cpu_ldub_code(env, s->pc++) & 0x3F;
                tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env,
                    offsetof(CPUX86State,xmm_regs[reg]));
                if (b1 == 1)
                    gen_helper_extrq_i(tcg_ctx, cpu_env, cpu_ptr0,
                                       tcg_const_i32(tcg_ctx, bit_index),
                                       tcg_const_i32(tcg_ctx, field_length));
                else
                    gen_helper_insertq_i(tcg_ctx, cpu_env, cpu_ptr0,
                                         tcg_const_i32(tcg_ctx, bit_index),
                                         tcg_const_i32(tcg_ctx, field_length));
            }
            break;
        case 0x7e: /* movd ea, mm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(tcg_ctx, *cpu_T[0], cpu_env,
                               offsetof(CPUX86State,fpregs[reg].mmx));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                 offsetof(CPUX86State,fpregs[reg].mmx.MMX_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x17e: /* movd ea, xmm */
#ifdef TARGET_X86_64
            if (s->dflag == MO_64) {
                tcg_gen_ld_i64(tcg_ctx, *cpu_T[0], cpu_env,
                               offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)));
                gen_ldst_modrm(env, s, modrm, MO_64, OR_TMP0, 1);
            } else
#endif
            {
                tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                 offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)));
                gen_ldst_modrm(env, s, modrm, MO_32, OR_TMP0, 1);
            }
            break;
        case 0x27e: /* movq xmm, ea */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_ldq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)));
            }
            gen_op_movq_env_0(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(1)));
            break;
        case 0x7f: /* movq ea, mm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State, fpregs[reg].mmx));
            } else {
                rm = (modrm & 7);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,fpregs[rm].mmx),
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
                gen_op_movo(tcg_ctx, offsetof(CPUX86State,xmm_regs[rm]),
                            offsetof(CPUX86State,xmm_regs[reg]));
            }
            break;
        case 0x211: /* movss ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)));
                gen_op_st_v(s, MO_32, *cpu_T[0], cpu_A0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movl(tcg_ctx, offsetof(CPUX86State,xmm_regs[rm].XMM_L(0)),
                            offsetof(CPUX86State,xmm_regs[reg].XMM_L(0)));
            }
            break;
        case 0x311: /* movsd ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)));
            }
            break;
        case 0x013: /* movlps */
        case 0x113: /* movlpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                goto illegal_op;
            }
            break;
        case 0x017: /* movhps */
        case 0x117: /* movhpd */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(1)));
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
            goto illegal_op;
            }
            val = cpu_ldub_code(env, s->pc++);
            if (is_xmm) {
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_t0.XMM_L(0)));
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], 0);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_t0.XMM_L(1)));
                op1_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,mmx_t0.MMX_L(0)));
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], 0);
                tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,mmx_t0.MMX_L(1)));
                op1_offset = offsetof(CPUX86State,mmx_t0);
            }
            sse_fn_epp = sse_op_table2[((b - 1) & 3) * 8 +
                                       (((modrm >> 3)) & 7)][b1];
            if (!sse_fn_epp) {
                goto illegal_op;
            }
            if (is_xmm) {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op2_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op1_offset);
            sse_fn_epp(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        case 0x050: /* movmskps */
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env,
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskps(tcg_ctx, cpu_tmp2_i32, cpu_env, cpu_ptr0);
            tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[reg], cpu_tmp2_i32);
            break;
        case 0x150: /* movmskpd */
            rm = (modrm & 7) | REX_B(s);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env,
                             offsetof(CPUX86State,xmm_regs[rm]));
            gen_helper_movmskpd(tcg_ctx, cpu_tmp2_i32, cpu_env, cpu_ptr0);
            tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[reg], cpu_tmp2_i32);
            break;
        case 0x02a: /* cvtpi2ps */
        case 0x12a: /* cvtpi2pd */
            gen_helper_enter_mmx(tcg_ctx, cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,mmx_t0);
                gen_ldq_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7);
                op2_offset = offsetof(CPUX86State,fpregs[rm].mmx);
            }
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            switch(b >> 8) {
            case 0x0:
                gen_helper_cvtpi2ps(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            default:
            case 0x1:
                gen_helper_cvtpi2pd(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            }
            break;
        case 0x22a: /* cvtsi2ss */
        case 0x32a: /* cvtsi2sd */
            ot = mo_64_32(s->dflag);
            gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
            op1_offset = offsetof(CPUX86State,xmm_regs[reg]);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            if (ot == MO_32) {
                SSEFunc_0_epi sse_fn_epi = sse_op_table3ai[(b >> 8) & 1];
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                sse_fn_epi(tcg_ctx, cpu_env, cpu_ptr0, cpu_tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_0_epl sse_fn_epl = sse_op_table3aq[(b >> 8) & 1];
                sse_fn_epl(tcg_ctx, cpu_env, cpu_ptr0, *cpu_T[0]);
#else
                goto illegal_op;
#endif
            }
            break;
        case 0x02c: /* cvttps2pi */
        case 0x12c: /* cvttpd2pi */
        case 0x02d: /* cvtps2pi */
        case 0x12d: /* cvtpd2pi */
            gen_helper_enter_mmx(tcg_ctx, cpu_env);
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                op2_offset = offsetof(CPUX86State,xmm_t0);
                gen_ldo_env_A0(s, op2_offset);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            op1_offset = offsetof(CPUX86State,fpregs[reg & 7].mmx);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            switch(b) {
            case 0x02c:
                gen_helper_cvttps2pi(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            case 0x12c:
                gen_helper_cvttpd2pi(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            case 0x02d:
                gen_helper_cvtps2pi(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
                break;
            case 0x12d:
                gen_helper_cvtpd2pi(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
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
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.XMM_Q(0)));
                } else {
                    gen_op_ld_v(s, MO_32, *cpu_T[0], cpu_A0);
                    tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,xmm_t0.XMM_L(0)));
                }
                op2_offset = offsetof(CPUX86State,xmm_t0);
            } else {
                rm = (modrm & 7) | REX_B(s);
                op2_offset = offsetof(CPUX86State,xmm_regs[rm]);
            }
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op2_offset);
            if (ot == MO_32) {
                SSEFunc_i_ep sse_fn_i_ep =
                    sse_op_table3bi[((b >> 7) & 2) | (b & 1)];
                sse_fn_i_ep(tcg_ctx, cpu_tmp2_i32, cpu_env, cpu_ptr0);
                tcg_gen_extu_i32_tl(tcg_ctx, *cpu_T[0], cpu_tmp2_i32);
            } else {
#ifdef TARGET_X86_64
                SSEFunc_l_ep sse_fn_l_ep =
                    sse_op_table3bq[((b >> 7) & 2) | (b & 1)];
                sse_fn_l_ep(tcg_ctx, *cpu_T[0], cpu_env, cpu_ptr0);
#else
                goto illegal_op;
#endif
            }
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
            break;
        case 0xc4: /* pinsrw */
        case 0x1c4:
            s->rip_offset = 1;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            val = cpu_ldub_code(env, s->pc++);
            if (b1) {
                val &= 7;
                tcg_gen_st16_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                offsetof(CPUX86State,xmm_regs[reg].XMM_W(val)));
            } else {
                val &= 3;
                tcg_gen_st16_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                offsetof(CPUX86State,fpregs[reg].mmx.MMX_W(val)));
            }
            break;
        case 0xc5: /* pextrw */
        case 0x1c5:
            if (mod != 3)
                goto illegal_op;
            ot = mo_64_32(s->dflag);
            val = cpu_ldub_code(env, s->pc++);
            if (b1) {
                val &= 7;
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_ld16u_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                 offsetof(CPUX86State,xmm_regs[rm].XMM_W(val)));
            } else {
                val &= 3;
                rm = (modrm & 7);
                tcg_gen_ld16u_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                offsetof(CPUX86State,fpregs[rm].mmx.MMX_W(val)));
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
            break;
        case 0x1d6: /* movq ea, xmm */
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_stq_env_A0(s, offsetof(CPUX86State,
                                           xmm_regs[reg].XMM_Q(0)));
            } else {
                rm = (modrm & 7) | REX_B(s);
                gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)),
                            offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)));
                gen_op_movq_env_0(tcg_ctx, offsetof(CPUX86State,xmm_regs[rm].XMM_Q(1)));
            }
            break;
        case 0x2d6: /* movq2dq */
            gen_helper_enter_mmx(tcg_ctx, cpu_env);
            rm = (modrm & 7);
            gen_op_movq(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(0)),
                        offsetof(CPUX86State,fpregs[rm].mmx));
            gen_op_movq_env_0(tcg_ctx, offsetof(CPUX86State,xmm_regs[reg].XMM_Q(1)));
            break;
        case 0x3d6: /* movdq2q */
            gen_helper_enter_mmx(tcg_ctx, cpu_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_movq(tcg_ctx, offsetof(CPUX86State,fpregs[reg & 7].mmx),
                        offsetof(CPUX86State,xmm_regs[rm].XMM_Q(0)));
            break;
        case 0xd7: /* pmovmskb */
        case 0x1d7:
            if (mod != 3)
                goto illegal_op;
            if (b1) {
                rm = (modrm & 7) | REX_B(s);
                tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, offsetof(CPUX86State,xmm_regs[rm]));
                gen_helper_pmovmskb_xmm(tcg_ctx, cpu_tmp2_i32, cpu_env, cpu_ptr0);
            } else {
                rm = (modrm & 7);
                tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, offsetof(CPUX86State,fpregs[rm].mmx));
                gen_helper_pmovmskb_mmx(tcg_ctx, cpu_tmp2_i32, cpu_env, cpu_ptr0);
            }
            reg = ((modrm >> 3) & 7) | rex_r;
            tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[reg], cpu_tmp2_i32);
            break;

        case 0x138:
        case 0x038:
            b = modrm;
            if ((b & 0xf0) == 0xf0) {
                goto do_0f_38_fx;
            }
            modrm = cpu_ldub_code(env, s->pc++);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto illegal_op;
            }

            sse_fn_epp = sse_op_table6[b].op[b1];
            if (!sse_fn_epp) {
                goto illegal_op;
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
                                        offsetof(XMMReg, XMM_Q(0)));
                        break;
                    case 0x21: case 0x31: /* pmovsxbd, pmovzxbd */
                    case 0x24: case 0x34: /* pmovsxwq, pmovzxwq */
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_st_i32(tcg_ctx, cpu_tmp2_i32, cpu_env, op2_offset +
                                        offsetof(XMMReg, XMM_L(0)));
                        break;
                    case 0x22: case 0x32: /* pmovsxbq, pmovzxbq */
                        tcg_gen_qemu_ld_tl(s->uc, cpu_tmp0, cpu_A0,
                                           s->mem_index, MO_LEUW);
                        tcg_gen_st16_tl(tcg_ctx, cpu_tmp0, cpu_env, op2_offset +
                                        offsetof(XMMReg, XMM_W(0)));
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
                goto illegal_op;
            }

            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);

            if (b == 0x17) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            break;

        case 0x238:
        case 0x338:
        do_0f_38_fx:
            /* Various integer extensions at 0f 38 f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = cpu_ldub_code(env, s->pc++);
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

                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_regs[reg]);
                gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
                gen_helper_crc32(tcg_ctx, *cpu_T[0], cpu_tmp2_i32,
                                 *cpu_T[0], tcg_const_i32(tcg_ctx, 8 << ot));

                ot = mo_64_32(s->dflag);
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
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
                    tcg_gen_qemu_ld_tl(s->uc, *cpu_T[0], cpu_A0,
                                       s->mem_index, ot | MO_BE);
                    gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
                } else {
                    tcg_gen_qemu_st_tl(s->uc, *cpu_regs[reg], cpu_A0,
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
                tcg_gen_andc_tl(tcg_ctx, *cpu_T[0], *cpu_regs[s->vex_v], *cpu_T[0]);
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
                gen_op_update1_cc(tcg_ctx);
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
                    tcg_gen_ext8u_tl(tcg_ctx, cpu_A0, *cpu_regs[s->vex_v]);
                    tcg_gen_shr_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_A0);

                    bound = tcg_const_tl(tcg_ctx, ot == MO_64 ? 63 : 31);
                    zero = tcg_const_tl(tcg_ctx, 0);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_LEU, *cpu_T[0], cpu_A0, bound,
                                       *cpu_T[0], zero);
                    tcg_temp_free(tcg_ctx, zero);

                    /* Extract the LEN into a mask.  Lengths larger than
                       operand size get all ones.  */
                    tcg_gen_shri_tl(tcg_ctx, cpu_A0, *cpu_regs[s->vex_v], 8);
                    tcg_gen_ext8u_tl(tcg_ctx, cpu_A0, cpu_A0);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_LEU, cpu_A0, cpu_A0, bound,
                                       cpu_A0, bound);
                    tcg_temp_free(tcg_ctx, bound);
                    tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], 1);
                    tcg_gen_shl_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], cpu_A0);
                    tcg_gen_subi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], 1);
                    tcg_gen_and_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);

                    gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
                    gen_op_update1_cc(tcg_ctx);
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
                tcg_gen_ext8u_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v]);
                {
                    TCGv bound = tcg_const_tl(tcg_ctx, ot == MO_64 ? 63 : 31);
                    /* Note that since we're using BMILG (in order to get O
                       cleared) we need to store the inverse into C.  */
                    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_LT, cpu_cc_src,
                                       *cpu_T[1], bound);
                    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_GT, *cpu_T[1], *cpu_T[1],
                                       bound, bound, *cpu_T[1]);
                    tcg_temp_free(tcg_ctx, bound);
                }
                tcg_gen_movi_tl(tcg_ctx, cpu_A0, -1);
                tcg_gen_shl_tl(tcg_ctx, cpu_A0, cpu_A0, *cpu_T[1]);
                tcg_gen_andc_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_A0);
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
                gen_op_update1_cc(tcg_ctx);
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
                    tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                    tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_regs[R_EDX]);
                    tcg_gen_mulu2_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp3_i32,
                                      cpu_tmp2_i32, cpu_tmp3_i32);
                    tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[s->vex_v], cpu_tmp2_i32);
                    tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[reg], cpu_tmp3_i32);
                    break;
#ifdef TARGET_X86_64
                case MO_64:
                    tcg_gen_mulu2_i64(tcg_ctx, *cpu_T[0], *cpu_T[1],
                                       *cpu_T[0], *cpu_regs[R_EDX]);
                    tcg_gen_mov_i64(tcg_ctx, *cpu_regs[s->vex_v], *cpu_T[0]);
                    tcg_gen_mov_i64(tcg_ctx, *cpu_regs[reg], *cpu_T[1]);
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
                    tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v]);
                }
                gen_helper_pdep(tcg_ctx, *cpu_regs[reg], *cpu_T[0], *cpu_T[1]);
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
                    tcg_gen_mov_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v]);
                } else {
                    tcg_gen_ext32u_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v]);
                }
                gen_helper_pext(tcg_ctx, *cpu_regs[reg], *cpu_T[0], *cpu_T[1]);
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
                    TCGV_UNUSED(carry_in);
                    carry_out = (b == 0x1f6 ? cpu_cc_dst : cpu_cc_src2);
                    switch (s->cc_op) {
                    case CC_OP_ADCX:
                        if (b == 0x1f6) {
                            carry_in = cpu_cc_dst;
                            end_op = CC_OP_ADCX;
                        } else {
                            end_op = CC_OP_ADCOX;
                        }
                        break;
                    case CC_OP_ADOX:
                        if (b == 0x1f6) {
                            end_op = CC_OP_ADCOX;
                        } else {
                            carry_in = cpu_cc_src2;
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
                    if (TCGV_IS_UNUSED(carry_in)) {
                        if (s->cc_op != CC_OP_ADCX && s->cc_op != CC_OP_ADOX) {
                            gen_compute_eflags(s);
                        }
                        carry_in = cpu_tmp0;
                        tcg_gen_shri_tl(tcg_ctx, carry_in, cpu_cc_src,
                                        ctz32(b == 0x1f6 ? CC_C : CC_O));
                        tcg_gen_andi_tl(tcg_ctx, carry_in, carry_in, 1);
                    }

                    switch (ot) {
#ifdef TARGET_X86_64
                    case MO_32:
                        /* If we know TL is 64-bit, and we want a 32-bit
                           result, just do everything in 64-bit arithmetic.  */
                        tcg_gen_ext32u_i64(tcg_ctx, *cpu_regs[reg], *cpu_regs[reg]);
                        tcg_gen_ext32u_i64(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                        tcg_gen_add_i64(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_regs[reg]);
                        tcg_gen_add_i64(tcg_ctx, *cpu_T[0], *cpu_T[0], carry_in);
                        tcg_gen_ext32u_i64(tcg_ctx, *cpu_regs[reg], *cpu_T[0]);
                        tcg_gen_shri_i64(tcg_ctx, carry_out, *cpu_T[0], 32);
                        break;
#endif
                    default:
                        /* Otherwise compute the carry-out in two steps.  */
                        zero = tcg_const_tl(tcg_ctx, 0);
                        tcg_gen_add2_tl(tcg_ctx, *cpu_T[0], carry_out,
                                        *cpu_T[0], zero,
                                        carry_in, zero);
                        tcg_gen_add2_tl(tcg_ctx, *cpu_regs[reg], carry_out,
                                        *cpu_regs[reg], carry_out,
                                        *cpu_T[0], zero);
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
                    tcg_gen_andi_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v], 63);
                } else {
                    tcg_gen_andi_tl(tcg_ctx, *cpu_T[1], *cpu_regs[s->vex_v], 31);
                }
                if (b == 0x1f7) {
                    tcg_gen_shl_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                } else if (b == 0x2f7) {
                    if (ot != MO_64) {
                        tcg_gen_ext32s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                    }
                    tcg_gen_sar_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                } else {
                    if (ot != MO_64) {
                        tcg_gen_ext32u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                    }
                    tcg_gen_shr_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                }
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
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

                switch (reg & 7) {
                case 1: /* blsr By,Ey */
                    tcg_gen_neg_tl(tcg_ctx, *cpu_T[1], *cpu_T[0]);
                    tcg_gen_and_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                    gen_op_mov_reg_v(tcg_ctx, ot, s->vex_v, *cpu_T[0]);
                    gen_op_update2_cc(tcg_ctx);
                    set_cc_op(s, CC_OP_BMILGB + ot);
                    break;

                case 2: /* blsmsk By,Ey */
                    tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_T[0]);
                    tcg_gen_subi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 1);
                    tcg_gen_xor_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_cc_src);
                    tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
                    set_cc_op(s, CC_OP_BMILGB + ot);
                    break;

                case 3: /* blsi By, Ey */
                    tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_T[0]);
                    tcg_gen_subi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 1);
                    tcg_gen_and_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_cc_src);
                    tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
                    set_cc_op(s, CC_OP_BMILGB + ot);
                    break;

                default:
                    goto illegal_op;
                }
                break;

            default:
                goto illegal_op;
            }
            break;

        case 0x03a:
        case 0x13a:
            b = modrm;
            modrm = cpu_ldub_code(env, s->pc++);
            rm = modrm & 7;
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            if (b1 >= 2) {
                goto illegal_op;
            }

            sse_fn_eppi = sse_op_table7[b].op[b1];
            if (!sse_fn_eppi) {
                goto illegal_op;
            }
            if (!(s->cpuid_ext_features & sse_op_table7[b].ext_mask))
                goto illegal_op;

            if (sse_fn_eppi == SSE_SPECIAL) {
                ot = mo_64_32(s->dflag);
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3)
                    gen_lea_modrm(env, s, modrm);
                reg = ((modrm >> 3) & 7) | rex_r;
                val = cpu_ldub_code(env, s->pc++);
                switch (b) {
                case 0x14: /* pextrb */
                    tcg_gen_ld8u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].XMM_B(val & 15)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
                    } else {
                        tcg_gen_qemu_st_tl(s->uc, *cpu_T[0], cpu_A0,
                                           s->mem_index, MO_UB);
                    }
                    break;
                case 0x15: /* pextrw */
                    tcg_gen_ld16u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].XMM_W(val & 7)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
                    } else {
                        tcg_gen_qemu_st_tl(s->uc, *cpu_T[0], cpu_A0,
                                           s->mem_index, MO_LEUW);
                    }
                    break;
                case 0x16:
                    if (ot == MO_32) { /* pextrd */
                        tcg_gen_ld_i32(tcg_ctx, cpu_tmp2_i32, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_L(val & 3)));
                        if (mod == 3) {
                            tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[rm], cpu_tmp2_i32);
                        } else {
                            tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                                s->mem_index, MO_LEUL);
                        }
                    } else { /* pextrq */
#ifdef TARGET_X86_64
                        tcg_gen_ld_i64(tcg_ctx, cpu_tmp1_i64, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_Q(val & 1)));
                        if (mod == 3) {
                            tcg_gen_mov_i64(tcg_ctx, *cpu_regs[rm], cpu_tmp1_i64);
                        } else {
                            tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_A0,
                                                s->mem_index, MO_LEQ);
                        }
#else
                        goto illegal_op;
#endif
                    }
                    break;
                case 0x17: /* extractps */
                    tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].XMM_L(val & 3)));
                    if (mod == 3) {
                        gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
                    } else {
                        tcg_gen_qemu_st_tl(s->uc, *cpu_T[0], cpu_A0,
                                           s->mem_index, MO_LEUL);
                    }
                    break;
                case 0x20: /* pinsrb */
                    if (mod == 3) {
                        gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], rm);
                    } else {
                        tcg_gen_qemu_ld_tl(s->uc, *cpu_T[0], cpu_A0,
                                           s->mem_index, MO_UB);
                    }
                    tcg_gen_st8_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,
                                            xmm_regs[reg].XMM_B(val & 15)));
                    break;
                case 0x21: /* insertps */
                    if (mod == 3) {
                        tcg_gen_ld_i32(tcg_ctx, cpu_tmp2_i32, cpu_env,
                                        offsetof(CPUX86State,xmm_regs[rm]
                                                .XMM_L((val >> 6) & 3)));
                    } else {
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                    }
                    tcg_gen_st_i32(tcg_ctx, cpu_tmp2_i32, cpu_env,
                                    offsetof(CPUX86State,xmm_regs[reg]
                                            .XMM_L((val >> 4) & 3)));
                    if ((val >> 0) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_L(0)));
                    if ((val >> 1) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_L(1)));
                    if ((val >> 2) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_L(2)));
                    if ((val >> 3) & 1)
                        tcg_gen_st_i32(tcg_ctx, tcg_const_i32(tcg_ctx, 0 /*float32_zero*/),
                                        cpu_env, offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_L(3)));
                    break;
                case 0x22:
                    if (ot == MO_32) { /* pinsrd */
                        if (mod == 3) {
                            tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_regs[rm]);
                        } else {
                            tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                                s->mem_index, MO_LEUL);
                        }
                        tcg_gen_st_i32(tcg_ctx, cpu_tmp2_i32, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_L(val & 3)));
                    } else { /* pinsrq */
#ifdef TARGET_X86_64
                        if (mod == 3) {
                            gen_op_mov_v_reg(tcg_ctx, ot, cpu_tmp1_i64, rm);
                        } else {
                            tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_A0,
                                                s->mem_index, MO_LEQ);
                        }
                        tcg_gen_st_i64(tcg_ctx, cpu_tmp1_i64, cpu_env,
                                        offsetof(CPUX86State,
                                                xmm_regs[reg].XMM_Q(val & 1)));
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
            val = cpu_ldub_code(env, s->pc++);

            if ((b & 0xfc) == 0x60) { /* pcmpXstrX */
                set_cc_op(s, CC_OP_EFLAGS);

                if (s->dflag == MO_64) {
                    /* The helper must use entire 64-bit gp registers */
                    val |= 1 << 8;
                }
            }

            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            sse_fn_eppi(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1, tcg_const_i32(tcg_ctx, val));
            break;

        case 0x33a:
            /* Various integer extensions at 0f 3a f[0-f].  */
            b = modrm | (b1 << 8);
            modrm = cpu_ldub_code(env, s->pc++);
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
                b = cpu_ldub_code(env, s->pc++);
                if (ot == MO_64) {
                    tcg_gen_rotri_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], b & 63);
                } else {
                    tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                    tcg_gen_rotri_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, b & 31);
                    tcg_gen_extu_i32_tl(tcg_ctx, *cpu_T[0], cpu_tmp2_i32);
                }
                gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
                break;

            default:
                goto illegal_op;
            }
            break;

        default:
            goto illegal_op;
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

                if( (b >= 0x50 && b <= 0x5a) ||
                    (b >= 0x5c && b <= 0x5f) ||
                    b == 0xc2 ) {
                    /* Most sse scalar operations.  */
                    if (b1 == 2) {
                        sz = 2;
                    } else if (b1 == 3) {
                        sz = 3;
                    }
                } else if( b == 0x2e ||	/* ucomis[sd] */
                         b == 0x2f )	/* comis[sd] */
                {
                    if (b1 == 0) {
                        sz = 2;
                    } else {
                        sz = 3;
                    }
                }

                switch (sz) {
                case 2:
                    /* 32 bit access */
                    gen_op_ld_v(s, MO_32, *cpu_T[0], cpu_A0);
                    tcg_gen_st32_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                    offsetof(CPUX86State,xmm_t0.XMM_L(0)));
                    break;
                case 3:
                    /* 64 bit access */
                    gen_ldq_env_A0(s, offsetof(CPUX86State, xmm_t0.XMM_D(0)));
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
            if (!(s->cpuid_ext2_features & CPUID_EXT2_3DNOW))
                goto illegal_op;
            val = cpu_ldub_code(env, s->pc++);
            sse_fn_epp = sse_op_table5[val];
            if (!sse_fn_epp) {
                goto illegal_op;
            }
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        case 0x70: /* pshufx insn */
        case 0xc6: /* pshufx insn */
            val = cpu_ldub_code(env, s->pc++);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_ppi = (SSEFunc_0_ppi)sse_fn_epp;
            sse_fn_ppi(tcg_ctx, cpu_ptr0, cpu_ptr1, tcg_const_i32(tcg_ctx, val));
            break;
        case 0xc2:
            /* compare insns */
            val = cpu_ldub_code(env, s->pc++);
            if (val >= 8)
                goto illegal_op;
            sse_fn_epp = sse_op_table4[val][b1];

            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
            break;
        case 0xf7:
            /* maskmov : we must prepare A0 */
            if (mod != 3)
                goto illegal_op;
            tcg_gen_mov_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EDI]);
            gen_extu(tcg_ctx, s->aflag, cpu_A0);
            gen_add_A0_ds_seg(s);

            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            /* XXX: introduce a new table? */
            sse_fn_eppt = (SSEFunc_0_eppt)sse_fn_epp;
            sse_fn_eppt(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1, cpu_A0);
            break;
        default:
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr0, cpu_env, op1_offset);
            tcg_gen_addi_ptr(tcg_ctx, cpu_ptr1, cpu_env, op2_offset);
            sse_fn_epp(tcg_ctx, cpu_env, cpu_ptr0, cpu_ptr1);
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
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv_ptr cpu_env = tcg_ctx->cpu_env;

    gen_update_cc_op(s);
    gen_helper_read_eflags(tcg_ctx, *cpu_T[0], cpu_env);
    tcg_gen_st_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, eflags));
}

/*
static void restore_eflags(DisasContext *s, TCGContext *tcg_ctx)
{
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv_ptr cpu_env = tcg_ctx->cpu_env;

    tcg_gen_ld_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, eflags));
    gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0], 
            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK | ID_MASK | NT_MASK) & 0xffff));
    set_cc_op(s, CC_OP_EFLAGS);
}
*/

/* convert one instruction. s->is_jmp is set if the translation must
   be stopped. Return the next pc value */
static target_ulong disas_insn(CPUX86State *env, DisasContext *s,
                               target_ulong pc_start)   // qq
{
    int b, prefixes;
    int shift;
    TCGMemOp ot, aflag, dflag;
    int modrm, reg, rm, mod, op, opreg, val;
    target_ulong next_eip, tval;
    int rex_w, rex_r;
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr cpu_env = tcg_ctx->cpu_env;
    TCGv_i32 cpu_tmp2_i32 = tcg_ctx->cpu_tmp2_i32;
    TCGv_i32 cpu_tmp3_i32 = tcg_ctx->cpu_tmp3_i32;
    TCGv_i64 cpu_tmp1_i64 = tcg_ctx->cpu_tmp1_i64;
    TCGv cpu_A0 = *(TCGv *)tcg_ctx->cpu_A0;
    TCGv cpu_cc_dst = *(TCGv *)tcg_ctx->cpu_cc_dst;
    TCGv cpu_cc_src = *(TCGv *)tcg_ctx->cpu_cc_src;
    TCGv cpu_cc_srcT = *(TCGv *)tcg_ctx->cpu_cc_srcT;
    TCGv cpu_tmp0 = *(TCGv *)tcg_ctx->cpu_tmp0;
    TCGv cpu_tmp4 = *(TCGv *)tcg_ctx->cpu_tmp4;
    TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
    TCGv **cpu_regs = (TCGv **)tcg_ctx->cpu_regs;
    TCGArg *save_opparam_ptr = tcg_ctx->gen_opparam_ptr;
    bool cc_op_dirty = s->cc_op_dirty;
    bool changed_cc_op = false;

    s->pc = pc_start;
    s->prefix = 0;

    // end address tells us to stop emulation
    if (s->pc == s->uc->addr_end) {
        // imitate the HLT instruction
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_hlt(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        s->is_jmp = DISAS_TB_JUMP;
        return s->pc;
    }

    if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT))) {
        tcg_gen_debug_insn_start(tcg_ctx, pc_start);
    }

    // Unicorn: trace this instruction on request
    if (HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_CODE, pc_start)) {
        if (s->last_cc_op != s->cc_op) {
            sync_eflags(s, tcg_ctx);
            s->last_cc_op = s->cc_op;
            changed_cc_op = true;
        }
        gen_uc_tracecode(tcg_ctx, 0xf1f1f1f1, UC_HOOK_CODE_IDX, env->uc, pc_start);
        // the callback might want to stop emulation immediately
        check_exit_request(tcg_ctx);
    }

    prefixes = 0;
    s->override = -1;
    rex_w = -1;
    rex_r = 0;
#ifdef TARGET_X86_64
    s->rex_x = 0;
    s->rex_b = 0;
    s->uc = env->uc;
    tcg_ctx->x86_64_hregs = 0;
#endif
    s->rip_offset = 0; /* for relative ip address */
    s->vex_l = 0;
    s->vex_v = 0;
 next_byte:
    b = cpu_ldub_code(env, s->pc);
    s->pc++;
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
            tcg_ctx->x86_64_hregs = 1; /* select uniform byte register addressing */
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
            int vex3, vex2 = cpu_ldub_code(env, s->pc);

            if (!CODE64(s) && (vex2 & 0xc0) != 0xc0) {
                /* 4.1.4.6: In 32-bit mode, bits [7:6] must be 11b,
                   otherwise the instruction is LES or LDS.  */
                break;
            }
            s->pc++;

            /* 4.1.1-4.1.3: No preceding lock, 66, f2, f3, or rex prefixes. */
            if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ
                            | PREFIX_LOCK | PREFIX_DATA)) {
                goto illegal_op;
            }
#ifdef TARGET_X86_64
            if (tcg_ctx->x86_64_hregs) {
                goto illegal_op;
            }
#endif
            rex_r = (~vex2 >> 4) & 8;
            if (b == 0xc5) {
                vex3 = vex2;
                b = cpu_ldub_code(env, s->pc++) | 0x100;
            } else {
#ifdef TARGET_X86_64
                s->rex_x = (~vex2 >> 3) & 8;
                s->rex_b = (~vex2 >> 2) & 8;
#endif
                vex3 = cpu_ldub_code(env, s->pc++);
                rex_w = (vex3 >> 7) & 1;
                switch (vex2 & 0x1f) {
                case 0x01: /* Implied 0f leading opcode bytes.  */
                    b = cpu_ldub_code(env, s->pc++) | 0x100;
                    break;
                case 0x02: /* Implied 0f 38 leading opcode bytes.  */
                    b = 0x138;
                    break;
                case 0x03: /* Implied 0f 3a leading opcode bytes.  */
                    b = 0x13a;
                    break;
                default:   /* Reserved for future use.  */
                    goto illegal_op;
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
        if (s->code32 ^ ((prefixes & PREFIX_DATA) != 0)) {  // qq
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

    /* lock generation */
    if (prefixes & PREFIX_LOCK)
        gen_helper_lock(tcg_ctx, cpu_env);

    /* now check op code */
 reswitch:
    switch(b) {
    case 0x0f:
        /**************************/
        /* extended op code */
        b = cpu_ldub_code(env, s->pc++) | 0x100;
        goto reswitch;

        /**************************/
        /* arith & logic */
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:	//case 0x00 ... 0x05:
    case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d:	//case 0x08 ... 0x0d:
    case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:	//case 0x10 ... 0x15:
    case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d:	//case 0x18 ... 0x1d:
    case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:	//case 0x20 ... 0x25:
    case 0x28: case 0x29: case 0x2a: case 0x2b: case 0x2c: case 0x2d:	//case 0x28 ... 0x2d:
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:	//case 0x30 ... 0x35:
    case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d:	//case 0x38 ... 0x3d:
        {
            int op, f, val;
            op = (b >> 3) & 7;
            f = (b >> 1) & 3;

            ot = mo_b_d(b, dflag);

            switch(f) {
            case 0: /* OP Ev, Gv */
                modrm = cpu_ldub_code(env, s->pc++);
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
                    tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], 0);
                    gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
                    break;
                } else {
                    opreg = rm;
                }
                gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], reg);
                gen_op(s, op, ot, opreg);
                break;
            case 1: /* OP Gv, Ev */
                modrm = cpu_ldub_code(env, s->pc++);
                mod = (modrm >> 6) & 3;
                reg = ((modrm >> 3) & 7) | rex_r;
                rm = (modrm & 7) | REX_B(s);
                if (mod != 3) {
                    gen_lea_modrm(env, s, modrm);
                    gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
                } else if (op == OP_XORL && rm == reg) {
                    goto xor_zero;
                } else {
                    gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], rm);
                }
                gen_op(s, op, ot, reg);
                break;
            case 2: /* OP A, Iv */
                val = insn_get(env, s, ot);
                tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
                gen_op(s, op, ot, OR_EAX);
                break;
            }
        }
        break;

    case 0x82:
        if (CODE64(s))
            goto illegal_op;
    case 0x80: /* GRP1 */
    case 0x81:
    case 0x83:
        {
            int val;

            ot = mo_b_d(b, dflag);

            modrm = cpu_ldub_code(env, s->pc++);
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
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
            gen_op(s, op, ot, opreg);
        }
        break;

        /**************************/
        /* inc, dec, and other misc arith */
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47: //case 0x40 ... 0x47: /* inc Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), 1);
        break;
    case 0x48: case 0x49: case 0x4a: case 0x4b:
    case 0x4c: case 0x4d: case 0x4e: case 0x4f: //case 0x48 ... 0x4f: /* dec Gv */
        ot = dflag;
        gen_inc(s, ot, OR_EAX + (b & 7), -1);
        break;
    case 0xf6: /* GRP3 */
    case 0xf7:
        ot = mo_b_d(b, dflag);

        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (mod != 3) {
            if (op == 0)
                s->rip_offset = insn_const_size(ot);
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
        } else {
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
        }

        switch(op) {
        case 0: /* test */
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
            gen_op_testl_T0_T1_cc(tcg_ctx);
            set_cc_op(s, CC_OP_LOGICB + ot);
            break;
        case 2: /* not */
            tcg_gen_not_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            if (mod != 3) {
                gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
            } else {
                gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
            }
            break;
        case 3: /* neg */
            tcg_gen_neg_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            if (mod != 3) {
                gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
            } else {
                gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
            }
            gen_op_update_neg_cc(tcg_ctx);
            set_cc_op(s, CC_OP_SUBB + ot);
            break;
        case 4: /* mul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(tcg_ctx, MO_8, *cpu_T[1], R_EAX);
                tcg_gen_ext8u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                tcg_gen_ext8u_tl(tcg_ctx, *cpu_T[1], *cpu_T[1]);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                gen_op_mov_reg_v(tcg_ctx, MO_16, R_EAX, *cpu_T[0]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
                tcg_gen_andi_tl(tcg_ctx, cpu_cc_src, *cpu_T[0], 0xff00);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(tcg_ctx, MO_16, *cpu_T[1], R_EAX);
                tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[1], *cpu_T[1]);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                gen_op_mov_reg_v(tcg_ctx, MO_16, R_EAX, *cpu_T[0]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
                tcg_gen_shri_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 16);
                gen_op_mov_reg_v(tcg_ctx, MO_16, R_EDX, *cpu_T[0]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_T[0]);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_regs[R_EAX]);
                tcg_gen_mulu2_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp3_i32,
                                  cpu_tmp2_i32, cpu_tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[R_EAX], cpu_tmp2_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[R_EDX], cpu_tmp3_i32);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_mulu2_i64(tcg_ctx, *cpu_regs[R_EAX], *cpu_regs[R_EDX],
                                  *cpu_T[0], *cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 5: /* imul */
            switch(ot) {
            case MO_8:
                gen_op_mov_v_reg(tcg_ctx, MO_8, *cpu_T[1], R_EAX);
                tcg_gen_ext8s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                tcg_gen_ext8s_tl(tcg_ctx, *cpu_T[1], *cpu_T[1]);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                gen_op_mov_reg_v(tcg_ctx, MO_16, R_EAX, *cpu_T[0]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
                tcg_gen_ext8s_tl(tcg_ctx, cpu_tmp0, *cpu_T[0]);
                tcg_gen_sub_tl(tcg_ctx, cpu_cc_src, *cpu_T[0], cpu_tmp0);
                set_cc_op(s, CC_OP_MULB);
                break;
            case MO_16:
                gen_op_mov_v_reg(tcg_ctx, MO_16, *cpu_T[1], R_EAX);
                tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[1], *cpu_T[1]);
                /* XXX: use 32 bit mul which could be faster */
                tcg_gen_mul_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
                gen_op_mov_reg_v(tcg_ctx, MO_16, R_EAX, *cpu_T[0]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
                tcg_gen_ext16s_tl(tcg_ctx, cpu_tmp0, *cpu_T[0]);
                tcg_gen_sub_tl(tcg_ctx, cpu_cc_src, *cpu_T[0], cpu_tmp0);
                tcg_gen_shri_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 16);
                gen_op_mov_reg_v(tcg_ctx, MO_16, R_EDX, *cpu_T[0]);
                set_cc_op(s, CC_OP_MULW);
                break;
            default:
            case MO_32:
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_regs[R_EAX]);
                tcg_gen_muls2_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp3_i32,
                                  cpu_tmp2_i32, cpu_tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[R_EAX], cpu_tmp2_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[R_EDX], cpu_tmp3_i32);
                tcg_gen_sari_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, 31);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_regs[R_EAX]);
                tcg_gen_sub_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
                tcg_gen_extu_i32_tl(tcg_ctx, cpu_cc_src, cpu_tmp2_i32);
                set_cc_op(s, CC_OP_MULL);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                tcg_gen_muls2_i64(tcg_ctx, *cpu_regs[R_EAX], *cpu_regs[R_EDX],
                                  *cpu_T[0], *cpu_regs[R_EAX]);
                tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_regs[R_EAX]);
                tcg_gen_sari_tl(tcg_ctx, cpu_cc_src, *cpu_regs[R_EAX], 63);
                tcg_gen_sub_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, *cpu_regs[R_EDX]);
                set_cc_op(s, CC_OP_MULQ);
                break;
#endif
            }
            break;
        case 6: /* div */
            switch(ot) {
            case MO_8:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_divb_AL(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
            case MO_16:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_divw_AX(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
            default:
            case MO_32:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_divl_EAX(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_divq_EAX(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
#endif
            }
            break;
        case 7: /* idiv */
            switch(ot) {
            case MO_8:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_idivb_AL(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
            case MO_16:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_idivw_AX(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
            default:
            case MO_32:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_idivl_EAX(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
#ifdef TARGET_X86_64
            case MO_64:
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_idivq_EAX(tcg_ctx, cpu_env, *cpu_T[0]);
                break;
#endif
            }
            break;
        default:
            goto illegal_op;
        }
        break;

    case 0xfe: /* GRP4 */
    case 0xff: /* GRP5 */
        ot = mo_b_d(b, dflag);

        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        op = (modrm >> 3) & 7;
        if (op >= 2 && b == 0xfe) {
            goto illegal_op;
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
                gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
        } else {
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
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
                tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            }
            next_eip = s->pc - s->cs_base;
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], next_eip);
            gen_push_v(s, *cpu_T[1]);
            gen_op_jmp_v(tcg_ctx, *cpu_T[0]);
            gen_eob(s);
            break;
        case 3: /* lcall Ev */
            gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, *cpu_T[0], cpu_A0);
        do_lcall:
            if (s->pe && !s->vm86) {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_lcall_protected(tcg_ctx, cpu_env, cpu_tmp2_i32, *cpu_T[1],
                                           tcg_const_i32(tcg_ctx, dflag - 1),
                                           tcg_const_i32(tcg_ctx, s->pc - pc_start));
            } else {
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_lcall_real(tcg_ctx, cpu_env, cpu_tmp2_i32, *cpu_T[1],
                                      tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, s->pc - s->cs_base));
            }
            gen_eob(s);
            break;
        case 4: /* jmp Ev */
            if (dflag == MO_16) {
                tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            }
            gen_op_jmp_v(tcg_ctx, *cpu_T[0]);
            gen_eob(s);
            break;
        case 5: /* ljmp Ev */
            gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
            gen_add_A0_im(s, 1 << ot);
            gen_op_ld_v(s, MO_16, *cpu_T[0], cpu_A0);
        do_ljmp:
            if (s->pe && !s->vm86) {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_ljmp_protected(tcg_ctx, cpu_env, cpu_tmp2_i32, *cpu_T[1],
                                          tcg_const_i32(tcg_ctx, s->pc - pc_start));
            } else {
                gen_op_movl_seg_T0_vm(tcg_ctx, R_CS);
                gen_op_jmp_v(tcg_ctx, *cpu_T[1]);
            }
            gen_eob(s);
            break;
        case 6: /* push Ev */
            gen_push_v(s, *cpu_T[0]);
            break;
        default:
            goto illegal_op;
        }
        break;

    case 0x84: /* test Ev, Gv */
    case 0x85:
        ot = mo_b_d(b, dflag);

        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], reg);
        gen_op_testl_T0_T1_cc(tcg_ctx);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;

    case 0xa8: /* test eAX, Iv */
    case 0xa9:
        ot = mo_b_d(b, dflag);
        val = insn_get(env, s, ot);

        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], OR_EAX);
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
        gen_op_testl_T0_T1_cc(tcg_ctx);
        set_cc_op(s, CC_OP_LOGICB + ot);
        break;

    case 0x98: /* CWDE/CBW */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], R_EAX);
            tcg_gen_ext32s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            gen_op_mov_reg_v(tcg_ctx, MO_64, R_EAX, *cpu_T[0]);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(tcg_ctx, MO_16, *cpu_T[0], R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            gen_op_mov_reg_v(tcg_ctx, MO_32, R_EAX, *cpu_T[0]);
            break;
        case MO_16:
            gen_op_mov_v_reg(tcg_ctx, MO_8, *cpu_T[0], R_EAX);
            tcg_gen_ext8s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            gen_op_mov_reg_v(tcg_ctx, MO_16, R_EAX, *cpu_T[0]);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x99: /* CDQ/CWD */
        switch (dflag) {
#ifdef TARGET_X86_64
        case MO_64:
            gen_op_mov_v_reg(tcg_ctx, MO_64, *cpu_T[0], R_EAX);
            tcg_gen_sari_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 63);
            gen_op_mov_reg_v(tcg_ctx, MO_64, R_EDX, *cpu_T[0]);
            break;
#endif
        case MO_32:
            gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], R_EAX);
            tcg_gen_ext32s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            tcg_gen_sari_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 31);
            gen_op_mov_reg_v(tcg_ctx, MO_32, R_EDX, *cpu_T[0]);
            break;
        case MO_16:
            gen_op_mov_v_reg(tcg_ctx, MO_16, *cpu_T[0], R_EAX);
            tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            tcg_gen_sari_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 15);
            gen_op_mov_reg_v(tcg_ctx, MO_16, R_EDX, *cpu_T[0]);
            break;
        default:
            tcg_abort();
        }
        break;
    case 0x1af: /* imul Gv, Ev */
    case 0x69: /* imul Gv, Ev, I */
    case 0x6b:
        ot = dflag;
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (b == 0x69)
            s->rip_offset = insn_const_size(ot);
        else if (b == 0x6b)
            s->rip_offset = 1;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        if (b == 0x69) {
            val = insn_get(env, s, ot);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
        } else if (b == 0x6b) {
            val = (int8_t)insn_get(env, s, MO_8);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
        } else {
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], reg);
        }
        switch (ot) {
#ifdef TARGET_X86_64
        case MO_64:
            tcg_gen_muls2_i64(tcg_ctx, *cpu_regs[reg], *cpu_T[1], *cpu_T[0], *cpu_T[1]);
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_regs[reg]);
            tcg_gen_sari_tl(tcg_ctx, cpu_cc_src, cpu_cc_dst, 63);
            tcg_gen_sub_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, *cpu_T[1]);
            break;
#endif
        case MO_32:
            tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
            tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_T[1]);
            tcg_gen_muls2_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp3_i32,
                              cpu_tmp2_i32, cpu_tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, *cpu_regs[reg], cpu_tmp2_i32);
            tcg_gen_sari_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, 31);
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_regs[reg]);
            tcg_gen_sub_i32(tcg_ctx, cpu_tmp2_i32, cpu_tmp2_i32, cpu_tmp3_i32);
            tcg_gen_extu_i32_tl(tcg_ctx, cpu_cc_src, cpu_tmp2_i32);
            break;
        default:
            tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[1], *cpu_T[1]);
            /* XXX: use 32 bit mul which could be faster */
            tcg_gen_mul_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
            tcg_gen_ext16s_tl(tcg_ctx, cpu_tmp0, *cpu_T[0]);
            tcg_gen_sub_tl(tcg_ctx, cpu_cc_src, *cpu_T[0], cpu_tmp0);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
            break;
        }
        set_cc_op(s, CC_OP_MULB + ot);
        break;
    case 0x1c0:
    case 0x1c1: /* xadd Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], rm);
            tcg_gen_add_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[1]);
            gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
            gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
            tcg_gen_add_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], *cpu_T[1]);
            gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[1]);
        }
        gen_op_update2_cc(tcg_ctx);
        set_cc_op(s, CC_OP_ADDB + ot);
        break;
    case 0x1b0:
    case 0x1b1: /* cmpxchg Ev, Gv */
        {
            int label1, label2;
            TCGv t0, t1, t2, a0;

            ot = mo_b_d(b, dflag);
            modrm = cpu_ldub_code(env, s->pc++);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            t0 = tcg_temp_local_new(tcg_ctx);
            t1 = tcg_temp_local_new(tcg_ctx);
            t2 = tcg_temp_local_new(tcg_ctx);
            a0 = tcg_temp_local_new(tcg_ctx);
            gen_op_mov_v_reg(tcg_ctx, ot, t1, reg);
            if (mod == 3) {
                rm = (modrm & 7) | REX_B(s);
                gen_op_mov_v_reg(tcg_ctx, ot, t0, rm);
            } else {
                gen_lea_modrm(env, s, modrm);
                tcg_gen_mov_tl(tcg_ctx, a0, cpu_A0);
                gen_op_ld_v(s, ot, t0, a0);
                rm = 0; /* avoid warning */
            }
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_mov_tl(tcg_ctx, t2, *cpu_regs[R_EAX]);
            gen_extu(tcg_ctx, ot, t0);
            gen_extu(tcg_ctx, ot, t2);
            tcg_gen_brcond_tl(tcg_ctx, TCG_COND_EQ, t2, t0, label1);
            label2 = gen_new_label(tcg_ctx);
            if (mod == 3) {
                gen_op_mov_reg_v(tcg_ctx, ot, R_EAX, t0);
                tcg_gen_br(tcg_ctx, label2);
                gen_set_label(tcg_ctx, label1);
                gen_op_mov_reg_v(tcg_ctx, ot, rm, t1);
            } else {
                /* perform no-op store cycle like physical cpu; must be
                   before changing accumulator to ensure idempotency if
                   the store faults and the instruction is restarted */
                gen_op_st_v(s, ot, t0, a0);
                gen_op_mov_reg_v(tcg_ctx, ot, R_EAX, t0);
                tcg_gen_br(tcg_ctx, label2);
                gen_set_label(tcg_ctx, label1);
                gen_op_st_v(s, ot, t1, a0);
            }
            gen_set_label(tcg_ctx, label2);
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, t0);
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_srcT, t2);
            tcg_gen_sub_tl(tcg_ctx, cpu_cc_dst, t2, t0);
            set_cc_op(s, CC_OP_SUBB + ot);
            tcg_temp_free(tcg_ctx, t0);
            tcg_temp_free(tcg_ctx, t1);
            tcg_temp_free(tcg_ctx, t2);
            tcg_temp_free(tcg_ctx, a0);
        }
        break;
    case 0x1c7: /* cmpxchg8b */
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        if ((mod == 3) || ((modrm & 0x38) != 0x8))
            goto illegal_op;
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            if (!(s->cpuid_ext_features & CPUID_EXT_CX16))
                goto illegal_op;
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_update_cc_op(s);
            gen_lea_modrm(env, s, modrm);
            gen_helper_cmpxchg16b(tcg_ctx, cpu_env, cpu_A0);
        } else
#endif
        {
            if (!(s->cpuid_features & CPUID_CX8))
                goto illegal_op;
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_update_cc_op(s);
            gen_lea_modrm(env, s, modrm);
            gen_helper_cmpxchg8b(tcg_ctx, cpu_env, cpu_A0);
        }
        set_cc_op(s, CC_OP_EFLAGS);
        break;

        /**************************/
        /* push/pop */
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57: //case 0x50 ... 0x57: /* push */
        gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], (b & 7) | REX_B(s));
        gen_push_v(s, *cpu_T[0]);
        break;
    case 0x58: case 0x59: case 0x5a: case 0x5b:
    case 0x5c: case 0x5d: case 0x5e: case 0x5f: //case 0x58 ... 0x5f: /* pop */
        ot = gen_pop_T0(s);
        /* NOTE: order is important for pop %sp */
        gen_pop_update(s, ot);
        gen_op_mov_reg_v(tcg_ctx, ot, (b & 7) | REX_B(s), *cpu_T[0]);
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
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
        gen_push_v(s, *cpu_T[0]);
        break;
    case 0x8f: /* pop Ev */
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        ot = gen_pop_T0(s);
        if (mod == 3) {
            /* NOTE: order is important for pop %sp */
            gen_pop_update(s, ot);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
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
            val = cpu_lduw_code(env, s->pc);
            s->pc += 2;
            level = cpu_ldub_code(env, s->pc++);
            gen_enter(s, val, level);
        }
        break;
    case 0xc9: /* leave */
        /* XXX: exception not precise (ESP is updated before potential exception) */
        if (CODE64(s)) {
            gen_op_mov_v_reg(tcg_ctx, MO_64, *cpu_T[0], R_EBP);
            gen_op_mov_reg_v(tcg_ctx, MO_64, R_ESP, *cpu_T[0]);
        } else if (s->ss32) {
            gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], R_EBP);
            gen_op_mov_reg_v(tcg_ctx, MO_32, R_ESP, *cpu_T[0]);
        } else {
            gen_op_mov_v_reg(tcg_ctx, MO_16, *cpu_T[0], R_EBP);
            gen_op_mov_reg_v(tcg_ctx, MO_16, R_ESP, *cpu_T[0]);
        }
        ot = gen_pop_T0(s);
        gen_op_mov_reg_v(tcg_ctx, ot, R_EBP, *cpu_T[0]);
        gen_pop_update(s, ot);
        break;
    case 0x06: /* push es */
    case 0x0e: /* push cs */
    case 0x16: /* push ss */
    case 0x1e: /* push ds */
        if (CODE64(s))
            goto illegal_op;
        gen_op_movl_T0_seg(tcg_ctx, b >> 3);
        gen_push_v(s, *cpu_T[0]);
        break;
    case 0x1a0: /* push fs */
    case 0x1a8: /* push gs */
        gen_op_movl_T0_seg(tcg_ctx, (b >> 3) & 7);
        gen_push_v(s, *cpu_T[0]);
        break;
    case 0x07: /* pop es */
    case 0x17: /* pop ss */
    case 0x1f: /* pop ds */
        if (CODE64(s))
            goto illegal_op;
        reg = b >> 3;
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, reg, pc_start - s->cs_base);
        gen_pop_update(s, ot);
        if (reg == R_SS) {
            /* if reg == SS, inhibit interrupts/trace. */
            /* If several instructions disable interrupts, only the
               _first_ does it */
            if (!(s->tb->flags & HF_INHIBIT_IRQ_MASK))
                gen_helper_set_inhibit_irq(tcg_ctx, cpu_env);
            s->tf = 0;
        }
        if (s->is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    case 0x1a1: /* pop fs */
    case 0x1a9: /* pop gs */
        ot = gen_pop_T0(s);
        gen_movl_seg_T0(s, (b >> 3) & 7, pc_start - s->cs_base);
        gen_pop_update(s, ot);
        if (s->is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;

        /**************************/
        /* mov */
    case 0x88:
    case 0x89: /* mov Gv, Ev */
        ot = mo_b_d(b, dflag);
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;

        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0xc6:
    case 0xc7: /* mov Ev, Iv */
        ot = mo_b_d(b, dflag);
        modrm = cpu_ldub_code(env, s->pc++);
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
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
        if (mod != 3) {
            gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
        } else {
            gen_op_mov_reg_v(tcg_ctx, ot, (modrm & 7) | REX_B(s), *cpu_T[0]);
        }
        break;
    case 0x8a:
    case 0x8b: /* mov Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
        break;
    case 0x8e: /* mov seg, Gv */
        modrm = cpu_ldub_code(env, s->pc++);
        reg = (modrm >> 3) & 7;
        if (reg >= 6 || reg == R_CS)
            goto illegal_op;
        gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
        gen_movl_seg_T0(s, reg, pc_start - s->cs_base);
        if (reg == R_SS) {
            /* if reg == SS, inhibit interrupts/trace */
            /* If several instructions disable interrupts, only the
               _first_ does it */
            if (!(s->tb->flags & HF_INHIBIT_IRQ_MASK))
                gen_helper_set_inhibit_irq(tcg_ctx, cpu_env);
            s->tf = 0;
        }
        if (s->is_jmp) {
            gen_jmp_im(s, s->pc - s->cs_base);
            gen_eob(s);
        }
        break;
    case 0x8c: /* mov Gv, seg */
        modrm = cpu_ldub_code(env, s->pc++);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (reg >= 6)
            goto illegal_op;
        gen_op_movl_T0_seg(tcg_ctx, reg);
        ot = mod == 3 ? dflag : MO_16;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 1);
        break;

    case 0x1b6: /* movzbS Gv, Eb */
    case 0x1b7: /* movzwS Gv, Eb */
    case 0x1be: /* movsbS Gv, Eb */
    case 0x1bf: /* movswS Gv, Eb */
        {
            TCGMemOp d_ot;
            TCGMemOp s_ot;

            /* d_ot is the size of destination */
            d_ot = dflag;
            /* ot is the size of source */
            ot = (b & 1) + MO_8;
            /* s_ot is the sign+size of source */
            s_ot = b & 8 ? MO_SIGN | ot : ot;

            modrm = cpu_ldub_code(env, s->pc++);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
                switch (s_ot) {
                case MO_UB:
                    tcg_gen_ext8u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                    break;
                case MO_SB:
                    tcg_gen_ext8s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                    break;
                case MO_UW:
                    tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                    break;
                default:
                case MO_SW:
                    tcg_gen_ext16s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                    break;
                }
                gen_op_mov_reg_v(tcg_ctx, d_ot, reg, *cpu_T[0]);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, s_ot, *cpu_T[0], cpu_A0);
                gen_op_mov_reg_v(tcg_ctx, d_ot, reg, *cpu_T[0]);
            }
        }
        break;

    case 0x8d: /* lea */
        ot = dflag;
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        /* we must ensure that no segment is added */
        s->override = -1;
        val = s->addseg;
        s->addseg = 0;
        gen_lea_modrm(env, s, modrm);
        s->addseg = val;
        gen_op_mov_reg_v(tcg_ctx, ot, reg, cpu_A0);
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
                offset_addr = cpu_ldq_code(env, s->pc);
                s->pc += 8;
                break;
#endif
            default:
                offset_addr = insn_get(env, s, s->aflag);
                break;
            }
            tcg_gen_movi_tl(tcg_ctx, cpu_A0, offset_addr);
            gen_add_A0_ds_seg(s);
            if ((b & 2) == 0) {
                gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
                gen_op_mov_reg_v(tcg_ctx, ot, R_EAX, *cpu_T[0]);
            } else {
                gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], R_EAX);
                gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
            }
        }
        break;
    case 0xd7: /* xlat */
        tcg_gen_mov_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EBX]);
        tcg_gen_ext8u_tl(tcg_ctx, *cpu_T[0], *cpu_regs[R_EAX]);
        tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, *cpu_T[0]);
        gen_extu(tcg_ctx, s->aflag, cpu_A0);
        gen_add_A0_ds_seg(s);
        gen_op_ld_v(s, MO_8, *cpu_T[0], cpu_A0);
        gen_op_mov_reg_v(tcg_ctx, MO_8, R_EAX, *cpu_T[0]);
        break;
    case 0xb0: case 0xb1: case 0xb2: case 0xb3:
    case 0xb4: case 0xb5: case 0xb6: case 0xb7: //case 0xb0 ... 0xb7: /* mov R, Ib */
        val = insn_get(env, s, MO_8);
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
        gen_op_mov_reg_v(tcg_ctx, MO_8, (b & 7) | REX_B(s), *cpu_T[0]);
        break;
    case 0xb8: case 0xb9: case 0xba: case 0xbb:
    case 0xbc: case 0xbd: case 0xbe: case 0xbf: //case 0xb8 ... 0xbf: /* mov R, Iv */
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            uint64_t tmp;
            /* 64 bit case */
            tmp = cpu_ldq_code(env, s->pc);
            s->pc += 8;
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], tmp);
            gen_op_mov_reg_v(tcg_ctx, MO_64, reg, *cpu_T[0]);
        } else
#endif
        {
            ot = dflag;
            val = insn_get(env, s, ot);
            reg = (b & 7) | REX_B(s);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
        }
        break;

    case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97: //case 0x91 ... 0x97: /* xchg R, EAX */
    do_xchg_reg_eax:
        ot = dflag;
        reg = (b & 7) | REX_B(s);
        rm = R_EAX;
        goto do_xchg_reg;
    case 0x86:
    case 0x87: /* xchg Ev, Gv */
        ot = mo_b_d(b, dflag);
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
        do_xchg_reg:
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], rm);
            gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[1]);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
            /* for xchg, lock is implicit */
            if (!(prefixes & PREFIX_LOCK))
                gen_helper_lock(tcg_ctx, cpu_env);
            gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
            gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
            if (!(prefixes & PREFIX_LOCK))
                gen_helper_unlock(tcg_ctx, cpu_env);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[1]);
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
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_lea_modrm(env, s, modrm);
        gen_op_ld_v(s, ot, *cpu_T[1], cpu_A0);
        gen_add_A0_im(s, 1 << ot);
        /* load the segment first to handle exceptions properly */
        gen_op_ld_v(s, MO_16, *cpu_T[0], cpu_A0);
        gen_movl_seg_T0(s, op, pc_start - s->cs_base);
        /* then put the data */
        gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[1]);
        if (s->is_jmp) {
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
            modrm = cpu_ldub_code(env, s->pc++);
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
                    shift = cpu_ldub_code(env, s->pc++);
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
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        reg = ((modrm >> 3) & 7) | rex_r;
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            opreg = OR_TMP0;
        } else {
            opreg = rm;
        }
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], reg);

        if (shift) {
            TCGv imm = tcg_const_tl(tcg_ctx, cpu_ldub_code(env, s->pc++));
            gen_shiftd_rm_T1(s, ot, opreg, op, imm);
            tcg_temp_free(tcg_ctx, imm);
        } else {
            gen_shiftd_rm_T1(s, ot, opreg, op, *cpu_regs[R_ECX]);
        }
        break;

        /************************/
        /* floats */
    case 0xd8: case 0xd9: case 0xda: case 0xdb:
    case 0xdc: case 0xdd: case 0xde: case 0xdf: //case 0xd8 ... 0xdf:
        if (s->flags & (HF_EM_MASK | HF_TS_MASK)) {
            /* if CR0.EM or CR0.TS are set, generate an FPU exception */
            /* XXX: what to do if illegal op ? */
            gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
            break;
        }
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        rm = modrm & 7;
        op = ((b & 7) << 3) | ((modrm >> 3) & 7);
        if (mod != 3) {
            /* memory op */
            gen_lea_modrm(env, s, modrm);
            
            if( (op >= 0x00 && op <= 0x07) || /* fxxxs */
                (op >= 0x10 && op <= 0x17) || /* fixxxl */
                (op >= 0x20 && op <= 0x27) || /* fxxxl */
                (op >= 0x30 && op <= 0x37) )  /* fixxx */
            {
                    int op1;
                    op1 = op & 7;

                    switch(op >> 4) {
                    case 0:
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_flds_FT0(tcg_ctx, cpu_env, cpu_tmp2_i32);
                        break;
                    case 1:
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_fildl_FT0(tcg_ctx, cpu_env, cpu_tmp2_i32);
                        break;
                    case 2:
                        tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        gen_helper_fldl_FT0(tcg_ctx, cpu_env, cpu_tmp1_i64);
                        break;
                    case 3:
                    default:
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LESW);
                        gen_helper_fildl_FT0(tcg_ctx, cpu_env, cpu_tmp2_i32);
                        break;
                    }

                    gen_helper_fp_arith_ST0_FT0(tcg_ctx, op1);
                    if (op1 == 3) {
                        /* fcomp needs pop */
                        gen_helper_fpop(tcg_ctx, cpu_env);
                    }
            }
            else if((op == 0x08) || /* flds */
                    (op == 0x0a) || /* fsts */
                    (op == 0x0b) || /* fstps */
                    (op >= 0x18 && op <= 0x1b) || /* fildl, fisttpl, fistl, fistpl */
                    (op >= 0x28 && op <= 0x2b) || /* fldl, fisttpll, fstl, fstpl */
                    (op >= 0x38 && op <= 0x3b) )  /* filds, fisttps, fists, fistps */
            {
                switch(op & 7) {
                case 0:
                    switch(op >> 4) {
                    case 0:
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_flds_ST0(tcg_ctx, cpu_env, cpu_tmp2_i32);
                        break;
                    case 1:
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        gen_helper_fildl_ST0(tcg_ctx, cpu_env, cpu_tmp2_i32);
                        break;
                    case 2:
                        tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        gen_helper_fldl_ST0(tcg_ctx, cpu_env, cpu_tmp1_i64);
                        break;
                    case 3:
                    default:
                        tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LESW);
                        gen_helper_fildl_ST0(tcg_ctx, cpu_env, cpu_tmp2_i32);
                        break;
                    }
                    break;
                case 1:
                    /* XXX: the corresponding CPUID bit must be tested ! */
                    switch(op >> 4) {
                    case 1:
                        gen_helper_fisttl_ST0(tcg_ctx, cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        break;
                    case 2:
                        gen_helper_fisttll_ST0(tcg_ctx, cpu_tmp1_i64, cpu_env);
                        tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        break;
                    case 3:
                    default:
                        gen_helper_fistt_ST0(tcg_ctx, cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUW);
                        break;
                    }
                    gen_helper_fpop(tcg_ctx, cpu_env);
                    break;
                default:
                    switch(op >> 4) {
                    case 0:
                        gen_helper_fsts_ST0(tcg_ctx, cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        break;
                    case 1:
                        gen_helper_fistl_ST0(tcg_ctx, cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUL);
                        break;
                    case 2:
                        gen_helper_fstl_ST0(tcg_ctx, cpu_tmp1_i64, cpu_env);
                        tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_A0,
                                            s->mem_index, MO_LEQ);
                        break;
                    case 3:
                    default:
                        gen_helper_fist_ST0(tcg_ctx, cpu_tmp2_i32, cpu_env);
                        tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                            s->mem_index, MO_LEUW);
                        break;
                    }
                    if ((op & 7) == 3)
                        gen_helper_fpop(tcg_ctx, cpu_env);
                    break;
                }
            }
            else if(op == 0x0c) /* fldenv mem */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fldenv(tcg_ctx, cpu_env, cpu_A0, tcg_const_i32(tcg_ctx, dflag - 1));
            }
            else if(op == 0x0d) /* fldcw mem */
            {
                tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUW);
                gen_helper_fldcw(tcg_ctx, cpu_env, cpu_tmp2_i32);
            }
            else if(op == 0x0e) /* fnstenv mem */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fstenv(tcg_ctx, cpu_env, cpu_A0, tcg_const_i32(tcg_ctx, dflag - 1));
            }
            else if(op == 0x0f) /* fnstcw mem */
            {
                gen_helper_fnstcw(tcg_ctx, cpu_tmp2_i32, cpu_env);
                tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUW);
            }
            else if(op == 0x1d) /* fldt mem */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fldt_ST0(tcg_ctx, cpu_env, cpu_A0);
            }
            else if(op == 0x1f) /* fstpt mem */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fstt_ST0(tcg_ctx, cpu_env, cpu_A0);
                gen_helper_fpop(tcg_ctx, cpu_env);
            }
            else if(op == 0x2c) /* frstor mem */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_frstor(tcg_ctx, cpu_env, cpu_A0, tcg_const_i32(tcg_ctx, dflag - 1));
            }
            else if(op == 0x2e) /* fnsave mem */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fsave(tcg_ctx, cpu_env, cpu_A0, tcg_const_i32(tcg_ctx, dflag - 1));
            }
            else if(op == 0x2f) /* fnstsw mem */
            {
                gen_helper_fnstsw(tcg_ctx, cpu_tmp2_i32, cpu_env);
                tcg_gen_qemu_st_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUW);
            }
            else if(op == 0x3c) /* fbld */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fbld_ST0(tcg_ctx, cpu_env, cpu_A0);
            }
            else if(op == 0x3e) /* fbstp */
            {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                gen_helper_fbst_ST0(tcg_ctx, cpu_env, cpu_A0);
                gen_helper_fpop(tcg_ctx, cpu_env);
            }
            else if(op == 0x3d) /* fildll */
            {
                tcg_gen_qemu_ld_i64(s->uc, cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
                gen_helper_fildll_ST0(tcg_ctx, cpu_env, cpu_tmp1_i64);
            }
            else if(op == 0x3f) /* fistpll */
            {
                gen_helper_fistll_ST0(tcg_ctx, cpu_tmp1_i64, cpu_env);
                tcg_gen_qemu_st_i64(s->uc, cpu_tmp1_i64, cpu_A0, s->mem_index, MO_LEQ);
                gen_helper_fpop(tcg_ctx, cpu_env);
            }
            else
            {
                goto illegal_op;
            }
        } else {
            /* register float ops */
            opreg = rm;

            switch(op) {
            case 0x08: /* fld sti */
                gen_helper_fpush(tcg_ctx, cpu_env);
                gen_helper_fmov_ST0_STN(tcg_ctx, cpu_env,
                                        tcg_const_i32(tcg_ctx, (opreg + 1) & 7));
                break;
            case 0x09: /* fxchg sti */
            case 0x29: /* fxchg4 sti, undocumented op */
            case 0x39: /* fxchg7 sti, undocumented op */
                gen_helper_fxchg_ST0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                break;
            case 0x0a: /* grp d9/2 */
                switch(rm) {
                case 0: /* fnop */
                    /* check exceptions (FreeBSD FPU probe) */
                    gen_update_cc_op(s);
                    gen_jmp_im(s, pc_start - s->cs_base);
                    gen_helper_fwait(tcg_ctx, cpu_env);
                    break;
                default:
                    goto illegal_op;
                }
                break;
            case 0x0c: /* grp d9/4 */
                switch(rm) {
                case 0: /* fchs */
                    gen_helper_fchs_ST0(tcg_ctx, cpu_env);
                    break;
                case 1: /* fabs */
                    gen_helper_fabs_ST0(tcg_ctx, cpu_env);
                    break;
                case 4: /* ftst */
                    gen_helper_fldz_FT0(tcg_ctx, cpu_env);
                    gen_helper_fcom_ST0_FT0(tcg_ctx, cpu_env);
                    break;
                case 5: /* fxam */
                    gen_helper_fxam_ST0(tcg_ctx, cpu_env);
                    break;
                default:
                    goto illegal_op;
                }
                break;
            case 0x0d: /* grp d9/5 */
                {
                    switch(rm) {
                    case 0:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fld1_ST0(tcg_ctx, cpu_env);
                        break;
                    case 1:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fldl2t_ST0(tcg_ctx, cpu_env);
                        break;
                    case 2:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fldl2e_ST0(tcg_ctx, cpu_env);
                        break;
                    case 3:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fldpi_ST0(tcg_ctx, cpu_env);
                        break;
                    case 4:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fldlg2_ST0(tcg_ctx, cpu_env);
                        break;
                    case 5:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fldln2_ST0(tcg_ctx, cpu_env);
                        break;
                    case 6:
                        gen_helper_fpush(tcg_ctx, cpu_env);
                        gen_helper_fldz_ST0(tcg_ctx, cpu_env);
                        break;
                    default:
                        goto illegal_op;
                    }
                }
                break;
            case 0x0e: /* grp d9/6 */
                switch(rm) {
                case 0: /* f2xm1 */
                    gen_helper_f2xm1(tcg_ctx, cpu_env);
                    break;
                case 1: /* fyl2x */
                    gen_helper_fyl2x(tcg_ctx, cpu_env);
                    break;
                case 2: /* fptan */
                    gen_helper_fptan(tcg_ctx, cpu_env);
                    break;
                case 3: /* fpatan */
                    gen_helper_fpatan(tcg_ctx, cpu_env);
                    break;
                case 4: /* fxtract */
                    gen_helper_fxtract(tcg_ctx, cpu_env);
                    break;
                case 5: /* fprem1 */
                    gen_helper_fprem1(tcg_ctx, cpu_env);
                    break;
                case 6: /* fdecstp */
                    gen_helper_fdecstp(tcg_ctx, cpu_env);
                    break;
                default:
                case 7: /* fincstp */
                    gen_helper_fincstp(tcg_ctx, cpu_env);
                    break;
                }
                break;
            case 0x0f: /* grp d9/7 */
                switch(rm) {
                case 0: /* fprem */
                    gen_helper_fprem(tcg_ctx, cpu_env);
                    break;
                case 1: /* fyl2xp1 */
                    gen_helper_fyl2xp1(tcg_ctx, cpu_env);
                    break;
                case 2: /* fsqrt */
                    gen_helper_fsqrt(tcg_ctx, cpu_env);
                    break;
                case 3: /* fsincos */
                    gen_helper_fsincos(tcg_ctx, cpu_env);
                    break;
                case 5: /* fscale */
                    gen_helper_fscale(tcg_ctx, cpu_env);
                    break;
                case 4: /* frndint */
                    gen_helper_frndint(tcg_ctx, cpu_env);
                    break;
                case 6: /* fsin */
                    gen_helper_fsin(tcg_ctx, cpu_env);
                    break;
                default:
                case 7: /* fcos */
                    gen_helper_fcos(tcg_ctx, cpu_env);
                    break;
                }
                break;
            case 0x00: case 0x01: case 0x04: case 0x05: case 0x06: case 0x07: /* fxxx st, sti */
            case 0x20: case 0x21: case 0x24: case 0x25: case 0x26: case 0x27: /* fxxx sti, st */
            case 0x30: case 0x31: case 0x34: case 0x35: case 0x36: case 0x37: /* fxxxp sti, st */
                {
                    int op1;

                    op1 = op & 7;
                    if (op >= 0x20) {
                        gen_helper_fp_arith_STN_ST0(tcg_ctx, op1, opreg);
                        if (op >= 0x30)
                            gen_helper_fpop(tcg_ctx, cpu_env);
                    } else {
                        gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                        gen_helper_fp_arith_ST0_FT0(tcg_ctx, op1);
                    }
                }
                break;
            case 0x02: /* fcom */
            case 0x22: /* fcom2, undocumented op */
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fcom_ST0_FT0(tcg_ctx, cpu_env);
                break;
            case 0x03: /* fcomp */
            case 0x23: /* fcomp3, undocumented op */
            case 0x32: /* fcomp5, undocumented op */
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fcom_ST0_FT0(tcg_ctx, cpu_env);
                gen_helper_fpop(tcg_ctx, cpu_env);
                break;
            case 0x15: /* da/5 */
                switch(rm) {
                case 1: /* fucompp */
                    gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, 1));
                    gen_helper_fucom_ST0_FT0(tcg_ctx, cpu_env);
                    gen_helper_fpop(tcg_ctx, cpu_env);
                    gen_helper_fpop(tcg_ctx, cpu_env);
                    break;
                default:
                    goto illegal_op;
                }
                break;
            case 0x1c:
                switch(rm) {
                case 0: /* feni (287 only, just do nop here) */
                    break;
                case 1: /* fdisi (287 only, just do nop here) */
                    break;
                case 2: /* fclex */
                    gen_helper_fclex(tcg_ctx, cpu_env);
                    break;
                case 3: /* fninit */
                    gen_helper_fninit(tcg_ctx, cpu_env);
                    break;
                case 4: /* fsetpm (287 only, just do nop here) */
                    break;
                default:
                    goto illegal_op;
                }
                break;
            case 0x1d: /* fucomi */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fucomi_ST0_FT0(tcg_ctx, cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x1e: /* fcomi */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fcomi_ST0_FT0(tcg_ctx, cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x28: /* ffree sti */
                gen_helper_ffree_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                break;
            case 0x2a: /* fst sti */
                gen_helper_fmov_STN_ST0(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                break;
            case 0x2b: /* fstp sti */
            case 0x0b: /* fstp1 sti, undocumented op */
            case 0x3a: /* fstp8 sti, undocumented op */
            case 0x3b: /* fstp9 sti, undocumented op */
                gen_helper_fmov_STN_ST0(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fpop(tcg_ctx, cpu_env);
                break;
            case 0x2c: /* fucom st(i) */
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fucom_ST0_FT0(tcg_ctx, cpu_env);
                break;
            case 0x2d: /* fucomp st(i) */
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fucom_ST0_FT0(tcg_ctx, cpu_env);
                gen_helper_fpop(tcg_ctx, cpu_env);
                break;
            case 0x33: /* de/3 */
                switch(rm) {
                case 1: /* fcompp */
                    gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, 1));
                    gen_helper_fcom_ST0_FT0(tcg_ctx, cpu_env);
                    gen_helper_fpop(tcg_ctx, cpu_env);
                    gen_helper_fpop(tcg_ctx, cpu_env);
                    break;
                default:
                    goto illegal_op;
                }
                break;
            case 0x38: /* ffreep sti, undocumented op */
                gen_helper_ffree_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fpop(tcg_ctx, cpu_env);
                break;
            case 0x3c: /* df/4 */
                switch(rm) {
                case 0:
                    gen_helper_fnstsw(tcg_ctx, cpu_tmp2_i32, cpu_env);
                    tcg_gen_extu_i32_tl(tcg_ctx, *cpu_T[0], cpu_tmp2_i32);
                    gen_op_mov_reg_v(tcg_ctx, MO_16, R_EAX, *cpu_T[0]);
                    break;
                default:
                    goto illegal_op;
                }
                break;
            case 0x3d: /* fucomip */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fucomi_ST0_FT0(tcg_ctx, cpu_env);
                gen_helper_fpop(tcg_ctx, cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x3e: /* fcomip */
                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                gen_update_cc_op(s);
                gen_helper_fmov_FT0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                gen_helper_fcomi_ST0_FT0(tcg_ctx, cpu_env);
                gen_helper_fpop(tcg_ctx, cpu_env);
                set_cc_op(s, CC_OP_EFLAGS);
                break;
            case 0x10: case 0x11: case 0x12: case 0x13: /* fcmovxx */
            case 0x18: case 0x19: case 0x1a: case 0x1b:
                {
                    int op1, l1;
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
                    gen_helper_fmov_ST0_STN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, opreg));
                    gen_set_label(tcg_ctx, l1);
                }
                break;
            default:
                goto illegal_op;
            }
        }
        tcg_gen_movi_tl(tcg_ctx, *(TCGv *)tcg_ctx->cpu_tmp0, pc_start - s->cs_base);
        tcg_gen_st_tl(tcg_ctx, *(TCGv *)tcg_ctx->cpu_tmp0, cpu_env, offsetof(CPUX86State, fpip));
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
    case 0x6c: /* insS */   // qq
    case 0x6d:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_ins(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_ins(s, ot);
        }
        break;
    case 0x6e: /* outsS */  // qq
    case 0x6f:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes) | 4);
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            gen_repz_outs(s, ot, pc_start - s->cs_base, s->pc - s->cs_base);
        } else {
            gen_outs(s, ot);
        }
        break;

        /************************/
        /* port I/O */

    case 0xe4:  // in
    case 0xe5:  // out
        ot = mo_b_d32(b, dflag);
        val = cpu_ldub_code(env, s->pc++);
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        tcg_gen_movi_i32(tcg_ctx, cpu_tmp2_i32, val);
        gen_helper_in_func(tcg_ctx, ot, *cpu_T[1], cpu_tmp2_i32);
        gen_op_mov_reg_v(tcg_ctx, ot, R_EAX, *cpu_T[1]);
        break;
    case 0xe6:
    case 0xe7:
        ot = mo_b_d32(b, dflag);
        val = cpu_ldub_code(env, s->pc++);
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], val);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], R_EAX);

        tcg_gen_movi_i32(tcg_ctx, cpu_tmp2_i32, val);
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_T[1]);
        gen_helper_out_func(tcg_ctx, ot, cpu_tmp2_i32, cpu_tmp3_i32);
        break;
    case 0xec:
    case 0xed:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     SVM_IOIO_TYPE_MASK | svm_is_rep(prefixes));
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        gen_helper_in_func(tcg_ctx, ot, *cpu_T[1], cpu_tmp2_i32);
        gen_op_mov_reg_v(tcg_ctx, ot, R_EAX, *cpu_T[1]);
        break;
    case 0xee:
    case 0xef:
        ot = mo_b_d32(b, dflag);
        tcg_gen_ext16u_tl(tcg_ctx, *cpu_T[0], *cpu_regs[R_EDX]);
        gen_check_io(s, ot, pc_start - s->cs_base,
                     svm_is_rep(prefixes));
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[1], R_EAX);

        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp3_i32, *cpu_T[1]);
        gen_helper_out_func(tcg_ctx, ot, cpu_tmp2_i32, cpu_tmp3_i32);
        break;

        /************************/
        /* control */
    case 0xc2: /* ret im */
        val = cpu_ldsw_code(env, s->pc);
        s->pc += 2;
        ot = gen_pop_T0(s);
        gen_stack_update(s, val + (1 << ot));
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(tcg_ctx, *cpu_T[0]);
        gen_eob(s);
        break;
    case 0xc3: /* ret */
        ot = gen_pop_T0(s);
        gen_pop_update(s, ot);
        /* Note that gen_pop_T0 uses a zero-extending load.  */
        gen_op_jmp_v(tcg_ctx, *cpu_T[0]);
        gen_eob(s);
        break;
    case 0xca: /* lret im */
        val = cpu_ldsw_code(env, s->pc);
        s->pc += 2;
    do_lret:
        if (s->pe && !s->vm86) {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_lret_protected(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, dflag - 1),
                                      tcg_const_i32(tcg_ctx, val));
        } else {
            gen_stack_A0(s);
            /* pop offset */
            gen_op_ld_v(s, dflag, *cpu_T[0], cpu_A0);
            /* NOTE: keeping EIP updated is not a problem in case of
               exception */
            gen_op_jmp_v(tcg_ctx, *cpu_T[0]);
            /* pop selector */
            gen_op_addl_A0_im(tcg_ctx, 1 << dflag);
            gen_op_ld_v(s, dflag, *cpu_T[0], cpu_A0);
            gen_op_movl_seg_T0_vm(tcg_ctx, R_CS);
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
            gen_helper_iret_real(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            set_cc_op(s, CC_OP_EFLAGS);
        } else if (s->vm86) {
            if (s->iopl != 3) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_helper_iret_real(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
                set_cc_op(s, CC_OP_EFLAGS);
            }
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_iret_protected(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, dflag - 1),
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
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], next_eip);
            gen_push_v(s, *cpu_T[0]);
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

            tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], selector);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], offset);
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

            tcg_gen_movi_tl(tcg_ctx, *cpu_T[0], selector);
            tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], offset);
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
    //case 0x70 ... 0x7f: /* jcc Jb */
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
        tval = (int8_t)insn_get(env, s, MO_8);
        goto do_jcc;
    //case 0x180 ... 0x18f: /* jcc Jv */
    case 0x180: case 0x181: case 0x182: case 0x183: case 0x184: case 0x185: case 0x186: case 0x187:
    case 0x188: case 0x189: case 0x18a: case 0x18b: case 0x18c: case 0x18d: case 0x18e: case 0x18f:
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
        gen_jcc(s, b, tval, next_eip);
        break;

    //case 0x190 ... 0x19f: /* setcc Gv */
    case 0x190: case 0x191: case 0x192: case 0x193: case 0x194: case 0x195: case 0x196: case 0x197:
    case 0x198: case 0x199: case 0x19a: case 0x19b: case 0x19c: case 0x19d: case 0x19e: case 0x19f:
        modrm = cpu_ldub_code(env, s->pc++);
        gen_setcc1(s, b, *cpu_T[0]);
        gen_ldst_modrm(env, s, modrm, MO_8, OR_TMP0, 1);
        break;
    //case 0x140 ... 0x14f: /* cmov Gv, Ev */
    case 0x140: case 0x141: case 0x142: case 0x143: case 0x144: case 0x145: case 0x146: case 0x147:
    case 0x148: case 0x149: case 0x14a: case 0x14b: case 0x14c: case 0x14d: case 0x14e: case 0x14f:
        if (!(s->cpuid_features & CPUID_CMOV)) {
            goto illegal_op;
        }
        ot = dflag;
        modrm = cpu_ldub_code(env, s->pc++);
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
            gen_helper_read_eflags(tcg_ctx, *cpu_T[0], cpu_env);
            gen_push_v(s, *cpu_T[0]);
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
                    gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
                                            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK |
                                                           IOPL_MASK)));
                } else {
                    gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
                                            tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                           ID_MASK | NT_MASK |
                                                           IF_MASK | IOPL_MASK)
                                                          & 0xffff));
                }
            } else {
                if (s->cpl <= s->iopl) {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
                                                tcg_const_i32(tcg_ctx, (TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)));
                    } else {
                        gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
                                                tcg_const_i32(tcg_ctx, (TF_MASK |
                                                               AC_MASK |
                                                               ID_MASK |
                                                               NT_MASK |
                                                               IF_MASK)
                                                              & 0xffff));
                    }
                } else {
                    if (dflag != MO_16) {
                        gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
                                           tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK |
                                                          ID_MASK | NT_MASK)));
                    } else {
                        gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
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
        gen_op_mov_v_reg(tcg_ctx, MO_8, *cpu_T[0], R_AH);
        gen_compute_eflags(s);
        tcg_gen_andi_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, CC_O);
        tcg_gen_andi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], CC_S | CC_Z | CC_A | CC_P | CC_C);
        tcg_gen_or_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, *cpu_T[0]);
        break;
    case 0x9f: /* lahf */
        if (CODE64(s) && !(s->cpuid_ext3_features & CPUID_EXT3_LAHF_LM))
            goto illegal_op;
        gen_compute_eflags(s);
        /* Note: gen_compute_eflags() only gives the condition codes */
        tcg_gen_ori_tl(tcg_ctx, *cpu_T[0], cpu_cc_src, 0x02);
        gen_op_mov_reg_v(tcg_ctx, MO_8, R_AH, *cpu_T[0]);
        break;
    case 0xf5: /* cmc */
        gen_compute_eflags(s);
        tcg_gen_xori_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, CC_C);
        break;
    case 0xf8: /* clc */
        gen_compute_eflags(s);
        tcg_gen_andi_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, ~CC_C);
        break;
    case 0xf9: /* stc */
        gen_compute_eflags(s);
        tcg_gen_ori_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, CC_C);
        break;
    case 0xfc: /* cld */
        tcg_gen_movi_i32(tcg_ctx, cpu_tmp2_i32, 1);
        tcg_gen_st_i32(tcg_ctx, cpu_tmp2_i32, cpu_env, offsetof(CPUX86State, df));
        break;
    case 0xfd: /* std */
        tcg_gen_movi_i32(tcg_ctx, cpu_tmp2_i32, -1);
        tcg_gen_st_i32(tcg_ctx, cpu_tmp2_i32, cpu_env, offsetof(CPUX86State, df));
        break;

        /************************/
        /* bit operations */
    case 0x1ba: /* bt/bts/btr/btc Gv, im */
        ot = dflag;
        modrm = cpu_ldub_code(env, s->pc++);
        op = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        if (mod != 3) {
            s->rip_offset = 1;
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
        } else {
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
        }
        /* load shift */
        val = cpu_ldub_code(env, s->pc++);
        tcg_gen_movi_tl(tcg_ctx, *cpu_T[1], val);
        if (op < 4)
            goto illegal_op;
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
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;
        mod = (modrm >> 6) & 3;
        rm = (modrm & 7) | REX_B(s);
        gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[1], reg);
        if (mod != 3) {
            gen_lea_modrm(env, s, modrm);
            /* specific case: we need to add a displacement */
            gen_exts(tcg_ctx, ot, *cpu_T[1]);
            tcg_gen_sari_tl(tcg_ctx, cpu_tmp0, *cpu_T[1], 3 + ot);
            tcg_gen_shli_tl(tcg_ctx, cpu_tmp0, cpu_tmp0, ot);
            tcg_gen_add_tl(tcg_ctx, cpu_A0, cpu_A0, cpu_tmp0);
            gen_op_ld_v(s, ot, *cpu_T[0], cpu_A0);
        } else {
            gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
        }
    bt_op:
        tcg_gen_andi_tl(tcg_ctx, *cpu_T[1], *cpu_T[1], (1 << (3 + ot)) - 1);
        tcg_gen_shr_tl(tcg_ctx, cpu_tmp4, *cpu_T[0], *cpu_T[1]);
        switch(op) {
        case 0:
            break;
        case 1:
            tcg_gen_movi_tl(tcg_ctx, cpu_tmp0, 1);
            tcg_gen_shl_tl(tcg_ctx, cpu_tmp0, cpu_tmp0, *cpu_T[1]);
            tcg_gen_or_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_tmp0);
            break;
        case 2:
            tcg_gen_movi_tl(tcg_ctx, cpu_tmp0, 1);
            tcg_gen_shl_tl(tcg_ctx, cpu_tmp0, cpu_tmp0, *cpu_T[1]);
            tcg_gen_andc_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_tmp0);
            break;
        default:
        case 3:
            tcg_gen_movi_tl(tcg_ctx, cpu_tmp0, 1);
            tcg_gen_shl_tl(tcg_ctx, cpu_tmp0, cpu_tmp0, *cpu_T[1]);
            tcg_gen_xor_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], cpu_tmp0);
            break;
        }
        if (op != 0) {
            if (mod != 3) {
                gen_op_st_v(s, ot, *cpu_T[0], cpu_A0);
            } else {
                gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
            }
        }

        /* Delay all CC updates until after the store above.  Note that
           C is the result of the test, Z is unchanged, and the others
           are all undefined.  */
        switch (s->cc_op) {
        case CC_OP_MULB: case CC_OP_MULW: case CC_OP_MULL: case CC_OP_MULQ:	//case CC_OP_MULB ... CC_OP_MULQ:
        case CC_OP_ADDB: case CC_OP_ADDW: case CC_OP_ADDL: case CC_OP_ADDQ:	//case CC_OP_ADDB ... CC_OP_ADDQ:
        case CC_OP_ADCB: case CC_OP_ADCW: case CC_OP_ADCL: case CC_OP_ADCQ:	//case CC_OP_ADCB ... CC_OP_ADCQ:
        case CC_OP_SUBB: case CC_OP_SUBW: case CC_OP_SUBL: case CC_OP_SUBQ:	//case CC_OP_SUBB ... CC_OP_SUBQ:
        case CC_OP_SBBB: case CC_OP_SBBW: case CC_OP_SBBL: case CC_OP_SBBQ: //case CC_OP_SBBB ... CC_OP_SBBQ:
        case CC_OP_LOGICB: case CC_OP_LOGICW: case CC_OP_LOGICL: case CC_OP_LOGICQ: //case CC_OP_LOGICB ... CC_OP_LOGICQ:
        case CC_OP_INCB: case CC_OP_INCW: case CC_OP_INCL: case CC_OP_INCQ: //case CC_OP_INCB ... CC_OP_INCQ:
        case CC_OP_DECB: case CC_OP_DECW: case CC_OP_DECL: case CC_OP_DECQ: //case CC_OP_DECB ... CC_OP_DECQ:
        case CC_OP_SHLB: case CC_OP_SHLW: case CC_OP_SHLL: case CC_OP_SHLQ: //case CC_OP_SHLB ... CC_OP_SHLQ:
        case CC_OP_SARB: case CC_OP_SARW: case CC_OP_SARL: case CC_OP_SARQ: //case CC_OP_SARB ... CC_OP_SARQ:
        case CC_OP_BMILGB: case CC_OP_BMILGW: case CC_OP_BMILGL: case CC_OP_BMILGQ: //case CC_OP_BMILGB ... CC_OP_BMILGQ:
            /* Z was going to be computed from the non-zero status of CC_DST.
               We can get that same Z value (and the new C value) by leaving
               CC_DST alone, setting CC_SRC, and using a CC_OP_SAR of the
               same width.  */
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, cpu_tmp4);
            set_cc_op(s, ((s->cc_op - CC_OP_MULB) & 3) + CC_OP_SARB);
            break;
        default:
            /* Otherwise, generate EFLAGS and replace the C bit.  */
            gen_compute_eflags(s);
            tcg_gen_deposit_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, cpu_tmp4,
                               ctz32(CC_C), 1);
            break;
        }
        break;
    case 0x1bc: /* bsf / tzcnt */
    case 0x1bd: /* bsr / lzcnt */
        ot = dflag;
        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;
        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_extu(tcg_ctx, ot, *cpu_T[0]);

        /* Note that lzcnt and tzcnt are in different extensions.  */
        if ((prefixes & PREFIX_REPZ)
            && (b & 1
                ? s->cpuid_ext3_features & CPUID_EXT3_ABM
                : s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_BMI1)) {
            int size = 8 << ot;
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_src, *cpu_T[0]);
            if (b & 1) {
                /* For lzcnt, reduce the target_ulong result by the
                   number of zeros that we expect to find at the top.  */
                gen_helper_clz(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                tcg_gen_subi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], TARGET_LONG_BITS - size);
            } else {
                /* For tzcnt, a zero input must return the operand size:
                   force all bits outside the operand size to 1.  */
                target_ulong mask = (target_ulong)-2 << (size - 1);
                tcg_gen_ori_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], mask);
                gen_helper_ctz(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            }
            /* For lzcnt/tzcnt, C and Z bits are defined and are
               related to the result.  */
            gen_op_update1_cc(tcg_ctx);
            set_cc_op(s, CC_OP_BMILGB + ot);
        } else {
            /* For bsr/bsf, only the Z bit is defined and it is related
               to the input and not the result.  */
            tcg_gen_mov_tl(tcg_ctx, cpu_cc_dst, *cpu_T[0]);
            set_cc_op(s, CC_OP_LOGICB + ot);
            if (b & 1) {
                /* For bsr, return the bit index of the first 1 bit,
                   not the count of leading zeros.  */
                gen_helper_clz(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                tcg_gen_xori_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], TARGET_LONG_BITS - 1);
            } else {
                gen_helper_ctz(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            }
            /* ??? The manual says that the output is undefined when the
               input is zero, but real hardware leaves it unchanged, and
               real programs appear to depend on that.  */
            tcg_gen_movi_tl(tcg_ctx, cpu_tmp0, 0);
            tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, *cpu_T[0], cpu_cc_dst, cpu_tmp0,
                               *cpu_regs[reg], *cpu_T[0]);
        }
        gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);
        break;
        /************************/
        /* bcd */
    case 0x27: /* daa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_daa(tcg_ctx, cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x2f: /* das */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_das(tcg_ctx, cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x37: /* aaa */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aaa(tcg_ctx, cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x3f: /* aas */
        if (CODE64(s))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_helper_aas(tcg_ctx, cpu_env);
        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0xd4: /* aam */
        if (CODE64(s))
            goto illegal_op;
        val = cpu_ldub_code(env, s->pc++);
        if (val == 0) {
            gen_exception(s, EXCP00_DIVZ, pc_start - s->cs_base);
        } else {
            gen_helper_aam(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, val));
            set_cc_op(s, CC_OP_LOGICB);
        }
        break;
    case 0xd5: /* aad */
        if (CODE64(s))
            goto illegal_op;
        val = cpu_ldub_code(env, s->pc++);
        gen_helper_aad(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, val));
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
            gen_helper_pause(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            s->is_jmp = DISAS_TB_JUMP;
        }
        break;
    case 0x9b: /* fwait */
        if ((s->flags & (HF_MP_MASK | HF_TS_MASK)) ==
            (HF_MP_MASK | HF_TS_MASK)) {
            gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_fwait(tcg_ctx, cpu_env);
        }
        break;
    case 0xcc: /* int3 */
        gen_interrupt(s, EXCP03_INT3, pc_start - s->cs_base, s->pc - s->cs_base);
        break;
    case 0xcd: /* int N */
        val = cpu_ldub_code(env, s->pc++);
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
        gen_helper_into(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        break;
#ifdef WANT_ICEBP
    case 0xf1: /* icebp (undocumented, exits to external debugger) */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_ICEBP);
#if 1
        gen_debug(s, pc_start - s->cs_base);
#else
        /* start debug */
        tb_flush(env);
        qemu_set_log(CPU_LOG_INT | CPU_LOG_TB_IN_ASM);
#endif
        break;
#endif
    case 0xfa: /* cli */
        if (!s->vm86) {
            if (s->cpl <= s->iopl) {
                gen_helper_cli(tcg_ctx, cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        } else {
            if (s->iopl == 3) {
                gen_helper_cli(tcg_ctx, cpu_env);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        }
        break;
    case 0xfb: /* sti */
        if (!s->vm86) {
            if (s->cpl <= s->iopl) {
            gen_sti:
                gen_helper_sti(tcg_ctx, cpu_env);
                /* interruptions are enabled only the first insn after sti */
                /* If several instructions disable interrupts, only the
                   _first_ does it */
                if (!(s->tb->flags & HF_INHIBIT_IRQ_MASK))
                    gen_helper_set_inhibit_irq(tcg_ctx, cpu_env);
                /* give a chance to handle pending irqs */
                gen_jmp_im(s, s->pc - s->cs_base);
                gen_eob(s);
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        } else {
            if (s->iopl == 3) {
                goto gen_sti;
            } else {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            }
        }
        break;
    case 0x62: /* bound */
        if (CODE64(s))
            goto illegal_op;
        ot = dflag;
        modrm = cpu_ldub_code(env, s->pc++);
        reg = (modrm >> 3) & 7;
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], reg);
        gen_lea_modrm(env, s, modrm);
        gen_jmp_im(s, pc_start - s->cs_base);
        tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
        if (ot == MO_16) {
            gen_helper_boundw(tcg_ctx, cpu_env, cpu_A0, cpu_tmp2_i32);
        } else {
            gen_helper_boundl(tcg_ctx, cpu_env, cpu_A0, cpu_tmp2_i32);
        }
        break;
    case 0x1c8: case 0x1c9: case 0x1ca: case 0x1cb:
    case 0x1cc: case 0x1cd: case 0x1ce: case 0x1cf: /* bswap reg */
        reg = (b & 7) | REX_B(s);
#ifdef TARGET_X86_64
        if (dflag == MO_64) {
            gen_op_mov_v_reg(tcg_ctx, MO_64, *cpu_T[0], reg);
            tcg_gen_bswap64_i64(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            gen_op_mov_reg_v(tcg_ctx, MO_64, reg, *cpu_T[0]);
        } else
#endif
        {
            gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], reg);
            tcg_gen_ext32u_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            tcg_gen_bswap32_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
            gen_op_mov_reg_v(tcg_ctx, MO_32, reg, *cpu_T[0]);
        }
        break;
    case 0xd6: /* salc */
        if (CODE64(s))
            goto illegal_op;
        gen_compute_eflags_c(s, *cpu_T[0]);
        tcg_gen_neg_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
        gen_op_mov_reg_v(tcg_ctx, MO_8, R_EAX, *cpu_T[0]);
        break;
    case 0xe0: /* loopnz */
    case 0xe1: /* loopz */
    case 0xe2: /* loop */
    case 0xe3: /* jecxz */
        {
            int l1, l2, l3;

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
                gen_op_add_reg_im(tcg_ctx, s->aflag, R_ECX, -1);
                gen_op_jz_ecx(tcg_ctx, s->aflag, l3);
                gen_jcc1(s, (JCC_Z << 1) | (b ^ 1), l1);
                break;
            case 2: /* loop */
                gen_op_add_reg_im(tcg_ctx, s->aflag, R_ECX, -1);
                gen_op_jnz_ecx(tcg_ctx, s->aflag, l1);
                break;
            default:
            case 3: /* jcxz */
                gen_op_jz_ecx(tcg_ctx, s->aflag, l1);
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
                gen_helper_rdmsr(tcg_ctx, cpu_env);
            } else {
                gen_helper_wrmsr(tcg_ctx, cpu_env);
            }
        }
        break;
    case 0x131: /* rdtsc */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_rdtsc(tcg_ctx, cpu_env);
        break;
    case 0x133: /* rdpmc */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_rdpmc(tcg_ctx, cpu_env);
        break;
    case 0x134: /* sysenter */
        /* For Intel SYSENTER is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;

        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_sysenter(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            gen_eob(s);
        }
        break;
    case 0x135: /* sysexit */
        /* For Intel SYSEXIT is valid on 64-bit */
        if (CODE64(s) && env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1)
            goto illegal_op;
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_sysexit(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            gen_eob(s);
        }
        break;
#ifdef TARGET_X86_64
    case 0x105: /* syscall */
        /* XXX: is it usable in real mode ? */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_syscall(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
        gen_eob(s);
        break;
    case 0x107: /* sysret */
        if (!s->pe) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_sysret(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, dflag - 1));
            /* condition codes are modified only in long mode */
            if (s->lma) {
                set_cc_op(s, CC_OP_EFLAGS);
            }
            gen_eob(s);
        }
        break;
#endif
    case 0x1a2: /* cpuid */
        gen_update_cc_op(s);
        gen_jmp_im(s, pc_start - s->cs_base);
        gen_helper_cpuid(tcg_ctx, cpu_env);
        break;
    case 0xf4: /* hlt */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_hlt(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
            s->is_jmp = DISAS_TB_JUMP;
        }
        break;
    case 0x100:
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* sldt */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_LDTR_READ);
            tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,ldt.selector));
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
                gen_jmp_im(s, pc_start - s->cs_base);
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_lldt(tcg_ctx, cpu_env, cpu_tmp2_i32);
            }
            break;
        case 1: /* str */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_TR_READ);
            tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,tr.selector));
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
                gen_jmp_im(s, pc_start - s->cs_base);
                tcg_gen_trunc_tl_i32(tcg_ctx, cpu_tmp2_i32, *cpu_T[0]);
                gen_helper_ltr(tcg_ctx, cpu_env, cpu_tmp2_i32);
            }
            break;
        case 4: /* verr */
        case 5: /* verw */
            if (!s->pe || s->vm86)
                goto illegal_op;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            gen_update_cc_op(s);
            if (op == 4) {
                gen_helper_verr(tcg_ctx, cpu_env, *cpu_T[0]);
            } else {
                gen_helper_verw(tcg_ctx, cpu_env, *cpu_T[0]);
            }
            set_cc_op(s, CC_OP_EFLAGS);
            break;
        default:
            goto illegal_op;
        }
        break;
    case 0x101:
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        rm = modrm & 7;
        switch(op) {
        case 0: /* sgdt */
            if (mod == 3)
                goto illegal_op;
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_GDTR_READ);
            gen_lea_modrm(env, s, modrm);
            tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, gdt.limit));
            gen_op_st_v(s, MO_16, *cpu_T[0], cpu_A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, gdt.base));
            if (dflag == MO_16) {
                tcg_gen_andi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 0xffffff);
            }
            gen_op_st_v(s, CODE64(s) + MO_32, *cpu_T[0], cpu_A0);
            break;
        case 1:
            if (mod == 3) {
                switch (rm) {
                case 0: /* monitor */
                    if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) ||
                        s->cpl != 0)
                        goto illegal_op;
                    gen_update_cc_op(s);
                    gen_jmp_im(s, pc_start - s->cs_base);
                    tcg_gen_mov_tl(tcg_ctx, cpu_A0, *cpu_regs[R_EAX]);
                    gen_extu(tcg_ctx, s->aflag, cpu_A0);
                    gen_add_A0_ds_seg(s);
                    gen_helper_monitor(tcg_ctx, cpu_env, cpu_A0);
                    break;
                case 1: /* mwait */
                    if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) ||
                        s->cpl != 0)
                        goto illegal_op;
                    gen_update_cc_op(s);
                    gen_jmp_im(s, pc_start - s->cs_base);
                    gen_helper_mwait(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->pc - pc_start));
                    gen_eob(s);
                    break;
                case 2: /* clac */
                    if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP) ||
                        s->cpl != 0) {
                        goto illegal_op;
                    }
                    gen_helper_clac(tcg_ctx, cpu_env);
                    gen_jmp_im(s, s->pc - s->cs_base);
                    gen_eob(s);
                    break;
                case 3: /* stac */
                    if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP) ||
                        s->cpl != 0) {
                        goto illegal_op;
                    }
                    gen_helper_stac(tcg_ctx, cpu_env);
                    gen_jmp_im(s, s->pc - s->cs_base);
                    gen_eob(s);
                    break;
                default:
                    goto illegal_op;
                }
            } else { /* sidt */
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_IDTR_READ);
                gen_lea_modrm(env, s, modrm);
                tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, idt.limit));
                gen_op_st_v(s, MO_16, *cpu_T[0], cpu_A0);
                gen_add_A0_im(s, 2);
                tcg_gen_ld_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, idt.base));
                if (dflag == MO_16) {
                    tcg_gen_andi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 0xffffff);
                }
                gen_op_st_v(s, CODE64(s) + MO_32, *cpu_T[0], cpu_A0);
            }
            break;
        case 2: /* lgdt */
        case 3: /* lidt */
            if (mod == 3) {
                gen_update_cc_op(s);
                gen_jmp_im(s, pc_start - s->cs_base);
                switch(rm) {
                case 0: /* VMRUN */
                    if (!(s->flags & HF_SVME_MASK) || !s->pe)
                        goto illegal_op;
                    if (s->cpl != 0) {
                        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        break;
                    } else {
                        gen_helper_vmrun(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1),
                                         tcg_const_i32(tcg_ctx, s->pc - pc_start));
                        tcg_gen_exit_tb(tcg_ctx, 0);
                        s->is_jmp = DISAS_TB_JUMP;
                    }
                    break;
                case 1: /* VMMCALL */
                    if (!(s->flags & HF_SVME_MASK))
                        goto illegal_op;
                    gen_helper_vmmcall(tcg_ctx, cpu_env);
                    break;
                case 2: /* VMLOAD */
                    if (!(s->flags & HF_SVME_MASK) || !s->pe)
                        goto illegal_op;
                    if (s->cpl != 0) {
                        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        break;
                    } else {
                        gen_helper_vmload(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
                    }
                    break;
                case 3: /* VMSAVE */
                    if (!(s->flags & HF_SVME_MASK) || !s->pe)
                        goto illegal_op;
                    if (s->cpl != 0) {
                        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        break;
                    } else {
                        gen_helper_vmsave(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, s->aflag - 1));
                    }
                    break;
                case 4: /* STGI */
                    if ((!(s->flags & HF_SVME_MASK) &&
                         !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT)) ||
                        !s->pe)
                        goto illegal_op;
                    if (s->cpl != 0) {
                        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        break;
                    } else {
                        gen_helper_stgi(tcg_ctx, cpu_env);
                    }
                    break;
                case 5: /* CLGI */
                    if (!(s->flags & HF_SVME_MASK) || !s->pe)
                        goto illegal_op;
                    if (s->cpl != 0) {
                        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        break;
                    } else {
                        gen_helper_clgi(tcg_ctx, cpu_env);
                    }
                    break;
                case 6: /* SKINIT */
                    if ((!(s->flags & HF_SVME_MASK) &&
                         !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT)) ||
                        !s->pe)
                        goto illegal_op;
                    gen_helper_skinit(tcg_ctx, cpu_env);
                    break;
                case 7: /* INVLPGA */
                    if (!(s->flags & HF_SVME_MASK) || !s->pe)
                        goto illegal_op;
                    if (s->cpl != 0) {
                        gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        break;
                    } else {
                        gen_helper_invlpga(tcg_ctx, cpu_env,
                                           tcg_const_i32(tcg_ctx, s->aflag - 1));
                    }
                    break;
                default:
                    goto illegal_op;
                }
            } else if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start,
                                        op==2 ? SVM_EXIT_GDTR_WRITE : SVM_EXIT_IDTR_WRITE);
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_16, *cpu_T[1], cpu_A0);
                gen_add_A0_im(s, 2);
                gen_op_ld_v(s, CODE64(s) + MO_32, *cpu_T[0], cpu_A0);
                if (dflag == MO_16) {
                    tcg_gen_andi_tl(tcg_ctx, *cpu_T[0], *cpu_T[0], 0xffffff);
                }
                if (op == 2) {
                    tcg_gen_st_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,gdt.base));
                    tcg_gen_st32_tl(tcg_ctx, *cpu_T[1], cpu_env, offsetof(CPUX86State,gdt.limit));
                } else {
                    tcg_gen_st_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,idt.base));
                    tcg_gen_st32_tl(tcg_ctx, *cpu_T[1], cpu_env, offsetof(CPUX86State,idt.limit));
                }
            }
            break;
        case 4: /* smsw */
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_CR0);
#if defined TARGET_X86_64 && defined HOST_WORDS_BIGENDIAN
            tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,cr[0]) + 4);
#else
            tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,cr[0]));
#endif
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 1);
            break;
        case 6: /* lmsw */
            if (s->cpl != 0) {
                gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
                gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
                gen_helper_lmsw(tcg_ctx, cpu_env, *cpu_T[0]);
                gen_jmp_im(s, s->pc - s->cs_base);
                gen_eob(s);
            }
            break;
        case 7:
            if (mod != 3) { /* invlpg */
                if (s->cpl != 0) {
                    gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                } else {
                    gen_update_cc_op(s);
                    gen_jmp_im(s, pc_start - s->cs_base);
                    gen_lea_modrm(env, s, modrm);
                    gen_helper_invlpg(tcg_ctx, cpu_env, cpu_A0);
                    gen_jmp_im(s, s->pc - s->cs_base);
                    gen_eob(s);
                }
            } else {
                switch (rm) {
                case 0: /* swapgs */
#ifdef TARGET_X86_64
                    if (CODE64(s)) {
                        if (s->cpl != 0) {
                            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
                        } else {
                            tcg_gen_ld_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                offsetof(CPUX86State,segs[R_GS].base));
                            tcg_gen_ld_tl(tcg_ctx, *cpu_T[1], cpu_env,
                                offsetof(CPUX86State,kernelgsbase));
                            tcg_gen_st_tl(tcg_ctx, *cpu_T[1], cpu_env,
                                offsetof(CPUX86State,segs[R_GS].base));
                            tcg_gen_st_tl(tcg_ctx, *cpu_T[0], cpu_env,
                                offsetof(CPUX86State,kernelgsbase));
                        }
                    } else
#endif
                    {
                        goto illegal_op;
                    }
                    break;
                case 1: /* rdtscp */
                    if (!(s->cpuid_ext2_features & CPUID_EXT2_RDTSCP))
                        goto illegal_op;
                    gen_update_cc_op(s);
                    gen_jmp_im(s, pc_start - s->cs_base);
                    gen_helper_rdtscp(tcg_ctx, cpu_env);
                    break;
                default:
                    goto illegal_op;
                }
            }
            break;
        default:
            goto illegal_op;
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

            modrm = cpu_ldub_code(env, s->pc++);
            reg = ((modrm >> 3) & 7) | rex_r;
            mod = (modrm >> 6) & 3;
            rm = (modrm & 7) | REX_B(s);

            if (mod == 3) {
                gen_op_mov_v_reg(tcg_ctx, MO_32, *cpu_T[0], rm);
                /* sign extend */
                if (d_ot == MO_64) {
                    tcg_gen_ext32s_tl(tcg_ctx, *cpu_T[0], *cpu_T[0]);
                }
                gen_op_mov_reg_v(tcg_ctx, d_ot, reg, *cpu_T[0]);
            } else {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, MO_32 | MO_SIGN, *cpu_T[0], cpu_A0);
                gen_op_mov_reg_v(tcg_ctx, d_ot, reg, *cpu_T[0]);
            }
        } else
#endif
        {
            int label1;
            TCGv t0, t1, t2, a0;

            if (!s->pe || s->vm86)
                goto illegal_op;
            t0 = tcg_temp_local_new(tcg_ctx);
            t1 = tcg_temp_local_new(tcg_ctx);
            t2 = tcg_temp_local_new(tcg_ctx);
            ot = MO_16;
            modrm = cpu_ldub_code(env, s->pc++);
            reg = (modrm >> 3) & 7;
            mod = (modrm >> 6) & 3;
            rm = modrm & 7;
            if (mod != 3) {
                gen_lea_modrm(env, s, modrm);
                gen_op_ld_v(s, ot, t0, cpu_A0);
                a0 = tcg_temp_local_new(tcg_ctx);
                tcg_gen_mov_tl(tcg_ctx, a0, cpu_A0);
            } else {
                gen_op_mov_v_reg(tcg_ctx, ot, t0, rm);
                TCGV_UNUSED(a0);
            }
            gen_op_mov_v_reg(tcg_ctx, ot, t1, reg);
            tcg_gen_andi_tl(tcg_ctx, cpu_tmp0, t0, 3);
            tcg_gen_andi_tl(tcg_ctx, t1, t1, 3);
            tcg_gen_movi_tl(tcg_ctx, t2, 0);
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GE, cpu_tmp0, t1, label1);
            tcg_gen_andi_tl(tcg_ctx, t0, t0, ~3);
            tcg_gen_or_tl(tcg_ctx, t0, t0, t1);
            tcg_gen_movi_tl(tcg_ctx, t2, CC_Z);
            gen_set_label(tcg_ctx, label1);
            if (mod != 3) {
                gen_op_st_v(s, ot, t0, a0);
                tcg_temp_free(tcg_ctx, a0);
           } else {
                gen_op_mov_reg_v(tcg_ctx, ot, rm, t0);
            }
            gen_compute_eflags(s);
            tcg_gen_andi_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, ~CC_Z);
            tcg_gen_or_tl(tcg_ctx, cpu_cc_src, cpu_cc_src, t2);
            tcg_temp_free(tcg_ctx, t0);
            tcg_temp_free(tcg_ctx, t1);
            tcg_temp_free(tcg_ctx, t2);
        }
        break;
    case 0x102: /* lar */
    case 0x103: /* lsl */
        {
            int label1;
            TCGv t0;
            if (!s->pe || s->vm86)
                goto illegal_op;
            ot = dflag != MO_16 ? MO_32 : MO_16;
            modrm = cpu_ldub_code(env, s->pc++);
            reg = ((modrm >> 3) & 7) | rex_r;
            gen_ldst_modrm(env, s, modrm, MO_16, OR_TMP0, 0);
            t0 = tcg_temp_local_new(tcg_ctx);
            gen_update_cc_op(s);
            if (b == 0x102) {
                gen_helper_lar(tcg_ctx, t0, cpu_env, *cpu_T[0]);
            } else {
                gen_helper_lsl(tcg_ctx, t0, cpu_env, *cpu_T[0]);
            }
            tcg_gen_andi_tl(tcg_ctx, cpu_tmp0, cpu_cc_src, CC_Z);
            label1 = gen_new_label(tcg_ctx);
            tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_tmp0, 0, label1);
            gen_op_mov_reg_v(tcg_ctx, ot, reg, t0);
            gen_set_label(tcg_ctx, label1);
            set_cc_op(s, CC_OP_EFLAGS);
            tcg_temp_free(tcg_ctx, t0);
        }
        break;
    case 0x118:
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* prefetchnta */
        case 1: /* prefetchnt0 */
        case 2: /* prefetchnt0 */
        case 3: /* prefetchnt0 */
            if (mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            /* nothing more to do */
            break;
        default: /* nop (multi byte) */
            gen_nop_modrm(env, s, modrm);
            break;
        }
        break;
    //case 0x119 ... 0x11f: /* nop (multi byte) */
    case 0x119: case 0x11a: case 0x11b: case 0x11c: case 0x11d: case 0x11e: case 0x11f:
        modrm = cpu_ldub_code(env, s->pc++);
        gen_nop_modrm(env, s, modrm);
        break;
    case 0x120: /* mov reg, crN */
    case 0x122: /* mov crN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = cpu_ldub_code(env, s->pc++);
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
                    gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
                    gen_helper_write_crN(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, reg),
                                         *cpu_T[0]);
                    gen_jmp_im(s, s->pc - s->cs_base);
                    gen_eob(s);
                } else {
                    gen_helper_read_crN(tcg_ctx, *cpu_T[0], cpu_env, tcg_const_i32(tcg_ctx, reg));
                    gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
                }
                break;
            default:
                goto illegal_op;
            }
        }
        break;
    case 0x121: /* mov reg, drN */
    case 0x123: /* mov drN, reg */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            modrm = cpu_ldub_code(env, s->pc++);
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
            /* XXX: do it dynamically with CR4.DE bit */
            if (reg == 4 || reg == 5 || reg >= 8)
                goto illegal_op;
            if (b & 2) {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_DR0 + reg);
                gen_op_mov_v_reg(tcg_ctx, ot, *cpu_T[0], rm);
                gen_helper_movl_drN_T0(tcg_ctx, cpu_env, tcg_const_i32(tcg_ctx, reg), *cpu_T[0]);
                gen_jmp_im(s, s->pc - s->cs_base);
                gen_eob(s);
            } else {
                gen_svm_check_intercept(s, pc_start, SVM_EXIT_READ_DR0 + reg);
                tcg_gen_ld_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State,dr[reg]));
                gen_op_mov_reg_v(tcg_ctx, ot, rm, *cpu_T[0]);
            }
        }
        break;
    case 0x106: /* clts */
        if (s->cpl != 0) {
            gen_exception(s, EXCP0D_GPF, pc_start - s->cs_base);
        } else {
            gen_svm_check_intercept(s, pc_start, SVM_EXIT_WRITE_CR0);
            gen_helper_clts(tcg_ctx, cpu_env);
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
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        reg = ((modrm >> 3) & 7) | rex_r;
        /* generate a generic store */
        gen_ldst_modrm(env, s, modrm, ot, reg, 1);
        break;
    case 0x1ae:
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* fxsave */
            if (mod == 3 || !(s->cpuid_features & CPUID_FXSR) ||
                (s->prefix & PREFIX_LOCK))
                goto illegal_op;
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_fxsave(tcg_ctx, cpu_env, cpu_A0, tcg_const_i32(tcg_ctx, dflag == MO_64));
            break;
        case 1: /* fxrstor */
            if (mod == 3 || !(s->cpuid_features & CPUID_FXSR) ||
                (s->prefix & PREFIX_LOCK))
                goto illegal_op;
            if ((s->flags & HF_EM_MASK) || (s->flags & HF_TS_MASK)) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            gen_lea_modrm(env, s, modrm);
            gen_update_cc_op(s);
            gen_jmp_im(s, pc_start - s->cs_base);
            gen_helper_fxrstor(tcg_ctx, cpu_env, cpu_A0, tcg_const_i32(tcg_ctx, dflag == MO_64));
            break;
        case 2: /* ldmxcsr */
        case 3: /* stmxcsr */
            if (s->flags & HF_TS_MASK) {
                gen_exception(s, EXCP07_PREX, pc_start - s->cs_base);
                break;
            }
            if ((s->flags & HF_EM_MASK) || !(s->flags & HF_OSFXSR_MASK) ||
                mod == 3)
                goto illegal_op;
            gen_lea_modrm(env, s, modrm);
            if (op == 2) {
                tcg_gen_qemu_ld_i32(s->uc, cpu_tmp2_i32, cpu_A0,
                                    s->mem_index, MO_LEUL);
                gen_helper_ldmxcsr(tcg_ctx, cpu_env, cpu_tmp2_i32);
            } else {
                tcg_gen_ld32u_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, mxcsr));
                gen_op_st_v(s, MO_32, *cpu_T[0], cpu_A0);
            }
            break;
        case 5: /* lfence */
        case 6: /* mfence */
            if ((modrm & 0xc7) != 0xc0 || !(s->cpuid_features & CPUID_SSE2))
                goto illegal_op;
            break;
        case 7: /* sfence / clflush */
            if ((modrm & 0xc7) == 0xc0) {
                /* sfence */
                /* XXX: also check for cpuid_ext2_features & CPUID_EXT2_EMMX */
                if (!(s->cpuid_features & CPUID_SSE))
                    goto illegal_op;
            } else {
                /* clflush */
                if (!(s->cpuid_features & CPUID_CLFLUSH))
                    goto illegal_op;
                gen_lea_modrm(env, s, modrm);
            }
            break;
        default:
            goto illegal_op;
        }
        break;
    case 0x10d: /* 3DNow! prefetch(w) */
        modrm = cpu_ldub_code(env, s->pc++);
        mod = (modrm >> 6) & 3;
        if (mod == 3)
            goto illegal_op;
        gen_lea_modrm(env, s, modrm);
        /* ignore for now */
        break;
    case 0x1aa: /* rsm */
        gen_svm_check_intercept(s, pc_start, SVM_EXIT_RSM);
        if (!(s->flags & HF_SMM_MASK))
            goto illegal_op;
        gen_update_cc_op(s);
        gen_jmp_im(s, s->pc - s->cs_base);
        gen_helper_rsm(tcg_ctx, cpu_env);
        gen_eob(s);
        break;
    case 0x1b8: /* SSE4.2 popcnt */
        if ((prefixes & (PREFIX_REPZ | PREFIX_LOCK | PREFIX_REPNZ)) !=
             PREFIX_REPZ)
            goto illegal_op;
        if (!(s->cpuid_ext_features & CPUID_EXT_POPCNT))
            goto illegal_op;

        modrm = cpu_ldub_code(env, s->pc++);
        reg = ((modrm >> 3) & 7) | rex_r;

        if (s->prefix & PREFIX_DATA) {
            ot = MO_16;
        } else {
            ot = mo_64_32(dflag);
        }

        gen_ldst_modrm(env, s, modrm, ot, OR_TMP0, 0);
        gen_helper_popcnt(tcg_ctx, *cpu_T[0], cpu_env, *cpu_T[0], tcg_const_i32(tcg_ctx, ot));
        gen_op_mov_reg_v(tcg_ctx, ot, reg, *cpu_T[0]);

        set_cc_op(s, CC_OP_EFLAGS);
        break;
    case 0x10e: case 0x10f:
        /* 3DNow! instructions, ignore prefixes */
        s->prefix &= ~(PREFIX_REPZ | PREFIX_REPNZ | PREFIX_DATA);
    case 0x110: case 0x111: case 0x112: case 0x113: case 0x114: case 0x115: case 0x116: case 0x117: //case 0x110 ... 0x117:
    case 0x128: case 0x129: case 0x12a: case 0x12b: case 0x12c: case 0x12d: case 0x12e: case 0x12f: //case 0x128 ... 0x12f:
    case 0x138: case 0x139: case 0x13a:
    // case 0x150 ... 0x179:
    case 0x150: case 0x151: case 0x152: case 0x153: case 0x154: case 0x155: case 0x156: case 0x157:
    case 0x158: case 0x159: case 0x15a: case 0x15b: case 0x15c: case 0x15d: case 0x15e: case 0x15f:
    case 0x160: case 0x161: case 0x162: case 0x163: case 0x164: case 0x165: case 0x166: case 0x167:
    case 0x168: case 0x169: case 0x16a: case 0x16b: case 0x16c: case 0x16d: case 0x16e: case 0x16f:
    case 0x170: case 0x171: case 0x172: case 0x173: case 0x174: case 0x175: case 0x176: case 0x177:
    case 0x178: case 0x179:
    // case 0x17c ... 0x17f:
    case 0x17c: case 0x17d: case 0x17e: case 0x17f:
    case 0x1c2:
    case 0x1c4: case 0x1c5: case 0x1c6:
    //case 0x1d0 ... 0x1fe:
    case 0x1d0: case 0x1d1: case 0x1d2: case 0x1d3: case 0x1d4: case 0x1d5: case 0x1d6: case 0x1d7:
    case 0x1d8: case 0x1d9: case 0x1da: case 0x1db: case 0x1dc: case 0x1dd: case 0x1de: case 0x1df:
    case 0x1e0: case 0x1e1: case 0x1e2: case 0x1e3: case 0x1e4: case 0x1e5: case 0x1e6: case 0x1e7:
    case 0x1e8: case 0x1e9: case 0x1ea: case 0x1eb: case 0x1ec: case 0x1ed: case 0x1ee: case 0x1ef:
    case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3: case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
    case 0x1f8: case 0x1f9: case 0x1fa: case 0x1fb: case 0x1fc: case 0x1fd: case 0x1fe:
        gen_sse(env, s, b, pc_start, rex_r);
        break;
    default:
        goto illegal_op;
    }
    /* lock generation */
    if (s->prefix & PREFIX_LOCK)
        gen_helper_unlock(tcg_ctx, cpu_env);

    // Unicorn: patch the callback for the instruction size
    if (HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_CODE, pc_start)) {
        // int i;
        // for(i = 0; i < 20; i++)
        //     printf("=== [%u] = %x\n", i, *(save_opparam_ptr + i));
        // printf("\n");
        if (changed_cc_op) {
            if (cc_op_dirty)
#if TCG_TARGET_REG_BITS == 32
                *(save_opparam_ptr + 16) = s->pc - pc_start;
            else
                *(save_opparam_ptr + 14) = s->pc - pc_start;
#else
                *(save_opparam_ptr + 12) = s->pc - pc_start;
            else
                *(save_opparam_ptr + 10) = s->pc - pc_start;
#endif
        } else {
            *(save_opparam_ptr + 1) = s->pc - pc_start;
        }
    }

    return s->pc;
 illegal_op:
    if (s->prefix & PREFIX_LOCK)
        gen_helper_unlock(tcg_ctx, cpu_env);
    /* XXX: ensure that no lock was generated */
    gen_exception(s, EXCP06_ILLOP, pc_start - s->cs_base);
    return s->pc;
}

void optimize_flags_init(struct uc_struct *uc)
{
    static const char reg_names[CPU_NB_REGS][4] = {
#ifdef TARGET_X86_64
        "rax",
        "rcx",
        "rdx",
        "rbx",
        "rsp",
        "rbp",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
#else
        "eax",
        "ecx",
        "edx",
        "ebx",
        "esp",
        "ebp",
        "esi",
        "edi",
#endif
    };
    int i;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    tcg_ctx->cpu_env = tcg_global_reg_new_ptr(uc->tcg_ctx, TCG_AREG0, "env");
    tcg_ctx->cpu_cc_op = tcg_global_mem_new_i32(uc->tcg_ctx, TCG_AREG0,
                                       offsetof(CPUX86State, cc_op), "cc_op");
    tcg_ctx->cpu_cc_dst = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_cc_dst) = tcg_global_mem_new(uc->tcg_ctx, TCG_AREG0,
            offsetof(CPUX86State, cc_dst), "cc_dst");

    tcg_ctx->cpu_cc_src = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_cc_src) = tcg_global_mem_new(uc->tcg_ctx, TCG_AREG0,
            offsetof(CPUX86State, cc_src), "cc_src");

    tcg_ctx->cpu_cc_src2 = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_cc_src2) = tcg_global_mem_new(uc->tcg_ctx, TCG_AREG0,
            offsetof(CPUX86State, cc_src2), "cc_src2");

    for (i = 0; i < CPU_NB_REGS; ++i) {
        tcg_ctx->cpu_regs[i] = g_malloc0(sizeof(TCGv));
        *((TCGv *)tcg_ctx->cpu_regs[i]) = tcg_global_mem_new(uc->tcg_ctx, TCG_AREG0,
                offsetof(CPUX86State, regs[i]),
                reg_names[i]);
    }
}

/* generate intermediate code in gen_opc_buf and gen_opparam_buf for
   basic block 'tb'. If search_pc is TRUE, also generate PC
   information for each intermediate instruction. */
static inline void gen_intermediate_code_internal(uint8_t *gen_opc_cc_op,
                                                  X86CPU *cpu,
                                                  TranslationBlock *tb,
                                                  bool search_pc)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    DisasContext dc1, *dc = &dc1;
    target_ulong pc_ptr;
    uint16_t *gen_opc_end;
    CPUBreakpoint *bp;
    int j;
    int lj = -1;
    uint64_t flags;
    target_ulong pc_start;
    target_ulong cs_base;
    int num_insns = 0;
    int max_insns;
    bool block_full = false;

    /* generate intermediate code */
    pc_start = tb->pc;
    cs_base = tb->cs_base;
    flags = tb->flags;

    dc->uc = env->uc;
    dc->pe = (flags >> HF_PE_SHIFT) & 1;
    dc->code32 = (flags >> HF_CS32_SHIFT) & 1;
    dc->ss32 = (flags >> HF_SS32_SHIFT) & 1;
    dc->addseg = (flags >> HF_ADDSEG_SHIFT) & 1;
    dc->f_st = 0;
    dc->vm86 = (flags >> VM_SHIFT) & 1;
    dc->cpl = (flags >> HF_CPL_SHIFT) & 3;
    dc->iopl = (flags >> IOPL_SHIFT) & 3;
    dc->tf = (flags >> TF_SHIFT) & 1;
    dc->singlestep_enabled = cs->singlestep_enabled;
    dc->last_cc_op = dc->cc_op = CC_OP_DYNAMIC;
    dc->cc_op_dirty = false;
    dc->cs_base = cs_base;
    dc->tb = tb;
    dc->popl_esp_hack = 0;
    /* select memory access functions */
    dc->mem_index = 0;
    if (flags & HF_SOFTMMU_MASK) {
        dc->mem_index = cpu_mmu_index(env);
    }
    dc->cpuid_features = env->features[FEAT_1_EDX];
    dc->cpuid_ext_features = env->features[FEAT_1_ECX];
    dc->cpuid_ext2_features = env->features[FEAT_8000_0001_EDX];
    dc->cpuid_ext3_features = env->features[FEAT_8000_0001_ECX];
    dc->cpuid_7_0_ebx_features = env->features[FEAT_7_0_EBX];
#ifdef TARGET_X86_64
    dc->lma = (flags >> HF_LMA_SHIFT) & 1;
    dc->code64 = (flags >> HF_CS64_SHIFT) & 1;
#endif
    dc->flags = flags;
    dc->jmp_opt = !(dc->tf || cs->singlestep_enabled ||
                    (flags & HF_INHIBIT_IRQ_MASK)
#ifndef CONFIG_SOFTMMU
                    || (flags & HF_SOFTMMU_MASK)
#endif
                    );
#if 0
    /* check addseg logic */
    if (!dc->addseg && (dc->vm86 || !dc->pe || !dc->code32))
        printf("ERROR addseg\n");
#endif

    if (!env->uc->init_tcg)
        tcg_ctx->cpu_T[0] = g_malloc0(sizeof(TCGv));
    *(TCGv *)tcg_ctx->cpu_T[0] = tcg_temp_new(tcg_ctx);

    if (!env->uc->init_tcg)
        tcg_ctx->cpu_T[1] = g_malloc0(sizeof(TCGv));
    *(TCGv *)tcg_ctx->cpu_T[1] = tcg_temp_new(tcg_ctx);

    if (!env->uc->init_tcg)
        tcg_ctx->cpu_A0 = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_A0) = tcg_temp_new(tcg_ctx);

    if (!env->uc->init_tcg)
        tcg_ctx->cpu_tmp0 = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_tmp0) = tcg_temp_new(tcg_ctx);

    if (!env->uc->init_tcg)
        tcg_ctx->cpu_tmp4 = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_tmp4) = tcg_temp_new(tcg_ctx);

    tcg_ctx->cpu_tmp1_i64 = tcg_temp_new_i64(tcg_ctx);
    tcg_ctx->cpu_tmp2_i32 = tcg_temp_new_i32(tcg_ctx);
    tcg_ctx->cpu_tmp3_i32 = tcg_temp_new_i32(tcg_ctx);
    tcg_ctx->cpu_ptr0 = tcg_temp_new_ptr(tcg_ctx);
    tcg_ctx->cpu_ptr1 = tcg_temp_new_ptr(tcg_ctx);

    if (!env->uc->init_tcg)
        tcg_ctx->cpu_cc_srcT = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->cpu_cc_srcT) = tcg_temp_local_new(tcg_ctx);

    // done with initializing TCG variables
    env->uc->init_tcg = true;

    pc_ptr = pc_start;

    // early check to see if the address of this block is the until address
    if (tb->pc == env->uc->addr_end) {
        // imitate the HLT instruction
        gen_tb_start(tcg_ctx);
        gen_jmp_im(dc, tb->pc - tb->cs_base);
        gen_helper_hlt(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, 0));
        dc->is_jmp = DISAS_TB_JUMP;
        goto done_generating;
    }

    gen_opc_end = tcg_ctx->gen_opc_buf + OPC_MAX_SIZE;

    dc->is_jmp = DISAS_NEXT;
    max_insns = tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0)
        max_insns = CF_COUNT_MASK;

    // Unicorn: trace this block on request
    // Only hook this block if the previous block was not truncated due to space
    if (!env->uc->block_full && HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_BLOCK, pc_start)) {
        env->uc->block_addr = pc_start;
        env->uc->size_arg = tcg_ctx->gen_opparam_buf - tcg_ctx->gen_opparam_ptr + 1;
        gen_uc_tracecode(tcg_ctx, 0xf8f8f8f8, UC_HOOK_BLOCK_IDX, env->uc, pc_start);
    } else {
        env->uc->size_arg = -1;
    }

    gen_tb_start(tcg_ctx);
    for(;;) {
        if (unlikely(!QTAILQ_EMPTY(&cs->breakpoints))) {
            QTAILQ_FOREACH(bp, &cs->breakpoints, entry) {
                if (bp->pc == pc_ptr &&
                    !((bp->flags & BP_CPU) && (tb->flags & HF_RF_MASK))) {
                    gen_debug(dc, pc_ptr - dc->cs_base);
                    goto done_generating;
                }
            }
        }
        if (search_pc) {
            j = tcg_ctx->gen_opc_ptr - tcg_ctx->gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j)
                    tcg_ctx->gen_opc_instr_start[lj++] = 0;
            }
            tcg_ctx->gen_opc_pc[lj] = pc_ptr;
            gen_opc_cc_op[lj] = dc->cc_op;
            tcg_ctx->gen_opc_instr_start[lj] = 1;
            // tcg_ctx->gen_opc_icount[lj] = num_insns;
        }
        //if (num_insns + 1 == max_insns && (tb->cflags & CF_LAST_IO))
        //    gen_io_start();

        // Unicorn: save current PC address to sync EIP
        dc->prev_pc = pc_ptr;
        pc_ptr = disas_insn(env, dc, pc_ptr);
        num_insns++;
        /* stop translation if indicated */
        if (dc->is_jmp)
            break;
        /* if single step mode, we generate only one instruction and
           generate an exception */
        /* if irq were inhibited with HF_INHIBIT_IRQ_MASK, we clear
           the flag and abort the translation to give the irqs a
           change to be happen */
        if (dc->tf || dc->singlestep_enabled ||
            (flags & HF_INHIBIT_IRQ_MASK)) {
            gen_jmp_im(dc, pc_ptr - dc->cs_base);
            gen_eob(dc);
            break;
        }
        /* if too long translation, stop generation too */
        if (tcg_ctx->gen_opc_ptr >= gen_opc_end ||
            (pc_ptr - pc_start) >= (TARGET_PAGE_SIZE - 32) ||
            num_insns >= max_insns) {
            gen_jmp_im(dc, pc_ptr - dc->cs_base);
            gen_eob(dc);
            block_full = true;
            break;
        }
        /*
        gen_jmp_im(dc, pc_ptr - dc->cs_base);
        gen_eob(dc);
        block_full = true;
        break;
        */
    }
    //if (tb->cflags & CF_LAST_IO)
    //    gen_io_end();
done_generating:
    gen_tb_end(tcg_ctx, tb, num_insns);
    *tcg_ctx->gen_opc_ptr = INDEX_op_end;
    /* we don't forget to fill the last values */
    if (search_pc) {
        j = tcg_ctx->gen_opc_ptr - tcg_ctx->gen_opc_buf;
        lj++;
        while (lj <= j)
            tcg_ctx->gen_opc_instr_start[lj++] = 0;
    }

    if (!search_pc) {
        tb->size = pc_ptr - pc_start;
    }

    env->uc->block_full = block_full;
}

void gen_intermediate_code(CPUX86State *env, TranslationBlock *tb)
{
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    gen_intermediate_code_internal(tcg_ctx->gen_opc_cc_op,
            x86_env_get_cpu(env), tb, false);
}

void gen_intermediate_code_pc(CPUX86State *env, TranslationBlock *tb)
{
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    gen_intermediate_code_internal(tcg_ctx->gen_opc_cc_op,
            x86_env_get_cpu(env), tb, true);
}

void restore_state_to_opc(CPUX86State *env, TranslationBlock *tb, int pc_pos)
{
    int cc_op;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    env->eip = tcg_ctx->gen_opc_pc[pc_pos] - tb->cs_base;
    cc_op = tcg_ctx->gen_opc_cc_op[pc_pos];
    if (cc_op != CC_OP_DYNAMIC)
        env->cc_op = cc_op;
}
