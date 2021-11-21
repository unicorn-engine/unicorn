/*
 *  m68k translation
 *
 *  Copyright (c) 2005-2007 CodeSourcery
 *  Written by Paul Brook
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
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg-op.h"
#include "exec/cpu_ldst.h"
#include "exec/translator.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "fpu/softfloat.h"


//#define DEBUG_DISPATCH 1

#define DEFO32(name, offset) static TCGv QREG_##name;
#define DEFO64(name, offset) static TCGv_i64 QREG_##name;
#include "qregs.def"
#undef DEFO32
#undef DEFO64

#define REG(insn, pos)  (((insn) >> (pos)) & 7)
#define DREG(insn, pos) tcg_ctx->cpu_dregs[REG(insn, pos)]
#define AREG(insn, pos) get_areg(s, REG(insn, pos))
#define MACREG(acc)     tcg_ctx->cpu_macc[acc]
#define QREG_SP         get_areg(s, 7)

#define IS_NULL_QREG(t) (t == tcg_ctx->NULL_QREG)

#include "exec/gen-icount.h"

void m68k_tcg_init(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    char *p;
    int i;

#define DEFO32(name, offset) \
    QREG_##name = tcg_global_mem_new_i32(tcg_ctx, tcg_ctx->cpu_env, \
        offsetof(CPUM68KState, offset), #name);
#define DEFO64(name, offset) \
    QREG_##name = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env, \
        offsetof(CPUM68KState, offset), #name);
#include "qregs.def"
#undef DEFO32
#undef DEFO64

    tcg_ctx->cpu_halted = tcg_global_mem_new_i32(tcg_ctx, tcg_ctx->cpu_env,
#ifdef _MSC_VER
                                        0 - offsetof(M68kCPU, env) +
#else
                                        -offsetof(M68kCPU, env) +
#endif
                                        offsetof(CPUState, halted), "HALTED");
    tcg_ctx->cpu_exception_index = tcg_global_mem_new_i32(tcg_ctx, tcg_ctx->cpu_env,
#ifdef _MSC_VER
                                                 0 - offsetof(M68kCPU, env) +
#else
                                                 -offsetof(M68kCPU, env) +
#endif
                                                 offsetof(CPUState, exception_index),
                                                 "EXCEPTION");

    p = tcg_ctx->cpu_reg_names;
    for (i = 0; i < 8; i++) {
        sprintf(p, "D%d", i);
        tcg_ctx->cpu_dregs[i] = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
                                          offsetof(CPUM68KState, dregs[i]), p);
        p += 3;
        sprintf(p, "A%d", i);
        tcg_ctx->cpu_aregs[i] = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
                                          offsetof(CPUM68KState, aregs[i]), p);
        p += 3;
    }
    for (i = 0; i < 4; i++) {
        sprintf(p, "ACC%d", i);
        tcg_ctx->cpu_macc[i] = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env,
                                         offsetof(CPUM68KState, macc[i]), p);
        p += 5;
    }

    tcg_ctx->NULL_QREG = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, -4, "NULL");
    tcg_ctx->store_dummy = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, -8, "NULL");
}

/* internal defines */
typedef struct DisasContext {
    DisasContextBase base;
    CPUM68KState *env;
    target_ulong pc;
    CCOp cc_op; /* Current CC operation */
    int cc_op_synced;
    TCGv_i64 mactmp;
    int done_mac;
    int writeback_mask;
    TCGv writeback[8];
#define MAX_TO_RELEASE 8
    int release_count;
    TCGv release[MAX_TO_RELEASE];

    // Unicorn
    struct uc_struct *uc;
} DisasContext;

static void init_release_array(DisasContext *s)
{
#ifdef CONFIG_DEBUG_TCG
    memset(s->release, 0, sizeof(s->release));
#endif
    s->release_count = 0;
}

static void do_release(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int i;
    for (i = 0; i < s->release_count; i++) {
        tcg_temp_free(tcg_ctx, s->release[i]);
    }
    init_release_array(s);
}

static TCGv mark_to_release(DisasContext *s, TCGv tmp)
{
    g_assert(s->release_count < MAX_TO_RELEASE);
    return s->release[s->release_count++] = tmp;
}

static TCGv get_areg(DisasContext *s, unsigned regno)
{
    if (s->writeback_mask & (1 << regno)) {
        return s->writeback[regno];
    } else {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        return tcg_ctx->cpu_aregs[regno];
    }
}

static void delay_set_areg(DisasContext *s, unsigned regno,
                           TCGv val, bool give_temp)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (s->writeback_mask & (1 << regno)) {
        if (give_temp) {
            tcg_temp_free(tcg_ctx, s->writeback[regno]);
            s->writeback[regno] = val;
        } else {
            tcg_gen_mov_i32(tcg_ctx, s->writeback[regno], val);
        }
    } else {
        s->writeback_mask |= 1 << regno;
        if (give_temp) {
            s->writeback[regno] = val;
        } else {
            TCGv tmp = tcg_temp_new(tcg_ctx);
            s->writeback[regno] = tmp;
            tcg_gen_mov_i32(tcg_ctx, tmp, val);
        }
    }
}

static void do_writebacks(DisasContext *s)
{
    unsigned mask = s->writeback_mask;
    if (mask) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        s->writeback_mask = 0;
        do {
            unsigned regno = ctz32(mask);
            tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_aregs[regno], s->writeback[regno]);
            tcg_temp_free(tcg_ctx, s->writeback[regno]);
            mask &= mask - 1;
        } while (mask);
    }
}

/* is_jmp field values */
#define DISAS_JUMP      DISAS_TARGET_0 /* only pc was modified dynamically */
#define DISAS_EXIT      DISAS_TARGET_1 /* cpu state was modified dynamically */

#define IS_USER(s)   (!(s->base.tb->flags & TB_FLAGS_MSR_S))
#define SFC_INDEX(s) ((s->base.tb->flags & TB_FLAGS_SFC_S) ? \
                      MMU_KERNEL_IDX : MMU_USER_IDX)
#define DFC_INDEX(s) ((s->base.tb->flags & TB_FLAGS_DFC_S) ? \
                      MMU_KERNEL_IDX : MMU_USER_IDX)

typedef void (*disas_proc)(CPUM68KState *env, DisasContext *s, uint16_t insn);

#ifdef DEBUG_DISPATCH
#define DISAS_INSN(name)                                                \
    static void real_disas_##name(CPUM68KState *env, DisasContext *s,   \
                                  uint16_t insn);                       \
    static void disas_##name(CPUM68KState *env, DisasContext *s,        \
                             uint16_t insn)                             \
    {                                                                   \
        qemu_log("Dispatch " #name "\n");                               \
        real_disas_##name(env, s, insn);                                \
    }                                                                   \
    static void real_disas_##name(CPUM68KState *env, DisasContext *s,   \
                                  uint16_t insn)
#else
#define DISAS_INSN(name)                                                \
    static void disas_##name(CPUM68KState *env, DisasContext *s,        \
                             uint16_t insn)
#endif

static const uint8_t cc_op_live[CC_OP_NB] = {
    [CC_OP_DYNAMIC] = CCF_C | CCF_V | CCF_Z | CCF_N | CCF_X,
    [CC_OP_FLAGS] = CCF_C | CCF_V | CCF_Z | CCF_N | CCF_X,

    [CC_OP_ADDB] = CCF_X | CCF_N | CCF_V,
    [CC_OP_ADDW] = CCF_X | CCF_N | CCF_V,
    [CC_OP_ADDL] = CCF_X | CCF_N | CCF_V,

    [CC_OP_SUBB] = CCF_X | CCF_N | CCF_V,
    [CC_OP_SUBW] = CCF_X | CCF_N | CCF_V,
    [CC_OP_SUBL] = CCF_X | CCF_N | CCF_V,

    [CC_OP_CMPB] = CCF_X | CCF_N | CCF_V,
    [CC_OP_CMPW] = CCF_X | CCF_N | CCF_V,
    [CC_OP_CMPL] = CCF_X | CCF_N | CCF_V,

    [CC_OP_LOGIC] = CCF_X | CCF_N
};

static void set_cc_op(DisasContext *s, CCOp op)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    CCOp old_op = s->cc_op;
    int dead;

    if (old_op == op) {
        return;
    }
    s->cc_op = op;
    s->cc_op_synced = 0;

    /*
     * Discard CC computation that will no longer be used.
     * Note that X and N are never dead.
     */
    dead = cc_op_live[old_op] & ~cc_op_live[op];
    if (dead & CCF_C) {
        tcg_gen_discard_i32(tcg_ctx, QREG_CC_C);
    }
    if (dead & CCF_Z) {
        tcg_gen_discard_i32(tcg_ctx, QREG_CC_Z);
    }
    if (dead & CCF_V) {
        tcg_gen_discard_i32(tcg_ctx, QREG_CC_V);
    }
}

/* Update the CPU env CC_OP state.  */
static void update_cc_op(DisasContext *s)
{
    if (!s->cc_op_synced) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        s->cc_op_synced = 1;
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_OP, s->cc_op);
    }
}

/* Generate a jump to an immediate address.  */
static void gen_jmp_im(DisasContext *s, uint32_t dest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    update_cc_op(s);
    tcg_gen_movi_i32(tcg_ctx, QREG_PC, dest);
    s->base.is_jmp = DISAS_JUMP;
}

/* Generate a jump to the address in qreg DEST.  */
static void gen_jmp(DisasContext *s, TCGv dest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    update_cc_op(s);
    tcg_gen_mov_i32(tcg_ctx, QREG_PC, dest);
    s->base.is_jmp = DISAS_JUMP;
}

static void gen_raise_exception(TCGContext *tcg_ctx, int nr)
{
    TCGv_i32 tmp;

    tmp = tcg_const_i32(tcg_ctx, nr);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, tmp);
    tcg_temp_free_i32(tcg_ctx, tmp);
}

static void gen_exception(DisasContext *s, uint32_t dest, int nr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    update_cc_op(s);
    tcg_gen_movi_i32(tcg_ctx, QREG_PC, dest);

    gen_raise_exception(tcg_ctx, nr);

    s->base.is_jmp = DISAS_NORETURN;
}

static inline void gen_addr_fault(DisasContext *s)
{
    gen_exception(s, s->base.pc_next, EXCP_ADDRESS);
}

/*
 * Generate a load from the specified address.  Narrow values are
 *  sign extended to full register width.
 */
static inline TCGv gen_load(DisasContext *s, int opsize, TCGv addr,
                            int sign, int index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;
    tmp = tcg_temp_new_i32(tcg_ctx);
    switch(opsize) {
    case OS_BYTE:
        if (sign)
            tcg_gen_qemu_ld8s(tcg_ctx, tmp, addr, index);
        else
            tcg_gen_qemu_ld8u(tcg_ctx, tmp, addr, index);
        break;
    case OS_WORD:
        if (sign)
            tcg_gen_qemu_ld16s(tcg_ctx, tmp, addr, index);
        else
            tcg_gen_qemu_ld16u(tcg_ctx, tmp, addr, index);
        break;
    case OS_LONG:
        tcg_gen_qemu_ld32u(tcg_ctx, tmp, addr, index);
        break;
    default:
        g_assert_not_reached();
    }
    return tmp;
}

/* Generate a store.  */
static inline void gen_store(DisasContext *s, int opsize, TCGv addr, TCGv val,
                             int index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    switch(opsize) {
    case OS_BYTE:
        tcg_gen_qemu_st8(tcg_ctx, val, addr, index);
        break;
    case OS_WORD:
        tcg_gen_qemu_st16(tcg_ctx, val, addr, index);
        break;
    case OS_LONG:
        tcg_gen_qemu_st32(tcg_ctx, val, addr, index);
        break;
    default:
        g_assert_not_reached();
    }
}

typedef enum {
    EA_STORE,
    EA_LOADU,
    EA_LOADS
} ea_what;

/*
 * Generate an unsigned load if VAL is 0 a signed load if val is -1,
 * otherwise generate a store.
 */
static TCGv gen_ldst(DisasContext *s, int opsize, TCGv addr, TCGv val,
                     ea_what what, int index)
{
    if (what == EA_STORE) {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        gen_store(s, opsize, addr, val, index);
        return tcg_ctx->store_dummy;
    } else {
        return mark_to_release(s, gen_load(s, opsize, addr,
                                           what == EA_LOADS, index));
    }
}

/* Read a 16-bit immediate constant */
static inline uint16_t read_im16(CPUM68KState *env, DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t im;
    im = translator_lduw(tcg_ctx, env, s->pc);
    s->pc += 2;
    return im;
}

/* Read an 8-bit immediate constant */
static inline uint8_t read_im8(CPUM68KState *env, DisasContext *s)
{
    return read_im16(env, s);
}

/* Read a 32-bit immediate constant.  */
static inline uint32_t read_im32(CPUM68KState *env, DisasContext *s)
{
    uint32_t im;
    im = read_im16(env, s) << 16;
    im |= 0xffff & read_im16(env, s);
    return im;
}

/* Read a 64-bit immediate constant.  */
static inline uint64_t read_im64(CPUM68KState *env, DisasContext *s)
{
    uint64_t im;
    im = (uint64_t)read_im32(env, s) << 32;
    im |= (uint64_t)read_im32(env, s);
    return im;
}

/* Calculate and address index.  */
static TCGv gen_addr_index(DisasContext *s, uint16_t ext, TCGv tmp)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv add;
    int scale;

    add = (ext & 0x8000) ? AREG(ext, 12) : DREG(ext, 12);
    if ((ext & 0x800) == 0) {
        tcg_gen_ext16s_i32(tcg_ctx, tmp, add);
        add = tmp;
    }
    scale = (ext >> 9) & 3;
    if (scale != 0) {
        tcg_gen_shli_i32(tcg_ctx, tmp, add, scale);
        add = tmp;
    }
    return add;
}

/*
 * Handle a base + index + displacement effective addresss.
 * A NULL_QREG base means pc-relative.
 */
static TCGv gen_lea_indexed(CPUM68KState *env, DisasContext *s, TCGv base)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint32_t offset;
    uint16_t ext;
    TCGv add;
    TCGv tmp;
    uint32_t bd, od;

    offset = s->pc;
    ext = read_im16(env, s);

    if ((ext & 0x800) == 0 && !m68k_feature(s->env, M68K_FEATURE_WORD_INDEX))
        return tcg_ctx->NULL_QREG;

    if (m68k_feature(s->env, M68K_FEATURE_M68000) &&
        !m68k_feature(s->env, M68K_FEATURE_SCALED_INDEX)) {
        ext &= ~(3 << 9);
    }

    if (ext & 0x100) {
        /* full extension word format */
        if (!m68k_feature(s->env, M68K_FEATURE_EXT_FULL))
            return tcg_ctx->NULL_QREG;

        if ((ext & 0x30) > 0x10) {
            /* base displacement */
            if ((ext & 0x30) == 0x20) {
                bd = (int16_t)read_im16(env, s);
            } else {
                bd = read_im32(env, s);
            }
        } else {
            bd = 0;
        }
        tmp = mark_to_release(s, tcg_temp_new(tcg_ctx));
        if ((ext & 0x44) == 0) {
            /* pre-index */
            add = gen_addr_index(s, ext, tmp);
        } else {
            add = tcg_ctx->NULL_QREG;
        }
        if ((ext & 0x80) == 0) {
            /* base not suppressed */
            if (IS_NULL_QREG(base)) {
                base = mark_to_release(s, tcg_const_i32(tcg_ctx, offset + bd));
                bd = 0;
            }
            if (!IS_NULL_QREG(add)) {
                tcg_gen_add_i32(tcg_ctx, tmp, add, base);
                add = tmp;
            } else {
                add = base;
            }
        }
        if (!IS_NULL_QREG(add)) {
            if (bd != 0) {
                tcg_gen_addi_i32(tcg_ctx, tmp, add, bd);
                add = tmp;
            }
        } else {
            add = mark_to_release(s, tcg_const_i32(tcg_ctx, bd));
        }
        if ((ext & 3) != 0) {
            /* memory indirect */
            base = mark_to_release(s, gen_load(s, OS_LONG, add, 0, IS_USER(s)));
            if ((ext & 0x44) == 4) {
                add = gen_addr_index(s, ext, tmp);
                tcg_gen_add_i32(tcg_ctx, tmp, add, base);
                add = tmp;
            } else {
                add = base;
            }
            if ((ext & 3) > 1) {
                /* outer displacement */
                if ((ext & 3) == 2) {
                    od = (int16_t)read_im16(env, s);
                } else {
                    od = read_im32(env, s);
                }
            } else {
                od = 0;
            }
            if (od != 0) {
                tcg_gen_addi_i32(tcg_ctx, tmp, add, od);
                add = tmp;
            }
        }
    } else {
        /* brief extension word format */
        tmp = mark_to_release(s, tcg_temp_new(tcg_ctx));
        add = gen_addr_index(s, ext, tmp);
        if (!IS_NULL_QREG(base)) {
            tcg_gen_add_i32(tcg_ctx, tmp, add, base);
            if ((int8_t)ext)
                tcg_gen_addi_i32(tcg_ctx, tmp, tmp, (int8_t)ext);
        } else {
            tcg_gen_addi_i32(tcg_ctx, tmp, add, offset + (int8_t)ext);
        }
        add = tmp;
    }
    return add;
}

/* Sign or zero extend a value.  */

static inline void gen_ext(TCGContext *tcg_ctx, TCGv res, TCGv val, int opsize, int sign)
{
    switch (opsize) {
    case OS_BYTE:
        if (sign) {
            tcg_gen_ext8s_i32(tcg_ctx, res, val);
        } else {
            tcg_gen_ext8u_i32(tcg_ctx, res, val);
        }
        break;
    case OS_WORD:
        if (sign) {
            tcg_gen_ext16s_i32(tcg_ctx, res, val);
        } else {
            tcg_gen_ext16u_i32(tcg_ctx, res, val);
        }
        break;
    case OS_LONG:
        tcg_gen_mov_i32(tcg_ctx, res, val);
        break;
    default:
        g_assert_not_reached();
    }
}

/* Evaluate all the CC flags.  */

static void gen_flush_flags(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv t0, t1;

    switch (s->cc_op) {
    case CC_OP_FLAGS:
        return;

    case CC_OP_ADDB:
    case CC_OP_ADDW:
    case CC_OP_ADDL:
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, QREG_CC_X);
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);
        /* Compute signed overflow for addition.  */
        t0 = tcg_temp_new(tcg_ctx);
        t1 = tcg_temp_new(tcg_ctx);
        tcg_gen_sub_i32(tcg_ctx, t0, QREG_CC_N, QREG_CC_V);
        gen_ext(tcg_ctx, t0, t0, s->cc_op - CC_OP_ADDB, 1);
        tcg_gen_xor_i32(tcg_ctx, t1, QREG_CC_N, QREG_CC_V);
        tcg_gen_xor_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, t0);
        tcg_temp_free(tcg_ctx, t0);
        tcg_gen_andc_i32(tcg_ctx, QREG_CC_V, t1, QREG_CC_V);
        tcg_temp_free(tcg_ctx, t1);
        break;

    case CC_OP_SUBB:
    case CC_OP_SUBW:
    case CC_OP_SUBL:
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, QREG_CC_X);
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);
        /* Compute signed overflow for subtraction.  */
        t0 = tcg_temp_new(tcg_ctx);
        t1 = tcg_temp_new(tcg_ctx);
        tcg_gen_add_i32(tcg_ctx, t0, QREG_CC_N, QREG_CC_V);
        gen_ext(tcg_ctx, t0, t0, s->cc_op - CC_OP_SUBB, 1);
        tcg_gen_xor_i32(tcg_ctx, t1, QREG_CC_N, t0);
        tcg_gen_xor_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, t0);
        tcg_temp_free(tcg_ctx, t0);
        tcg_gen_and_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, t1);
        tcg_temp_free(tcg_ctx, t1);
        break;

    case CC_OP_CMPB:
    case CC_OP_CMPW:
    case CC_OP_CMPL:
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_C, QREG_CC_N, QREG_CC_V);
        tcg_gen_sub_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N, QREG_CC_V);
        gen_ext(tcg_ctx, QREG_CC_Z, QREG_CC_Z, s->cc_op - CC_OP_CMPB, 1);
        /* Compute signed overflow for subtraction.  */
        t0 = tcg_temp_new(tcg_ctx);
        tcg_gen_xor_i32(tcg_ctx, t0, QREG_CC_Z, QREG_CC_N);
        tcg_gen_xor_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, QREG_CC_N);
        tcg_gen_and_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, t0);
        tcg_temp_free(tcg_ctx, t0);
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_N, QREG_CC_Z);
        break;

    case CC_OP_LOGIC:
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_C, 0);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0);
        break;

    case CC_OP_DYNAMIC:
        gen_helper_flush_flags(tcg_ctx, tcg_ctx->cpu_env, QREG_CC_OP);
        s->cc_op_synced = 1;
        break;

    default:
        t0 = tcg_const_i32(tcg_ctx, s->cc_op);
        gen_helper_flush_flags(tcg_ctx, tcg_ctx->cpu_env, t0);
        tcg_temp_free(tcg_ctx, t0);
        s->cc_op_synced = 1;
        break;
    }

    /* Note that flush_flags also assigned to env->cc_op.  */
    s->cc_op = CC_OP_FLAGS;
}

static inline TCGv gen_extend(DisasContext *s, TCGv val, int opsize, int sign)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    if (opsize == OS_LONG) {
        tmp = val;
    } else {
        tmp = mark_to_release(s, tcg_temp_new(tcg_ctx));
        gen_ext(tcg_ctx, tmp, val, opsize, sign);
    }

    return tmp;
}

static void gen_logic_cc(DisasContext *s, TCGv val, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_ext(tcg_ctx, QREG_CC_N, val, opsize, 1);
    set_cc_op(s, CC_OP_LOGIC);
}

static void gen_update_cc_cmp(DisasContext *s, TCGv dest, TCGv src, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_N, dest);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_V, src);
    set_cc_op(s, CC_OP_CMPB + opsize);
}

static void gen_update_cc_add(TCGContext *tcg_ctx, TCGv dest, TCGv src, int opsize)
{
    gen_ext(tcg_ctx, QREG_CC_N, dest, opsize, 1);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_V, src);
}

static inline int opsize_bytes(int opsize)
{
    switch (opsize) {
    case OS_BYTE: return 1;
    case OS_WORD: return 2;
    case OS_LONG: return 4;
    case OS_SINGLE: return 4;
    case OS_DOUBLE: return 8;
    case OS_EXTENDED: return 12;
    case OS_PACKED: return 12;
    default:
        // g_assert_not_reached();
        return 0;
    }
}

static inline int insn_opsize(int insn)
{
    switch ((insn >> 6) & 3) {
    case 0: return OS_BYTE;
    case 1: return OS_WORD;
    case 2: return OS_LONG;
    default:
        // g_assert_not_reached();
        return 0;
    }
}

static inline int ext_opsize(int ext, int pos)
{
    switch ((ext >> pos) & 7) {
    case 0: return OS_LONG;
    case 1: return OS_SINGLE;
    case 2: return OS_EXTENDED;
    case 3: return OS_PACKED;
    case 4: return OS_WORD;
    case 5: return OS_DOUBLE;
    case 6: return OS_BYTE;
    default:
        // g_assert_not_reached();
        return 0;
    }
}

/*
 * Assign value to a register.  If the width is less than the register width
 * only the low part of the register is set.
 */
static void gen_partset_reg(TCGContext *tcg_ctx, int opsize, TCGv reg, TCGv val)
{
    TCGv tmp;
    switch (opsize) {
    case OS_BYTE:
        tcg_gen_andi_i32(tcg_ctx, reg, reg, 0xffffff00);
        tmp = tcg_temp_new(tcg_ctx);
        tcg_gen_ext8u_i32(tcg_ctx, tmp, val);
        tcg_gen_or_i32(tcg_ctx, reg, reg, tmp);
        tcg_temp_free(tcg_ctx, tmp);
        break;
    case OS_WORD:
        tcg_gen_andi_i32(tcg_ctx, reg, reg, 0xffff0000);
        tmp = tcg_temp_new(tcg_ctx);
        tcg_gen_ext16u_i32(tcg_ctx, tmp, val);
        tcg_gen_or_i32(tcg_ctx, reg, reg, tmp);
        tcg_temp_free(tcg_ctx, tmp);
        break;
    case OS_LONG:
    case OS_SINGLE:
        tcg_gen_mov_i32(tcg_ctx, reg, val);
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * Generate code for an "effective address".  Does not adjust the base
 * register for autoincrement addressing modes.
 */
static TCGv gen_lea_mode(CPUM68KState *env, DisasContext *s,
                         int mode, int reg0, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv tmp;
    uint16_t ext;
    uint32_t offset;

    switch (mode) {
    case 0: /* Data register direct.  */
    case 1: /* Address register direct.  */
        return tcg_ctx->NULL_QREG;
    case 3: /* Indirect postincrement.  */
        if (opsize == OS_UNSIZED) {
            return tcg_ctx->NULL_QREG;
        }
        /* fallthru */
    case 2: /* Indirect register */
        return get_areg(s, reg0);
    case 4: /* Indirect predecrememnt.  */
        if (opsize == OS_UNSIZED) {
            return tcg_ctx->NULL_QREG;
        }
        reg = get_areg(s, reg0);
        tmp = mark_to_release(s, tcg_temp_new(tcg_ctx));
        if (reg0 == 7 && opsize == OS_BYTE &&
            m68k_feature(s->env, M68K_FEATURE_M68000)) {
            tcg_gen_subi_i32(tcg_ctx, tmp, reg, 2);
        } else {
            tcg_gen_subi_i32(tcg_ctx, tmp, reg, opsize_bytes(opsize));
        }
        return tmp;
    case 5: /* Indirect displacement.  */
        reg = get_areg(s, reg0);
        tmp = mark_to_release(s, tcg_temp_new(tcg_ctx));
        ext = read_im16(env, s);
        tcg_gen_addi_i32(tcg_ctx, tmp, reg, (int16_t)ext);
        return tmp;
    case 6: /* Indirect index + displacement.  */
        reg = get_areg(s, reg0);
        return gen_lea_indexed(env, s, reg);
    case 7: /* Other */
        switch (reg0) {
        case 0: /* Absolute short.  */
            offset = (int16_t)read_im16(env, s);
            return mark_to_release(s, tcg_const_i32(tcg_ctx, offset));
        case 1: /* Absolute long.  */
            offset = read_im32(env, s);
            return mark_to_release(s, tcg_const_i32(tcg_ctx, offset));
        case 2: /* pc displacement  */
            offset = s->pc;
            offset += (int16_t)read_im16(env, s);
            return mark_to_release(s, tcg_const_i32(tcg_ctx, offset));
        case 3: /* pc index+displacement.  */
            return gen_lea_indexed(env, s, tcg_ctx->NULL_QREG);
        case 4: /* Immediate.  */
        default:
            return tcg_ctx->NULL_QREG;
        }
    }
    /* Should never happen.  */
    return tcg_ctx->NULL_QREG;
}

static TCGv gen_lea(CPUM68KState *env, DisasContext *s, uint16_t insn,
                    int opsize)
{
    int mode = extract32(insn, 3, 3);
    int reg0 = REG(insn, 0);
    return gen_lea_mode(env, s, mode, reg0, opsize);
}

/*
 * Generate code to load/store a value from/into an EA.  If WHAT > 0 this is
 * a write otherwise it is a read (0 == sign extend, -1 == zero extend).
 * ADDRP is non-null for readwrite operands.
 */
static TCGv gen_ea_mode(CPUM68KState *env, DisasContext *s, int mode, int reg0,
                        int opsize, TCGv val, TCGv *addrp, ea_what what,
                        int index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg, tmp, result;
    int32_t offset;

    switch (mode) {
    case 0: /* Data register direct.  */
        reg = tcg_ctx->cpu_dregs[reg0];
        if (what == EA_STORE) {
            gen_partset_reg(tcg_ctx, opsize, reg, val);
            return tcg_ctx->store_dummy;
        } else {
            return gen_extend(s, reg, opsize, what == EA_LOADS);
        }
    case 1: /* Address register direct.  */
        reg = get_areg(s, reg0);
        if (what == EA_STORE) {
            tcg_gen_mov_i32(tcg_ctx, reg, val);
            return tcg_ctx->store_dummy;
        } else {
            return gen_extend(s, reg, opsize, what == EA_LOADS);
        }
    case 2: /* Indirect register */
        reg = get_areg(s, reg0);
        return gen_ldst(s, opsize, reg, val, what, index);
    case 3: /* Indirect postincrement.  */
        reg = get_areg(s, reg0);
        result = gen_ldst(s, opsize, reg, val, what, index);
        if (what == EA_STORE || !addrp) {
            TCGv tmp = tcg_temp_new(tcg_ctx);
            if (reg0 == 7 && opsize == OS_BYTE &&
                m68k_feature(s->env, M68K_FEATURE_M68000)) {
                tcg_gen_addi_i32(tcg_ctx, tmp, reg, 2);
            } else {
                tcg_gen_addi_i32(tcg_ctx, tmp, reg, opsize_bytes(opsize));
            }
            delay_set_areg(s, reg0, tmp, true);
        }
        return result;
    case 4: /* Indirect predecrememnt.  */
        if (addrp && what == EA_STORE) {
            tmp = *addrp;
        } else {
            tmp = gen_lea_mode(env, s, mode, reg0, opsize);
            if (IS_NULL_QREG(tmp)) {
                return tmp;
            }
            if (addrp) {
                *addrp = tmp;
            }
        }
        result = gen_ldst(s, opsize, tmp, val, what, index);
        if (what == EA_STORE || !addrp) {
            delay_set_areg(s, reg0, tmp, false);
        }
        return result;
    case 5: /* Indirect displacement.  */
    case 6: /* Indirect index + displacement.  */
    do_indirect:
        if (addrp && what == EA_STORE) {
            tmp = *addrp;
        } else {
            tmp = gen_lea_mode(env, s, mode, reg0, opsize);
            if (IS_NULL_QREG(tmp)) {
                return tmp;
            }
            if (addrp) {
                *addrp = tmp;
            }
        }
        return gen_ldst(s, opsize, tmp, val, what, index);
    case 7: /* Other */
        switch (reg0) {
        case 0: /* Absolute short.  */
        case 1: /* Absolute long.  */
        case 2: /* pc displacement  */
        case 3: /* pc index+displacement.  */
            goto do_indirect;
        case 4: /* Immediate.  */
            /* Sign extend values for consistency.  */
            switch (opsize) {
            case OS_BYTE:
                if (what == EA_LOADS) {
                    offset = (int8_t)read_im8(env, s);
                } else {
                    offset = read_im8(env, s);
                }
                break;
            case OS_WORD:
                if (what == EA_LOADS) {
                    offset = (int16_t)read_im16(env, s);
                } else {
                    offset = read_im16(env, s);
                }
                break;
            case OS_LONG:
                offset = read_im32(env, s);
                break;
            default:
                g_assert_not_reached();
            }
            return mark_to_release(s, tcg_const_i32(tcg_ctx, offset));
        default:
            return tcg_ctx->NULL_QREG;
        }
    }
    /* Should never happen.  */
    return tcg_ctx->NULL_QREG;
}

static TCGv gen_ea(CPUM68KState *env, DisasContext *s, uint16_t insn,
                   int opsize, TCGv val, TCGv *addrp, ea_what what, int index)
{
    int mode = extract32(insn, 3, 3);
    int reg0 = REG(insn, 0);
    return gen_ea_mode(env, s, mode, reg0, opsize, val, addrp, what, index);
}

static TCGv_ptr gen_fp_ptr(TCGContext *tcg_ctx, int freg)
{
    TCGv_ptr fp = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, fp, tcg_ctx->cpu_env, offsetof(CPUM68KState, fregs[freg]));
    return fp;
}

static TCGv_ptr gen_fp_result_ptr(TCGContext *tcg_ctx)
{
    TCGv_ptr fp = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, fp, tcg_ctx->cpu_env, offsetof(CPUM68KState, fp_result));
    return fp;
}

static void gen_fp_move(TCGContext *tcg_ctx, TCGv_ptr dest, TCGv_ptr src)
{
    TCGv t32;
    TCGv_i64 t64;

    t32 = tcg_temp_new(tcg_ctx);
    tcg_gen_ld16u_i32(tcg_ctx, t32, src, offsetof(FPReg, l.upper));
    tcg_gen_st16_i32(tcg_ctx, t32, dest, offsetof(FPReg, l.upper));
    tcg_temp_free(tcg_ctx, t32);

    t64 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_ld_i64(tcg_ctx, t64, src, offsetof(FPReg, l.lower));
    tcg_gen_st_i64(tcg_ctx, t64, dest, offsetof(FPReg, l.lower));
    tcg_temp_free_i64(tcg_ctx, t64);
}

static void gen_load_fp(DisasContext *s, int opsize, TCGv addr, TCGv_ptr fp,
                        int index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;
    TCGv_i64 t64;

    t64 = tcg_temp_new_i64(tcg_ctx);
    tmp = tcg_temp_new(tcg_ctx);
    switch (opsize) {
    case OS_BYTE:
        tcg_gen_qemu_ld8s(tcg_ctx, tmp, addr, index);
        gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
        break;
    case OS_WORD:
        tcg_gen_qemu_ld16s(tcg_ctx, tmp, addr, index);
        gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
        break;
    case OS_LONG:
        tcg_gen_qemu_ld32u(tcg_ctx, tmp, addr, index);
        gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
        break;
    case OS_SINGLE:
        tcg_gen_qemu_ld32u(tcg_ctx, tmp, addr, index);
        gen_helper_extf32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
        break;
    case OS_DOUBLE:
        tcg_gen_qemu_ld64(tcg_ctx, t64, addr, index);
        gen_helper_extf64(tcg_ctx, tcg_ctx->cpu_env, fp, t64);
        break;
    case OS_EXTENDED:
        if (m68k_feature(s->env, M68K_FEATURE_CF_FPU)) {
            gen_exception(s, s->base.pc_next, EXCP_FP_UNIMP);
            break;
        }
        tcg_gen_qemu_ld32u(tcg_ctx, tmp, addr, index);
        tcg_gen_shri_i32(tcg_ctx, tmp, tmp, 16);
        tcg_gen_st16_i32(tcg_ctx, tmp, fp, offsetof(FPReg, l.upper));
        tcg_gen_addi_i32(tcg_ctx, tmp, addr, 4);
        tcg_gen_qemu_ld64(tcg_ctx, t64, tmp, index);
        tcg_gen_st_i64(tcg_ctx, t64, fp, offsetof(FPReg, l.lower));
        break;
    case OS_PACKED:
        /*
         * unimplemented data type on 68040/ColdFire
         * FIXME if needed for another FPU
         */
        gen_exception(s, s->base.pc_next, EXCP_FP_UNIMP);
        break;
    default:
        g_assert_not_reached();
    }
    tcg_temp_free(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, t64);
}

static void gen_store_fp(DisasContext *s, int opsize, TCGv addr, TCGv_ptr fp,
                         int index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;
    TCGv_i64 t64;

    t64 = tcg_temp_new_i64(tcg_ctx);
    tmp = tcg_temp_new(tcg_ctx);
    switch (opsize) {
    case OS_BYTE:
        gen_helper_reds32(tcg_ctx, tmp, tcg_ctx->cpu_env, fp);
        tcg_gen_qemu_st8(tcg_ctx, tmp, addr, index);
        break;
    case OS_WORD:
        gen_helper_reds32(tcg_ctx, tmp, tcg_ctx->cpu_env, fp);
        tcg_gen_qemu_st16(tcg_ctx, tmp, addr, index);
        break;
    case OS_LONG:
        gen_helper_reds32(tcg_ctx, tmp, tcg_ctx->cpu_env, fp);
        tcg_gen_qemu_st32(tcg_ctx, tmp, addr, index);
        break;
    case OS_SINGLE:
        gen_helper_redf32(tcg_ctx, tmp, tcg_ctx->cpu_env, fp);
        tcg_gen_qemu_st32(tcg_ctx, tmp, addr, index);
        break;
    case OS_DOUBLE:
        gen_helper_redf64(tcg_ctx, t64, tcg_ctx->cpu_env, fp);
        tcg_gen_qemu_st64(tcg_ctx, t64, addr, index);
        break;
    case OS_EXTENDED:
        if (m68k_feature(s->env, M68K_FEATURE_CF_FPU)) {
            gen_exception(s, s->base.pc_next, EXCP_FP_UNIMP);
            break;
        }
        tcg_gen_ld16u_i32(tcg_ctx, tmp, fp, offsetof(FPReg, l.upper));
        tcg_gen_shli_i32(tcg_ctx, tmp, tmp, 16);
        tcg_gen_qemu_st32(tcg_ctx, tmp, addr, index);
        tcg_gen_addi_i32(tcg_ctx, tmp, addr, 4);
        tcg_gen_ld_i64(tcg_ctx, t64, fp, offsetof(FPReg, l.lower));
        tcg_gen_qemu_st64(tcg_ctx, t64, tmp, index);
        break;
    case OS_PACKED:
        /*
         * unimplemented data type on 68040/ColdFire
         * FIXME if needed for another FPU
         */
        gen_exception(s, s->base.pc_next, EXCP_FP_UNIMP);
        break;
    default:
        g_assert_not_reached();
    }
    tcg_temp_free(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, t64);
}

static void gen_ldst_fp(DisasContext *s, int opsize, TCGv addr,
                        TCGv_ptr fp, ea_what what, int index)
{
    if (what == EA_STORE) {
        gen_store_fp(s, opsize, addr, fp, index);
    } else {
        gen_load_fp(s, opsize, addr, fp, index);
    }
}

static int gen_ea_mode_fp(CPUM68KState *env, DisasContext *s, int mode,
                          int reg0, int opsize, TCGv_ptr fp, ea_what what,
                          int index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg, addr, tmp;
    TCGv_i64 t64;

    switch (mode) {
    case 0: /* Data register direct.  */
        reg = tcg_ctx->cpu_dregs[reg0];
        if (what == EA_STORE) {
            switch (opsize) {
            case OS_BYTE:
            case OS_WORD:
            case OS_LONG:
                gen_helper_reds32(tcg_ctx, reg, tcg_ctx->cpu_env, fp);
                break;
            case OS_SINGLE:
                gen_helper_redf32(tcg_ctx, reg, tcg_ctx->cpu_env, fp);
                break;
            default:
                g_assert_not_reached();
            }
        } else {
            tmp = tcg_temp_new(tcg_ctx);
            switch (opsize) {
            case OS_BYTE:
                tcg_gen_ext8s_i32(tcg_ctx, tmp, reg);
                gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
                break;
            case OS_WORD:
                tcg_gen_ext16s_i32(tcg_ctx, tmp, reg);
                gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
                break;
            case OS_LONG:
                gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, reg);
                break;
            case OS_SINGLE:
                gen_helper_extf32(tcg_ctx, tcg_ctx->cpu_env, fp, reg);
                break;
            default:
                g_assert_not_reached();
            }
            tcg_temp_free(tcg_ctx, tmp);
        }
        return 0;
    case 1: /* Address register direct.  */
        return -1;
    case 2: /* Indirect register */
        addr = get_areg(s, reg0);
        gen_ldst_fp(s, opsize, addr, fp, what, index);
        return 0;
    case 3: /* Indirect postincrement.  */
        addr = tcg_ctx->cpu_aregs[reg0];
        gen_ldst_fp(s, opsize, addr, fp, what, index);
        tcg_gen_addi_i32(tcg_ctx, addr, addr, opsize_bytes(opsize));
        return 0;
    case 4: /* Indirect predecrememnt.  */
        addr = gen_lea_mode(env, s, mode, reg0, opsize);
        if (IS_NULL_QREG(addr)) {
            return -1;
        }
        gen_ldst_fp(s, opsize, addr, fp, what, index);
        tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_aregs[reg0], addr);
        return 0;
    case 5: /* Indirect displacement.  */
    case 6: /* Indirect index + displacement.  */
    do_indirect:
        addr = gen_lea_mode(env, s, mode, reg0, opsize);
        if (IS_NULL_QREG(addr)) {
            return -1;
        }
        gen_ldst_fp(s, opsize, addr, fp, what, index);
        return 0;
    case 7: /* Other */
        switch (reg0) {
        case 0: /* Absolute short.  */
        case 1: /* Absolute long.  */
        case 2: /* pc displacement  */
        case 3: /* pc index+displacement.  */
            goto do_indirect;
        case 4: /* Immediate.  */
            if (what == EA_STORE) {
                return -1;
            }
            switch (opsize) {
            case OS_BYTE:
                tmp = tcg_const_i32(tcg_ctx, (int8_t)read_im8(env, s));
                gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
                tcg_temp_free(tcg_ctx, tmp);
                break;
            case OS_WORD:
                tmp = tcg_const_i32(tcg_ctx, (int16_t)read_im16(env, s));
                gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
                tcg_temp_free(tcg_ctx, tmp);
                break;
            case OS_LONG:
                tmp = tcg_const_i32(tcg_ctx, read_im32(env, s));
                gen_helper_exts32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
                tcg_temp_free(tcg_ctx, tmp);
                break;
            case OS_SINGLE:
                tmp = tcg_const_i32(tcg_ctx, read_im32(env, s));
                gen_helper_extf32(tcg_ctx, tcg_ctx->cpu_env, fp, tmp);
                tcg_temp_free(tcg_ctx, tmp);
                break;
            case OS_DOUBLE:
                t64 = tcg_const_i64(tcg_ctx, read_im64(env, s));
                gen_helper_extf64(tcg_ctx, tcg_ctx->cpu_env, fp, t64);
                tcg_temp_free_i64(tcg_ctx, t64);
                break;
            case OS_EXTENDED:
                if (m68k_feature(s->env, M68K_FEATURE_CF_FPU)) {
                    gen_exception(s, s->base.pc_next, EXCP_FP_UNIMP);
                    break;
                }
                tmp = tcg_const_i32(tcg_ctx, read_im32(env, s) >> 16);
                tcg_gen_st16_i32(tcg_ctx, tmp, fp, offsetof(FPReg, l.upper));
                tcg_temp_free(tcg_ctx, tmp);
                t64 = tcg_const_i64(tcg_ctx, read_im64(env, s));
                tcg_gen_st_i64(tcg_ctx, t64, fp, offsetof(FPReg, l.lower));
                tcg_temp_free_i64(tcg_ctx, t64);
                break;
            case OS_PACKED:
                /*
                 * unimplemented data type on 68040/ColdFire
                 * FIXME if needed for another FPU
                 */
                gen_exception(s, s->base.pc_next, EXCP_FP_UNIMP);
                break;
            default:
                g_assert_not_reached();
            }
            return 0;
        default:
            return -1;
        }
    }
    return -1;
}

static int gen_ea_fp(CPUM68KState *env, DisasContext *s, uint16_t insn,
                       int opsize, TCGv_ptr fp, ea_what what, int index)
{
    int mode = extract32(insn, 3, 3);
    int reg0 = REG(insn, 0);
    return gen_ea_mode_fp(env, s, mode, reg0, opsize, fp, what, index);
}

typedef struct {
    TCGCond tcond;
    bool g1;
    bool g2;
    TCGv v1;
    TCGv v2;
} DisasCompare;

static void gen_cc_cond(DisasCompare *c, DisasContext *s, int cond)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp, tmp2;
    TCGCond tcond;
    CCOp op = s->cc_op;

    /* The CC_OP_CMP form can handle most normal comparisons directly.  */
    if (op == CC_OP_CMPB || op == CC_OP_CMPW || op == CC_OP_CMPL) {
        c->g1 = c->g2 = 1;
        c->v1 = QREG_CC_N;
        c->v2 = QREG_CC_V;
        switch (cond) {
        case 2: /* HI */
        case 3: /* LS */
            tcond = TCG_COND_LEU;
            goto done;
        case 4: /* CC */
        case 5: /* CS */
            tcond = TCG_COND_LTU;
            goto done;
        case 6: /* NE */
        case 7: /* EQ */
            tcond = TCG_COND_EQ;
            goto done;
        case 10: /* PL */
        case 11: /* MI */
            c->g1 = c->g2 = 0;
            c->v2 = tcg_const_i32(tcg_ctx, 0);
            c->v1 = tmp = tcg_temp_new(tcg_ctx);
            tcg_gen_sub_i32(tcg_ctx, tmp, QREG_CC_N, QREG_CC_V);
            gen_ext(tcg_ctx, tmp, tmp, op - CC_OP_CMPB, 1);
            /* fallthru */
        case 12: /* GE */
        case 13: /* LT */
            tcond = TCG_COND_LT;
            goto done;
        case 14: /* GT */
        case 15: /* LE */
            tcond = TCG_COND_LE;
            goto done;
        }
    }

    c->g1 = 1;
    c->g2 = 0;
    c->v2 = tcg_const_i32(tcg_ctx, 0);

    switch (cond) {
    case 0: /* T */
    case 1: /* F */
        c->v1 = c->v2;
        tcond = TCG_COND_NEVER;
        goto done;
    case 14: /* GT (!(Z || (N ^ V))) */
    case 15: /* LE (Z || (N ^ V)) */
        /*
         * Logic operations clear V, which simplifies LE to (Z || N),
         * and since Z and N are co-located, this becomes a normal
         * comparison vs N.
         */
        if (op == CC_OP_LOGIC) {
            c->v1 = QREG_CC_N;
            tcond = TCG_COND_LE;
            goto done;
        }
        break;
    case 12: /* GE (!(N ^ V)) */
    case 13: /* LT (N ^ V) */
        /* Logic operations clear V, which simplifies this to N.  */
        if (op != CC_OP_LOGIC) {
            break;
        }
        /* fallthru */
    case 10: /* PL (!N) */
    case 11: /* MI (N) */
        /* Several cases represent N normally.  */
        if (op == CC_OP_ADDB || op == CC_OP_ADDW || op == CC_OP_ADDL ||
            op == CC_OP_SUBB || op == CC_OP_SUBW || op == CC_OP_SUBL ||
            op == CC_OP_LOGIC) {
            c->v1 = QREG_CC_N;
            tcond = TCG_COND_LT;
            goto done;
        }
        break;
    case 6: /* NE (!Z) */
    case 7: /* EQ (Z) */
        /* Some cases fold Z into N.  */
        if (op == CC_OP_ADDB || op == CC_OP_ADDW || op == CC_OP_ADDL ||
            op == CC_OP_SUBB || op == CC_OP_SUBW || op == CC_OP_SUBL ||
            op == CC_OP_LOGIC) {
            tcond = TCG_COND_EQ;
            c->v1 = QREG_CC_N;
            goto done;
        }
        break;
    case 4: /* CC (!C) */
    case 5: /* CS (C) */
        /* Some cases fold C into X.  */
        if (op == CC_OP_ADDB || op == CC_OP_ADDW || op == CC_OP_ADDL ||
            op == CC_OP_SUBB || op == CC_OP_SUBW || op == CC_OP_SUBL) {
            tcond = TCG_COND_NE;
            c->v1 = QREG_CC_X;
            goto done;
        }
        /* fallthru */
    case 8: /* VC (!V) */
    case 9: /* VS (V) */
        /* Logic operations clear V and C.  */
        if (op == CC_OP_LOGIC) {
            tcond = TCG_COND_NEVER;
            c->v1 = c->v2;
            goto done;
        }
        break;
    }

    /* Otherwise, flush flag state to CC_OP_FLAGS.  */
    gen_flush_flags(s);

    switch (cond) {
    case 0: /* T */
    case 1: /* F */
    default:
        /* Invalid, or handled above.  */
        abort();
    case 2: /* HI (!C && !Z) -> !(C || Z)*/
    case 3: /* LS (C || Z) */
        c->v1 = tmp = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_EQ, tmp, QREG_CC_Z, c->v2);
        tcg_gen_or_i32(tcg_ctx, tmp, tmp, QREG_CC_C);
        tcond = TCG_COND_NE;
        break;
    case 4: /* CC (!C) */
    case 5: /* CS (C) */
        c->v1 = QREG_CC_C;
        tcond = TCG_COND_NE;
        break;
    case 6: /* NE (!Z) */
    case 7: /* EQ (Z) */
        c->v1 = QREG_CC_Z;
        tcond = TCG_COND_EQ;
        break;
    case 8: /* VC (!V) */
    case 9: /* VS (V) */
        c->v1 = QREG_CC_V;
        tcond = TCG_COND_LT;
        break;
    case 10: /* PL (!N) */
    case 11: /* MI (N) */
        c->v1 = QREG_CC_N;
        tcond = TCG_COND_LT;
        break;
    case 12: /* GE (!(N ^ V)) */
    case 13: /* LT (N ^ V) */
        c->v1 = tmp = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_xor_i32(tcg_ctx, tmp, QREG_CC_N, QREG_CC_V);
        tcond = TCG_COND_LT;
        break;
    case 14: /* GT (!(Z || (N ^ V))) */
    case 15: /* LE (Z || (N ^ V)) */
        c->v1 = tmp = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_EQ, tmp, QREG_CC_Z, c->v2);
        tcg_gen_neg_i32(tcg_ctx, tmp, tmp);
        tmp2 = tcg_temp_new(tcg_ctx);
        tcg_gen_xor_i32(tcg_ctx, tmp2, QREG_CC_N, QREG_CC_V);
        tcg_gen_or_i32(tcg_ctx, tmp, tmp, tmp2);
        tcg_temp_free(tcg_ctx, tmp2);
        tcond = TCG_COND_LT;
        break;
    }

 done:
    if ((cond & 1) == 0) {
        tcond = tcg_invert_cond(tcond);
    }
    c->tcond = tcond;
}

static void free_cond(TCGContext *tcg_ctx, DisasCompare *c)
{
    if (!c->g1) {
        tcg_temp_free(tcg_ctx, c->v1);
    }
    if (!c->g2) {
        tcg_temp_free(tcg_ctx, c->v2);
    }
}

static void gen_jmpcc(DisasContext *s, int cond, TCGLabel *l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    DisasCompare c;

    gen_cc_cond(&c, s, cond);
    update_cc_op(s);
    tcg_gen_brcond_i32(tcg_ctx, c.tcond, c.v1, c.v2, l1);
    free_cond(tcg_ctx, &c);
}

/* Force a TB lookup after an instruction that changes the CPU state.  */
static void gen_exit_tb(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    update_cc_op(s);
    tcg_gen_movi_i32(tcg_ctx, QREG_PC, s->pc);
    s->base.is_jmp = DISAS_EXIT;
}

#define SRC_EA(env, result, opsize, op_sign, addrp) do {                \
        result = gen_ea(env, s, insn, opsize, tcg_ctx->NULL_QREG, addrp,         \
                        op_sign ? EA_LOADS : EA_LOADU, IS_USER(s));     \
        if (IS_NULL_QREG(result)) {                                     \
            gen_addr_fault(s);                                          \
            return;                                                     \
        }                                                               \
    } while (0)

#define DEST_EA(env, insn, opsize, val, addrp) do {                     \
        TCGv ea_result = gen_ea(env, s, insn, opsize, val, addrp,       \
                                EA_STORE, IS_USER(s));                  \
        if (IS_NULL_QREG(ea_result)) {                                  \
            gen_addr_fault(s);                                          \
            return;                                                     \
        }                                                               \
    } while (0)

static inline bool use_goto_tb(DisasContext *s, uint32_t dest)
{
    return (s->base.pc_first & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK)
        || (s->base.pc_next & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK);
}

/* Generate a jump to an immediate address.  */
static void gen_jmp_tb(DisasContext *s, int n, uint32_t dest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (unlikely(s->base.singlestep_enabled)) {
        gen_exception(s, dest, EXCP_DEBUG);
    } else if (use_goto_tb(s, dest)) {
        tcg_gen_goto_tb(tcg_ctx, n);
        tcg_gen_movi_i32(tcg_ctx, QREG_PC, dest);
        tcg_gen_exit_tb(tcg_ctx, s->base.tb, n);
    } else {
        gen_jmp_im(s, dest);
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    }
    s->base.is_jmp = DISAS_NORETURN;
}

DISAS_INSN(scc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    DisasCompare c;
    int cond;
    TCGv tmp;

    cond = (insn >> 8) & 0xf;
    gen_cc_cond(&c, s, cond);

    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_setcond_i32(tcg_ctx, c.tcond, tmp, c.v1, c.v2);
    free_cond(tcg_ctx, &c);

    tcg_gen_neg_i32(tcg_ctx, tmp, tmp);
    DEST_EA(env, insn, OS_BYTE, tmp, NULL);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(dbcc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGLabel *l1;
    TCGv reg;
    TCGv tmp;
    int16_t offset;
    uint32_t base;

    reg = DREG(insn, 0);
    base = s->pc;
    offset = (int16_t)read_im16(env, s);
    l1 = gen_new_label(tcg_ctx);
    gen_jmpcc(s, (insn >> 8) & 0xf, l1);

    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_ext16s_i32(tcg_ctx, tmp, reg);
    tcg_gen_addi_i32(tcg_ctx, tmp, tmp, -1);
    gen_partset_reg(tcg_ctx, OS_WORD, reg, tmp);
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_EQ, tmp, -1, l1);
    gen_jmp_tb(s, 1, base + offset);
    gen_set_label(tcg_ctx, l1);
    gen_jmp_tb(s, 0, s->pc);
}

DISAS_INSN(undef_mac)
{
    gen_exception(s, s->base.pc_next, EXCP_LINEA);
}

DISAS_INSN(undef_fpu)
{
    gen_exception(s, s->base.pc_next, EXCP_LINEF);
}

DISAS_INSN(undef)
{
    /*
     * ??? This is both instructions that are as yet unimplemented
     * for the 680x0 series, as well as those that are implemented
     * but actually illegal for CPU32 or pre-68020.
     */
    //qemu_log_mask(LOG_UNIMP, "Illegal instruction: %04x @ %08x\n",
    //              insn, s->base.pc_next);
    gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
}

DISAS_INSN(mulw)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv tmp;
    TCGv src;
    int sign;

    sign = (insn & 0x100) != 0;
    reg = DREG(insn, 9);
    tmp = tcg_temp_new(tcg_ctx);
    if (sign)
        tcg_gen_ext16s_i32(tcg_ctx, tmp, reg);
    else
        tcg_gen_ext16u_i32(tcg_ctx, tmp, reg);
    SRC_EA(env, src, OS_WORD, sign, NULL);
    tcg_gen_mul_i32(tcg_ctx, tmp, tmp, src);
    tcg_gen_mov_i32(tcg_ctx, reg, tmp);
    gen_logic_cc(s, tmp, OS_LONG);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(divw)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int sign;
    TCGv src;
    TCGv destr;

    /* divX.w <EA>,Dn    32/16 -> 16r:16q */

    sign = (insn & 0x100) != 0;

    /* dest.l / src.w */

    SRC_EA(env, src, OS_WORD, sign, NULL);
    destr = tcg_const_i32(tcg_ctx, REG(insn, 9));
    if (sign) {
        gen_helper_divsw(tcg_ctx, tcg_ctx->cpu_env, destr, src);
    } else {
        gen_helper_divuw(tcg_ctx, tcg_ctx->cpu_env, destr, src);
    }
    tcg_temp_free(tcg_ctx, destr);

    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(divl)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv num, reg, den;
    int sign;
    uint16_t ext;

    ext = read_im16(env, s);

    sign = (ext & 0x0800) != 0;

    if (ext & 0x400) {
        if (!m68k_feature(s->env, M68K_FEATURE_QUAD_MULDIV)) {
            gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
            return;
        }

        /* divX.l <EA>, Dr:Dq    64/32 -> 32r:32q */

        SRC_EA(env, den, OS_LONG, 0, NULL);
        num = tcg_const_i32(tcg_ctx, REG(ext, 12));
        reg = tcg_const_i32(tcg_ctx, REG(ext, 0));
        if (sign) {
            gen_helper_divsll(tcg_ctx, tcg_ctx->cpu_env, num, reg, den);
        } else {
            gen_helper_divull(tcg_ctx, tcg_ctx->cpu_env, num, reg, den);
        }
        tcg_temp_free(tcg_ctx, reg);
        tcg_temp_free(tcg_ctx, num);
        set_cc_op(s, CC_OP_FLAGS);
        return;
    }

    /* divX.l <EA>, Dq        32/32 -> 32q     */
    /* divXl.l <EA>, Dr:Dq    32/32 -> 32r:32q */

    SRC_EA(env, den, OS_LONG, 0, NULL);
    num = tcg_const_i32(tcg_ctx, REG(ext, 12));
    reg = tcg_const_i32(tcg_ctx, REG(ext, 0));
    if (sign) {
        gen_helper_divsl(tcg_ctx, tcg_ctx->cpu_env, num, reg, den);
    } else {
        gen_helper_divul(tcg_ctx, tcg_ctx->cpu_env, num, reg, den);
    }
    tcg_temp_free(tcg_ctx, reg);
    tcg_temp_free(tcg_ctx, num);

    set_cc_op(s, CC_OP_FLAGS);
}

static void bcd_add(TCGContext *tcg_ctx, TCGv dest, TCGv src)
{
    TCGv t0, t1;

    /*
     * dest10 = dest10 + src10 + X
     *
     *        t1 = src
     *        t2 = t1 + 0x066
     *        t3 = t2 + dest + X
     *        t4 = t2 ^ dest
     *        t5 = t3 ^ t4
     *        t6 = ~t5 & 0x110
     *        t7 = (t6 >> 2) | (t6 >> 3)
     *        return t3 - t7
     */

    /*
     * t1 = (src + 0x066) + dest + X
     *    = result with some possible exceding 0x6
     */

    t0 = tcg_const_i32(tcg_ctx, 0x066);
    tcg_gen_add_i32(tcg_ctx, t0, t0, src);

    t1 = tcg_temp_new(tcg_ctx);
    tcg_gen_add_i32(tcg_ctx, t1, t0, dest);
    tcg_gen_add_i32(tcg_ctx, t1, t1, QREG_CC_X);

    /* we will remove exceding 0x6 where there is no carry */

    /*
     * t0 = (src + 0x0066) ^ dest
     *    = t1 without carries
     */

    tcg_gen_xor_i32(tcg_ctx, t0, t0, dest);

    /*
     * extract the carries
     * t0 = t0 ^ t1
     *    = only the carries
     */

    tcg_gen_xor_i32(tcg_ctx, t0, t0, t1);

    /*
     * generate 0x1 where there is no carry
     * and for each 0x10, generate a 0x6
     */

    tcg_gen_shri_i32(tcg_ctx, t0, t0, 3);
    tcg_gen_not_i32(tcg_ctx, t0, t0);
    tcg_gen_andi_i32(tcg_ctx, t0, t0, 0x22);
    tcg_gen_add_i32(tcg_ctx, dest, t0, t0);
    tcg_gen_add_i32(tcg_ctx, dest, dest, t0);
    tcg_temp_free(tcg_ctx, t0);

    /*
     * remove the exceding 0x6
     * for digits that have not generated a carry
     */

    tcg_gen_sub_i32(tcg_ctx, dest, t1, dest);
    tcg_temp_free(tcg_ctx, t1);
}

static void bcd_sub(TCGContext *tcg_ctx, TCGv dest, TCGv src)
{
    TCGv t0, t1, t2;

    /*
     *  dest10 = dest10 - src10 - X
     *         = bcd_add(tcg_ctx, dest + 1 - X, 0x199 - src)
     */

    /* t0 = 0x066 + (0x199 - src) */

    t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_subfi_i32(tcg_ctx, t0, 0x1ff, src);

    /* t1 = t0 + dest + 1 - X*/

    t1 = tcg_temp_new(tcg_ctx);
    tcg_gen_add_i32(tcg_ctx, t1, t0, dest);
    tcg_gen_addi_i32(tcg_ctx, t1, t1, 1);
    tcg_gen_sub_i32(tcg_ctx, t1, t1, QREG_CC_X);

    /* t2 = t0 ^ dest */

    t2 = tcg_temp_new(tcg_ctx);
    tcg_gen_xor_i32(tcg_ctx, t2, t0, dest);

    /* t0 = t1 ^ t2 */

    tcg_gen_xor_i32(tcg_ctx, t0, t1, t2);

    /*
     * t2 = ~t0 & 0x110
     * t0 = (t2 >> 2) | (t2 >> 3)
     *
     * to fit on 8bit operands, changed in:
     *
     * t2 = ~(t0 >> 3) & 0x22
     * t0 = t2 + t2
     * t0 = t0 + t2
     */

    tcg_gen_shri_i32(tcg_ctx, t2, t0, 3);
    tcg_gen_not_i32(tcg_ctx, t2, t2);
    tcg_gen_andi_i32(tcg_ctx, t2, t2, 0x22);
    tcg_gen_add_i32(tcg_ctx, t0, t2, t2);
    tcg_gen_add_i32(tcg_ctx, t0, t0, t2);
    tcg_temp_free(tcg_ctx, t2);

    /* return t1 - t0 */

    tcg_gen_sub_i32(tcg_ctx, dest, t1, t0);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
}

static void bcd_flags(TCGContext *tcg_ctx, TCGv val)
{
    tcg_gen_andi_i32(tcg_ctx, QREG_CC_C, val, 0x0ff);
    tcg_gen_or_i32(tcg_ctx, QREG_CC_Z, QREG_CC_Z, QREG_CC_C);

    tcg_gen_extract_i32(tcg_ctx, QREG_CC_C, val, 8, 1);

    tcg_gen_mov_i32(tcg_ctx, QREG_CC_X, QREG_CC_C);
}

DISAS_INSN(abcd_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv dest;

    gen_flush_flags(s); /* !Z is sticky */

    src = gen_extend(s, DREG(insn, 0), OS_BYTE, 0);
    dest = gen_extend(s, DREG(insn, 9), OS_BYTE, 0);
    bcd_add(tcg_ctx, dest, src);
    gen_partset_reg(tcg_ctx, OS_BYTE, DREG(insn, 9), dest);

    bcd_flags(tcg_ctx, dest);
}

DISAS_INSN(abcd_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src, dest, addr;

    gen_flush_flags(s); /* !Z is sticky */

    /* Indirect pre-decrement load (mode 4) */

    src = gen_ea_mode(env, s, 4, REG(insn, 0), OS_BYTE,
                      tcg_ctx->NULL_QREG, NULL, EA_LOADU, IS_USER(s));
    dest = gen_ea_mode(env, s, 4, REG(insn, 9), OS_BYTE,
                       tcg_ctx->NULL_QREG, &addr, EA_LOADU, IS_USER(s));

    bcd_add(tcg_ctx, dest, src);

    gen_ea_mode(env, s, 4, REG(insn, 9), OS_BYTE, dest, &addr,
                EA_STORE, IS_USER(s));

    bcd_flags(tcg_ctx, dest);
}

DISAS_INSN(sbcd_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src, dest;

    gen_flush_flags(s); /* !Z is sticky */

    src = gen_extend(s, DREG(insn, 0), OS_BYTE, 0);
    dest = gen_extend(s, DREG(insn, 9), OS_BYTE, 0);

    bcd_sub(tcg_ctx, dest, src);

    gen_partset_reg(tcg_ctx, OS_BYTE, DREG(insn, 9), dest);

    bcd_flags(tcg_ctx, dest);
}

DISAS_INSN(sbcd_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src, dest, addr;

    gen_flush_flags(s); /* !Z is sticky */

    /* Indirect pre-decrement load (mode 4) */

    src = gen_ea_mode(env, s, 4, REG(insn, 0), OS_BYTE,
                      tcg_ctx->NULL_QREG, NULL, EA_LOADU, IS_USER(s));
    dest = gen_ea_mode(env, s, 4, REG(insn, 9), OS_BYTE,
                       tcg_ctx->NULL_QREG, &addr, EA_LOADU, IS_USER(s));

    bcd_sub(tcg_ctx, dest, src);

    gen_ea_mode(env, s, 4, REG(insn, 9), OS_BYTE, dest, &addr,
                EA_STORE, IS_USER(s));

    bcd_flags(tcg_ctx, dest);
}

DISAS_INSN(nbcd)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src, dest;
    TCGv addr;

    gen_flush_flags(s); /* !Z is sticky */

    SRC_EA(env, src, OS_BYTE, 0, &addr);

    dest = tcg_const_i32(tcg_ctx, 0);
    bcd_sub(tcg_ctx, dest, src);

    DEST_EA(env, insn, OS_BYTE, dest, &addr);

    bcd_flags(tcg_ctx, dest);

    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(addsub)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv dest;
    TCGv src;
    TCGv tmp;
    TCGv addr;
    int add;
    int opsize;

    add = (insn & 0x4000) != 0;
    opsize = insn_opsize(insn);
    reg = gen_extend(s, DREG(insn, 9), opsize, 1);
    dest = tcg_temp_new(tcg_ctx);
    if (insn & 0x100) {
        SRC_EA(env, tmp, opsize, 1, &addr);
        src = reg;
    } else {
        tmp = reg;
        SRC_EA(env, src, opsize, 1, NULL);
    }
    if (add) {
        tcg_gen_add_i32(tcg_ctx, dest, tmp, src);
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_X, dest, src);
        set_cc_op(s, CC_OP_ADDB + opsize);
    } else {
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_X, tmp, src);
        tcg_gen_sub_i32(tcg_ctx, dest, tmp, src);
        set_cc_op(s, CC_OP_SUBB + opsize);
    }
    gen_update_cc_add(tcg_ctx, dest, src, opsize);
    if (insn & 0x100) {
        DEST_EA(env, insn, opsize, dest, &addr);
    } else {
        gen_partset_reg(tcg_ctx, opsize, DREG(insn, 9), dest);
    }
    tcg_temp_free(tcg_ctx, dest);
}

/* Reverse the order of the bits in REG.  */
DISAS_INSN(bitrev)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    reg = DREG(insn, 0);
    gen_helper_bitrev(tcg_ctx, reg, reg);
}

DISAS_INSN(bitop_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    int op;
    TCGv src1;
    TCGv src2;
    TCGv tmp;
    TCGv addr;
    TCGv dest;

    if ((insn & 0x38) != 0)
        opsize = OS_BYTE;
    else
        opsize = OS_LONG;
    op = (insn >> 6) & 3;
    SRC_EA(env, src1, opsize, 0, op ? &addr: NULL);

    gen_flush_flags(s);
    src2 = tcg_temp_new(tcg_ctx);
    if (opsize == OS_BYTE)
        tcg_gen_andi_i32(tcg_ctx, src2, DREG(insn, 9), 7);
    else
        tcg_gen_andi_i32(tcg_ctx, src2, DREG(insn, 9), 31);

    tmp = tcg_const_i32(tcg_ctx, 1);
    tcg_gen_shl_i32(tcg_ctx, tmp, tmp, src2);
    tcg_temp_free(tcg_ctx, src2);

    tcg_gen_and_i32(tcg_ctx, QREG_CC_Z, src1, tmp);

    dest = tcg_temp_new(tcg_ctx);
    switch (op) {
    case 1: /* bchg */
        tcg_gen_xor_i32(tcg_ctx, dest, src1, tmp);
        break;
    case 2: /* bclr */
        tcg_gen_andc_i32(tcg_ctx, dest, src1, tmp);
        break;
    case 3: /* bset */
        tcg_gen_or_i32(tcg_ctx, dest, src1, tmp);
        break;
    default: /* btst */
        break;
    }
    tcg_temp_free(tcg_ctx, tmp);
    if (op) {
        DEST_EA(env, insn, opsize, dest, &addr);
    }
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(sats)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    reg = DREG(insn, 0);
    gen_flush_flags(s);
    gen_helper_sats(tcg_ctx, reg, reg, QREG_CC_V);
    gen_logic_cc(s, reg, OS_LONG);
}

static void gen_push(DisasContext *s, TCGv val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_subi_i32(tcg_ctx, tmp, QREG_SP, 4);
    gen_store(s, OS_LONG, tmp, val, IS_USER(s));
    tcg_gen_mov_i32(tcg_ctx, QREG_SP, tmp);
    tcg_temp_free(tcg_ctx, tmp);
}

static TCGv mreg(TCGContext *tcg_ctx, int reg)
{
    if (reg < 8) {
        /* Dx */
        return tcg_ctx->cpu_dregs[reg];
    }
    /* Ax */
    return tcg_ctx->cpu_aregs[reg & 7];
}

DISAS_INSN(movem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv addr, incr, tmp, r[16];
    int is_load = (insn & 0x0400) != 0;
    int opsize = (insn & 0x40) != 0 ? OS_LONG : OS_WORD;
    uint16_t mask = read_im16(env, s);
    int mode = extract32(insn, 3, 3);
    int reg0 = REG(insn, 0);
    int i;

    tmp = tcg_ctx->cpu_aregs[reg0];

    switch (mode) {
    case 0: /* data register direct */
    case 1: /* addr register direct */
    do_addr_fault:
        gen_addr_fault(s);
        return;

    case 2: /* indirect */
        break;

    case 3: /* indirect post-increment */
        if (!is_load) {
            /* post-increment is not allowed */
            goto do_addr_fault;
        }
        break;

    case 4: /* indirect pre-decrement */
        if (is_load) {
            /* pre-decrement is not allowed */
            goto do_addr_fault;
        }
        /*
         * We want a bare copy of the address reg, without any pre-decrement
         * adjustment, as gen_lea would provide.
         */
        break;

    default:
        tmp = gen_lea_mode(env, s, mode, reg0, opsize);
        if (IS_NULL_QREG(tmp)) {
            goto do_addr_fault;
        }
        break;
    }

    addr = tcg_temp_new(tcg_ctx);
    tcg_gen_mov_i32(tcg_ctx, addr, tmp);
    incr = tcg_const_i32(tcg_ctx, opsize_bytes(opsize));

    if (is_load) {
        /* memory to register */
        for (i = 0; i < 16; i++) {
            if (mask & (1 << i)) {
                r[i] = gen_load(s, opsize, addr, 1, IS_USER(s));
                tcg_gen_add_i32(tcg_ctx, addr, addr, incr);
            }
        }
        for (i = 0; i < 16; i++) {
            if (mask & (1 << i)) {
                tcg_gen_mov_i32(tcg_ctx, mreg(tcg_ctx, i), r[i]);
                tcg_temp_free(tcg_ctx, r[i]);
            }
        }
        if (mode == 3) {
            /* post-increment: movem (An)+,X */
            tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_aregs[reg0], addr);
        }
    } else {
        /* register to memory */
        if (mode == 4) {
            /* pre-decrement: movem X,-(An) */
            for (i = 15; i >= 0; i--) {
                if ((mask << i) & 0x8000) {
                    tcg_gen_sub_i32(tcg_ctx, addr, addr, incr);
                    if (reg0 + 8 == i &&
                        m68k_feature(s->env, M68K_FEATURE_EXT_FULL)) {
                        /*
                         * M68020+: if the addressing register is the
                         * register moved to memory, the value written
                         * is the initial value decremented by the size of
                         * the operation, regardless of how many actual
                         * stores have been performed until this point.
                         * M68000/M68010: the value is the initial value.
                         */
                        tmp = tcg_temp_new(tcg_ctx);
                        tcg_gen_sub_i32(tcg_ctx, tmp, tcg_ctx->cpu_aregs[reg0], incr);
                        gen_store(s, opsize, addr, tmp, IS_USER(s));
                        tcg_temp_free(tcg_ctx, tmp);
                    } else {
                        gen_store(s, opsize, addr, mreg(tcg_ctx, i), IS_USER(s));
                    }
                }
            }
            tcg_gen_mov_i32(tcg_ctx, tcg_ctx->cpu_aregs[reg0], addr);
        } else {
            for (i = 0; i < 16; i++) {
                if (mask & (1 << i)) {
                    gen_store(s, opsize, addr, mreg(tcg_ctx, i), IS_USER(s));
                    tcg_gen_add_i32(tcg_ctx, addr, addr, incr);
                }
            }
        }
    }

    tcg_temp_free(tcg_ctx, incr);
    tcg_temp_free(tcg_ctx, addr);
}

DISAS_INSN(movep)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint8_t i;
    int16_t displ;
    TCGv reg;
    TCGv addr;
    TCGv abuf;
    TCGv dbuf;

    displ = read_im16(env, s);

    addr = AREG(insn, 0);
    reg = DREG(insn, 9);

    abuf = tcg_temp_new(tcg_ctx);
    tcg_gen_addi_i32(tcg_ctx, abuf, addr, displ);
    dbuf = tcg_temp_new(tcg_ctx);

    if (insn & 0x40) {
        i = 4;
    } else {
        i = 2;
    }

    if (insn & 0x80) {
        for ( ; i > 0 ; i--) {
            tcg_gen_shri_i32(tcg_ctx, dbuf, reg, (i - 1) * 8);
            tcg_gen_qemu_st8(tcg_ctx, dbuf, abuf, IS_USER(s));
            if (i > 1) {
                tcg_gen_addi_i32(tcg_ctx, abuf, abuf, 2);
            }
        }
    } else {
        for ( ; i > 0 ; i--) {
            tcg_gen_qemu_ld8u(tcg_ctx, dbuf, abuf, IS_USER(s));
            tcg_gen_deposit_i32(tcg_ctx, reg, reg, dbuf, (i - 1) * 8, 8);
            if (i > 1) {
                tcg_gen_addi_i32(tcg_ctx, abuf, abuf, 2);
            }
        }
    }
    tcg_temp_free(tcg_ctx, abuf);
    tcg_temp_free(tcg_ctx, dbuf);
}

DISAS_INSN(bitop_im)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    int op;
    TCGv src1;
    uint32_t mask;
    int bitnum;
    TCGv tmp;
    TCGv addr;

    if ((insn & 0x38) != 0)
        opsize = OS_BYTE;
    else
        opsize = OS_LONG;
    op = (insn >> 6) & 3;

    bitnum = read_im16(env, s);
    if (m68k_feature(s->env, M68K_FEATURE_M68000)) {
        if (bitnum & 0xfe00) {
            disas_undef(env, s, insn);
            return;
        }
    } else {
        if (bitnum & 0xff00) {
            disas_undef(env, s, insn);
            return;
        }
    }

    SRC_EA(env, src1, opsize, 0, op ? &addr: NULL);

    gen_flush_flags(s);
    if (opsize == OS_BYTE)
        bitnum &= 7;
    else
        bitnum &= 31;
    mask = 1 << bitnum;

   tcg_gen_andi_i32(tcg_ctx, QREG_CC_Z, src1, mask);

    if (op) {
        tmp = tcg_temp_new(tcg_ctx);
        switch (op) {
        case 1: /* bchg */
            tcg_gen_xori_i32(tcg_ctx, tmp, src1, mask);
            break;
        case 2: /* bclr */
            tcg_gen_andi_i32(tcg_ctx, tmp, src1, ~mask);
            break;
        case 3: /* bset */
            tcg_gen_ori_i32(tcg_ctx, tmp, src1, mask);
            break;
        default: /* btst */
            break;
        }
        DEST_EA(env, insn, opsize, tmp, &addr);
        tcg_temp_free(tcg_ctx, tmp);
    }
}

static TCGv gen_get_ccr(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv dest;

    update_cc_op(s);
    dest = tcg_temp_new(tcg_ctx);
    gen_helper_get_ccr(tcg_ctx, dest, tcg_ctx->cpu_env);
    return dest;
}

static TCGv gen_get_sr(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv ccr;
    TCGv sr;

    ccr = gen_get_ccr(s);
    sr = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_i32(tcg_ctx, sr, QREG_SR, 0xffe0);
    tcg_gen_or_i32(tcg_ctx, sr, sr, ccr);
    tcg_temp_free(tcg_ctx, ccr);
    return sr;
}

static void gen_set_sr_im(DisasContext *s, uint16_t val, int ccr_only)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (ccr_only) {
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_C, val & CCF_C ? 1 : 0);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, val & CCF_V ? -1 : 0);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_Z, val & CCF_Z ? 0 : 1);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_N, val & CCF_N ? -1 : 0);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_X, val & CCF_X ? 1 : 0);
    } else {
        TCGv sr = tcg_const_i32(tcg_ctx, val);
        gen_helper_set_sr(tcg_ctx, tcg_ctx->cpu_env, sr);
        tcg_temp_free(tcg_ctx, sr);
    }
    set_cc_op(s, CC_OP_FLAGS);
}

static void gen_set_sr(DisasContext *s, TCGv val, int ccr_only)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (ccr_only) {
        gen_helper_set_ccr(tcg_ctx, tcg_ctx->cpu_env, val);
    } else {
        gen_helper_set_sr(tcg_ctx, tcg_ctx->cpu_env, val);
    }
    set_cc_op(s, CC_OP_FLAGS);
}

static void gen_move_to_sr(CPUM68KState *env, DisasContext *s, uint16_t insn,
                           bool ccr_only)
{
    if ((insn & 0x3f) == 0x3c) {
        uint16_t val;
        val = read_im16(env, s);
        gen_set_sr_im(s, val, ccr_only);
    } else {
        TCGContext *tcg_ctx = s->uc->tcg_ctx;
        TCGv src;
        SRC_EA(env, src, OS_WORD, 0, NULL);
        gen_set_sr(s, src, ccr_only);
    }
}

DISAS_INSN(arith_im)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int op;
    TCGv im;
    TCGv src1;
    TCGv dest;
    TCGv addr;
    int opsize;
    bool with_SR = ((insn & 0x3f) == 0x3c);

    op = (insn >> 9) & 7;
    opsize = insn_opsize(insn);
    switch (opsize) {
    case OS_BYTE:
        im = tcg_const_i32(tcg_ctx, (int8_t)read_im8(env, s));
        break;
    case OS_WORD:
        im = tcg_const_i32(tcg_ctx, (int16_t)read_im16(env, s));
        break;
    case OS_LONG:
        im = tcg_const_i32(tcg_ctx, read_im32(env, s));
        break;
    default:
        g_assert_not_reached();
    }

    if (with_SR) {
        /* SR/CCR can only be used with andi/eori/ori */
        if (op == 2 || op == 3 || op == 6) {
            disas_undef(env, s, insn);
            return;
        }
        switch (opsize) {
        case OS_BYTE:
            src1 = gen_get_ccr(s);
            break;
        case OS_WORD:
            if (IS_USER(s)) {
                gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
                return;
            }
            src1 = gen_get_sr(s);
            break;
        default:
            /* OS_LONG; others already g_assert_not_reached.  */
            disas_undef(env, s, insn);
            return;
        }
    } else {
        SRC_EA(env, src1, opsize, 1, (op == 6) ? NULL : &addr);
    }
    dest = tcg_temp_new(tcg_ctx);
    switch (op) {
    case 0: /* ori */
        tcg_gen_or_i32(tcg_ctx, dest, src1, im);
        if (with_SR) {
            gen_set_sr(s, dest, opsize == OS_BYTE);
        } else {
            DEST_EA(env, insn, opsize, dest, &addr);
            gen_logic_cc(s, dest, opsize);
        }
        break;
    case 1: /* andi */
        tcg_gen_and_i32(tcg_ctx, dest, src1, im);
        if (with_SR) {
            gen_set_sr(s, dest, opsize == OS_BYTE);
        } else {
            DEST_EA(env, insn, opsize, dest, &addr);
            gen_logic_cc(s, dest, opsize);
        }
        break;
    case 2: /* subi */
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_X, src1, im);
        tcg_gen_sub_i32(tcg_ctx, dest, src1, im);
        gen_update_cc_add(tcg_ctx, dest, im, opsize);
        set_cc_op(s, CC_OP_SUBB + opsize);
        DEST_EA(env, insn, opsize, dest, &addr);
        break;
    case 3: /* addi */
        tcg_gen_add_i32(tcg_ctx, dest, src1, im);
        gen_update_cc_add(tcg_ctx, dest, im, opsize);
        tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_X, dest, im);
        set_cc_op(s, CC_OP_ADDB + opsize);
        DEST_EA(env, insn, opsize, dest, &addr);
        break;
    case 5: /* eori */
        tcg_gen_xor_i32(tcg_ctx, dest, src1, im);
        if (with_SR) {
            gen_set_sr(s, dest, opsize == OS_BYTE);
        } else {
            DEST_EA(env, insn, opsize, dest, &addr);
            gen_logic_cc(s, dest, opsize);
        }
        break;
    case 6: /* cmpi */
        gen_update_cc_cmp(s, src1, im, opsize);
        break;
    default:
        abort();
    }
    tcg_temp_free(tcg_ctx, im);
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(cas)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    TCGv addr;
    uint16_t ext;
    TCGv load;
    TCGv cmp;
    MemOp opc;

    switch ((insn >> 9) & 3) {
    case 1:
        opsize = OS_BYTE;
        opc = MO_SB;
        break;
    case 2:
        opsize = OS_WORD;
        opc = MO_TESW;
        break;
    case 3:
        opsize = OS_LONG;
        opc = MO_TESL;
        break;
    default:
        /* unreachable */
        abort();
    }

    ext = read_im16(env, s);

    /* cas Dc,Du,<EA> */

    addr = gen_lea(env, s, insn, opsize);
    if (IS_NULL_QREG(addr)) {
        gen_addr_fault(s);
        return;
    }

    cmp = gen_extend(s, DREG(ext, 0), opsize, 1);

    /*
     * if  <EA> == Dc then
     *     <EA> = Du
     *     Dc = <EA> (because <EA> == Dc)
     * else
     *     Dc = <EA>
     */

    load = tcg_temp_new(tcg_ctx);
    tcg_gen_atomic_cmpxchg_i32(tcg_ctx, load, addr, cmp, DREG(ext, 6),
                               IS_USER(s), opc);
    /* update flags before setting cmp to load */
    gen_update_cc_cmp(s, load, cmp, opsize);
    gen_partset_reg(tcg_ctx, opsize, DREG(ext, 0), load);

    tcg_temp_free(tcg_ctx, load);

    switch (extract32(insn, 3, 3)) {
    case 3: /* Indirect postincrement.  */
        tcg_gen_addi_i32(tcg_ctx, AREG(insn, 0), addr, opsize_bytes(opsize));
        break;
    case 4: /* Indirect predecrememnt.  */
        tcg_gen_mov_i32(tcg_ctx, AREG(insn, 0), addr);
        break;
    }
}

DISAS_INSN(cas2w)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext1, ext2;
    TCGv addr1, addr2;
    TCGv regs;

    /* cas2 Dc1:Dc2,Du1:Du2,(Rn1):(Rn2) */

    ext1 = read_im16(env, s);

    if (ext1 & 0x8000) {
        /* Address Register */
        addr1 = AREG(ext1, 12);
    } else {
        /* Data Register */
        addr1 = DREG(ext1, 12);
    }

    ext2 = read_im16(env, s);
    if (ext2 & 0x8000) {
        /* Address Register */
        addr2 = AREG(ext2, 12);
    } else {
        /* Data Register */
        addr2 = DREG(ext2, 12);
    }

    /*
     * if (R1) == Dc1 && (R2) == Dc2 then
     *     (R1) = Du1
     *     (R2) = Du2
     * else
     *     Dc1 = (R1)
     *     Dc2 = (R2)
     */

    regs = tcg_const_i32(tcg_ctx, REG(ext2, 6) |
                         (REG(ext1, 6) << 3) |
                         (REG(ext2, 0) << 6) |
                         (REG(ext1, 0) << 9));
    if (tb_cflags(s->base.tb) & CF_PARALLEL) {
        gen_helper_exit_atomic(tcg_ctx, tcg_ctx->cpu_env);
    } else {
        gen_helper_cas2w(tcg_ctx, tcg_ctx->cpu_env, regs, addr1, addr2);
    }
    tcg_temp_free(tcg_ctx, regs);

    /* Note that cas2w also assigned to env->cc_op.  */
    s->cc_op = CC_OP_CMPW;
    s->cc_op_synced = 1;
}

DISAS_INSN(cas2l)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext1, ext2;
    TCGv addr1, addr2, regs;

    /* cas2 Dc1:Dc2,Du1:Du2,(Rn1):(Rn2) */

    ext1 = read_im16(env, s);

    if (ext1 & 0x8000) {
        /* Address Register */
        addr1 = AREG(ext1, 12);
    } else {
        /* Data Register */
        addr1 = DREG(ext1, 12);
    }

    ext2 = read_im16(env, s);
    if (ext2 & 0x8000) {
        /* Address Register */
        addr2 = AREG(ext2, 12);
    } else {
        /* Data Register */
        addr2 = DREG(ext2, 12);
    }

    /*
     * if (R1) == Dc1 && (R2) == Dc2 then
     *     (R1) = Du1
     *     (R2) = Du2
     * else
     *     Dc1 = (R1)
     *     Dc2 = (R2)
     */

    regs = tcg_const_i32(tcg_ctx, REG(ext2, 6) |
                         (REG(ext1, 6) << 3) |
                         (REG(ext2, 0) << 6) |
                         (REG(ext1, 0) << 9));
    if (tb_cflags(s->base.tb) & CF_PARALLEL) {
        gen_helper_cas2l_parallel(tcg_ctx, tcg_ctx->cpu_env, regs, addr1, addr2);
    } else {
        gen_helper_cas2l(tcg_ctx, tcg_ctx->cpu_env, regs, addr1, addr2);
    }
    tcg_temp_free(tcg_ctx, regs);

    /* Note that cas2l also assigned to env->cc_op.  */
    s->cc_op = CC_OP_CMPL;
    s->cc_op_synced = 1;
}

DISAS_INSN(byterev)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;

    reg = DREG(insn, 0);
    tcg_gen_bswap32_i32(tcg_ctx, reg, reg);
}

DISAS_INSN(move)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv dest;
    int op;
    int opsize;

    switch (insn >> 12) {
    case 1: /* move.b */
        opsize = OS_BYTE;
        break;
    case 2: /* move.l */
        opsize = OS_LONG;
        break;
    case 3: /* move.w */
        opsize = OS_WORD;
        break;
    default:
        abort();
    }
    SRC_EA(env, src, opsize, 1, NULL);
    op = (insn >> 6) & 7;
    if (op == 1) {
        /* movea */
        /* The value will already have been sign extended.  */
        dest = AREG(insn, 9);
        tcg_gen_mov_i32(tcg_ctx, dest, src);
    } else {
        /* normal move */
        uint16_t dest_ea;
        dest_ea = ((insn >> 9) & 7) | (op << 3);
        DEST_EA(env, dest_ea, opsize, src, NULL);
        /* This will be correct because loads sign extend.  */
        gen_logic_cc(s, src, opsize);
    }
}

DISAS_INSN(negx)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv z;
    TCGv src;
    TCGv addr;
    int opsize;

    opsize = insn_opsize(insn);
    SRC_EA(env, src, opsize, 1, &addr);

    gen_flush_flags(s); /* compute old Z */

    /*
     * Perform substract with borrow.
     * (X, N) =  -(src + X);
     */

    z = tcg_const_i32(tcg_ctx, 0);
    tcg_gen_add2_i32(tcg_ctx, QREG_CC_N, QREG_CC_X, src, z, QREG_CC_X, z);
    tcg_gen_sub2_i32(tcg_ctx, QREG_CC_N, QREG_CC_X, z, z, QREG_CC_N, QREG_CC_X);
    tcg_temp_free(tcg_ctx, z);
    gen_ext(tcg_ctx, QREG_CC_N, QREG_CC_N, opsize, 1);

    tcg_gen_andi_i32(tcg_ctx, QREG_CC_X, QREG_CC_X, 1);

    /*
     * Compute signed-overflow for negation.  The normal formula for
     * subtraction is (res ^ src) & (src ^ dest), but with dest==0
     * this simplies to res & src.
     */

    tcg_gen_and_i32(tcg_ctx, QREG_CC_V, QREG_CC_N, src);

    /* Copy the rest of the results into place.  */
    tcg_gen_or_i32(tcg_ctx, QREG_CC_Z, QREG_CC_Z, QREG_CC_N); /* !Z is sticky */
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, QREG_CC_X);

    set_cc_op(s, CC_OP_FLAGS);

    /* result is in QREG_CC_N */

    DEST_EA(env, insn, opsize, QREG_CC_N, &addr);
}

DISAS_INSN(lea)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv tmp;

    reg = AREG(insn, 9);
    tmp = gen_lea(env, s, insn, OS_LONG);
    if (IS_NULL_QREG(tmp)) {
        gen_addr_fault(s);
        return;
    }
    tcg_gen_mov_i32(tcg_ctx, reg, tmp);
}

DISAS_INSN(clr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    TCGv zero;

    zero = tcg_const_i32(tcg_ctx, 0);

    opsize = insn_opsize(insn);
    DEST_EA(env, insn, opsize, zero, NULL);
    gen_logic_cc(s, zero, opsize);
    tcg_temp_free(tcg_ctx, zero);
}

DISAS_INSN(move_from_ccr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv ccr;

    ccr = gen_get_ccr(s);
    DEST_EA(env, insn, OS_WORD, ccr, NULL);
}

DISAS_INSN(neg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src1;
    TCGv dest;
    TCGv addr;
    int opsize;

    opsize = insn_opsize(insn);
    SRC_EA(env, src1, opsize, 1, &addr);
    dest = tcg_temp_new(tcg_ctx);
    tcg_gen_neg_i32(tcg_ctx, dest, src1);
    set_cc_op(s, CC_OP_SUBB + opsize);
    gen_update_cc_add(tcg_ctx, dest, src1, opsize);
    tcg_gen_setcondi_i32(tcg_ctx, TCG_COND_NE, QREG_CC_X, dest, 0);
    DEST_EA(env, insn, opsize, dest, &addr);
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(move_to_ccr)
{
    gen_move_to_sr(env, s, insn, true);
}

DISAS_INSN(not)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src1;
    TCGv dest;
    TCGv addr;
    int opsize;

    opsize = insn_opsize(insn);
    SRC_EA(env, src1, opsize, 1, &addr);
    dest = tcg_temp_new(tcg_ctx);
    tcg_gen_not_i32(tcg_ctx, dest, src1);
    DEST_EA(env, insn, opsize, dest, &addr);
    gen_logic_cc(s, dest, opsize);
}

DISAS_INSN(swap)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src1;
    TCGv src2;
    TCGv reg;

    src1 = tcg_temp_new(tcg_ctx);
    src2 = tcg_temp_new(tcg_ctx);
    reg = DREG(insn, 0);
    tcg_gen_shli_i32(tcg_ctx, src1, reg, 16);
    tcg_gen_shri_i32(tcg_ctx, src2, reg, 16);
    tcg_gen_or_i32(tcg_ctx, reg, src1, src2);
    tcg_temp_free(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, src1);
    gen_logic_cc(s, reg, OS_LONG);
}

DISAS_INSN(bkpt)
{
    gen_exception(s, s->base.pc_next, EXCP_DEBUG);
}

DISAS_INSN(pea)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    tmp = gen_lea(env, s, insn, OS_LONG);
    if (IS_NULL_QREG(tmp)) {
        gen_addr_fault(s);
        return;
    }
    gen_push(s, tmp);
}

DISAS_INSN(ext)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int op;
    TCGv reg;
    TCGv tmp;

    reg = DREG(insn, 0);
    op = (insn >> 6) & 7;
    tmp = tcg_temp_new(tcg_ctx);
    if (op == 3)
        tcg_gen_ext16s_i32(tcg_ctx, tmp, reg);
    else
        tcg_gen_ext8s_i32(tcg_ctx, tmp, reg);
    if (op == 2)
        gen_partset_reg(tcg_ctx, OS_WORD, reg, tmp);
    else
        tcg_gen_mov_i32(tcg_ctx, reg, tmp);
    gen_logic_cc(s, tmp, OS_LONG);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(tst)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    TCGv tmp;

    opsize = insn_opsize(insn);
    SRC_EA(env, tmp, opsize, 1, NULL);
    gen_logic_cc(s, tmp, opsize);
}

DISAS_INSN(pulse)
{
  /* Implemented as a NOP.  */
}

DISAS_INSN(illegal)
{
    gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
}

/* ??? This should be atomic.  */
DISAS_INSN(tas)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv dest;
    TCGv src1;
    TCGv addr;

    dest = tcg_temp_new(tcg_ctx);
    SRC_EA(env, src1, OS_BYTE, 1, &addr);
    gen_logic_cc(s, src1, OS_BYTE);
    tcg_gen_ori_i32(tcg_ctx, dest, src1, 0x80);
    DEST_EA(env, insn, OS_BYTE, dest, &addr);
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(mull)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext;
    TCGv src1;
    int sign;

    ext = read_im16(env, s);

    sign = ext & 0x800;

    if (ext & 0x400) {
        if (!m68k_feature(s->env, M68K_FEATURE_QUAD_MULDIV)) {
            gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
            return;
        }

        SRC_EA(env, src1, OS_LONG, 0, NULL);

        if (sign) {
            tcg_gen_muls2_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N, src1, DREG(ext, 12));
        } else {
            tcg_gen_mulu2_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N, src1, DREG(ext, 12));
        }
        /* if Dl == Dh, 68040 returns low word */
        tcg_gen_mov_i32(tcg_ctx, DREG(ext, 0), QREG_CC_N);
        tcg_gen_mov_i32(tcg_ctx, DREG(ext, 12), QREG_CC_Z);
        tcg_gen_or_i32(tcg_ctx, QREG_CC_Z, QREG_CC_Z, QREG_CC_N);

        tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0);
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_C, 0);

        set_cc_op(s, CC_OP_FLAGS);
        return;
    }
    SRC_EA(env, src1, OS_LONG, 0, NULL);
    if (m68k_feature(s->env, M68K_FEATURE_M68000)) {
        tcg_gen_movi_i32(tcg_ctx, QREG_CC_C, 0);
        if (sign) {
            tcg_gen_muls2_i32(tcg_ctx, QREG_CC_N, QREG_CC_V, src1, DREG(ext, 12));
            /* QREG_CC_V is -(QREG_CC_V != (QREG_CC_N >> 31)) */
            tcg_gen_sari_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N, 31);
            tcg_gen_setcond_i32(tcg_ctx, TCG_COND_NE, QREG_CC_V, QREG_CC_V, QREG_CC_Z);
        } else {
            tcg_gen_mulu2_i32(tcg_ctx, QREG_CC_N, QREG_CC_V, src1, DREG(ext, 12));
            /* QREG_CC_V is -(QREG_CC_V != 0), use QREG_CC_C as 0 */
            tcg_gen_setcond_i32(tcg_ctx, TCG_COND_NE, QREG_CC_V, QREG_CC_V, QREG_CC_C);
        }
        tcg_gen_neg_i32(tcg_ctx, QREG_CC_V, QREG_CC_V);
        tcg_gen_mov_i32(tcg_ctx, DREG(ext, 12), QREG_CC_N);

        tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);

        set_cc_op(s, CC_OP_FLAGS);
    } else {
        /*
         * The upper 32 bits of the product are discarded, so
         * muls.l and mulu.l are functionally equivalent.
         */
        tcg_gen_mul_i32(tcg_ctx, DREG(ext, 12), src1, DREG(ext, 12));
        gen_logic_cc(s, DREG(ext, 12), OS_LONG);
    }
}

static void gen_link(DisasContext *s, uint16_t insn, int32_t offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv tmp;

    reg = AREG(insn, 0);
    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_subi_i32(tcg_ctx, tmp, QREG_SP, 4);
    gen_store(s, OS_LONG, tmp, reg, IS_USER(s));
    if ((insn & 7) != 7) {
        tcg_gen_mov_i32(tcg_ctx, reg, tmp);
    }
    tcg_gen_addi_i32(tcg_ctx, QREG_SP, tmp, offset);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(link)
{
    int16_t offset;

    offset = read_im16(env, s);
    gen_link(s, insn, offset);
}

DISAS_INSN(linkl)
{
    int32_t offset;

    offset = read_im32(env, s);
    gen_link(s, insn, offset);
}

DISAS_INSN(unlk)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv reg;
    TCGv tmp;

    src = tcg_temp_new(tcg_ctx);
    reg = AREG(insn, 0);
    tcg_gen_mov_i32(tcg_ctx, src, reg);
    tmp = gen_load(s, OS_LONG, src, 0, IS_USER(s));
    tcg_gen_mov_i32(tcg_ctx, reg, tmp);
    tcg_gen_addi_i32(tcg_ctx, QREG_SP, src, 4);
    tcg_temp_free(tcg_ctx, src);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(reset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    gen_helper_reset(tcg_ctx, tcg_ctx->cpu_env);
}

DISAS_INSN(nop)
{
}

DISAS_INSN(rtd)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;
    int16_t offset = read_im16(env, s);

    tmp = gen_load(s, OS_LONG, QREG_SP, 0, IS_USER(s));
    tcg_gen_addi_i32(tcg_ctx, QREG_SP, QREG_SP, offset + 4);
    gen_jmp(s, tmp);
}

DISAS_INSN(rts)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    tmp = gen_load(s, OS_LONG, QREG_SP, 0, IS_USER(s));
    tcg_gen_addi_i32(tcg_ctx, QREG_SP, QREG_SP, 4);
    gen_jmp(s, tmp);
}

DISAS_INSN(jump)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    /*
     * Load the target address first to ensure correct exception
     * behavior.
     */
    tmp = gen_lea(env, s, insn, OS_LONG);
    if (IS_NULL_QREG(tmp)) {
        gen_addr_fault(s);
        return;
    }
    if ((insn & 0x40) == 0) {
        /* jsr */
        gen_push(s, tcg_const_i32(tcg_ctx, s->pc));
    }
    gen_jmp(s, tmp);
}

DISAS_INSN(addsubq)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv dest;
    TCGv val;
    int imm;
    TCGv addr;
    int opsize;

    if ((insn & 070) == 010) {
        /* Operation on address register is always long.  */
        opsize = OS_LONG;
    } else {
        opsize = insn_opsize(insn);
    }
    SRC_EA(env, src, opsize, 1, &addr);
    imm = (insn >> 9) & 7;
    if (imm == 0) {
        imm = 8;
    }
    val = tcg_const_i32(tcg_ctx, imm);
    dest = tcg_temp_new(tcg_ctx);
    tcg_gen_mov_i32(tcg_ctx, dest, src);
    if ((insn & 0x38) == 0x08) {
        /*
         * Don't update condition codes if the destination is an
         * address register.
         */
        if (insn & 0x0100) {
            tcg_gen_sub_i32(tcg_ctx, dest, dest, val);
        } else {
            tcg_gen_add_i32(tcg_ctx, dest, dest, val);
        }
    } else {
        if (insn & 0x0100) {
            tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_X, dest, val);
            tcg_gen_sub_i32(tcg_ctx, dest, dest, val);
            set_cc_op(s, CC_OP_SUBB + opsize);
        } else {
            tcg_gen_add_i32(tcg_ctx, dest, dest, val);
            tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, QREG_CC_X, dest, val);
            set_cc_op(s, CC_OP_ADDB + opsize);
        }
        gen_update_cc_add(tcg_ctx, dest, val, opsize);
    }
    tcg_temp_free(tcg_ctx, val);
    DEST_EA(env, insn, opsize, dest, &addr);
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(tpf)
{
    switch (insn & 7) {
    case 2: /* One extension word.  */
        s->pc += 2;
        break;
    case 3: /* Two extension words.  */
        s->pc += 4;
        break;
    case 4: /* No extension words.  */
        break;
    default:
        disas_undef(env, s, insn);
    }
}

DISAS_INSN(branch)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int32_t offset;
    uint32_t base;
    int op;

    base = s->pc;
    op = (insn >> 8) & 0xf;
    offset = (int8_t)insn;
    if (offset == 0) {
        offset = (int16_t)read_im16(env, s);
    } else if (offset == -1) {
        offset = read_im32(env, s);
    }
    if (op == 1) {
        /* bsr */
        gen_push(s, tcg_const_i32(tcg_ctx, s->pc));
    }
    if (op > 1) {
        /* Bcc */
        TCGLabel *l1 = gen_new_label(tcg_ctx);
        gen_jmpcc(s, ((insn >> 8) & 0xf) ^ 1, l1);
        gen_jmp_tb(s, 1, base + offset);
        gen_set_label(tcg_ctx, l1);
        gen_jmp_tb(s, 0, s->pc);
    } else {
        /* Unconditional branch.  */
        update_cc_op(s);
        gen_jmp_tb(s, 0, base + offset);
    }
}

DISAS_INSN(moveq)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_movi_i32(tcg_ctx, DREG(insn, 9), (int8_t)insn);
    gen_logic_cc(s, DREG(insn, 9), OS_LONG);
}

DISAS_INSN(mvzs)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    TCGv src;
    TCGv reg;

    if (insn & 0x40)
        opsize = OS_WORD;
    else
        opsize = OS_BYTE;
    SRC_EA(env, src, opsize, (insn & 0x80) == 0, NULL);
    reg = DREG(insn, 9);
    tcg_gen_mov_i32(tcg_ctx, reg, src);
    gen_logic_cc(s, src, opsize);
}

DISAS_INSN(or)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv dest;
    TCGv src;
    TCGv addr;
    int opsize;

    opsize = insn_opsize(insn);
    reg = gen_extend(s, DREG(insn, 9), opsize, 0);
    dest = tcg_temp_new(tcg_ctx);
    if (insn & 0x100) {
        SRC_EA(env, src, opsize, 0, &addr);
        tcg_gen_or_i32(tcg_ctx, dest, src, reg);
        DEST_EA(env, insn, opsize, dest, &addr);
    } else {
        SRC_EA(env, src, opsize, 0, NULL);
        tcg_gen_or_i32(tcg_ctx, dest, src, reg);
        gen_partset_reg(tcg_ctx, opsize, DREG(insn, 9), dest);
    }
    gen_logic_cc(s, dest, opsize);
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(suba)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv reg;

    SRC_EA(env, src, (insn & 0x100) ? OS_LONG : OS_WORD, 1, NULL);
    reg = AREG(insn, 9);
    tcg_gen_sub_i32(tcg_ctx, reg, reg, src);
}

static inline void gen_subx(DisasContext *s, TCGv src, TCGv dest, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    gen_flush_flags(s); /* compute old Z */

    /*
     * Perform substract with borrow.
     * (X, N) = dest - (src + X);
     */

    tmp = tcg_const_i32(tcg_ctx, 0);
    tcg_gen_add2_i32(tcg_ctx, QREG_CC_N, QREG_CC_X, src, tmp, QREG_CC_X, tmp);
    tcg_gen_sub2_i32(tcg_ctx, QREG_CC_N, QREG_CC_X, dest, tmp, QREG_CC_N, QREG_CC_X);
    gen_ext(tcg_ctx, QREG_CC_N, QREG_CC_N, opsize, 1);
    tcg_gen_andi_i32(tcg_ctx, QREG_CC_X, QREG_CC_X, 1);

    /* Compute signed-overflow for substract.  */

    tcg_gen_xor_i32(tcg_ctx, QREG_CC_V, QREG_CC_N, dest);
    tcg_gen_xor_i32(tcg_ctx, tmp, dest, src);
    tcg_gen_and_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, tmp);
    tcg_temp_free(tcg_ctx, tmp);

    /* Copy the rest of the results into place.  */
    tcg_gen_or_i32(tcg_ctx, QREG_CC_Z, QREG_CC_Z, QREG_CC_N); /* !Z is sticky */
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, QREG_CC_X);

    set_cc_op(s, CC_OP_FLAGS);

    /* result is in QREG_CC_N */
}

DISAS_INSN(subx_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv dest;
    TCGv src;
    int opsize;

    opsize = insn_opsize(insn);

    src = gen_extend(s, DREG(insn, 0), opsize, 1);
    dest = gen_extend(s, DREG(insn, 9), opsize, 1);

    gen_subx(s, src, dest, opsize);

    gen_partset_reg(tcg_ctx, opsize, DREG(insn, 9), QREG_CC_N);
}

DISAS_INSN(subx_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv addr_src;
    TCGv dest;
    TCGv addr_dest;
    int opsize;

    opsize = insn_opsize(insn);

    addr_src = AREG(insn, 0);
    tcg_gen_subi_i32(tcg_ctx, addr_src, addr_src, opsize_bytes(opsize));
    src = gen_load(s, opsize, addr_src, 1, IS_USER(s));

    addr_dest = AREG(insn, 9);
    tcg_gen_subi_i32(tcg_ctx, addr_dest, addr_dest, opsize_bytes(opsize));
    dest = gen_load(s, opsize, addr_dest, 1, IS_USER(s));

    gen_subx(s, src, dest, opsize);

    gen_store(s, opsize, addr_dest, QREG_CC_N, IS_USER(s));

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, src);
}

DISAS_INSN(mov3q)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    int val;

    val = (insn >> 9) & 7;
    if (val == 0)
        val = -1;
    src = tcg_const_i32(tcg_ctx, val);
    gen_logic_cc(s, src, OS_LONG);
    DEST_EA(env, insn, OS_LONG, src, NULL);
    tcg_temp_free(tcg_ctx, src);
}

DISAS_INSN(cmp)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv reg;
    int opsize;

    opsize = insn_opsize(insn);
    SRC_EA(env, src, opsize, 1, NULL);
    reg = gen_extend(s, DREG(insn, 9), opsize, 1);
    gen_update_cc_cmp(s, reg, src, opsize);
}

DISAS_INSN(cmpa)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    TCGv src;
    TCGv reg;

    if (insn & 0x100) {
        opsize = OS_LONG;
    } else {
        opsize = OS_WORD;
    }
    SRC_EA(env, src, opsize, 1, NULL);
    reg = AREG(insn, 9);
    gen_update_cc_cmp(s, reg, src, OS_LONG);
}

DISAS_INSN(cmpm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize = insn_opsize(insn);
    TCGv src, dst;

    /* Post-increment load (mode 3) from Ay.  */
    src = gen_ea_mode(env, s, 3, REG(insn, 0), opsize,
                      tcg_ctx->NULL_QREG, NULL, EA_LOADS, IS_USER(s));
    /* Post-increment load (mode 3) from Ax.  */
    dst = gen_ea_mode(env, s, 3, REG(insn, 9), opsize,
                      tcg_ctx->NULL_QREG, NULL, EA_LOADS, IS_USER(s));

    gen_update_cc_cmp(s, dst, src, opsize);
}

DISAS_INSN(eor)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv dest;
    TCGv addr;
    int opsize;

    opsize = insn_opsize(insn);

    SRC_EA(env, src, opsize, 0, &addr);
    dest = tcg_temp_new(tcg_ctx);
    tcg_gen_xor_i32(tcg_ctx, dest, src, DREG(insn, 9));
    gen_logic_cc(s, dest, opsize);
    DEST_EA(env, insn, opsize, dest, &addr);
    tcg_temp_free(tcg_ctx, dest);
}

static void do_exg(TCGContext *tcg_ctx, TCGv reg1, TCGv reg2)
{
    TCGv temp = tcg_temp_new(tcg_ctx);
    tcg_gen_mov_i32(tcg_ctx, temp, reg1);
    tcg_gen_mov_i32(tcg_ctx, reg1, reg2);
    tcg_gen_mov_i32(tcg_ctx, reg2, temp);
    tcg_temp_free(tcg_ctx, temp);
}

DISAS_INSN(exg_dd)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    /* exchange Dx and Dy */
    do_exg(tcg_ctx, DREG(insn, 9), DREG(insn, 0));
}

DISAS_INSN(exg_aa)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    /* exchange Ax and Ay */
    do_exg(tcg_ctx, AREG(insn, 9), AREG(insn, 0));
}

DISAS_INSN(exg_da)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    /* exchange Dx and Ay */
    do_exg(tcg_ctx, DREG(insn, 9), AREG(insn, 0));
}

DISAS_INSN(and)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv reg;
    TCGv dest;
    TCGv addr;
    int opsize;

    dest = tcg_temp_new(tcg_ctx);

    opsize = insn_opsize(insn);
    reg = DREG(insn, 9);
    if (insn & 0x100) {
        SRC_EA(env, src, opsize, 0, &addr);
        tcg_gen_and_i32(tcg_ctx, dest, src, reg);
        DEST_EA(env, insn, opsize, dest, &addr);
    } else {
        SRC_EA(env, src, opsize, 0, NULL);
        tcg_gen_and_i32(tcg_ctx, dest, src, reg);
        gen_partset_reg(tcg_ctx, opsize, reg, dest);
    }
    gen_logic_cc(s, dest, opsize);
    tcg_temp_free(tcg_ctx, dest);
}

DISAS_INSN(adda)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv reg;

    SRC_EA(env, src, (insn & 0x100) ? OS_LONG : OS_WORD, 1, NULL);
    reg = AREG(insn, 9);
    tcg_gen_add_i32(tcg_ctx, reg, reg, src);
}

static inline void gen_addx(DisasContext *s, TCGv src, TCGv dest, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp;

    gen_flush_flags(s); /* compute old Z */

    /*
     * Perform addition with carry.
     * (X, N) = src + dest + X;
     */

    tmp = tcg_const_i32(tcg_ctx, 0);
    tcg_gen_add2_i32(tcg_ctx, QREG_CC_N, QREG_CC_X, QREG_CC_X, tmp, dest, tmp);
    tcg_gen_add2_i32(tcg_ctx, QREG_CC_N, QREG_CC_X, QREG_CC_N, QREG_CC_X, src, tmp);
    gen_ext(tcg_ctx, QREG_CC_N, QREG_CC_N, opsize, 1);

    /* Compute signed-overflow for addition.  */

    tcg_gen_xor_i32(tcg_ctx, QREG_CC_V, QREG_CC_N, src);
    tcg_gen_xor_i32(tcg_ctx, tmp, dest, src);
    tcg_gen_andc_i32(tcg_ctx, QREG_CC_V, QREG_CC_V, tmp);
    tcg_temp_free(tcg_ctx, tmp);

    /* Copy the rest of the results into place.  */
    tcg_gen_or_i32(tcg_ctx, QREG_CC_Z, QREG_CC_Z, QREG_CC_N); /* !Z is sticky */
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, QREG_CC_X);

    set_cc_op(s, CC_OP_FLAGS);

    /* result is in QREG_CC_N */
}

DISAS_INSN(addx_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv dest;
    TCGv src;
    int opsize;

    opsize = insn_opsize(insn);

    dest = gen_extend(s, DREG(insn, 9), opsize, 1);
    src = gen_extend(s, DREG(insn, 0), opsize, 1);

    gen_addx(s, src, dest, opsize);

    gen_partset_reg(tcg_ctx, opsize, DREG(insn, 9), QREG_CC_N);
}

DISAS_INSN(addx_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv addr_src;
    TCGv dest;
    TCGv addr_dest;
    int opsize;

    opsize = insn_opsize(insn);

    addr_src = AREG(insn, 0);
    tcg_gen_subi_i32(tcg_ctx, addr_src, addr_src, opsize_bytes(opsize));
    src = gen_load(s, opsize, addr_src, 1, IS_USER(s));

    addr_dest = AREG(insn, 9);
    tcg_gen_subi_i32(tcg_ctx, addr_dest, addr_dest, opsize_bytes(opsize));
    dest = gen_load(s, opsize, addr_dest, 1, IS_USER(s));

    gen_addx(s, src, dest, opsize);

    gen_store(s, opsize, addr_dest, QREG_CC_N, IS_USER(s));

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, src);
}

static inline void shift_im(DisasContext *s, uint16_t insn, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int count = (insn >> 9) & 7;
    int logical = insn & 8;
    int left = insn & 0x100;
    int bits = opsize_bytes(opsize) * 8;
    TCGv reg = gen_extend(s, DREG(insn, 0), opsize, !logical);

    if (count == 0) {
        count = 8;
    }

    tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0);
    if (left) {
        tcg_gen_shri_i32(tcg_ctx, QREG_CC_C, reg, bits - count);
        tcg_gen_shli_i32(tcg_ctx, QREG_CC_N, reg, count);

        /*
         * Note that ColdFire always clears V (done above),
         * while M68000 sets if the most significant bit is changed at
         * any time during the shift operation.
         */
        if (!logical && m68k_feature(s->env, M68K_FEATURE_M68000)) {
            /* if shift count >= bits, V is (reg != 0) */
            if (count >= bits) {
                tcg_gen_setcond_i32(tcg_ctx, TCG_COND_NE, QREG_CC_V, reg, QREG_CC_V);
            } else {
                TCGv t0 = tcg_temp_new(tcg_ctx);
                tcg_gen_sari_i32(tcg_ctx, QREG_CC_V, reg, bits - 1);
                tcg_gen_sari_i32(tcg_ctx, t0, reg, bits - count - 1);
                tcg_gen_setcond_i32(tcg_ctx, TCG_COND_NE, QREG_CC_V, QREG_CC_V, t0);
                tcg_temp_free(tcg_ctx, t0);
            }
            tcg_gen_neg_i32(tcg_ctx, QREG_CC_V, QREG_CC_V);
        }
    } else {
        tcg_gen_shri_i32(tcg_ctx, QREG_CC_C, reg, count - 1);
        if (logical) {
            tcg_gen_shri_i32(tcg_ctx, QREG_CC_N, reg, count);
        } else {
            tcg_gen_sari_i32(tcg_ctx, QREG_CC_N, reg, count);
        }
    }

    gen_ext(tcg_ctx, QREG_CC_N, QREG_CC_N, opsize, 1);
    tcg_gen_andi_i32(tcg_ctx, QREG_CC_C, QREG_CC_C, 1);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_X, QREG_CC_C);

    gen_partset_reg(tcg_ctx, opsize, DREG(insn, 0), QREG_CC_N);
    set_cc_op(s, CC_OP_FLAGS);
}

static inline void shift_reg(DisasContext *s, uint16_t insn, int opsize)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int logical = insn & 8;
    int left = insn & 0x100;
    int bits = opsize_bytes(opsize) * 8;
    TCGv reg = gen_extend(s, DREG(insn, 0), opsize, !logical);
    TCGv s32;
    TCGv_i64 t64, s64;

    t64 = tcg_temp_new_i64(tcg_ctx);
    s64 = tcg_temp_new_i64(tcg_ctx);
    s32 = tcg_temp_new(tcg_ctx);

    /*
     * Note that m68k truncates the shift count modulo 64, not 32.
     * In addition, a 64-bit shift makes it easy to find "the last
     * bit shifted out", for the carry flag.
     */
    tcg_gen_andi_i32(tcg_ctx, s32, DREG(insn, 9), 63);
    tcg_gen_extu_i32_i64(tcg_ctx, s64, s32);
    tcg_gen_extu_i32_i64(tcg_ctx, t64, reg);

    /* Optimistically set V=0.  Also used as a zero source below.  */
    tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0);
    if (left) {
        tcg_gen_shl_i64(tcg_ctx, t64, t64, s64);

        if (opsize == OS_LONG) {
            tcg_gen_extr_i64_i32(tcg_ctx, QREG_CC_N, QREG_CC_C, t64);
            /* Note that C=0 if shift count is 0, and we get that for free.  */
        } else {
            TCGv zero = tcg_const_i32(tcg_ctx, 0);
            tcg_gen_extrl_i64_i32(tcg_ctx, QREG_CC_N, t64);
            tcg_gen_shri_i32(tcg_ctx, QREG_CC_C, QREG_CC_N, bits);
            tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, QREG_CC_C,
                                s32, zero, zero, QREG_CC_C);
            tcg_temp_free(tcg_ctx, zero);
        }
        tcg_gen_andi_i32(tcg_ctx, QREG_CC_C, QREG_CC_C, 1);

        /* X = C, but only if the shift count was non-zero.  */
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, QREG_CC_X, s32, QREG_CC_V,
                            QREG_CC_C, QREG_CC_X);

        /*
         * M68000 sets V if the most significant bit is changed at
         * any time during the shift operation.  Do this via creating
         * an extension of the sign bit, comparing, and discarding
         * the bits below the sign bit.  I.e.
         *     int64_t s = (intN_t)reg;
         *     int64_t t = (int64_t)(intN_t)reg << count;
         *     V = ((s ^ t) & (-1 << (bits - 1))) != 0
         */
        if (!logical && m68k_feature(s->env, M68K_FEATURE_M68000)) {
            TCGv_i64 tt = tcg_const_i64(tcg_ctx, 32);
            /* if shift is greater than 32, use 32 */
            tcg_gen_movcond_i64(tcg_ctx, TCG_COND_GT, s64, s64, tt, tt, s64);
            tcg_temp_free_i64(tcg_ctx, tt);
            /* Sign extend the input to 64 bits; re-do the shift.  */
            tcg_gen_ext_i32_i64(tcg_ctx, t64, reg);
            tcg_gen_shl_i64(tcg_ctx, s64, t64, s64);
            /* Clear all bits that are unchanged.  */
            tcg_gen_xor_i64(tcg_ctx, t64, t64, s64);
            /* Ignore the bits below the sign bit.  */
#ifdef _MSC_VER
            tcg_gen_andi_i64(tcg_ctx, t64, t64, 0xffffffffffffffffULL << (bits - 1));
#else
            tcg_gen_andi_i64(tcg_ctx, t64, t64, -1ULL << (bits - 1));
#endif
            /* If any bits remain set, we have overflow.  */
            tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_NE, t64, t64, 0);
            tcg_gen_extrl_i64_i32(tcg_ctx, QREG_CC_V, t64);
            tcg_gen_neg_i32(tcg_ctx, QREG_CC_V, QREG_CC_V);
        }
    } else {
        tcg_gen_shli_i64(tcg_ctx, t64, t64, 32);
        if (logical) {
            tcg_gen_shr_i64(tcg_ctx, t64, t64, s64);
        } else {
            tcg_gen_sar_i64(tcg_ctx, t64, t64, s64);
        }
        tcg_gen_extr_i64_i32(tcg_ctx, QREG_CC_C, QREG_CC_N, t64);

        /* Note that C=0 if shift count is 0, and we get that for free.  */
        tcg_gen_shri_i32(tcg_ctx, QREG_CC_C, QREG_CC_C, 31);

        /* X = C, but only if the shift count was non-zero.  */
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, QREG_CC_X, s32, QREG_CC_V,
                            QREG_CC_C, QREG_CC_X);
    }
    gen_ext(tcg_ctx, QREG_CC_N, QREG_CC_N, opsize, 1);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);

    tcg_temp_free(tcg_ctx, s32);
    tcg_temp_free_i64(tcg_ctx, s64);
    tcg_temp_free_i64(tcg_ctx, t64);

    /* Write back the result.  */
    gen_partset_reg(tcg_ctx, opsize, DREG(insn, 0), QREG_CC_N);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(shift8_im)
{
    shift_im(s, insn, OS_BYTE);
}

DISAS_INSN(shift16_im)
{
    shift_im(s, insn, OS_WORD);
}

DISAS_INSN(shift_im)
{
    shift_im(s, insn, OS_LONG);
}

DISAS_INSN(shift8_reg)
{
    shift_reg(s, insn, OS_BYTE);
}

DISAS_INSN(shift16_reg)
{
    shift_reg(s, insn, OS_WORD);
}

DISAS_INSN(shift_reg)
{
    shift_reg(s, insn, OS_LONG);
}

DISAS_INSN(shift_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int logical = insn & 8;
    int left = insn & 0x100;
    TCGv src;
    TCGv addr;

    SRC_EA(env, src, OS_WORD, !logical, &addr);
    tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0);
    if (left) {
        tcg_gen_shri_i32(tcg_ctx, QREG_CC_C, src, 15);
        tcg_gen_shli_i32(tcg_ctx, QREG_CC_N, src, 1);

        /*
         * Note that ColdFire always clears V,
         * while M68000 sets if the most significant bit is changed at
         * any time during the shift operation
         */
        if (!logical && m68k_feature(s->env, M68K_FEATURE_M68000)) {
            src = gen_extend(s, src, OS_WORD, 1);
            tcg_gen_xor_i32(tcg_ctx, QREG_CC_V, QREG_CC_N, src);
        }
    } else {
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, src);
        if (logical) {
            tcg_gen_shri_i32(tcg_ctx, QREG_CC_N, src, 1);
        } else {
            tcg_gen_sari_i32(tcg_ctx, QREG_CC_N, src, 1);
        }
    }

    gen_ext(tcg_ctx, QREG_CC_N, QREG_CC_N, OS_WORD, 1);
    tcg_gen_andi_i32(tcg_ctx, QREG_CC_C, QREG_CC_C, 1);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, QREG_CC_N);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_X, QREG_CC_C);

    DEST_EA(env, insn, OS_WORD, QREG_CC_N, &addr);
    set_cc_op(s, CC_OP_FLAGS);
}

static void rotate(TCGContext *tcg_ctx, TCGv reg, TCGv shift, int left, int size)
{
    switch (size) {
    case 8:
        /* Replicate the 8-bit input so that a 32-bit rotate works.  */
        tcg_gen_ext8u_i32(tcg_ctx, reg, reg);
        tcg_gen_muli_i32(tcg_ctx, reg, reg, 0x01010101);
        goto do_long;
    case 16:
        /* Replicate the 16-bit input so that a 32-bit rotate works.  */
        tcg_gen_deposit_i32(tcg_ctx, reg, reg, reg, 16, 16);
        goto do_long;
    do_long:
    default:
        if (left) {
            tcg_gen_rotl_i32(tcg_ctx, reg, reg, shift);
        } else {
            tcg_gen_rotr_i32(tcg_ctx, reg, reg, shift);
        }
    }

    /* compute flags */

    switch (size) {
    case 8:
        tcg_gen_ext8s_i32(tcg_ctx, reg, reg);
        break;
    case 16:
        tcg_gen_ext16s_i32(tcg_ctx, reg, reg);
        break;
    default:
        break;
    }

    /* QREG_CC_X is not affected */

    tcg_gen_mov_i32(tcg_ctx, QREG_CC_N, reg);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, reg);

    if (left) {
        tcg_gen_andi_i32(tcg_ctx, QREG_CC_C, reg, 1);
    } else {
        tcg_gen_shri_i32(tcg_ctx, QREG_CC_C, reg, 31);
    }

    tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0); /* always cleared */
}

static void rotate_x_flags(TCGContext *tcg_ctx, TCGv reg, TCGv X, int size)
{
    switch (size) {
    case 8:
        tcg_gen_ext8s_i32(tcg_ctx, reg, reg);
        break;
    case 16:
        tcg_gen_ext16s_i32(tcg_ctx, reg, reg);
        break;
    default:
        break;
    }
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_N, reg);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_Z, reg);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_X, X);
    tcg_gen_mov_i32(tcg_ctx, QREG_CC_C, X);
    tcg_gen_movi_i32(tcg_ctx, QREG_CC_V, 0);
}

/* Result of rotate_x() is valid if 0 <= shift <= size */
static TCGv rotate_x(TCGContext *tcg_ctx, TCGv reg, TCGv shift, int left, int size)
{
    TCGv X, shl, shr, shx, sz, zero;

    sz = tcg_const_i32(tcg_ctx, size);

    shr = tcg_temp_new(tcg_ctx);
    shl = tcg_temp_new(tcg_ctx);
    shx = tcg_temp_new(tcg_ctx);
    if (left) {
        tcg_gen_mov_i32(tcg_ctx, shl, shift);      /* shl = shift */
        tcg_gen_movi_i32(tcg_ctx, shr, size + 1);
        tcg_gen_sub_i32(tcg_ctx, shr, shr, shift); /* shr = size + 1 - shift */
        tcg_gen_subi_i32(tcg_ctx, shx, shift, 1);  /* shx = shift - 1 */
        /* shx = shx < 0 ? size : shx; */
        zero = tcg_const_i32(tcg_ctx, 0);
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_LT, shx, shx, zero, sz, shx);
        tcg_temp_free(tcg_ctx, zero);
    } else {
        tcg_gen_mov_i32(tcg_ctx, shr, shift);      /* shr = shift */
        tcg_gen_movi_i32(tcg_ctx, shl, size + 1);
        tcg_gen_sub_i32(tcg_ctx, shl, shl, shift); /* shl = size + 1 - shift */
        tcg_gen_sub_i32(tcg_ctx, shx, sz, shift); /* shx = size - shift */
    }
    tcg_temp_free_i32(tcg_ctx, sz);

    /* reg = (reg << shl) | (reg >> shr) | (x << shx); */

    tcg_gen_shl_i32(tcg_ctx, shl, reg, shl);
    tcg_gen_shr_i32(tcg_ctx, shr, reg, shr);
    tcg_gen_or_i32(tcg_ctx, reg, shl, shr);
    tcg_temp_free(tcg_ctx, shl);
    tcg_temp_free(tcg_ctx, shr);
    tcg_gen_shl_i32(tcg_ctx, shx, QREG_CC_X, shx);
    tcg_gen_or_i32(tcg_ctx, reg, reg, shx);
    tcg_temp_free(tcg_ctx, shx);

    /* X = (reg >> size) & 1 */

    X = tcg_temp_new(tcg_ctx);
    tcg_gen_extract_i32(tcg_ctx, X, reg, size, 1);

    return X;
}

/* Result of rotate32_x() is valid if 0 <= shift < 33 */
static TCGv rotate32_x(TCGContext *tcg_ctx, TCGv reg, TCGv shift, int left)
{
    TCGv_i64 t0, shift64;
    TCGv X, lo, hi, zero;

    shift64 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_extu_i32_i64(tcg_ctx, shift64, shift);

    t0 = tcg_temp_new_i64(tcg_ctx);

    X = tcg_temp_new(tcg_ctx);
    lo = tcg_temp_new(tcg_ctx);
    hi = tcg_temp_new(tcg_ctx);

    if (left) {
        /* create [reg:X:..] */

        tcg_gen_shli_i32(tcg_ctx, lo, QREG_CC_X, 31);
        tcg_gen_concat_i32_i64(tcg_ctx, t0, lo, reg);

        /* rotate */

        tcg_gen_rotl_i64(tcg_ctx, t0, t0, shift64);
        tcg_temp_free_i64(tcg_ctx, shift64);

        /* result is [reg:..:reg:X] */

        tcg_gen_extr_i64_i32(tcg_ctx, lo, hi, t0);
        tcg_gen_andi_i32(tcg_ctx, X, lo, 1);

        tcg_gen_shri_i32(tcg_ctx, lo, lo, 1);
    } else {
        /* create [..:X:reg] */

        tcg_gen_concat_i32_i64(tcg_ctx, t0, reg, QREG_CC_X);

        tcg_gen_rotr_i64(tcg_ctx, t0, t0, shift64);
        tcg_temp_free_i64(tcg_ctx, shift64);

        /* result is value: [X:reg:..:reg] */

        tcg_gen_extr_i64_i32(tcg_ctx, lo, hi, t0);

        /* extract X */

        tcg_gen_shri_i32(tcg_ctx, X, hi, 31);

        /* extract result */

        tcg_gen_shli_i32(tcg_ctx, hi, hi, 1);
    }
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_gen_or_i32(tcg_ctx, lo, lo, hi);
    tcg_temp_free(tcg_ctx, hi);

    /* if shift == 0, register and X are not affected */

    zero = tcg_const_i32(tcg_ctx, 0);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, X, shift, zero, QREG_CC_X, X);
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, reg, shift, zero, reg, lo);
    tcg_temp_free(tcg_ctx, zero);
    tcg_temp_free(tcg_ctx, lo);

    return X;
}

DISAS_INSN(rotate_im)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv shift;
    int tmp;
    int left = (insn & 0x100);

    tmp = (insn >> 9) & 7;
    if (tmp == 0) {
        tmp = 8;
    }

    shift = tcg_const_i32(tcg_ctx, tmp);
    if (insn & 8) {
        rotate(tcg_ctx, DREG(insn, 0), shift, left, 32);
    } else {
        TCGv X = rotate32_x(tcg_ctx, DREG(insn, 0), shift, left);
        rotate_x_flags(tcg_ctx, DREG(insn, 0), X, 32);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, shift);

    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(rotate8_im)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int left = (insn & 0x100);
    TCGv reg;
    TCGv shift;
    int tmp;

    reg = gen_extend(s, DREG(insn, 0), OS_BYTE, 0);

    tmp = (insn >> 9) & 7;
    if (tmp == 0) {
        tmp = 8;
    }

    shift = tcg_const_i32(tcg_ctx, tmp);
    if (insn & 8) {
        rotate(tcg_ctx, reg, shift, left, 8);
    } else {
        TCGv X = rotate_x(tcg_ctx, reg, shift, left, 8);
        rotate_x_flags(tcg_ctx, reg, X, 8);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, shift);
    gen_partset_reg(tcg_ctx, OS_BYTE, DREG(insn, 0), reg);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(rotate16_im)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int left = (insn & 0x100);
    TCGv reg;
    TCGv shift;
    int tmp;

    reg = gen_extend(s, DREG(insn, 0), OS_WORD, 0);
    tmp = (insn >> 9) & 7;
    if (tmp == 0) {
        tmp = 8;
    }

    shift = tcg_const_i32(tcg_ctx, tmp);
    if (insn & 8) {
        rotate(tcg_ctx, reg, shift, left, 16);
    } else {
        TCGv X = rotate_x(tcg_ctx, reg, shift, left, 16);
        rotate_x_flags(tcg_ctx, reg, X, 16);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, shift);
    gen_partset_reg(tcg_ctx, OS_WORD, DREG(insn, 0), reg);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(rotate_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv src;
    TCGv t0, t1;
    int left = (insn & 0x100);

    reg = DREG(insn, 0);
    src = DREG(insn, 9);
    /* shift in [0..63] */
    t0 = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_i32(tcg_ctx, t0, src, 63);
    t1 = tcg_temp_new_i32(tcg_ctx);
    if (insn & 8) {
        tcg_gen_andi_i32(tcg_ctx, t1, src, 31);
        rotate(tcg_ctx, reg, t1, left, 32);
        /* if shift == 0, clear C */
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, QREG_CC_C,
                            t0, QREG_CC_V /* 0 */,
                            QREG_CC_V /* 0 */, QREG_CC_C);
    } else {
        TCGv X;
        /* modulo 33 */
        tcg_gen_movi_i32(tcg_ctx, t1, 33);
        tcg_gen_remu_i32(tcg_ctx, t1, t0, t1);
        X = rotate32_x(tcg_ctx, DREG(insn, 0), t1, left);
        rotate_x_flags(tcg_ctx, DREG(insn, 0), X, 32);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t0);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(rotate8_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv src;
    TCGv t0, t1;
    int left = (insn & 0x100);

    reg = gen_extend(s, DREG(insn, 0), OS_BYTE, 0);
    src = DREG(insn, 9);
    /* shift in [0..63] */
    t0 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_andi_i32(tcg_ctx, t0, src, 63);
    t1 = tcg_temp_new_i32(tcg_ctx);
    if (insn & 8) {
        tcg_gen_andi_i32(tcg_ctx, t1, src, 7);
        rotate(tcg_ctx, reg, t1, left, 8);
        /* if shift == 0, clear C */
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, QREG_CC_C,
                            t0, QREG_CC_V /* 0 */,
                            QREG_CC_V /* 0 */, QREG_CC_C);
    } else {
        TCGv X;
        /* modulo 9 */
        tcg_gen_movi_i32(tcg_ctx, t1, 9);
        tcg_gen_remu_i32(tcg_ctx, t1, t0, t1);
        X = rotate_x(tcg_ctx, reg, t1, left, 8);
        rotate_x_flags(tcg_ctx, reg, X, 8);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t0);
    gen_partset_reg(tcg_ctx, OS_BYTE, DREG(insn, 0), reg);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(rotate16_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv src;
    TCGv t0, t1;
    int left = (insn & 0x100);

    reg = gen_extend(s, DREG(insn, 0), OS_WORD, 0);
    src = DREG(insn, 9);
    /* shift in [0..63] */
    t0 = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_andi_i32(tcg_ctx, t0, src, 63);
    t1 = tcg_temp_new_i32(tcg_ctx);
    if (insn & 8) {
        tcg_gen_andi_i32(tcg_ctx, t1, src, 15);
        rotate(tcg_ctx, reg, t1, left, 16);
        /* if shift == 0, clear C */
        tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, QREG_CC_C,
                            t0, QREG_CC_V /* 0 */,
                            QREG_CC_V /* 0 */, QREG_CC_C);
    } else {
        TCGv X;
        /* modulo 17 */
        tcg_gen_movi_i32(tcg_ctx, t1, 17);
        tcg_gen_remu_i32(tcg_ctx, t1, t0, t1);
        X = rotate_x(tcg_ctx, reg, t1, left, 16);
        rotate_x_flags(tcg_ctx, reg, X, 16);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t0);
    gen_partset_reg(tcg_ctx, OS_WORD, DREG(insn, 0), reg);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(rotate_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src;
    TCGv addr;
    TCGv shift;
    int left = (insn & 0x100);

    SRC_EA(env, src, OS_WORD, 0, &addr);

    shift = tcg_const_i32(tcg_ctx, 1);
    if (insn & 0x0200) {
        rotate(tcg_ctx, src, shift, left, 16);
    } else {
        TCGv X = rotate_x(tcg_ctx, src, shift, left, 16);
        rotate_x_flags(tcg_ctx, src, X, 16);
        tcg_temp_free(tcg_ctx, X);
    }
    tcg_temp_free(tcg_ctx, shift);
    DEST_EA(env, insn, OS_WORD, src, &addr);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(bfext_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int ext = read_im16(env, s);
    int is_sign = insn & 0x200;
    TCGv src = DREG(insn, 0);
    TCGv dst = DREG(ext, 12);
    int len = ((extract32(ext, 0, 5) - 1) & 31) + 1;
    int ofs = extract32(ext, 6, 5);  /* big bit-endian */
    int pos = 32 - ofs - len;        /* little bit-endian */
    TCGv tmp = tcg_temp_new(tcg_ctx);
    TCGv shift;

    /*
     * In general, we're going to rotate the field so that it's at the
     * top of the word and then right-shift by the complement of the
     * width to extend the field.
     */
    if (ext & 0x20) {
        /* Variable width.  */
        if (ext & 0x800) {
            /* Variable offset.  */
            tcg_gen_andi_i32(tcg_ctx, tmp, DREG(ext, 6), 31);
            tcg_gen_rotl_i32(tcg_ctx, tmp, src, tmp);
        } else {
            tcg_gen_rotli_i32(tcg_ctx, tmp, src, ofs);
        }

        shift = tcg_temp_new(tcg_ctx);
        tcg_gen_neg_i32(tcg_ctx, shift, DREG(ext, 0));
        tcg_gen_andi_i32(tcg_ctx, shift, shift, 31);
        tcg_gen_sar_i32(tcg_ctx, QREG_CC_N, tmp, shift);
        if (is_sign) {
            tcg_gen_mov_i32(tcg_ctx, dst, QREG_CC_N);
        } else {
            tcg_gen_shr_i32(tcg_ctx, dst, tmp, shift);
        }
        tcg_temp_free(tcg_ctx, shift);
    } else {
        /* Immediate width.  */
        if (ext & 0x800) {
            /* Variable offset */
            tcg_gen_andi_i32(tcg_ctx, tmp, DREG(ext, 6), 31);
            tcg_gen_rotl_i32(tcg_ctx, tmp, src, tmp);
            src = tmp;
            pos = 32 - len;
        } else {
            /*
             * Immediate offset.  If the field doesn't wrap around the
             * end of the word, rely on (s)extract completely.
             */
            if (pos < 0) {
                tcg_gen_rotli_i32(tcg_ctx, tmp, src, ofs);
                src = tmp;
                pos = 32 - len;
            }
        }

        tcg_gen_sextract_i32(tcg_ctx, QREG_CC_N, src, pos, len);
        if (is_sign) {
            tcg_gen_mov_i32(tcg_ctx, dst, QREG_CC_N);
        } else {
            tcg_gen_extract_i32(tcg_ctx, dst, src, pos, len);
        }
    }

    tcg_temp_free(tcg_ctx, tmp);
    set_cc_op(s, CC_OP_LOGIC);
}

DISAS_INSN(bfext_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int ext = read_im16(env, s);
    int is_sign = insn & 0x200;
    TCGv dest = DREG(ext, 12);
    TCGv addr, len, ofs;

    addr = gen_lea(env, s, insn, OS_UNSIZED);
    if (IS_NULL_QREG(addr)) {
        gen_addr_fault(s);
        return;
    }

    if (ext & 0x20) {
        len = DREG(ext, 0);
    } else {
        len = tcg_const_i32(tcg_ctx, extract32(ext, 0, 5));
    }
    if (ext & 0x800) {
        ofs = DREG(ext, 6);
    } else {
        ofs = tcg_const_i32(tcg_ctx, extract32(ext, 6, 5));
    }

    if (is_sign) {
        gen_helper_bfexts_mem(tcg_ctx, dest, tcg_ctx->cpu_env, addr, ofs, len);
        tcg_gen_mov_i32(tcg_ctx, QREG_CC_N, dest);
    } else {
        TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
        gen_helper_bfextu_mem(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, ofs, len);
        tcg_gen_extr_i64_i32(tcg_ctx, dest, QREG_CC_N, tmp);
        tcg_temp_free_i64(tcg_ctx, tmp);
    }
    set_cc_op(s, CC_OP_LOGIC);

    if (!(ext & 0x20)) {
        tcg_temp_free(tcg_ctx, len);
    }
    if (!(ext & 0x800)) {
        tcg_temp_free(tcg_ctx, ofs);
    }
}

DISAS_INSN(bfop_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int ext = read_im16(env, s);
    TCGv src = DREG(insn, 0);
    int len = ((extract32(ext, 0, 5) - 1) & 31) + 1;
    int ofs = extract32(ext, 6, 5);  /* big bit-endian */
    TCGv mask, tofs, tlen;

    tofs = NULL;
    tlen = NULL;
    if ((insn & 0x0f00) == 0x0d00) { /* bfffo */
        tofs = tcg_temp_new(tcg_ctx);
        tlen = tcg_temp_new(tcg_ctx);
    }

    if ((ext & 0x820) == 0) {
        /* Immediate width and offset.  */
        uint32_t maski = 0x7fffffffu >> (len - 1);
        if (ofs + len <= 32) {
            tcg_gen_shli_i32(tcg_ctx, QREG_CC_N, src, ofs);
        } else {
            tcg_gen_rotli_i32(tcg_ctx, QREG_CC_N, src, ofs);
        }
        tcg_gen_andi_i32(tcg_ctx, QREG_CC_N, QREG_CC_N, ~maski);
        mask = tcg_const_i32(tcg_ctx, ror32(maski, ofs));
        if (tofs) {
            tcg_gen_movi_i32(tcg_ctx, tofs, ofs);
            tcg_gen_movi_i32(tcg_ctx, tlen, len);
        }
    } else {
        TCGv tmp = tcg_temp_new(tcg_ctx);
        if (ext & 0x20) {
            /* Variable width */
            tcg_gen_subi_i32(tcg_ctx, tmp, DREG(ext, 0), 1);
            tcg_gen_andi_i32(tcg_ctx, tmp, tmp, 31);
            mask = tcg_const_i32(tcg_ctx, 0x7fffffffu);
            tcg_gen_shr_i32(tcg_ctx, mask, mask, tmp);
            if (tlen) {
                tcg_gen_addi_i32(tcg_ctx, tlen, tmp, 1);
            }
        } else {
            /* Immediate width */
            mask = tcg_const_i32(tcg_ctx, 0x7fffffffu >> (len - 1));
            if (tlen) {
                tcg_gen_movi_i32(tcg_ctx, tlen, len);
            }
        }
        if (ext & 0x800) {
            /* Variable offset */
            tcg_gen_andi_i32(tcg_ctx, tmp, DREG(ext, 6), 31);
            tcg_gen_rotl_i32(tcg_ctx, QREG_CC_N, src, tmp);
            tcg_gen_andc_i32(tcg_ctx, QREG_CC_N, QREG_CC_N, mask);
            tcg_gen_rotr_i32(tcg_ctx, mask, mask, tmp);
            if (tofs) {
                tcg_gen_mov_i32(tcg_ctx, tofs, tmp);
            }
        } else {
            /* Immediate offset (and variable width) */
            tcg_gen_rotli_i32(tcg_ctx, QREG_CC_N, src, ofs);
            tcg_gen_andc_i32(tcg_ctx, QREG_CC_N, QREG_CC_N, mask);
            tcg_gen_rotri_i32(tcg_ctx, mask, mask, ofs);
            if (tofs) {
                tcg_gen_movi_i32(tcg_ctx, tofs, ofs);
            }
        }
        tcg_temp_free(tcg_ctx, tmp);
    }
    set_cc_op(s, CC_OP_LOGIC);

    switch (insn & 0x0f00) {
    case 0x0a00: /* bfchg */
        tcg_gen_eqv_i32(tcg_ctx, src, src, mask);
        break;
    case 0x0c00: /* bfclr */
        tcg_gen_and_i32(tcg_ctx, src, src, mask);
        break;
    case 0x0d00: /* bfffo */
        gen_helper_bfffo_reg(tcg_ctx, DREG(ext, 12), QREG_CC_N, tofs, tlen);
        tcg_temp_free(tcg_ctx, tlen);
        tcg_temp_free(tcg_ctx, tofs);
        break;
    case 0x0e00: /* bfset */
        tcg_gen_orc_i32(tcg_ctx, src, src, mask);
        break;
    case 0x0800: /* bftst */
        /* flags already set; no other work to do.  */
        break;
    default:
        g_assert_not_reached();
    }
    tcg_temp_free(tcg_ctx, mask);
}

DISAS_INSN(bfop_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int ext = read_im16(env, s);
    TCGv addr, len, ofs;
    TCGv_i64 t64;

    addr = gen_lea(env, s, insn, OS_UNSIZED);
    if (IS_NULL_QREG(addr)) {
        gen_addr_fault(s);
        return;
    }

    if (ext & 0x20) {
        len = DREG(ext, 0);
    } else {
        len = tcg_const_i32(tcg_ctx, extract32(ext, 0, 5));
    }
    if (ext & 0x800) {
        ofs = DREG(ext, 6);
    } else {
        ofs = tcg_const_i32(tcg_ctx, extract32(ext, 6, 5));
    }

    switch (insn & 0x0f00) {
    case 0x0a00: /* bfchg */
        gen_helper_bfchg_mem(tcg_ctx, QREG_CC_N, tcg_ctx->cpu_env, addr, ofs, len);
        break;
    case 0x0c00: /* bfclr */
        gen_helper_bfclr_mem(tcg_ctx, QREG_CC_N, tcg_ctx->cpu_env, addr, ofs, len);
        break;
    case 0x0d00: /* bfffo */
        t64 = tcg_temp_new_i64(tcg_ctx);
        gen_helper_bfffo_mem(tcg_ctx, t64, tcg_ctx->cpu_env, addr, ofs, len);
        tcg_gen_extr_i64_i32(tcg_ctx, DREG(ext, 12), QREG_CC_N, t64);
        tcg_temp_free_i64(tcg_ctx, t64);
        break;
    case 0x0e00: /* bfset */
        gen_helper_bfset_mem(tcg_ctx, QREG_CC_N, tcg_ctx->cpu_env, addr, ofs, len);
        break;
    case 0x0800: /* bftst */
        gen_helper_bfexts_mem(tcg_ctx, QREG_CC_N, tcg_ctx->cpu_env, addr, ofs, len);
        break;
    default:
        g_assert_not_reached();
    }
    set_cc_op(s, CC_OP_LOGIC);

    if (!(ext & 0x20)) {
        tcg_temp_free(tcg_ctx, len);
    }
    if (!(ext & 0x800)) {
        tcg_temp_free(tcg_ctx, ofs);
    }
}

DISAS_INSN(bfins_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int ext = read_im16(env, s);
    TCGv dst = DREG(insn, 0);
    TCGv src = DREG(ext, 12);
    int len = ((extract32(ext, 0, 5) - 1) & 31) + 1;
    int ofs = extract32(ext, 6, 5);  /* big bit-endian */
    int pos = 32 - ofs - len;        /* little bit-endian */
    TCGv tmp;

    tmp = tcg_temp_new(tcg_ctx);

    if (ext & 0x20) {
        /* Variable width */
        tcg_gen_neg_i32(tcg_ctx, tmp, DREG(ext, 0));
        tcg_gen_andi_i32(tcg_ctx, tmp, tmp, 31);
        tcg_gen_shl_i32(tcg_ctx, QREG_CC_N, src, tmp);
    } else {
        /* Immediate width */
        tcg_gen_shli_i32(tcg_ctx, QREG_CC_N, src, 32 - len);
    }
    set_cc_op(s, CC_OP_LOGIC);

    /* Immediate width and offset */
    if ((ext & 0x820) == 0) {
        /* Check for suitability for deposit.  */
        if (pos >= 0) {
            tcg_gen_deposit_i32(tcg_ctx, dst, dst, src, pos, len);
        } else {
#ifdef _MSC_VER
            uint32_t maski = 0xfffffffeU << (len - 1);
#else
            uint32_t maski = -2U << (len - 1);
#endif
            uint32_t roti = (ofs + len) & 31;
            tcg_gen_andi_i32(tcg_ctx, tmp, src, ~maski);
            tcg_gen_rotri_i32(tcg_ctx, tmp, tmp, roti);
            tcg_gen_andi_i32(tcg_ctx, dst, dst, ror32(maski, roti));
            tcg_gen_or_i32(tcg_ctx, dst, dst, tmp);
        }
    } else {
        TCGv mask = tcg_temp_new(tcg_ctx);
        TCGv rot = tcg_temp_new(tcg_ctx);

        if (ext & 0x20) {
            /* Variable width */
            tcg_gen_subi_i32(tcg_ctx, rot, DREG(ext, 0), 1);
            tcg_gen_andi_i32(tcg_ctx, rot, rot, 31);
            tcg_gen_movi_i32(tcg_ctx, mask, -2);
            tcg_gen_shl_i32(tcg_ctx, mask, mask, rot);
            tcg_gen_mov_i32(tcg_ctx, rot, DREG(ext, 0));
            tcg_gen_andc_i32(tcg_ctx, tmp, src, mask);
        } else {
            /* Immediate width (variable offset) */
#ifdef _MSC_VER
            uint32_t maski = 0xfffffffeU << (len - 1);
#else
            uint32_t maski = -2U << (len - 1);
#endif
            tcg_gen_andi_i32(tcg_ctx, tmp, src, ~maski);
            tcg_gen_movi_i32(tcg_ctx, mask, maski);
            tcg_gen_movi_i32(tcg_ctx, rot, len & 31);
        }
        if (ext & 0x800) {
            /* Variable offset */
            tcg_gen_add_i32(tcg_ctx, rot, rot, DREG(ext, 6));
        } else {
            /* Immediate offset (variable width) */
            tcg_gen_addi_i32(tcg_ctx, rot, rot, ofs);
        }
        tcg_gen_andi_i32(tcg_ctx, rot, rot, 31);
        tcg_gen_rotr_i32(tcg_ctx, mask, mask, rot);
        tcg_gen_rotr_i32(tcg_ctx, tmp, tmp, rot);
        tcg_gen_and_i32(tcg_ctx, dst, dst, mask);
        tcg_gen_or_i32(tcg_ctx, dst, dst, tmp);

        tcg_temp_free(tcg_ctx, rot);
        tcg_temp_free(tcg_ctx, mask);
    }
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(bfins_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int ext = read_im16(env, s);
    TCGv src = DREG(ext, 12);
    TCGv addr, len, ofs;

    addr = gen_lea(env, s, insn, OS_UNSIZED);
    if (IS_NULL_QREG(addr)) {
        gen_addr_fault(s);
        return;
    }

    if (ext & 0x20) {
        len = DREG(ext, 0);
    } else {
        len = tcg_const_i32(tcg_ctx, extract32(ext, 0, 5));
    }
    if (ext & 0x800) {
        ofs = DREG(ext, 6);
    } else {
        ofs = tcg_const_i32(tcg_ctx, extract32(ext, 6, 5));
    }

    gen_helper_bfins_mem(tcg_ctx, QREG_CC_N, tcg_ctx->cpu_env, addr, src, ofs, len);
    set_cc_op(s, CC_OP_LOGIC);

    if (!(ext & 0x20)) {
        tcg_temp_free(tcg_ctx, len);
    }
    if (!(ext & 0x800)) {
        tcg_temp_free(tcg_ctx, ofs);
    }
}

DISAS_INSN(ff1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    reg = DREG(insn, 0);
    gen_logic_cc(s, reg, OS_LONG);
    gen_helper_ff1(tcg_ctx, reg, reg);
}

DISAS_INSN(chk)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv src, reg;
    int opsize;

    switch ((insn >> 7) & 3) {
    case 3:
        opsize = OS_WORD;
        break;
    case 2:
        if (m68k_feature(env, M68K_FEATURE_CHK2)) {
            opsize = OS_LONG;
            break;
        }
        /* fallthru */
    default:
        gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
        return;
    }
    SRC_EA(env, src, opsize, 1, NULL);
    reg = gen_extend(s, DREG(insn, 9), opsize, 1);

    gen_flush_flags(s);
    gen_helper_chk(tcg_ctx, tcg_ctx->cpu_env, reg, src);
}

DISAS_INSN(chk2)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext;
    TCGv addr1, addr2, bound1, bound2, reg;
    int opsize;

    switch ((insn >> 9) & 3) {
    case 0:
        opsize = OS_BYTE;
        break;
    case 1:
        opsize = OS_WORD;
        break;
    case 2:
        opsize = OS_LONG;
        break;
    default:
        gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
        return;
    }

    ext = read_im16(env, s);
    if ((ext & 0x0800) == 0) {
        gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
        return;
    }

    addr1 = gen_lea(env, s, insn, OS_UNSIZED);
    addr2 = tcg_temp_new(tcg_ctx);
    tcg_gen_addi_i32(tcg_ctx, addr2, addr1, opsize_bytes(opsize));

    bound1 = gen_load(s, opsize, addr1, 1, IS_USER(s));
    tcg_temp_free(tcg_ctx, addr1);
    bound2 = gen_load(s, opsize, addr2, 1, IS_USER(s));
    tcg_temp_free(tcg_ctx, addr2);

    reg = tcg_temp_new(tcg_ctx);
    if (ext & 0x8000) {
        tcg_gen_mov_i32(tcg_ctx, reg, AREG(ext, 12));
    } else {
        gen_ext(tcg_ctx, reg, DREG(ext, 12), opsize, 1);
    }

    gen_flush_flags(s);
    gen_helper_chk2(tcg_ctx, tcg_ctx->cpu_env, reg, bound1, bound2);
    tcg_temp_free(tcg_ctx, reg);
    tcg_temp_free(tcg_ctx, bound1);
    tcg_temp_free(tcg_ctx, bound2);
}

static void m68k_copy_line(TCGContext *tcg_ctx, TCGv dst, TCGv src, int index)
{
    TCGv addr;
    TCGv_i64 t0, t1;

    addr = tcg_temp_new(tcg_ctx);

    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i32(tcg_ctx, addr, src, ~15);
    tcg_gen_qemu_ld64(tcg_ctx, t0, addr, index);
    tcg_gen_addi_i32(tcg_ctx, addr, addr, 8);
    tcg_gen_qemu_ld64(tcg_ctx, t1, addr, index);

    tcg_gen_andi_i32(tcg_ctx, addr, dst, ~15);
    tcg_gen_qemu_st64(tcg_ctx, t0, addr, index);
    tcg_gen_addi_i32(tcg_ctx, addr, addr, 8);
    tcg_gen_qemu_st64(tcg_ctx, t1, addr, index);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, addr);
}

DISAS_INSN(move16_reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int index = IS_USER(s);
    TCGv tmp;
    uint16_t ext;

    ext = read_im16(env, s);
    if ((ext & (1 << 15)) == 0) {
        gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
    }

    m68k_copy_line(tcg_ctx, AREG(ext, 12), AREG(insn, 0), index);

    /* Ax can be Ay, so save Ay before incrementing Ax */
    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_mov_i32(tcg_ctx, tmp, AREG(ext, 12));
    tcg_gen_addi_i32(tcg_ctx, AREG(insn, 0), AREG(insn, 0), 16);
    tcg_gen_addi_i32(tcg_ctx, AREG(ext, 12), tmp, 16);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(move16_mem)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int index = IS_USER(s);
    TCGv reg, addr;

    reg = AREG(insn, 0);
    addr = tcg_const_i32(tcg_ctx, read_im32(env, s));

    if ((insn >> 3) & 1) {
        /* MOVE16 (xxx).L, (Ay) */
        m68k_copy_line(tcg_ctx, reg, addr, index);
    } else {
        /* MOVE16 (Ay), (xxx).L */
        m68k_copy_line(tcg_ctx, addr, reg, index);
    }

    tcg_temp_free(tcg_ctx, addr);

    if (((insn >> 3) & 2) == 0) {
        /* (Ay)+ */
        tcg_gen_addi_i32(tcg_ctx, reg, reg, 16);
    }
}

DISAS_INSN(strldsr)
{
    uint16_t ext;
    uint32_t addr;

    addr = s->pc - 2;
    ext = read_im16(env, s);
    if (ext != 0x46FC) {
        gen_exception(s, addr, EXCP_ILLEGAL);
        return;
    }
    ext = read_im16(env, s);
    if (IS_USER(s) || (ext & SR_S) == 0) {
        gen_exception(s, addr, EXCP_PRIVILEGE);
        return;
    }
    gen_push(s, gen_get_sr(s));
    gen_set_sr_im(s, ext, 0);
}

DISAS_INSN(move_from_sr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv sr;

    if (IS_USER(s) && !m68k_feature(env, M68K_FEATURE_M68000)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    sr = gen_get_sr(s);
    DEST_EA(env, insn, OS_WORD, sr, NULL);
}

DISAS_INSN(moves)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    uint16_t ext;
    TCGv reg;
    TCGv addr;
    int extend;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    ext = read_im16(env, s);

    opsize = insn_opsize(insn);

    if (ext & 0x8000) {
        /* address register */
        reg = AREG(ext, 12);
        extend = 1;
    } else {
        /* data register */
        reg = DREG(ext, 12);
        extend = 0;
    }

    addr = gen_lea(env, s, insn, opsize);
    if (IS_NULL_QREG(addr)) {
        gen_addr_fault(s);
        return;
    }

    if (ext & 0x0800) {
        /* from reg to ea */
        gen_store(s, opsize, addr, reg, DFC_INDEX(s));
    } else {
        /* from ea to reg */
        TCGv tmp = gen_load(s, opsize, addr, 0, SFC_INDEX(s));
        if (extend) {
            gen_ext(tcg_ctx, reg, tmp, opsize, 1);
        } else {
            gen_partset_reg(tcg_ctx, opsize, reg, tmp);
        }
        tcg_temp_free(tcg_ctx, tmp);
    }
    switch (extract32(insn, 3, 3)) {
    case 3: /* Indirect postincrement.  */
        tcg_gen_addi_i32(tcg_ctx, AREG(insn, 0), addr,
                         REG(insn, 0) == 7 && opsize == OS_BYTE
                         ? 2
                         : opsize_bytes(opsize));
        break;
    case 4: /* Indirect predecrememnt.  */
        tcg_gen_mov_i32(tcg_ctx, AREG(insn, 0), addr);
        break;
    }
}

DISAS_INSN(move_to_sr)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    gen_move_to_sr(env, s, insn, false);
    gen_exit_tb(s);
}

DISAS_INSN(move_from_usp)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    tcg_gen_ld_i32(tcg_ctx, AREG(insn, 0), tcg_ctx->cpu_env,
                   offsetof(CPUM68KState, sp[M68K_USP]));
}

DISAS_INSN(move_to_usp)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    tcg_gen_st_i32(tcg_ctx, AREG(insn, 0), tcg_ctx->cpu_env,
                   offsetof(CPUM68KState, sp[M68K_USP]));
}

DISAS_INSN(halt)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    gen_exception(s, s->pc, EXCP_HALT_INSN);
}

DISAS_INSN(stop)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    ext = read_im16(env, s);

    gen_set_sr_im(s, ext, 0);
    tcg_gen_movi_i32(tcg_ctx, tcg_ctx->cpu_halted, 1);
    gen_exception(s, s->pc, EXCP_HLT);
}

DISAS_INSN(rte)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    gen_exception(s, s->base.pc_next, EXCP_RTE);
}

DISAS_INSN(cf_movec)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext;
    TCGv reg;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    ext = read_im16(env, s);

    if (ext & 0x8000) {
        reg = AREG(ext, 12);
    } else {
        reg = DREG(ext, 12);
    }
    gen_helper_cf_movec_to(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, ext & 0xfff), reg);
    gen_exit_tb(s);
}

DISAS_INSN(m68k_movec)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext;
    TCGv reg;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    ext = read_im16(env, s);

    if (ext & 0x8000) {
        reg = AREG(ext, 12);
    } else {
        reg = DREG(ext, 12);
    }
    if (insn & 1) {
        gen_helper_m68k_movec_to(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, ext & 0xfff), reg);
    } else {
        gen_helper_m68k_movec_from(tcg_ctx, reg, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, ext & 0xfff));
    }
    gen_exit_tb(s);
}

DISAS_INSN(intouch)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    /* ICache fetch.  Implement as no-op.  */
}

DISAS_INSN(cpushl)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    /* Cache push/invalidate.  Implement as no-op.  */
}

DISAS_INSN(cpush)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    /* Cache push/invalidate.  Implement as no-op.  */
}

DISAS_INSN(cinv)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    /* Invalidate cache line.  Implement as no-op.  */
}

DISAS_INSN(pflush)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv opmode;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    opmode = tcg_const_i32(tcg_ctx, (insn >> 3) & 3);
    gen_helper_pflush(tcg_ctx, tcg_ctx->cpu_env, AREG(insn, 0), opmode);
    tcg_temp_free(tcg_ctx, opmode);
}

DISAS_INSN(ptest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv is_read;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    is_read = tcg_const_i32(tcg_ctx, (insn >> 5) & 1);
    gen_helper_ptest(tcg_ctx, tcg_ctx->cpu_env, AREG(insn, 0), is_read);
    tcg_temp_free(tcg_ctx, is_read);
}

DISAS_INSN(wddata)
{
    gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
}

DISAS_INSN(wdebug)
{
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    /* TODO: Implement wdebug.  */
    cpu_abort(env_cpu(env), "WDEBUG not implemented");
}

DISAS_INSN(trap)
{
    gen_exception(s, s->base.pc_next, EXCP_TRAP0 + (insn & 0xf));
}

static void gen_load_fcr(DisasContext *s, TCGv res, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    switch (reg) {
    case M68K_FPIAR:
        tcg_gen_movi_i32(tcg_ctx, res, 0);
        break;
    case M68K_FPSR:
        tcg_gen_ld_i32(tcg_ctx, res, tcg_ctx->cpu_env, offsetof(CPUM68KState, fpsr));
        break;
    case M68K_FPCR:
        tcg_gen_ld_i32(tcg_ctx, res, tcg_ctx->cpu_env, offsetof(CPUM68KState, fpcr));
        break;
    }
}

static void gen_store_fcr(DisasContext *s, TCGv val, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    switch (reg) {
    case M68K_FPIAR:
        break;
    case M68K_FPSR:
        tcg_gen_st_i32(tcg_ctx, val, tcg_ctx->cpu_env, offsetof(CPUM68KState, fpsr));
        break;
    case M68K_FPCR:
        gen_helper_set_fpcr(tcg_ctx, tcg_ctx->cpu_env, val);
        break;
    }
}

static void gen_qemu_store_fcr(DisasContext *s, TCGv addr, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int index = IS_USER(s);
    TCGv tmp;

    tmp = tcg_temp_new(tcg_ctx);
    gen_load_fcr(s, tmp, reg);
    tcg_gen_qemu_st32(tcg_ctx, tmp, addr, index);
    tcg_temp_free(tcg_ctx, tmp);
}

static void gen_qemu_load_fcr(DisasContext *s, TCGv addr, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int index = IS_USER(s);
    TCGv tmp;

    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_qemu_ld32u(tcg_ctx, tmp, addr, index);
    gen_store_fcr(s, tmp, reg);
    tcg_temp_free(tcg_ctx, tmp);
}


static void gen_op_fmove_fcr(CPUM68KState *env, DisasContext *s,
                             uint32_t insn, uint32_t ext)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int mask = (ext >> 10) & 7;
    int is_write = (ext >> 13) & 1;
    int mode = extract32(insn, 3, 3);
    int i;
    TCGv addr, tmp;

    switch (mode) {
    case 0: /* Dn */
        if (mask != M68K_FPIAR && mask != M68K_FPSR && mask != M68K_FPCR) {
            gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
            return;
        }
        if (is_write) {
            gen_load_fcr(s, DREG(insn, 0), mask);
        } else {
            gen_store_fcr(s, DREG(insn, 0), mask);
        }
        return;
    case 1: /* An, only with FPIAR */
        if (mask != M68K_FPIAR) {
            gen_exception(s, s->base.pc_next, EXCP_ILLEGAL);
            return;
        }
        if (is_write) {
            gen_load_fcr(s, AREG(insn, 0), mask);
        } else {
            gen_store_fcr(s, AREG(insn, 0), mask);
        }
        return;
    default:
        break;
    }

    tmp = gen_lea(env, s, insn, OS_LONG);
    if (IS_NULL_QREG(tmp)) {
        gen_addr_fault(s);
        return;
    }

    addr = tcg_temp_new(tcg_ctx);
    tcg_gen_mov_i32(tcg_ctx, addr, tmp);

    /*
     * mask:
     *
     * 0b100 Floating-Point Control Register
     * 0b010 Floating-Point Status Register
     * 0b001 Floating-Point Instruction Address Register
     *
     */

    if (is_write && mode == 4) {
        for (i = 2; i >= 0; i--, mask >>= 1) {
            if (mask & 1) {
                gen_qemu_store_fcr(s, addr, 1 << i);
                if (mask != 1) {
                    tcg_gen_subi_i32(tcg_ctx, addr, addr, opsize_bytes(OS_LONG));
                }
            }
       }
       tcg_gen_mov_i32(tcg_ctx, AREG(insn, 0), addr);
    } else {
        for (i = 0; i < 3; i++, mask >>= 1) {
            if (mask & 1) {
                if (is_write) {
                    gen_qemu_store_fcr(s, addr, 1 << i);
                } else {
                    gen_qemu_load_fcr(s, addr, 1 << i);
                }
                if (mask != 1 || mode == 3) {
                    tcg_gen_addi_i32(tcg_ctx, addr, addr, opsize_bytes(OS_LONG));
                }
            }
        }
        if (mode == 3) {
            tcg_gen_mov_i32(tcg_ctx, AREG(insn, 0), addr);
        }
    }
    tcg_temp_free_i32(tcg_ctx, addr);
}

static void gen_op_fmovem(CPUM68KState *env, DisasContext *s,
                          uint32_t insn, uint32_t ext)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int opsize;
    TCGv addr, tmp;
    int mode = (ext >> 11) & 0x3;
    int is_load = ((ext & 0x2000) == 0);

    if (m68k_feature(s->env, M68K_FEATURE_FPU)) {
        opsize = OS_EXTENDED;
    } else {
        opsize = OS_DOUBLE;  /* FIXME */
    }

    addr = gen_lea(env, s, insn, opsize);
    if (IS_NULL_QREG(addr)) {
        gen_addr_fault(s);
        return;
    }

    tmp = tcg_temp_new(tcg_ctx);
    if (mode & 0x1) {
        /* Dynamic register list */
        tcg_gen_ext8u_i32(tcg_ctx, tmp, DREG(ext, 4));
    } else {
        /* Static register list */
        tcg_gen_movi_i32(tcg_ctx, tmp, ext & 0xff);
    }

    if (!is_load && (mode & 2) == 0) {
        /*
         * predecrement addressing mode
         * only available to store register to memory
         */
        if (opsize == OS_EXTENDED) {
            gen_helper_fmovemx_st_predec(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, tmp);
        } else {
            gen_helper_fmovemd_st_predec(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, tmp);
        }
    } else {
        /* postincrement addressing mode */
        if (opsize == OS_EXTENDED) {
            if (is_load) {
                gen_helper_fmovemx_ld_postinc(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, tmp);
            } else {
                gen_helper_fmovemx_st_postinc(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, tmp);
            }
        } else {
            if (is_load) {
                gen_helper_fmovemd_ld_postinc(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, tmp);
            } else {
                gen_helper_fmovemd_st_postinc(tcg_ctx, tmp, tcg_ctx->cpu_env, addr, tmp);
            }
        }
    }
    if ((insn & 070) == 030 || (insn & 070) == 040) {
        tcg_gen_mov_i32(tcg_ctx, AREG(insn, 0), tmp);
    }
    tcg_temp_free(tcg_ctx, tmp);
}

/*
 * ??? FP exceptions are not implemented.  Most exceptions are deferred until
 * immediately before the next FP instruction is executed.
 */
DISAS_INSN(fpu)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint16_t ext;
    int opmode;
    int opsize;
    TCGv_ptr cpu_src, cpu_dest;

    ext = read_im16(env, s);
    opmode = ext & 0x7f;
    switch ((ext >> 13) & 7) {
    case 0:
        break;
    case 1:
        goto undef;
    case 2:
        if (insn == 0xf200 && (ext & 0xfc00) == 0x5c00) {
            /* fmovecr */
            TCGv rom_offset = tcg_const_i32(tcg_ctx, opmode);
            cpu_dest = gen_fp_ptr(tcg_ctx, REG(ext, 7));
            gen_helper_fconst(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, rom_offset);
            tcg_temp_free_ptr(tcg_ctx, cpu_dest);
            tcg_temp_free(tcg_ctx, rom_offset);
            return;
        }
        break;
    case 3: /* fmove out */
        cpu_src = gen_fp_ptr(tcg_ctx, REG(ext, 7));
        opsize = ext_opsize(ext, 10);
        if (gen_ea_fp(env, s, insn, opsize, cpu_src,
                      EA_STORE, IS_USER(s)) == -1) {
            gen_addr_fault(s);
        }
        gen_helper_ftst(tcg_ctx, tcg_ctx->cpu_env, cpu_src);
        tcg_temp_free_ptr(tcg_ctx, cpu_src);
        return;
    case 4: /* fmove to control register.  */
    case 5: /* fmove from control register.  */
        gen_op_fmove_fcr(env, s, insn, ext);
        return;
    case 6: /* fmovem */
    case 7:
        if ((ext & 0x1000) == 0 && !m68k_feature(s->env, M68K_FEATURE_FPU)) {
            goto undef;
        }
        gen_op_fmovem(env, s, insn, ext);
        return;
    }
    if (ext & (1 << 14)) {
        /* Source effective address.  */
        opsize = ext_opsize(ext, 10);
        cpu_src = gen_fp_result_ptr(tcg_ctx);
        if (gen_ea_fp(env, s, insn, opsize, cpu_src,
                      EA_LOADS, IS_USER(s)) == -1) {
            gen_addr_fault(s);
            return;
        }
    } else {
        /* Source register.  */
        opsize = OS_EXTENDED;
        cpu_src = gen_fp_ptr(tcg_ctx, REG(ext, 10));
    }
    cpu_dest = gen_fp_ptr(tcg_ctx, REG(ext, 7));
    switch (opmode) {
    case 0: /* fmove */
        gen_fp_move(tcg_ctx, cpu_dest, cpu_src);
        break;
    case 0x40: /* fsmove */
        gen_helper_fsround(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x44: /* fdmove */
        gen_helper_fdround(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 1: /* fint */
        gen_helper_firound(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 2: /* fsinh */
        gen_helper_fsinh(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 3: /* fintrz */
        gen_helper_fitrunc(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 4: /* fsqrt */
        gen_helper_fsqrt(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x41: /* fssqrt */
        gen_helper_fssqrt(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x45: /* fdsqrt */
        gen_helper_fdsqrt(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x06: /* flognp1 */
        gen_helper_flognp1(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x09: /* ftanh */
        gen_helper_ftanh(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x0a: /* fatan */
        gen_helper_fatan(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x0c: /* fasin */
        gen_helper_fasin(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x0d: /* fatanh */
        gen_helper_fatanh(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x0e: /* fsin */
        gen_helper_fsin(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x0f: /* ftan */
        gen_helper_ftan(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x10: /* fetox */
        gen_helper_fetox(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x11: /* ftwotox */
        gen_helper_ftwotox(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x12: /* ftentox */
        gen_helper_ftentox(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x14: /* flogn */
        gen_helper_flogn(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x15: /* flog10 */
        gen_helper_flog10(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x16: /* flog2 */
        gen_helper_flog2(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x18: /* fabs */
        gen_helper_fabs(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x58: /* fsabs */
        gen_helper_fsabs(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x5c: /* fdabs */
        gen_helper_fdabs(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x19: /* fcosh */
        gen_helper_fcosh(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x1a: /* fneg */
        gen_helper_fneg(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x5a: /* fsneg */
        gen_helper_fsneg(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x5e: /* fdneg */
        gen_helper_fdneg(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x1c: /* facos */
        gen_helper_facos(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x1d: /* fcos */
        gen_helper_fcos(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x1e: /* fgetexp */
        gen_helper_fgetexp(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x1f: /* fgetman */
        gen_helper_fgetman(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src);
        break;
    case 0x20: /* fdiv */
        gen_helper_fdiv(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x60: /* fsdiv */
        gen_helper_fsdiv(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x64: /* fddiv */
        gen_helper_fddiv(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x21: /* fmod */
        gen_helper_fmod(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x22: /* fadd */
        gen_helper_fadd(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x62: /* fsadd */
        gen_helper_fsadd(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x66: /* fdadd */
        gen_helper_fdadd(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x23: /* fmul */
        gen_helper_fmul(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x63: /* fsmul */
        gen_helper_fsmul(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x67: /* fdmul */
        gen_helper_fdmul(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x24: /* fsgldiv */
        gen_helper_fsgldiv(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x25: /* frem */
        gen_helper_frem(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x26: /* fscale */
        gen_helper_fscale(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x27: /* fsglmul */
        gen_helper_fsglmul(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x28: /* fsub */
        gen_helper_fsub(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x68: /* fssub */
        gen_helper_fssub(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x6c: /* fdsub */
        gen_helper_fdsub(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_src, cpu_dest);
        break;
    case 0x30: case 0x31: case 0x32:
    case 0x33: case 0x34: case 0x35:
    case 0x36: case 0x37: {
            TCGv_ptr cpu_dest2 = gen_fp_ptr(tcg_ctx, REG(ext, 0));
            gen_helper_fsincos(tcg_ctx, tcg_ctx->cpu_env, cpu_dest, cpu_dest2, cpu_src);
            tcg_temp_free_ptr(tcg_ctx, cpu_dest2);
        }
        break;
    case 0x38: /* fcmp */
        gen_helper_fcmp(tcg_ctx, tcg_ctx->cpu_env, cpu_src, cpu_dest);
        return;
    case 0x3a: /* ftst */
        gen_helper_ftst(tcg_ctx, tcg_ctx->cpu_env, cpu_src);
        return;
    default:
        goto undef;
    }
    tcg_temp_free_ptr(tcg_ctx, cpu_src);
    gen_helper_ftst(tcg_ctx, tcg_ctx->cpu_env, cpu_dest);
    tcg_temp_free_ptr(tcg_ctx, cpu_dest);
    return;
undef:
    /* FIXME: Is this right for offset addressing modes?  */
    s->pc -= 2;
    disas_undef_fpu(env, s, insn);
}

static void gen_fcc_cond(DisasCompare *c, DisasContext *s, int cond)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv fpsr;

    c->g1 = 1;
    c->v2 = tcg_const_i32(tcg_ctx, 0);
    c->g2 = 0;
    /* TODO: Raise BSUN exception.  */
    fpsr = tcg_temp_new(tcg_ctx);
    gen_load_fcr(s, fpsr, M68K_FPSR);
    switch (cond) {
    case 0:  /* False */
    case 16: /* Signaling False */
        c->v1 = c->v2;
        c->tcond = TCG_COND_NEVER;
        break;
    case 1:  /* EQual Z */
    case 17: /* Signaling EQual Z */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_Z);
        c->tcond = TCG_COND_NE;
        break;
    case 2:  /* Ordered Greater Than !(A || Z || N) */
    case 18: /* Greater Than !(A || Z || N) */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr,
                         FPSR_CC_A | FPSR_CC_Z | FPSR_CC_N);
        c->tcond = TCG_COND_EQ;
        break;
    case 3:  /* Ordered Greater than or Equal Z || !(A || N) */
    case 19: /* Greater than or Equal Z || !(A || N) */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A);
        tcg_gen_shli_i32(tcg_ctx, c->v1, c->v1, ctz32(FPSR_CC_N) - ctz32(FPSR_CC_A));
        tcg_gen_andi_i32(tcg_ctx, fpsr, fpsr, FPSR_CC_Z | FPSR_CC_N);
        tcg_gen_or_i32(tcg_ctx, c->v1, c->v1, fpsr);
        tcg_gen_xori_i32(tcg_ctx, c->v1, c->v1, FPSR_CC_N);
        c->tcond = TCG_COND_NE;
        break;
    case 4:  /* Ordered Less Than !(!N || A || Z); */
    case 20: /* Less Than !(!N || A || Z); */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_xori_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_N);
        tcg_gen_andi_i32(tcg_ctx, c->v1, c->v1, FPSR_CC_N | FPSR_CC_A | FPSR_CC_Z);
        c->tcond = TCG_COND_EQ;
        break;
    case 5:  /* Ordered Less than or Equal Z || (N && !A) */
    case 21: /* Less than or Equal Z || (N && !A) */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A);
        tcg_gen_shli_i32(tcg_ctx, c->v1, c->v1, ctz32(FPSR_CC_N) - ctz32(FPSR_CC_A));
        tcg_gen_andc_i32(tcg_ctx, c->v1, fpsr, c->v1);
        tcg_gen_andi_i32(tcg_ctx, c->v1, c->v1, FPSR_CC_Z | FPSR_CC_N);
        c->tcond = TCG_COND_NE;
        break;
    case 6:  /* Ordered Greater or Less than !(A || Z) */
    case 22: /* Greater or Less than !(A || Z) */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A | FPSR_CC_Z);
        c->tcond = TCG_COND_EQ;
        break;
    case 7:  /* Ordered !A */
    case 23: /* Greater, Less or Equal !A */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A);
        c->tcond = TCG_COND_EQ;
        break;
    case 8:  /* Unordered A */
    case 24: /* Not Greater, Less or Equal A */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A);
        c->tcond = TCG_COND_NE;
        break;
    case 9:  /* Unordered or Equal A || Z */
    case 25: /* Not Greater or Less then A || Z */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A | FPSR_CC_Z);
        c->tcond = TCG_COND_NE;
        break;
    case 10: /* Unordered or Greater Than A || !(N || Z)) */
    case 26: /* Not Less or Equal A || !(N || Z)) */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_Z);
        tcg_gen_shli_i32(tcg_ctx, c->v1, c->v1, ctz32(FPSR_CC_N) - ctz32(FPSR_CC_Z));
        tcg_gen_andi_i32(tcg_ctx, fpsr, fpsr, FPSR_CC_A | FPSR_CC_N);
        tcg_gen_or_i32(tcg_ctx, c->v1, c->v1, fpsr);
        tcg_gen_xori_i32(tcg_ctx, c->v1, c->v1, FPSR_CC_N);
        c->tcond = TCG_COND_NE;
        break;
    case 11: /* Unordered or Greater or Equal A || Z || !N */
    case 27: /* Not Less Than A || Z || !N */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A | FPSR_CC_Z | FPSR_CC_N);
        tcg_gen_xori_i32(tcg_ctx, c->v1, c->v1, FPSR_CC_N);
        c->tcond = TCG_COND_NE;
        break;
    case 12: /* Unordered or Less Than A || (N && !Z) */
    case 28: /* Not Greater than or Equal A || (N && !Z) */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_Z);
        tcg_gen_shli_i32(tcg_ctx, c->v1, c->v1, ctz32(FPSR_CC_N) - ctz32(FPSR_CC_Z));
        tcg_gen_andc_i32(tcg_ctx, c->v1, fpsr, c->v1);
        tcg_gen_andi_i32(tcg_ctx, c->v1, c->v1, FPSR_CC_A | FPSR_CC_N);
        c->tcond = TCG_COND_NE;
        break;
    case 13: /* Unordered or Less or Equal A || Z || N */
    case 29: /* Not Greater Than A || Z || N */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_A | FPSR_CC_Z | FPSR_CC_N);
        c->tcond = TCG_COND_NE;
        break;
    case 14: /* Not Equal !Z */
    case 30: /* Signaling Not Equal !Z */
        c->v1 = tcg_temp_new(tcg_ctx);
        c->g1 = 0;
        tcg_gen_andi_i32(tcg_ctx, c->v1, fpsr, FPSR_CC_Z);
        c->tcond = TCG_COND_EQ;
        break;
    case 15: /* True */
    case 31: /* Signaling True */
        c->v1 = c->v2;
        c->tcond = TCG_COND_ALWAYS;
        break;
    }
    tcg_temp_free(tcg_ctx, fpsr);
}

static void gen_fjmpcc(DisasContext *s, int cond, TCGLabel *l1)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    DisasCompare c;

    gen_fcc_cond(&c, s, cond);
    update_cc_op(s);
    tcg_gen_brcond_i32(tcg_ctx, c.tcond, c.v1, c.v2, l1);
    free_cond(tcg_ctx, &c);
}

DISAS_INSN(fbcc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint32_t offset;
    uint32_t base;
    TCGLabel *l1;

    base = s->pc;
    offset = (int16_t)read_im16(env, s);
    if (insn & (1 << 6)) {
        offset = (offset << 16) | read_im16(env, s);
    }

    l1 = gen_new_label(tcg_ctx);
    update_cc_op(s);
    gen_fjmpcc(s, insn & 0x3f, l1);
    gen_jmp_tb(s, 0, s->pc);
    gen_set_label(tcg_ctx, l1);
    gen_jmp_tb(s, 1, base + offset);
}

DISAS_INSN(fscc)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    DisasCompare c;
    int cond;
    TCGv tmp;
    uint16_t ext;

    ext = read_im16(env, s);
    cond = ext & 0x3f;
    gen_fcc_cond(&c, s, cond);

    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_setcond_i32(tcg_ctx, c.tcond, tmp, c.v1, c.v2);
    free_cond(tcg_ctx, &c);

    tcg_gen_neg_i32(tcg_ctx, tmp, tmp);
    DEST_EA(env, insn, OS_BYTE, tmp, NULL);
    tcg_temp_free(tcg_ctx, tmp);
}

DISAS_INSN(frestore)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv addr;

    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }
    if (m68k_feature(s->env, M68K_FEATURE_M68040)) {
        SRC_EA(env, addr, OS_LONG, 0, NULL);
        /* FIXME: check the state frame */
    } else {
        disas_undef(env, s, insn);
    }
}

DISAS_INSN(fsave)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (IS_USER(s)) {
        gen_exception(s, s->base.pc_next, EXCP_PRIVILEGE);
        return;
    }

    if (m68k_feature(s->env, M68K_FEATURE_M68040)) {
        /* always write IDLE */
        TCGv idle = tcg_const_i32(tcg_ctx, 0x41000000);
        DEST_EA(env, insn, OS_LONG, idle, NULL);
        tcg_temp_free(tcg_ctx, idle);
    } else {
        disas_undef(env, s, insn);
    }
}

static inline TCGv gen_mac_extract_word(DisasContext *s, TCGv val, int upper)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp = tcg_temp_new(tcg_ctx);
    if (s->env->macsr & MACSR_FI) {
        if (upper)
            tcg_gen_andi_i32(tcg_ctx, tmp, val, 0xffff0000);
        else
            tcg_gen_shli_i32(tcg_ctx, tmp, val, 16);
    } else if (s->env->macsr & MACSR_SU) {
        if (upper)
            tcg_gen_sari_i32(tcg_ctx, tmp, val, 16);
        else
            tcg_gen_ext16s_i32(tcg_ctx, tmp, val);
    } else {
        if (upper)
            tcg_gen_shri_i32(tcg_ctx, tmp, val, 16);
        else
            tcg_gen_ext16u_i32(tcg_ctx, tmp, val);
    }
    return tmp;
}

static void gen_mac_clear_flags(TCGContext *tcg_ctx)
{
    tcg_gen_andi_i32(tcg_ctx, QREG_MACSR, QREG_MACSR,
                     ~(MACSR_V | MACSR_Z | MACSR_N | MACSR_EV));
}

DISAS_INSN(mac)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv rx;
    TCGv ry;
    uint16_t ext;
    int acc;
    TCGv tmp;
    TCGv addr;
    TCGv loadval;
    int dual;
    TCGv saved_flags;

    if (!s->done_mac) {
        s->mactmp = tcg_temp_new_i64(tcg_ctx);
        s->done_mac = 1;
    }

    ext = read_im16(env, s);

    acc = ((insn >> 7) & 1) | ((ext >> 3) & 2);
    dual = ((insn & 0x30) != 0 && (ext & 3) != 0);
    if (dual && !m68k_feature(s->env, M68K_FEATURE_CF_EMAC_B)) {
        disas_undef(env, s, insn);
        return;
    }
    if (insn & 0x30) {
        /* MAC with load.  */
        tmp = gen_lea(env, s, insn, OS_LONG);
        addr = tcg_temp_new(tcg_ctx);
        tcg_gen_and_i32(tcg_ctx, addr, tmp, QREG_MAC_MASK);
        /*
         * Load the value now to ensure correct exception behavior.
         * Perform writeback after reading the MAC inputs.
         */
        loadval = gen_load(s, OS_LONG, addr, 0, IS_USER(s));

        acc ^= 1;
        rx = (ext & 0x8000) ? AREG(ext, 12) : DREG(insn, 12);
        ry = (ext & 8) ? AREG(ext, 0) : DREG(ext, 0);
    } else {
        loadval = addr = tcg_ctx->NULL_QREG;
        rx = (insn & 0x40) ? AREG(insn, 9) : DREG(insn, 9);
        ry = (insn & 8) ? AREG(insn, 0) : DREG(insn, 0);
    }

    gen_mac_clear_flags(tcg_ctx);
#if 0
    l1 = -1;
    /* Disabled because conditional branches clobber temporary vars.  */
    if ((s->env->macsr & MACSR_OMC) != 0 && !dual) {
        /* Skip the multiply if we know we will ignore it.  */
        l1 = gen_new_label(tcg_ctx);
        tmp = tcg_temp_new(tcg_ctx);
        tcg_gen_andi_i32(tcg_ctx, tmp, QREG_MACSR, 1 << (acc + 8));
        gen_op_jmp_nz32(tmp, l1);
    }
#endif

    if ((ext & 0x0800) == 0) {
        /* Word.  */
        rx = gen_mac_extract_word(s, rx, (ext & 0x80) != 0);
        ry = gen_mac_extract_word(s, ry, (ext & 0x40) != 0);
    }
    if (s->env->macsr & MACSR_FI) {
        gen_helper_macmulf(tcg_ctx, s->mactmp, tcg_ctx->cpu_env, rx, ry);
    } else {
        if (s->env->macsr & MACSR_SU)
            gen_helper_macmuls(tcg_ctx, s->mactmp, tcg_ctx->cpu_env, rx, ry);
        else
            gen_helper_macmulu(tcg_ctx, s->mactmp, tcg_ctx->cpu_env, rx, ry);
        switch ((ext >> 9) & 3) {
        case 1:
            tcg_gen_shli_i64(tcg_ctx, s->mactmp, s->mactmp, 1);
            break;
        case 3:
            tcg_gen_shri_i64(tcg_ctx, s->mactmp, s->mactmp, 1);
            break;
        }
    }

    if (dual) {
        /* Save the overflow flag from the multiply.  */
        saved_flags = tcg_temp_new(tcg_ctx);
        tcg_gen_mov_i32(tcg_ctx, saved_flags, QREG_MACSR);
    } else {
        saved_flags = tcg_ctx->NULL_QREG;
    }

#if 0
    /* Disabled because conditional branches clobber temporary vars.  */
    if ((s->env->macsr & MACSR_OMC) != 0 && dual) {
        /* Skip the accumulate if the value is already saturated.  */
        l1 = gen_new_label(tcg_ctx);
        tmp = tcg_temp_new(tcg_ctx);
        gen_op_and32(tmp, QREG_MACSR, tcg_const_i32(tcg_ctx, MACSR_PAV0 << acc));
        gen_op_jmp_nz32(tmp, l1);
    }
#endif

    if (insn & 0x100)
        tcg_gen_sub_i64(tcg_ctx, MACREG(acc), MACREG(acc), s->mactmp);
    else
        tcg_gen_add_i64(tcg_ctx, MACREG(acc), MACREG(acc), s->mactmp);

    if (s->env->macsr & MACSR_FI)
        gen_helper_macsatf(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));
    else if (s->env->macsr & MACSR_SU)
        gen_helper_macsats(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));
    else
        gen_helper_macsatu(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));

#if 0
    /* Disabled because conditional branches clobber temporary vars.  */
    if (l1 != -1)
        gen_set_label(tcg_ctx, l1);
#endif

    if (dual) {
        /* Dual accumulate variant.  */
        acc = (ext >> 2) & 3;
        /* Restore the overflow flag from the multiplier.  */
        tcg_gen_mov_i32(tcg_ctx, QREG_MACSR, saved_flags);
#if 0
        /* Disabled because conditional branches clobber temporary vars.  */
        if ((s->env->macsr & MACSR_OMC) != 0) {
            /* Skip the accumulate if the value is already saturated.  */
            l1 = gen_new_label(tcg_ctx);
            tmp = tcg_temp_new(tcg_ctx);
            gen_op_and32(tmp, QREG_MACSR, tcg_const_i32(tcg_ctx, MACSR_PAV0 << acc));
            gen_op_jmp_nz32(tmp, l1);
        }
#endif
        if (ext & 2)
            tcg_gen_sub_i64(tcg_ctx, MACREG(acc), MACREG(acc), s->mactmp);
        else
            tcg_gen_add_i64(tcg_ctx, MACREG(acc), MACREG(acc), s->mactmp);
        if (s->env->macsr & MACSR_FI)
            gen_helper_macsatf(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));
        else if (s->env->macsr & MACSR_SU)
            gen_helper_macsats(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));
        else
            gen_helper_macsatu(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));
#if 0
        /* Disabled because conditional branches clobber temporary vars.  */
        if (l1 != -1)
            gen_set_label(tcg_ctx, l1);
#endif
    }
    gen_helper_mac_set_flags(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, acc));

    if (insn & 0x30) {
        TCGv rw;
        rw = (insn & 0x40) ? AREG(insn, 9) : DREG(insn, 9);
        tcg_gen_mov_i32(tcg_ctx, rw, loadval);
        /*
         * FIXME: Should address writeback happen with the masked or
         * unmasked value?
         */
        switch ((insn >> 3) & 7) {
        case 3: /* Post-increment.  */
            tcg_gen_addi_i32(tcg_ctx, AREG(insn, 0), addr, 4);
            break;
        case 4: /* Pre-decrement.  */
            tcg_gen_mov_i32(tcg_ctx, AREG(insn, 0), addr);
        }
        tcg_temp_free(tcg_ctx, loadval);
    }
}

DISAS_INSN(from_mac)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv rx;
    TCGv_i64 acc;
    int accnum;

    rx = (insn & 8) ? AREG(insn, 0) : DREG(insn, 0);
    accnum = (insn >> 9) & 3;
    acc = MACREG(accnum);
    if (s->env->macsr & MACSR_FI) {
        gen_helper_get_macf(tcg_ctx, rx, tcg_ctx->cpu_env, acc);
    } else if ((s->env->macsr & MACSR_OMC) == 0) {
        tcg_gen_extrl_i64_i32(tcg_ctx, rx, acc);
    } else if (s->env->macsr & MACSR_SU) {
        gen_helper_get_macs(tcg_ctx, rx, acc);
    } else {
        gen_helper_get_macu(tcg_ctx, rx, acc);
    }
    if (insn & 0x40) {
        tcg_gen_movi_i64(tcg_ctx, acc, 0);
        tcg_gen_andi_i32(tcg_ctx, QREG_MACSR, QREG_MACSR, ~(MACSR_PAV0 << accnum));
    }
}

DISAS_INSN(move_mac)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    /* FIXME: This can be done without a helper.  */
    int src;
    TCGv dest;
    src = insn & 3;
    dest = tcg_const_i32(tcg_ctx, (insn >> 9) & 3);
    gen_helper_mac_move(tcg_ctx, tcg_ctx->cpu_env, dest, tcg_const_i32(tcg_ctx, src));
    gen_mac_clear_flags(tcg_ctx);
    gen_helper_mac_set_flags(tcg_ctx, tcg_ctx->cpu_env, dest);
}

DISAS_INSN(from_macsr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;

    reg = (insn & 8) ? AREG(insn, 0) : DREG(insn, 0);
    tcg_gen_mov_i32(tcg_ctx, reg, QREG_MACSR);
}

DISAS_INSN(from_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    reg = (insn & 8) ? AREG(insn, 0) : DREG(insn, 0);
    tcg_gen_mov_i32(tcg_ctx, reg, QREG_MAC_MASK);
}

DISAS_INSN(from_mext)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv reg;
    TCGv acc;
    reg = (insn & 8) ? AREG(insn, 0) : DREG(insn, 0);
    acc = tcg_const_i32(tcg_ctx, (insn & 0x400) ? 2 : 0);
    if (s->env->macsr & MACSR_FI)
        gen_helper_get_mac_extf(tcg_ctx, reg, tcg_ctx->cpu_env, acc);
    else
        gen_helper_get_mac_exti(tcg_ctx, reg, tcg_ctx->cpu_env, acc);
}

DISAS_INSN(macsr_to_ccr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_andi_i32(tcg_ctx, tmp, QREG_MACSR, 0xf);
    gen_helper_set_sr(tcg_ctx, tcg_ctx->cpu_env, tmp);
    tcg_temp_free(tcg_ctx, tmp);
    set_cc_op(s, CC_OP_FLAGS);
}

DISAS_INSN(to_mac)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 acc;
    TCGv val;
    int accnum;
    accnum = (insn >> 9) & 3;
    acc = MACREG(accnum);
    SRC_EA(env, val, OS_LONG, 0, NULL);
    if (s->env->macsr & MACSR_FI) {
        tcg_gen_ext_i32_i64(tcg_ctx, acc, val);
        tcg_gen_shli_i64(tcg_ctx, acc, acc, 8);
    } else if (s->env->macsr & MACSR_SU) {
        tcg_gen_ext_i32_i64(tcg_ctx, acc, val);
    } else {
        tcg_gen_extu_i32_i64(tcg_ctx, acc, val);
    }
    tcg_gen_andi_i32(tcg_ctx, QREG_MACSR, QREG_MACSR, ~(MACSR_PAV0 << accnum));
    gen_mac_clear_flags(tcg_ctx);
    gen_helper_mac_set_flags(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, accnum));
}

DISAS_INSN(to_macsr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv val;
    SRC_EA(env, val, OS_LONG, 0, NULL);
    gen_helper_set_macsr(tcg_ctx, tcg_ctx->cpu_env, val);
    gen_exit_tb(s);
}

DISAS_INSN(to_mask)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv val;
    SRC_EA(env, val, OS_LONG, 0, NULL);
    tcg_gen_ori_i32(tcg_ctx, QREG_MAC_MASK, val, 0xffff0000);
}

DISAS_INSN(to_mext)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv val;
    TCGv acc;
    SRC_EA(env, val, OS_LONG, 0, NULL);
    acc = tcg_const_i32(tcg_ctx, (insn & 0x400) ? 2 : 0);
    if (s->env->macsr & MACSR_FI)
        gen_helper_set_mac_extf(tcg_ctx, tcg_ctx->cpu_env, val, acc);
    else if (s->env->macsr & MACSR_SU)
        gen_helper_set_mac_exts(tcg_ctx, tcg_ctx->cpu_env, val, acc);
    else
        gen_helper_set_mac_extu(tcg_ctx, tcg_ctx->cpu_env, val, acc);
}

static disas_proc opcode_table[65536];

static void
register_opcode (disas_proc proc, uint16_t opcode, uint16_t mask)
{
  int i;
  int from;
  int to;

  /* Sanity check.  All set bits must be included in the mask.  */
  if (opcode & ~mask) {
      fprintf(stderr,
              "qemu internal error: bogus opcode definition %04x/%04x\n",
              opcode, mask);
      abort();
  }
  /*
   * This could probably be cleverer.  For now just optimize the case where
   * the top bits are known.
   */
  /* Find the first zero bit in the mask.  */
  i = 0x8000;
  while ((i & mask) != 0)
      i >>= 1;
  /* Iterate over all combinations of this and lower bits.  */
  if (i == 0)
      i = 1;
  else
      i <<= 1;
  from = opcode & ~(i - 1);
  to = from + i;
  for (i = from; i < to; i++) {
      if ((i & mask) == opcode)
          opcode_table[i] = proc;
  }
}

/*
 * Register m68k opcode handlers.  Order is important.
 * Later insn override earlier ones.
 */
void register_m68k_insns (CPUM68KState *env)
{
    /*
     * Build the opcode table only once to avoid
     * multithreading issues.
     */
    if (opcode_table[0] != NULL) {
        return;
    }

    /*
     * use BASE() for instruction available
     * for CF_ISA_A and M68000.
     */
#define BASE(name, opcode, mask) \
    register_opcode(disas_##name, 0x##opcode, 0x##mask)
#define INSN(name, opcode, mask, feature) do { \
    if (m68k_feature(env, M68K_FEATURE_##feature)) \
        BASE(name, opcode, mask); \
    } while(0)
    BASE(undef,     0000, 0000);
    INSN(arith_im,  0080, fff8, CF_ISA_A);
    INSN(arith_im,  0000, ff00, M68000);
    INSN(chk2,      00c0, f9c0, CHK2);
    INSN(bitrev,    00c0, fff8, CF_ISA_APLUSC);
    BASE(bitop_reg, 0100, f1c0);
    BASE(bitop_reg, 0140, f1c0);
    BASE(bitop_reg, 0180, f1c0);
    BASE(bitop_reg, 01c0, f1c0);
    INSN(movep,     0108, f138, MOVEP);
    INSN(arith_im,  0280, fff8, CF_ISA_A);
    INSN(arith_im,  0200, ff00, M68000);
    INSN(undef,     02c0, ffc0, M68000);
    INSN(byterev,   02c0, fff8, CF_ISA_APLUSC);
    INSN(arith_im,  0480, fff8, CF_ISA_A);
    INSN(arith_im,  0400, ff00, M68000);
    INSN(undef,     04c0, ffc0, M68000);
    INSN(arith_im,  0600, ff00, M68000);
    INSN(undef,     06c0, ffc0, M68000);
    INSN(ff1,       04c0, fff8, CF_ISA_APLUSC);
    INSN(arith_im,  0680, fff8, CF_ISA_A);
    INSN(arith_im,  0c00, ff38, CF_ISA_A);
    INSN(arith_im,  0c00, ff00, M68000);
    BASE(bitop_im,  0800, ffc0);
    BASE(bitop_im,  0840, ffc0);
    BASE(bitop_im,  0880, ffc0);
    BASE(bitop_im,  08c0, ffc0);
    INSN(arith_im,  0a80, fff8, CF_ISA_A);
    INSN(arith_im,  0a00, ff00, M68000);
    INSN(moves,     0e00, ff00, M68000);
    INSN(cas,       0ac0, ffc0, CAS);
    INSN(cas,       0cc0, ffc0, CAS);
    INSN(cas,       0ec0, ffc0, CAS);
    INSN(cas2w,     0cfc, ffff, CAS);
    INSN(cas2l,     0efc, ffff, CAS);
    BASE(move,      1000, f000);
    BASE(move,      2000, f000);
    BASE(move,      3000, f000);
    INSN(chk,       4000, f040, M68000);
    INSN(strldsr,   40e7, ffff, CF_ISA_APLUSC);
    INSN(negx,      4080, fff8, CF_ISA_A);
    INSN(negx,      4000, ff00, M68000);
    INSN(undef,     40c0, ffc0, M68000);
    INSN(move_from_sr, 40c0, fff8, CF_ISA_A);
    INSN(move_from_sr, 40c0, ffc0, M68000);
    BASE(lea,       41c0, f1c0);
    BASE(clr,       4200, ff00);
    BASE(undef,     42c0, ffc0);
    INSN(move_from_ccr, 42c0, fff8, CF_ISA_A);
    INSN(move_from_ccr, 42c0, ffc0, M68000);
    INSN(neg,       4480, fff8, CF_ISA_A);
    INSN(neg,       4400, ff00, M68000);
    INSN(undef,     44c0, ffc0, M68000);
    BASE(move_to_ccr, 44c0, ffc0);
    INSN(not,       4680, fff8, CF_ISA_A);
    INSN(not,       4600, ff00, M68000);
    BASE(move_to_sr, 46c0, ffc0);
    INSN(nbcd,      4800, ffc0, M68000);
    INSN(linkl,     4808, fff8, M68000);
    BASE(pea,       4840, ffc0);
    BASE(swap,      4840, fff8);
    INSN(bkpt,      4848, fff8, BKPT);
    INSN(movem,     48d0, fbf8, CF_ISA_A);
    INSN(movem,     48e8, fbf8, CF_ISA_A);
    INSN(movem,     4880, fb80, M68000);
    BASE(ext,       4880, fff8);
    BASE(ext,       48c0, fff8);
    BASE(ext,       49c0, fff8);
    BASE(tst,       4a00, ff00);
    INSN(tas,       4ac0, ffc0, CF_ISA_B);
    INSN(tas,       4ac0, ffc0, M68000);
    INSN(halt,      4ac8, ffff, CF_ISA_A);
    INSN(pulse,     4acc, ffff, CF_ISA_A);
    BASE(illegal,   4afc, ffff);
    INSN(mull,      4c00, ffc0, CF_ISA_A);
    INSN(mull,      4c00, ffc0, LONG_MULDIV);
    INSN(divl,      4c40, ffc0, CF_ISA_A);
    INSN(divl,      4c40, ffc0, LONG_MULDIV);
    INSN(sats,      4c80, fff8, CF_ISA_B);
    BASE(trap,      4e40, fff0);
    BASE(link,      4e50, fff8);
    BASE(unlk,      4e58, fff8);
    INSN(move_to_usp, 4e60, fff8, USP);
    INSN(move_from_usp, 4e68, fff8, USP);
    INSN(reset,     4e70, ffff, M68000);
    BASE(stop,      4e72, ffff);
    BASE(rte,       4e73, ffff);
    INSN(cf_movec,  4e7b, ffff, CF_ISA_A);
    INSN(m68k_movec, 4e7a, fffe, M68000);
    BASE(nop,       4e71, ffff);
    INSN(rtd,       4e74, ffff, RTD);
    BASE(rts,       4e75, ffff);
    BASE(jump,      4e80, ffc0);
    BASE(jump,      4ec0, ffc0);
    INSN(addsubq,   5000, f080, M68000);
    BASE(addsubq,   5080, f0c0);
    INSN(scc,       50c0, f0f8, CF_ISA_A); /* Scc.B Dx   */
    INSN(scc,       50c0, f0c0, M68000);   /* Scc.B <EA> */
    INSN(dbcc,      50c8, f0f8, M68000);
    INSN(tpf,       51f8, fff8, CF_ISA_A);

    /* Branch instructions.  */
    BASE(branch,    6000, f000);
    /* Disable long branch instructions, then add back the ones we want.  */
    BASE(undef,     60ff, f0ff); /* All long branches.  */
    INSN(branch,    60ff, f0ff, CF_ISA_B);
    INSN(undef,     60ff, ffff, CF_ISA_B); /* bra.l */
    INSN(branch,    60ff, ffff, BRAL);
    INSN(branch,    60ff, f0ff, BCCL);

    BASE(moveq,     7000, f100);
    INSN(mvzs,      7100, f100, CF_ISA_B);
    BASE(or,        8000, f000);
    BASE(divw,      80c0, f0c0);
    INSN(sbcd_reg,  8100, f1f8, M68000);
    INSN(sbcd_mem,  8108, f1f8, M68000);
    BASE(addsub,    9000, f000);
    INSN(undef,     90c0, f0c0, CF_ISA_A);
    INSN(subx_reg,  9180, f1f8, CF_ISA_A);
    INSN(subx_reg,  9100, f138, M68000);
    INSN(subx_mem,  9108, f138, M68000);
    INSN(suba,      91c0, f1c0, CF_ISA_A);
    INSN(suba,      90c0, f0c0, M68000);

    BASE(undef_mac, a000, f000);
    INSN(mac,       a000, f100, CF_EMAC);
    INSN(from_mac,  a180, f9b0, CF_EMAC);
    INSN(move_mac,  a110, f9fc, CF_EMAC);
    INSN(from_macsr,a980, f9f0, CF_EMAC);
    INSN(from_mask, ad80, fff0, CF_EMAC);
    INSN(from_mext, ab80, fbf0, CF_EMAC);
    INSN(macsr_to_ccr, a9c0, ffff, CF_EMAC);
    INSN(to_mac,    a100, f9c0, CF_EMAC);
    INSN(to_macsr,  a900, ffc0, CF_EMAC);
    INSN(to_mext,   ab00, fbc0, CF_EMAC);
    INSN(to_mask,   ad00, ffc0, CF_EMAC);

    INSN(mov3q,     a140, f1c0, CF_ISA_B);
    INSN(cmp,       b000, f1c0, CF_ISA_B); /* cmp.b */
    INSN(cmp,       b040, f1c0, CF_ISA_B); /* cmp.w */
    INSN(cmpa,      b0c0, f1c0, CF_ISA_B); /* cmpa.w */
    INSN(cmp,       b080, f1c0, CF_ISA_A);
    INSN(cmpa,      b1c0, f1c0, CF_ISA_A);
    INSN(cmp,       b000, f100, M68000);
    INSN(eor,       b100, f100, M68000);
    INSN(cmpm,      b108, f138, M68000);
    INSN(cmpa,      b0c0, f0c0, M68000);
    INSN(eor,       b180, f1c0, CF_ISA_A);
    BASE(and,       c000, f000);
    INSN(exg_dd,    c140, f1f8, M68000);
    INSN(exg_aa,    c148, f1f8, M68000);
    INSN(exg_da,    c188, f1f8, M68000);
    BASE(mulw,      c0c0, f0c0);
    INSN(abcd_reg,  c100, f1f8, M68000);
    INSN(abcd_mem,  c108, f1f8, M68000);
    BASE(addsub,    d000, f000);
    INSN(undef,     d0c0, f0c0, CF_ISA_A);
    INSN(addx_reg,      d180, f1f8, CF_ISA_A);
    INSN(addx_reg,  d100, f138, M68000);
    INSN(addx_mem,  d108, f138, M68000);
    INSN(adda,      d1c0, f1c0, CF_ISA_A);
    INSN(adda,      d0c0, f0c0, M68000);
    INSN(shift_im,  e080, f0f0, CF_ISA_A);
    INSN(shift_reg, e0a0, f0f0, CF_ISA_A);
    INSN(shift8_im, e000, f0f0, M68000);
    INSN(shift16_im, e040, f0f0, M68000);
    INSN(shift_im,  e080, f0f0, M68000);
    INSN(shift8_reg, e020, f0f0, M68000);
    INSN(shift16_reg, e060, f0f0, M68000);
    INSN(shift_reg, e0a0, f0f0, M68000);
    INSN(shift_mem, e0c0, fcc0, M68000);
    INSN(rotate_im, e090, f0f0, M68000);
    INSN(rotate8_im, e010, f0f0, M68000);
    INSN(rotate16_im, e050, f0f0, M68000);
    INSN(rotate_reg, e0b0, f0f0, M68000);
    INSN(rotate8_reg, e030, f0f0, M68000);
    INSN(rotate16_reg, e070, f0f0, M68000);
    INSN(rotate_mem, e4c0, fcc0, M68000);
    INSN(bfext_mem, e9c0, fdc0, BITFIELD);  /* bfextu & bfexts */
    INSN(bfext_reg, e9c0, fdf8, BITFIELD);
    INSN(bfins_mem, efc0, ffc0, BITFIELD);
    INSN(bfins_reg, efc0, fff8, BITFIELD);
    INSN(bfop_mem, eac0, ffc0, BITFIELD);   /* bfchg */
    INSN(bfop_reg, eac0, fff8, BITFIELD);   /* bfchg */
    INSN(bfop_mem, ecc0, ffc0, BITFIELD);   /* bfclr */
    INSN(bfop_reg, ecc0, fff8, BITFIELD);   /* bfclr */
    INSN(bfop_mem, edc0, ffc0, BITFIELD);   /* bfffo */
    INSN(bfop_reg, edc0, fff8, BITFIELD);   /* bfffo */
    INSN(bfop_mem, eec0, ffc0, BITFIELD);   /* bfset */
    INSN(bfop_reg, eec0, fff8, BITFIELD);   /* bfset */
    INSN(bfop_mem, e8c0, ffc0, BITFIELD);   /* bftst */
    INSN(bfop_reg, e8c0, fff8, BITFIELD);   /* bftst */
    BASE(undef_fpu, f000, f000);
    INSN(fpu,       f200, ffc0, CF_FPU);
    INSN(fbcc,      f280, ffc0, CF_FPU);
    INSN(fpu,       f200, ffc0, FPU);
    INSN(fscc,      f240, ffc0, FPU);
    INSN(fbcc,      f280, ff80, FPU);
    INSN(frestore,  f340, ffc0, CF_FPU);
    INSN(fsave,     f300, ffc0, CF_FPU);
    INSN(frestore,  f340, ffc0, FPU);
    INSN(fsave,     f300, ffc0, FPU);
    INSN(intouch,   f340, ffc0, CF_ISA_A);
    INSN(cpushl,    f428, ff38, CF_ISA_A);
    INSN(cpush,     f420, ff20, M68040);
    INSN(cinv,      f400, ff20, M68040);
    INSN(pflush,    f500, ffe0, M68040);
    INSN(ptest,     f548, ffd8, M68040);
    INSN(wddata,    fb00, ff00, CF_ISA_A);
    INSN(wdebug,    fbc0, ffc0, CF_ISA_A);
    INSN(move16_mem, f600, ffe0, M68040);
    INSN(move16_reg, f620, fff8, M68040);
#undef INSN
}

static void m68k_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    CPUM68KState *env = cpu->env_ptr;

    // unicorn setup
    dc->uc = cpu->uc;

    dc->env = env;
    dc->pc = dc->base.pc_first;
    dc->cc_op = CC_OP_DYNAMIC;
    dc->cc_op_synced = 1;
    dc->done_mac = 0;
    dc->writeback_mask = 0;
    init_release_array(dc);
}

static void m68k_tr_tb_start(DisasContextBase *dcbase, CPUState *cpu)
{
}

static void m68k_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = dc->uc->tcg_ctx;
    tcg_gen_insn_start(tcg_ctx, dc->base.pc_next, dc->cc_op);
}

static bool m68k_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                     const CPUBreakpoint *bp)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    gen_exception(dc, dc->base.pc_next, EXCP_DEBUG);
    /*
     * The address covered by the breakpoint must be included in
     * [tb->pc, tb->pc + tb->size) in order to for it to be
     * properly cleared -- thus we increment the PC here so that
     * the logic setting tb->size below does the right thing.
     */
    dc->base.pc_next += 2;

    return true;
}

static void m68k_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    struct uc_struct *uc = dc->uc;
    TCGContext *tcg_ctx = uc->tcg_ctx;
    CPUM68KState *env = cpu->env_ptr;
    uint16_t insn;

    // Unicorn: end address tells us to stop emulation
    if (uc_addr_is_exit(uc, dc->pc)) {
        gen_exception(dc, dc->pc, EXCP_HLT);
        return;
    }

    // Unicorn: trace this instruction on request
    if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_CODE, dc->pc)) {

        // Sync PC in advance
        tcg_gen_movi_i32(tcg_ctx, QREG_PC, dc->pc);

        gen_uc_tracecode(tcg_ctx, 2, UC_HOOK_CODE_IDX, uc, dc->pc);
        // the callback might want to stop emulation immediately
        check_exit_request(tcg_ctx);
    }

    insn = read_im16(env, dc);

    opcode_table[insn](env, dc, insn);
    do_writebacks(dc);
    do_release(dc);

    dc->base.pc_next = dc->pc;

    if (dc->base.is_jmp == DISAS_NEXT) {
        /*
         * Stop translation when the next insn might touch a new page.
         * This ensures that prefetch aborts at the right place.
         *
         * We cannot determine the size of the next insn without
         * completely decoding it.  However, the maximum insn size
         * is 32 bytes, so end if we do not have that much remaining.
         * This may produce several small TBs at the end of each page,
         * but they will all be linked with goto_tb.
         *
         * ??? ColdFire maximum is 4 bytes; MC68000's maximum is also
         * smaller than MC68020's.
         */
        target_ulong start_page_offset
            = dc->pc - (dc->base.pc_first & TARGET_PAGE_MASK);

        if (start_page_offset >= TARGET_PAGE_SIZE - 32) {
            dc->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static void m68k_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = dc->uc->tcg_ctx;

    switch (dc->base.is_jmp) {
    case DISAS_NORETURN:
        break;
    case DISAS_TOO_MANY:
        update_cc_op(dc);
        if (dc->base.singlestep_enabled) {
            tcg_gen_movi_i32(tcg_ctx, QREG_PC, dc->pc);
            gen_raise_exception(tcg_ctx, EXCP_DEBUG);
        } else {
            gen_jmp_tb(dc, 0, dc->pc);
        }
        break;
    case DISAS_JUMP:
        /* We updated CC_OP and PC in gen_jmp/gen_jmp_im.  */
        if (dc->base.singlestep_enabled) {
            gen_raise_exception(tcg_ctx, EXCP_DEBUG);
        } else {
            tcg_gen_lookup_and_goto_ptr(tcg_ctx);
        }
        break;
    case DISAS_EXIT:
        /*
         * We updated CC_OP and PC in gen_exit_tb, but also modified
         * other state that may require returning to the main loop.
         */
        if (dc->base.singlestep_enabled) {
            gen_raise_exception(tcg_ctx, EXCP_DEBUG);
        } else {
            tcg_gen_exit_tb(tcg_ctx, NULL, 0);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps m68k_tr_ops = {
    .init_disas_context = m68k_tr_init_disas_context,
    .tb_start           = m68k_tr_tb_start,
    .insn_start         = m68k_tr_insn_start,
    .breakpoint_check   = m68k_tr_breakpoint_check,
    .translate_insn     = m68k_tr_translate_insn,
    .tb_stop            = m68k_tr_tb_stop,
};

void gen_intermediate_code(CPUState *cpu, TranslationBlock *tb, int max_insns)
{
    DisasContext dc;

    memset(&dc, 0, sizeof(dc));
    translator_loop(&m68k_tr_ops, &dc.base, cpu, tb, max_insns);
}

#if 0
static double floatx80_to_double(CPUM68KState *env, uint16_t high, uint64_t low)
{
    floatx80 a = { .high = high, .low = low };
    union {
        float64 f64;
        double d;
    } u;

    u.f64 = floatx80_to_float64(a, &env->fp_status);
    return u.d;
}
#endif

void restore_state_to_opc(CPUM68KState *env, TranslationBlock *tb,
                          target_ulong *data)
{
    int cc_op = data[1];
    env->pc = data[0];
    if (cc_op != CC_OP_DYNAMIC) {
        env->cc_op = cc_op;
    }
}
