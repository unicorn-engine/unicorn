/*
 * RISC-V emulation for qemu: main translation routines.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "tcg/tcg-op.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "exec/translator.h"

#include "instmap.h"

#include "unicorn/platform.h"
#include "uc_priv.h"

#include "exec/gen-icount.h"

/*
 * Unicorn: Special disas state for exiting in the middle of tb.
 */
#define DISAS_UC_EXIT    DISAS_TARGET_6

typedef struct DisasContext {
    DisasContextBase base;
    /* pc_succ_insn points to the instruction following base.pc_next */
    target_ulong pc_succ_insn;
    target_ulong priv_ver;
    bool virt_enabled;
    uint32_t opcode;
    uint32_t mstatus_fs;
    uint32_t misa;
    uint32_t mem_idx;
    /* Remember the rounding mode encoded in the previous fp instruction,
       which we have already installed into env->fp_status.  Or -1 for
       no previous fp instruction.  Note that we exit the TB when writing
       to any system register, which includes CSR_FRM, so we do not have
       to reset this known value.  */
    int frm;
    bool ext_ifencei;

    // Unicorn
    struct uc_struct *uc;
    bool invalid;   // invalid instruction, discoverd by translator
} DisasContext;

#ifdef TARGET_RISCV64
/* convert riscv funct3 to qemu memop for load/store */
static const int tcg_memop_lookup[8] = {
    // [0 ... 7] = -1,
    [0] = MO_SB,
    [1] = MO_TESW,
    [2] = MO_TESL,
    [3] = MO_TEQ,
    [4] = MO_UB,
    [5] = MO_TEUW,
    [6] = MO_TEUL,
    [7] = -1,
};
#endif

#ifdef TARGET_RISCV64
#define CASE_OP_32_64(X) case X: case glue(X, W)
#else
#define CASE_OP_32_64(X) case X
#endif

static inline bool has_ext(DisasContext *ctx, uint32_t ext)
{
    return ctx->misa & ext;
}

static void generate_exception(DisasContext *ctx, int excp)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);
    TCGv_i32 helper_tmp = tcg_const_i32(tcg_ctx, excp);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, helper_tmp);
    tcg_temp_free_i32(tcg_ctx, helper_tmp);
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void generate_exception_mbadaddr(DisasContext *ctx, int excp)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);
    tcg_gen_st_tl(tcg_ctx, tcg_ctx->cpu_pc, tcg_ctx->cpu_env, offsetof(CPURISCVState, badaddr));
    TCGv_i32 helper_tmp = tcg_const_i32(tcg_ctx, excp);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, helper_tmp);
    tcg_temp_free_i32(tcg_ctx, helper_tmp);
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_exception_debug(TCGContext *tcg_ctx)
{
    TCGv_i32 helper_tmp = tcg_const_i32(tcg_ctx, EXCP_DEBUG);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, helper_tmp);
    tcg_temp_free_i32(tcg_ctx, helper_tmp);
}

/* Wrapper around tcg_gen_exit_tb that handles single stepping */
static void exit_tb(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (ctx->base.singlestep_enabled) {
        gen_exception_debug(tcg_ctx);
    } else {
        tcg_gen_exit_tb(tcg_ctx, NULL, 0);
    }
}

/* Wrapper around tcg_gen_lookup_and_goto_ptr that handles single stepping */
static void lookup_and_goto_ptr(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (ctx->base.singlestep_enabled) {
        gen_exception_debug(tcg_ctx);
    } else {
        tcg_gen_lookup_and_goto_ptr(tcg_ctx);
    }
}

static void gen_exception_illegal(DisasContext *ctx)
{
    generate_exception(ctx, RISCV_EXCP_ILLEGAL_INST);
}

static void gen_exception_inst_addr_mis(DisasContext *ctx)
{
    generate_exception_mbadaddr(ctx, RISCV_EXCP_INST_ADDR_MIS);
}

static inline bool use_goto_tb(DisasContext *ctx, target_ulong dest)
{
    if (unlikely(ctx->base.singlestep_enabled)) {
        return false;
    }

    return (ctx->base.tb->pc & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK);
}

static void gen_goto_tb(DisasContext *ctx, int n, target_ulong dest)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (use_goto_tb(ctx, dest)) {
        /* chaining is only allowed when the jump is to the same page */
        tcg_gen_goto_tb(tcg_ctx, n);
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, dest);

        /* No need to check for single stepping here as use_goto_tb() will
         * return false in case of single stepping.
         */
        tcg_gen_exit_tb(tcg_ctx, ctx->base.tb, n);
    } else {
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, dest);
        lookup_and_goto_ptr(ctx);
    }
}

/* Wrapper for getting reg values - need to check of reg is zero since
 * cpu_gpr[0] is not actually allocated
 */
static inline void gen_get_gpr(TCGContext *tcg_ctx, TCGv t, int reg_num)
{
    if (reg_num == 0) {
        tcg_gen_movi_tl(tcg_ctx, t, 0);
    } else {
        tcg_gen_mov_tl(tcg_ctx, t, tcg_ctx->cpu_gpr[reg_num]);
    }
}

/* Wrapper for setting reg values - need to check of reg is zero since
 * cpu_gpr[0] is not actually allocated. this is more for safety purposes,
 * since we usually avoid calling the OP_TYPE_gen function if we see a write to
 * $zero
 */
static inline void gen_set_gpr(TCGContext *tcg_ctx, int reg_num_dst, TCGv t)
{
    if (reg_num_dst != 0) {
        tcg_gen_mov_tl(tcg_ctx, tcg_ctx->cpu_gpr[reg_num_dst], t);
    }
}

static void gen_mulhsu(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    TCGv rl = tcg_temp_new(tcg_ctx);
    TCGv rh = tcg_temp_new(tcg_ctx);

    tcg_gen_mulu2_tl(tcg_ctx, rl, rh, arg1, arg2);
    /* fix up for one negative */
    tcg_gen_sari_tl(tcg_ctx, rl, arg1, TARGET_LONG_BITS - 1);
    tcg_gen_and_tl(tcg_ctx, rl, rl, arg2);
    tcg_gen_sub_tl(tcg_ctx, ret, rh, rl);

    tcg_temp_free(tcg_ctx, rl);
    tcg_temp_free(tcg_ctx, rh);
}

static void gen_div(TCGContext *tcg_ctx, TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, cond2, zeroreg, resultopt1;
    /*
     * Handle by altering args to tcg_gen_div to produce req'd results:
     * For overflow: want source1 in source1 and 1 in source2
     * For div by zero: want -1 in source1 and 1 in source2 -> -1 result
     */
    cond1 = tcg_temp_new(tcg_ctx);
    cond2 = tcg_temp_new(tcg_ctx);
    zeroreg = tcg_const_tl(tcg_ctx, 0);
    resultopt1 = tcg_temp_new(tcg_ctx);

    tcg_gen_movi_tl(tcg_ctx, resultopt1, (target_ulong)-1);
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond2, source2, (target_ulong)(~0L));
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond1, source1,
                        ((target_ulong)1) << (TARGET_LONG_BITS - 1));
    tcg_gen_and_tl(tcg_ctx, cond1, cond1, cond2); /* cond1 = overflow */
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond2, source2, 0); /* cond2 = div 0 */
    /* if div by zero, set source1 to -1, otherwise don't change */
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, source1, cond2, zeroreg, source1,
            resultopt1);
    /* if overflow or div by zero, set source2 to 1, else don't change */
    tcg_gen_or_tl(tcg_ctx, cond1, cond1, cond2);
    tcg_gen_movi_tl(tcg_ctx, resultopt1, (target_ulong)1);
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, source2, cond1, zeroreg, source2,
            resultopt1);
    tcg_gen_div_tl(tcg_ctx, ret, source1, source2);

    tcg_temp_free(tcg_ctx, cond1);
    tcg_temp_free(tcg_ctx, cond2);
    tcg_temp_free(tcg_ctx, zeroreg);
    tcg_temp_free(tcg_ctx, resultopt1);
}

static void gen_divu(TCGContext *tcg_ctx, TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, zeroreg, resultopt1;
    cond1 = tcg_temp_new(tcg_ctx);

    zeroreg = tcg_const_tl(tcg_ctx, 0);
    resultopt1 = tcg_temp_new(tcg_ctx);

    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond1, source2, 0);
    tcg_gen_movi_tl(tcg_ctx, resultopt1, (target_ulong)-1);
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, source1, cond1, zeroreg, source1,
            resultopt1);
    tcg_gen_movi_tl(tcg_ctx, resultopt1, (target_ulong)1);
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, source2, cond1, zeroreg, source2,
            resultopt1);
    tcg_gen_divu_tl(tcg_ctx, ret, source1, source2);

    tcg_temp_free(tcg_ctx, cond1);
    tcg_temp_free(tcg_ctx, zeroreg);
    tcg_temp_free(tcg_ctx, resultopt1);
}

static void gen_rem(TCGContext *tcg_ctx, TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, cond2, zeroreg, resultopt1;

    cond1 = tcg_temp_new(tcg_ctx);
    cond2 = tcg_temp_new(tcg_ctx);
    zeroreg = tcg_const_tl(tcg_ctx, 0);
    resultopt1 = tcg_temp_new(tcg_ctx);

    tcg_gen_movi_tl(tcg_ctx, resultopt1, 1L);
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond2, source2, (target_ulong)-1);
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond1, source1,
                        (target_ulong)1 << (TARGET_LONG_BITS - 1));
    tcg_gen_and_tl(tcg_ctx, cond2, cond1, cond2); /* cond1 = overflow */
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond1, source2, 0); /* cond2 = div 0 */
    /* if overflow or div by zero, set source2 to 1, else don't change */
    tcg_gen_or_tl(tcg_ctx, cond2, cond1, cond2);
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, source2, cond2, zeroreg, source2,
            resultopt1);
    tcg_gen_rem_tl(tcg_ctx, resultopt1, source1, source2);
    /* if div by zero, just return the original dividend */
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, ret, cond1, zeroreg, resultopt1,
            source1);

    tcg_temp_free(tcg_ctx, cond1);
    tcg_temp_free(tcg_ctx, cond2);
    tcg_temp_free(tcg_ctx, zeroreg);
    tcg_temp_free(tcg_ctx, resultopt1);
}

static void gen_remu(TCGContext *tcg_ctx, TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, zeroreg, resultopt1;
    cond1 = tcg_temp_new(tcg_ctx);
    zeroreg = tcg_const_tl(tcg_ctx, 0);
    resultopt1 = tcg_temp_new(tcg_ctx);

    tcg_gen_movi_tl(tcg_ctx, resultopt1, (target_ulong)1);
    tcg_gen_setcondi_tl(tcg_ctx, TCG_COND_EQ, cond1, source2, 0);
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, source2, cond1, zeroreg, source2,
            resultopt1);
    tcg_gen_remu_tl(tcg_ctx, resultopt1, source1, source2);
    /* if div by zero, just return the original dividend */
    tcg_gen_movcond_tl(tcg_ctx, TCG_COND_EQ, ret, cond1, zeroreg, resultopt1,
            source1);

    tcg_temp_free(tcg_ctx, cond1);
    tcg_temp_free(tcg_ctx, zeroreg);
    tcg_temp_free(tcg_ctx, resultopt1);
}

static void gen_jal(DisasContext *ctx, int rd, target_ulong imm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    target_ulong next_pc;

    /* check misaligned: */
    next_pc = ctx->base.pc_next + imm;
    if (!has_ext(ctx, RVC)) {
        if ((next_pc & 0x3) != 0) {
            gen_exception_inst_addr_mis(ctx);
            return;
        }
    }
    if (rd != 0) {
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr[rd], ctx->pc_succ_insn);
    }

    gen_goto_tb(ctx, 0, ctx->base.pc_next + imm); /* must use this for safety */
    ctx->base.is_jmp = DISAS_NORETURN;
}

#ifdef TARGET_RISCV64
static void gen_load_c(DisasContext *ctx, uint32_t opc, int rd, int rs1,
        target_long imm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, imm);
    int memop = tcg_memop_lookup[(opc >> 12) & 0x7];

    if (memop < 0) {
        gen_exception_illegal(ctx);
        return;
    }

    tcg_gen_qemu_ld_tl(tcg_ctx, t1, t0, ctx->mem_idx, memop);
    gen_set_gpr(tcg_ctx, rd, t1);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
}

static void gen_store_c(DisasContext *ctx, uint32_t opc, int rs1, int rs2,
        target_long imm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv dat = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, t0, rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, imm);
    gen_get_gpr(tcg_ctx, dat, rs2);
    int memop = tcg_memop_lookup[(opc >> 12) & 0x7];

    if (memop < 0) {
        gen_exception_illegal(ctx);
        return;
    }

    tcg_gen_qemu_st_tl(tcg_ctx, dat, t0, ctx->mem_idx, memop);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, dat);
}
#endif

/* The states of mstatus_fs are:
 * 0 = disabled, 1 = initial, 2 = clean, 3 = dirty
 * We will have already diagnosed disabled state,
 * and need to turn initial/clean into dirty.
 */
static void mark_fs_dirty(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv tmp;
    if (ctx->mstatus_fs == MSTATUS_FS) {
        return;
    }
    /* Remember the state change for the rest of the TB.  */
    ctx->mstatus_fs = MSTATUS_FS;

    tmp = tcg_temp_new(tcg_ctx);
    tcg_gen_ld_tl(tcg_ctx, tmp, tcg_ctx->cpu_env, offsetof(CPURISCVState, mstatus));
    tcg_gen_ori_tl(tcg_ctx, tmp, tmp, MSTATUS_FS | MSTATUS_SD);
    tcg_gen_st_tl(tcg_ctx, tmp, tcg_ctx->cpu_env, offsetof(CPURISCVState, mstatus));

    if (ctx->virt_enabled) {
        tcg_gen_ld_tl(tcg_ctx, tmp, tcg_ctx->cpu_env, offsetof(CPURISCVState, mstatus_hs));
        tcg_gen_ori_tl(tcg_ctx, tmp, tmp, MSTATUS_FS | MSTATUS_SD);
        tcg_gen_st_tl(tcg_ctx, tmp, tcg_ctx->cpu_env, offsetof(CPURISCVState, mstatus_hs));
    }
    tcg_temp_free(tcg_ctx, tmp);
}

#if !defined(TARGET_RISCV64)
static void gen_fp_load(DisasContext *ctx, uint32_t opc, int rd,
        int rs1, target_long imm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0;

    if (ctx->mstatus_fs == 0) {
        gen_exception_illegal(ctx);
        return;
    }

    t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, imm);

    switch (opc) {
    case OPC_RISC_FLW:
        if (!has_ext(ctx, RVF)) {
            goto do_illegal;
        }
        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_fpr[rd], t0, ctx->mem_idx, MO_TEUL);
        /* RISC-V requires NaN-boxing of narrower width floating point values */
        tcg_gen_ori_i64(tcg_ctx, tcg_ctx->cpu_fpr[rd], tcg_ctx->cpu_fpr[rd], 0xffffffff00000000ULL);
        break;
    case OPC_RISC_FLD:
        if (!has_ext(ctx, RVD)) {
            goto do_illegal;
        }
        tcg_gen_qemu_ld_i64(tcg_ctx, tcg_ctx->cpu_fpr[rd], t0, ctx->mem_idx, MO_TEQ);
        break;
    do_illegal:
    default:
        gen_exception_illegal(ctx);
        break;
    }
    tcg_temp_free(tcg_ctx, t0);

    mark_fs_dirty(ctx);
}

static void gen_fp_store(DisasContext *ctx, uint32_t opc, int rs1,
        int rs2, target_long imm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0;

    if (ctx->mstatus_fs == 0) {
        gen_exception_illegal(ctx);
        return;
    }

    t0 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, imm);

    switch (opc) {
    case OPC_RISC_FSW:
        if (!has_ext(ctx, RVF)) {
            goto do_illegal;
        }
        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_fpr[rs2], t0, ctx->mem_idx, MO_TEUL);
        break;
    case OPC_RISC_FSD:
        if (!has_ext(ctx, RVD)) {
            goto do_illegal;
        }
        tcg_gen_qemu_st_i64(tcg_ctx, tcg_ctx->cpu_fpr[rs2], t0, ctx->mem_idx, MO_TEQ);
        break;
    do_illegal:
    default:
        gen_exception_illegal(ctx);
        break;
    }

    tcg_temp_free(tcg_ctx, t0);
}
#endif

static void gen_set_rm(DisasContext *ctx, int rm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t0;

    if (ctx->frm == rm) {
        return;
    }
    ctx->frm = rm;
    t0 = tcg_const_i32(tcg_ctx, rm);
    gen_helper_set_rounding_mode(tcg_ctx, tcg_ctx->cpu_env, t0);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void decode_RV32_64C0(DisasContext *ctx, uint16_t opcode)
{
    uint8_t funct3 = extract16(opcode, 13, 3);
    uint8_t rd_rs2 = GET_C_RS2S(opcode);
    uint8_t rs1s = GET_C_RS1S(opcode);

    switch (funct3) {
    case 3:
#if defined(TARGET_RISCV64)
        /* C.LD(RV64/128) -> ld rd', offset[7:3](rs1')*/
        gen_load_c(ctx, OPC_RISC_LD, rd_rs2, rs1s,
                 GET_C_LD_IMM(opcode));
#else
        /* C.FLW (RV32) -> flw rd', offset[6:2](rs1')*/
        gen_fp_load(ctx, OPC_RISC_FLW, rd_rs2, rs1s,
                    GET_C_LW_IMM(opcode));
#endif
        break;
    case 7:
#if defined(TARGET_RISCV64)
        /* C.SD (RV64/128) -> sd rs2', offset[7:3](rs1')*/
        gen_store_c(ctx, OPC_RISC_SD, rs1s, rd_rs2,
                  GET_C_LD_IMM(opcode));
#else
        /* C.FSW (RV32) -> fsw rs2', offset[6:2](rs1')*/
        gen_fp_store(ctx, OPC_RISC_FSW, rs1s, rd_rs2,
                     GET_C_LW_IMM(opcode));
#endif
        break;
    }
}

static void decode_RV32_64C(DisasContext *ctx, uint16_t opcode)
{
    uint8_t op = extract16(opcode, 0, 2);

    switch (op) {
    case 0:
        decode_RV32_64C0(ctx, opcode);
        break;
    }
}

#define EX_SH(amount) \
    static int ex_shift_##amount(DisasContext *ctx, int imm) \
    {                                         \
        return imm << amount;                 \
    }
EX_SH(1)
EX_SH(2)
EX_SH(3)
EX_SH(4)
EX_SH(12)

#define REQUIRE_EXT(ctx, ext) do { \
    if (!has_ext(ctx, ext)) {      \
        return false;              \
    }                              \
} while (0)

static int ex_rvc_register(DisasContext *ctx, int reg)
{
    return 8 + reg;
}

static int ex_rvc_shifti(DisasContext *ctx, int imm)
{
    /* For RV128 a shamt of 0 means a shift by 64. */
    return imm ? imm : 64;
}

/* Include the auto-generated decoder for 32 bit insn */
#ifdef TARGET_RISCV32
#include "riscv32/decode_insn32.inc.c"
#else
#include "riscv64/decode_insn32.inc.c"
#endif

static bool gen_arith_imm_fn(DisasContext *ctx, arg_i *a,
                             void (*func)(TCGContext *, TCGv, TCGv, target_long))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1;
    source1 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);

    (*func)(tcg_ctx, source1, source1, a->imm);

    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    return true;
}

static bool gen_arith_imm_tl(DisasContext *ctx, arg_i *a,
                             void (*func)(TCGContext *, TCGv, TCGv, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, source2;
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    tcg_gen_movi_tl(tcg_ctx, source2, a->imm);

    (*func)(tcg_ctx, source1, source1, source2);

    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

#ifdef TARGET_RISCV64
static void gen_addw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_add_tl(tcg_ctx, ret, arg1, arg2);
    tcg_gen_ext32s_tl(tcg_ctx, ret, ret);
}

static void gen_subw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_sub_tl(tcg_ctx, ret, arg1, arg2);
    tcg_gen_ext32s_tl(tcg_ctx, ret, ret);
}

static void gen_mulw(TCGContext *tcg_ctx, TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_mul_tl(tcg_ctx, ret, arg1, arg2);
    tcg_gen_ext32s_tl(tcg_ctx, ret, ret);
}

static bool gen_arith_div_w(TCGContext *tcg_ctx, arg_r *a,
                            void(*func)(TCGContext *, TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    tcg_gen_ext32s_tl(tcg_ctx, source2, source2);

    (*func)(tcg_ctx, source1, source1, source2);

    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

static bool gen_arith_div_uw(TCGContext *tcg_ctx, arg_r *a,
                            void(*func)(TCGContext *, TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);
    tcg_gen_ext32u_tl(tcg_ctx, source1, source1);
    tcg_gen_ext32u_tl(tcg_ctx, source2, source2);

    (*func)(tcg_ctx, source1, source1, source2);

    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

#endif

static bool gen_arith(TCGContext *tcg_ctx, arg_r *a,
                      void(*func)(TCGContext *, TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);

    (*func)(tcg_ctx, source1, source1, source2);

    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

static bool gen_shift(DisasContext *ctx, arg_r *a,
                        void(*func)(TCGContext *, TCGv, TCGv, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);

    tcg_gen_andi_tl(tcg_ctx, source2, source2, TARGET_LONG_BITS - 1);
    (*func)(tcg_ctx, source1, source1, source2);

    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

/* Include insn module translation function */
#include "insn_trans/trans_rvi.inc.c"
#include "insn_trans/trans_rvm.inc.c"
#include "insn_trans/trans_rva.inc.c"
#include "insn_trans/trans_rvf.inc.c"
#include "insn_trans/trans_rvd.inc.c"
#include "insn_trans/trans_privileged.inc.c"

/* Include the auto-generated decoder for 16 bit insn */
#ifdef TARGET_RISCV32
#include "riscv32/decode_insn16.inc.c"
#else
#include "riscv64/decode_insn16.inc.c"
#endif

static void decode_opc(CPURISCVState *env, DisasContext *ctx, uint16_t opcode)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /* check for compressed insn */
    if (extract16(opcode, 0, 2) != 3) {
        if (!has_ext(ctx, RVC)) {
            gen_exception_illegal(ctx);
        } else {
            ctx->invalid = false;
            ctx->pc_succ_insn = ctx->base.pc_next + 2;
            if (!decode_insn16(ctx, opcode)) {
                /* fall back to old decoder */
                decode_RV32_64C(ctx, opcode);
            } else {
                // invalid instruction does not advance PC
                if (ctx->invalid) {
                    ctx->pc_succ_insn -= 2;
                }
            }
        }
    } else {
        uint32_t opcode32 = opcode;
        opcode32 = deposit32(opcode32, 16, 16,
                             translator_lduw(tcg_ctx, env, ctx->base.pc_next + 2));
        ctx->pc_succ_insn = ctx->base.pc_next + 4;
        if (!decode_insn32(ctx, opcode32)) {
            ctx->pc_succ_insn = ctx->base.pc_next - 4;
            gen_exception_illegal(ctx);
        }
    }
}

static void riscv_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPURISCVState *env = cs->env_ptr;
    RISCVCPU *cpu = RISCV_CPU(cs);

    // unicorn setup
    ctx->uc = cs->uc;

    ctx->pc_succ_insn = ctx->base.pc_first;
    ctx->mem_idx = ctx->base.tb->flags & TB_FLAGS_MMU_MASK;
    ctx->mstatus_fs = ctx->base.tb->flags & TB_FLAGS_MSTATUS_FS;
    ctx->priv_ver = env->priv_ver;

    if (riscv_has_ext(env, RVH)) {
        ctx->virt_enabled = riscv_cpu_virt_enabled(env);
        if (env->priv_ver == PRV_M &&
            get_field(env->mstatus, MSTATUS_MPRV) &&
            MSTATUS_MPV_ISSET(env)) {
            ctx->virt_enabled = true;
        } else if (env->priv == PRV_S &&
                   !riscv_cpu_virt_enabled(env) &&
                   get_field(env->hstatus, HSTATUS_SPRV) &&
                   get_field(env->hstatus, HSTATUS_SPV)) {
            ctx->virt_enabled = true;
        }
    } else {
        ctx->virt_enabled = false;
    }

    ctx->misa = env->misa;
    ctx->frm = -1;  /* unknown rounding mode */
    ctx->ext_ifencei = cpu->cfg.ext_ifencei;
}

static void riscv_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void riscv_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    tcg_gen_insn_start(tcg_ctx, ctx->base.pc_next);
}

static bool riscv_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                      const CPUBreakpoint *bp)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);
    ctx->base.is_jmp = DISAS_NORETURN;
    gen_exception_debug(tcg_ctx);
    /* The address covered by the breakpoint must be included in
       [tb->pc, tb->pc + tb->size) in order to for it to be
       properly cleared -- thus we increment the PC here so that
       the logic setting tb->size below does the right thing.  */
    ctx->base.pc_next += 4;
    return true;
}

static void riscv_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    struct uc_struct *uc = ctx->uc;
    TCGContext *tcg_ctx = uc->tcg_ctx;
    CPURISCVState *env = cpu->env_ptr;
    uint16_t opcode16 = translator_lduw(tcg_ctx, env, ctx->base.pc_next);
    TCGOp *tcg_op, *prev_op = NULL;
    bool insn_hook = false;

    // Unicorn: end address tells us to stop emulation
    if (uc_addr_is_exit(uc, ctx->base.pc_next)) {
        // Unicorn: We have to exit current execution here.
        dcbase->is_jmp = DISAS_UC_EXIT;
    } else {
        // Unicorn: trace this instruction on request
        if (HOOK_EXISTS_BOUNDED(uc, UC_HOOK_CODE, ctx->base.pc_next)) {

            // Sync PC in advance
            tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);

            // save the last operand
            prev_op = tcg_last_op(tcg_ctx);
            insn_hook = true;
            gen_uc_tracecode(tcg_ctx, 4, UC_HOOK_CODE_IDX, uc, ctx->base.pc_next);
            // the callback might want to stop emulation immediately
            check_exit_request(tcg_ctx);
        }

        decode_opc(env, ctx, opcode16);

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
                // so the instruction operand is the first operand
                tcg_op = QTAILQ_FIRST(&tcg_ctx->ops);
            }

            tcg_op->args[1] = ctx->pc_succ_insn - ctx->base.pc_next;
        }

        ctx->base.pc_next = ctx->pc_succ_insn;

        if (ctx->base.is_jmp == DISAS_NEXT) {
            target_ulong page_start;

            page_start = ctx->base.pc_first & TARGET_PAGE_MASK;
            if (ctx->base.pc_next - page_start >= TARGET_PAGE_SIZE) {
                ctx->base.is_jmp = DISAS_TOO_MANY;
            }
        }
    }
}

static void riscv_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    switch (ctx->base.is_jmp) {
    case DISAS_TOO_MANY:
        gen_goto_tb(ctx, 0, ctx->base.pc_next);
        break;
    case DISAS_NORETURN:
        break;
    case DISAS_UC_EXIT:
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);
        gen_helper_uc_riscv_exit(ctx->uc->tcg_ctx, ctx->uc->tcg_ctx->cpu_env);
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps riscv_tr_ops = {
    .init_disas_context = riscv_tr_init_disas_context,
    .tb_start           = riscv_tr_tb_start,
    .insn_start         = riscv_tr_insn_start,
    .breakpoint_check   = riscv_tr_breakpoint_check,
    .translate_insn     = riscv_tr_translate_insn,
    .tb_stop            = riscv_tr_tb_stop,
};

void gen_intermediate_code(CPUState *cs, TranslationBlock *tb, int max_insns)
{
    DisasContext ctx;

    memset(&ctx, 0, sizeof(ctx));
    translator_loop(&riscv_tr_ops, &ctx.base, cs, tb, max_insns);
}

void riscv_translate_init(struct uc_struct *uc)
{
    int i;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    /* cpu_gpr[0] is a placeholder for the zero register. Do not use it. */
    /* Use the gen_set_gpr and gen_get_gpr helper functions when accessing */
    /* registers, unless you specifically block reads/writes to reg 0 */
    tcg_ctx->cpu_gpr[0] = NULL;

    for (i = 1; i < 32; i++) {
        tcg_ctx->cpu_gpr[i] = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env,
            offsetof(CPURISCVState, gpr[i]), riscv_int_regnames[i]);
    }

    for (i = 0; i < 32; i++) {
        tcg_ctx->cpu_fpr[i] = tcg_global_mem_new_i64(tcg_ctx, tcg_ctx->cpu_env,
            offsetof(CPURISCVState, fpr[i]), riscv_fpr_regnames[i]);
    }

    tcg_ctx->cpu_pc = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPURISCVState, pc), "pc");
    tcg_ctx->load_res = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPURISCVState, load_res),
                             "load_res");
    tcg_ctx->load_val = tcg_global_mem_new(tcg_ctx, tcg_ctx->cpu_env, offsetof(CPURISCVState, load_val),
                             "load_val");
}
