/*
 * RISC-V translation routines for the RVXI Base Integer Instruction Set.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2018 Peer Adelt, peer.adelt@hni.uni-paderborn.de
 *                    Bastian Koppelmann, kbastian@mail.uni-paderborn.de
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

#define GEN_RISCV_INSN_HOOK(ctx, type, insn_id, ...)                     \
    do {                                                                 \
        if (HOOK_EXISTS((ctx)->uc, UC_HOOK_INSN)) {                      \
            gen_insn_hook_##type((ctx), (insn_id), __VA_ARGS__);         \
        }                                                                \
    } while (0)

#define GEN_RISCV_RTYPE_INSN_HOOK(insn_id) GEN_RISCV_INSN_HOOK(ctx, rtype, (uint32_t)insn_id, (uint32_t)a->rs1, (uint32_t)a->rs2, (uint32_t)a->rd)
#define GEN_RISCV_ITYPE_INSN_HOOK(insn_id) GEN_RISCV_INSN_HOOK(ctx, itype, (uint32_t)insn_id, (uint32_t)a->imm, (uint32_t)a->rs1, (uint32_t)a->rd)
#define GEN_RISCV_STYPE_INSN_HOOK(insn_id) GEN_RISCV_INSN_HOOK(ctx, stype, (uint32_t)insn_id, (uint32_t)a->imm, (uint32_t)a->rs1, (uint32_t)a->rs2)
#define GEN_RISCV_UTYPE_INSN_HOOK(insn_id) GEN_RISCV_INSN_HOOK(ctx, utype, (uint32_t)insn_id, (uint32_t)a->imm, (uint32_t)a->rd)

// SHIFT, FENCE and CSR instructions are structurally Integer Register-Immediate instructions 
// These macros are direct binding to I-type instruction hooks
// cf: The RISC-V Instruction Set Manual, Volume I: Unprivileged Architecture - 2.4.1. Integer Register-Immediate Instructions
// FENCE type has no meta macro as FENCE and FENCE.I instructions sends different datas to the callback handler
#define GEN_RISCV_SHAMT_TYPE_INSN_HOOK(insn_id) GEN_RISCV_INSN_HOOK(ctx, itype, (uint32_t)insn_id, (uint32_t)a->shamt, (uint32_t)a->rs1, (uint32_t)a->rd)
#define GEN_RISCV_CSR_TYPE_INSN_HOOK(insn_id) GEN_RISCV_INSN_HOOK(ctx, itype, (uint32_t)insn_id, (uint32_t)a->csr, (uint32_t)a->rs1, (uint32_t)a->rd)

static bool trans_illegal(DisasContext *ctx, arg_empty *a)
{
    gen_exception_illegal(ctx);

    return true;
}

static bool trans_lui(DisasContext *ctx, arg_lui *a)
{
    GEN_RISCV_UTYPE_INSN_HOOK(UC_RISCV_INS_LUI);
    if (a->rd != 0) {
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr[a->rd], a->imm);
    }
    return true;
}

static bool trans_auipc(DisasContext *ctx, arg_auipc *a)
{
    GEN_RISCV_UTYPE_INSN_HOOK(UC_RISCV_INS_AUIPC);
    if (a->rd != 0) {
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr[a->rd], a->imm + ctx->base.pc_next);
    }
    return true;
}

static bool trans_jal(DisasContext *ctx, arg_jal *a)
{
    GEN_RISCV_UTYPE_INSN_HOOK(UC_RISCV_INS_JAL);
    gen_jal(ctx, a->rd, a->imm);
    return true;
}

static bool trans_jalr(DisasContext *ctx, arg_jalr *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_JALR);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    /* no chaining with JALR */
    TCGLabel *misaligned = NULL;
    TCGv t0 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, tcg_ctx->cpu_pc, a->rs1);
    tcg_gen_addi_tl(tcg_ctx, tcg_ctx->cpu_pc, tcg_ctx->cpu_pc, a->imm);
    tcg_gen_andi_tl(tcg_ctx, tcg_ctx->cpu_pc, tcg_ctx->cpu_pc, (target_ulong)-2);

    if (!has_ext(ctx, RVC)) {
        misaligned = gen_new_label(tcg_ctx);
        tcg_gen_andi_tl(tcg_ctx, t0, tcg_ctx->cpu_pc, 0x2);
        tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_NE, t0, 0x0, misaligned);
    }

    if (a->rd != 0) {
        tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_gpr[a->rd], ctx->pc_succ_insn);
    }
    lookup_and_goto_ptr(ctx);

    if (misaligned) {
        gen_set_label(tcg_ctx, misaligned);
        gen_exception_inst_addr_mis(ctx);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, t0);
    return true;
}

static bool gen_branch(DisasContext *ctx, arg_b *a, TCGCond cond)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *l = gen_new_label(tcg_ctx);
    TCGv source1, source2;
    source1 = tcg_temp_new(tcg_ctx);
    source2 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);

    tcg_gen_brcond_tl(tcg_ctx, cond, source1, source2, l);
    gen_goto_tb(ctx, 1, ctx->pc_succ_insn);
    gen_set_label(tcg_ctx, l); /* branch taken */

    if (!has_ext(ctx, RVC) && ((ctx->base.pc_next + a->imm) & 0x3)) {
        /* misaligned */
        gen_exception_inst_addr_mis(ctx);
    } else {
        gen_goto_tb(ctx, 0, ctx->base.pc_next + a->imm);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);

    return true;
}

static bool trans_beq(DisasContext *ctx, arg_beq *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_BEQ);
    return gen_branch(ctx, a, TCG_COND_EQ);
}

static bool trans_bne(DisasContext *ctx, arg_bne *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_BNE);
    return gen_branch(ctx, a, TCG_COND_NE);
}

static bool trans_blt(DisasContext *ctx, arg_blt *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_BLT);
    return gen_branch(ctx, a, TCG_COND_LT);
}

static bool trans_bge(DisasContext *ctx, arg_bge *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_BGE);
    return gen_branch(ctx, a, TCG_COND_GE);
}

static bool trans_bltu(DisasContext *ctx, arg_bltu *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_BLTU);
    return gen_branch(ctx, a, TCG_COND_LTU);
}

static bool trans_bgeu(DisasContext *ctx, arg_bgeu *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_BGEU);
    return gen_branch(ctx, a, TCG_COND_GEU);
}

static bool gen_load(DisasContext *ctx, arg_lb *a, MemOp memop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv t1 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);

    tcg_gen_qemu_ld_tl(tcg_ctx, t1, t0, ctx->mem_idx, memop);
    gen_set_gpr(tcg_ctx, a->rd, t1);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    return true;
}

static bool trans_lb(DisasContext *ctx, arg_lb *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LB);
    return gen_load(ctx, a, MO_SB);
}

static bool trans_lh(DisasContext *ctx, arg_lh *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LH);
    return gen_load(ctx, a, MO_TESW);
}

static bool trans_lw(DisasContext *ctx, arg_lw *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LW);
    return gen_load(ctx, a, MO_TESL);
}

static bool trans_lbu(DisasContext *ctx, arg_lbu *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LBU);
    return gen_load(ctx, a, MO_UB);
}

static bool trans_lhu(DisasContext *ctx, arg_lhu *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LHU);
    return gen_load(ctx, a, MO_TEUW);
}

static bool gen_store(DisasContext *ctx, arg_sb *a, MemOp memop)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t0 = tcg_temp_new(tcg_ctx);
    TCGv dat = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t0, a->rs1);
    tcg_gen_addi_tl(tcg_ctx, t0, t0, a->imm);
    gen_get_gpr(tcg_ctx, dat, a->rs2);

    tcg_gen_qemu_st_tl(tcg_ctx, dat, t0, ctx->mem_idx, memop);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, dat);
    return true;
}


static bool trans_sb(DisasContext *ctx, arg_sb *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_SB);
    return gen_store(ctx, a, MO_SB);
}

static bool trans_sh(DisasContext *ctx, arg_sh *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_SH);
    return gen_store(ctx, a, MO_TESW);
}

static bool trans_sw(DisasContext *ctx, arg_sw *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_SW);
    return gen_store(ctx, a, MO_TESL);
}

#ifdef TARGET_RISCV64
static bool trans_lwu(DisasContext *ctx, arg_lwu *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LWU);
    return gen_load(ctx, a, MO_TEUL);
}

static bool trans_ld(DisasContext *ctx, arg_ld *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_LD);
    return gen_load(ctx, a, MO_TEQ);
}

static bool trans_sd(DisasContext *ctx, arg_sd *a)
{
    GEN_RISCV_STYPE_INSN_HOOK(UC_RISCV_INS_SD);
    return gen_store(ctx, a, MO_TEQ);
}
#endif

static bool trans_addi(DisasContext *ctx, arg_addi *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_ADDI);
    return gen_arith_imm_fn(ctx, a, &tcg_gen_addi_tl);
}

static void gen_slt(TCGContext *tcg_ctx, TCGv ret, TCGv s1, TCGv s2)
{
    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_LT, ret, s1, s2);
}

static void gen_sltu(TCGContext *tcg_ctx, TCGv ret, TCGv s1, TCGv s2)
{
    tcg_gen_setcond_tl(tcg_ctx, TCG_COND_LTU, ret, s1, s2);
}


static bool trans_slti(DisasContext *ctx, arg_slti *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_SLTI);
    return gen_arith_imm_tl(ctx, a, &gen_slt);
}

static bool trans_sltiu(DisasContext *ctx, arg_sltiu *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_SLTIU);
    return gen_arith_imm_tl(ctx, a, &gen_sltu);
}

static bool trans_xori(DisasContext *ctx, arg_xori *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_XORI);
    return gen_arith_imm_fn(ctx, a, &tcg_gen_xori_tl);
}
static bool trans_ori(DisasContext *ctx, arg_ori *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_ORI);
    return gen_arith_imm_fn(ctx, a, &tcg_gen_ori_tl);
}
static bool trans_andi(DisasContext *ctx, arg_andi *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_ANDI);
    return gen_arith_imm_fn(ctx, a, &tcg_gen_andi_tl);
}
static bool trans_slli(DisasContext *ctx, arg_slli *a)
{
    GEN_RISCV_SHAMT_TYPE_INSN_HOOK(UC_RISCV_INS_SLLI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (a->shamt >= TARGET_LONG_BITS) {
        return false;
    }

    if (a->rd != 0) {
        TCGv t = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, t, a->rs1);

        tcg_gen_shli_tl(tcg_ctx, t, t, a->shamt);

        gen_set_gpr(tcg_ctx, a->rd, t);
        tcg_temp_free(tcg_ctx, t);
    } /* NOP otherwise */
    return true;
}

static bool trans_srli(DisasContext *ctx, arg_srli *a)
{
    GEN_RISCV_SHAMT_TYPE_INSN_HOOK(UC_RISCV_INS_SRLI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (a->shamt >= TARGET_LONG_BITS) {
        return false;
    }

    if (a->rd != 0) {
        TCGv t = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, t, a->rs1);

        tcg_gen_shri_tl(tcg_ctx, t, t, a->shamt);
        gen_set_gpr(tcg_ctx, a->rd, t);
        tcg_temp_free(tcg_ctx, t);
    } /* NOP otherwise */
    return true;
}

static bool trans_srai(DisasContext *ctx, arg_srai *a)
{
    GEN_RISCV_SHAMT_TYPE_INSN_HOOK(UC_RISCV_INS_SRAI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (a->shamt >= TARGET_LONG_BITS) {
        return false;
    }

    if (a->rd != 0) {
        TCGv t = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, t, a->rs1);

        tcg_gen_sari_tl(tcg_ctx, t, t, a->shamt);
        gen_set_gpr(tcg_ctx, a->rd, t);
        tcg_temp_free(tcg_ctx, t);
    } /* NOP otherwise */
    return true;
}

static bool trans_add(DisasContext *ctx, arg_add *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_ADD);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &tcg_gen_add_tl);
}

static bool trans_sub(DisasContext *ctx, arg_sub *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SUB);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &tcg_gen_sub_tl);
}

static bool trans_sll(DisasContext *ctx, arg_sll *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SLL);
    return gen_shift(ctx, a, &tcg_gen_shl_tl);
}

static bool trans_slt(DisasContext *ctx, arg_slt *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SLT);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &gen_slt);
}

static bool trans_sltu(DisasContext *ctx, arg_sltu *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SLTU);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &gen_sltu);
}

static bool trans_xor(DisasContext *ctx, arg_xor *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_XOR);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &tcg_gen_xor_tl);
}

static bool trans_srl(DisasContext *ctx, arg_srl *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SRL);
    return gen_shift(ctx, a, &tcg_gen_shr_tl);
}

static bool trans_sra(DisasContext *ctx, arg_sra *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SRA);
    return gen_shift(ctx, a, &tcg_gen_sar_tl);
}

static bool trans_or(DisasContext *ctx, arg_or *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_OR);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &tcg_gen_or_tl);
}

static bool trans_and(DisasContext *ctx, arg_and *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_AND);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &tcg_gen_and_tl);
}

#ifdef TARGET_RISCV64
static bool trans_addiw(DisasContext *ctx, arg_addiw *a)
{
    GEN_RISCV_ITYPE_INSN_HOOK(UC_RISCV_INS_ADDIW);
    return gen_arith_imm_tl(ctx, a, &gen_addw);
}

static bool trans_slliw(DisasContext *ctx, arg_slliw *a)
{
    GEN_RISCV_SHAMT_TYPE_INSN_HOOK(UC_RISCV_INS_SLLIW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1;
    source1 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, source1, a->rs1);

    tcg_gen_shli_tl(tcg_ctx, source1, source1, a->shamt);
    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    gen_set_gpr(tcg_ctx, a->rd, source1);

    tcg_temp_free(tcg_ctx, source1);
    return true;
}

static bool trans_srliw(DisasContext *ctx, arg_srliw *a)
{
    GEN_RISCV_SHAMT_TYPE_INSN_HOOK(UC_RISCV_INS_SRLIW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t, a->rs1);
    tcg_gen_extract_tl(tcg_ctx, t, t, a->shamt, 32 - a->shamt);
    /* sign-extend for W instructions */
    tcg_gen_ext32s_tl(tcg_ctx, t, t);
    gen_set_gpr(tcg_ctx, a->rd, t);
    tcg_temp_free(tcg_ctx, t);
    return true;
}

static bool trans_sraiw(DisasContext *ctx, arg_sraiw *a)
{
    GEN_RISCV_SHAMT_TYPE_INSN_HOOK(UC_RISCV_INS_SRAIW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv t = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, t, a->rs1);
    tcg_gen_sextract_tl(tcg_ctx, t, t, a->shamt, 32 - a->shamt);
    gen_set_gpr(tcg_ctx, a->rd, t);
    tcg_temp_free(tcg_ctx, t);
    return true;
}

static bool trans_addw(DisasContext *ctx, arg_addw *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_ADDW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &gen_addw);
}

static bool trans_subw(DisasContext *ctx, arg_subw *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SUBW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    return gen_arith(tcg_ctx, a, &gen_subw);
}

static bool trans_sllw(DisasContext *ctx, arg_sllw *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SLLW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);

    tcg_gen_andi_tl(tcg_ctx, source2, source2, 0x1F);
    tcg_gen_shl_tl(tcg_ctx, source1, source1, source2);

    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

static bool trans_srlw(DisasContext *ctx, arg_srlw *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SRLW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);

    /* clear upper 32 */
    tcg_gen_ext32u_tl(tcg_ctx, source1, source1);
    tcg_gen_andi_tl(tcg_ctx, source2, source2, 0x1F);
    tcg_gen_shr_tl(tcg_ctx, source1, source1, source2);

    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);
    return true;
}

static bool trans_sraw(DisasContext *ctx, arg_sraw *a)
{
    GEN_RISCV_RTYPE_INSN_HOOK(UC_RISCV_INS_SRAW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1 = tcg_temp_new(tcg_ctx);
    TCGv source2 = tcg_temp_new(tcg_ctx);

    gen_get_gpr(tcg_ctx, source1, a->rs1);
    gen_get_gpr(tcg_ctx, source2, a->rs2);

    /*
     * first, trick to get it to act like working on 32 bits (get rid of
     * upper 32, sign extend to fill space)
     */
    tcg_gen_ext32s_tl(tcg_ctx, source1, source1);
    tcg_gen_andi_tl(tcg_ctx, source2, source2, 0x1F);
    tcg_gen_sar_tl(tcg_ctx, source1, source1, source2);

    gen_set_gpr(tcg_ctx, a->rd, source1);
    tcg_temp_free(tcg_ctx, source1);
    tcg_temp_free(tcg_ctx, source2);

    return true;
}
#endif

static bool trans_fence(DisasContext *ctx, arg_fence *a)
{
    GEN_RISCV_INSN_HOOK(ctx, itype, (uint32_t)UC_RISCV_INS_FENCE, (uint32_t)((a->pred << 4) | a->succ), 0, 0);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    /* FENCE is a full memory barrier. */
    tcg_gen_mb(tcg_ctx, TCG_MO_ALL | TCG_BAR_SC);
    return true;
}

static bool trans_fence_i(DisasContext *ctx, arg_fence_i *a)
{
    GEN_RISCV_INSN_HOOK(ctx, itype, (uint32_t)UC_RISCV_INS_FENCEI, 0, 0, 0);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (!ctx->ext_ifencei) {
        return false;
    }

    /*
     * FENCE_I is a no-op in QEMU,
     * however we need to end the translation block
     */
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->pc_succ_insn);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

#define RISCV_OP_CSR_PRE do {\
    source1 = tcg_temp_new(tcg_ctx); \
    csr_store = tcg_temp_new(tcg_ctx); \
    dest = tcg_temp_new(tcg_ctx); \
    rs1_pass = tcg_temp_new(tcg_ctx); \
    gen_get_gpr(tcg_ctx, source1, a->rs1); \
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next); \
    tcg_gen_movi_tl(tcg_ctx, rs1_pass, a->rs1); \
    tcg_gen_movi_tl(tcg_ctx, csr_store, a->csr); \
    gen_io_start(tcg_ctx);\
} while (0)

#define RISCV_OP_CSR_POST do {\
    gen_set_gpr(tcg_ctx, a->rd, dest); \
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->pc_succ_insn); \
    exit_tb(ctx); \
    ctx->base.is_jmp = DISAS_NORETURN; \
    tcg_temp_free(tcg_ctx, source1); \
    tcg_temp_free(tcg_ctx, csr_store); \
    tcg_temp_free(tcg_ctx, dest); \
    tcg_temp_free(tcg_ctx, rs1_pass); \
} while (0)


static bool trans_csrrw(DisasContext *ctx, arg_csrrw *a)
{
    GEN_RISCV_CSR_TYPE_INSN_HOOK(UC_RISCV_INS_CSRRW);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrw(tcg_ctx, dest, tcg_ctx->cpu_env, source1, csr_store);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrs(DisasContext *ctx, arg_csrrs *a)
{
    GEN_RISCV_CSR_TYPE_INSN_HOOK(UC_RISCV_INS_CSRRS);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrs(tcg_ctx, dest, tcg_ctx->cpu_env, source1, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrc(DisasContext *ctx, arg_csrrc *a)
{
    GEN_RISCV_CSR_TYPE_INSN_HOOK(UC_RISCV_INS_CSRRC);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrc(tcg_ctx, dest, tcg_ctx->cpu_env, source1, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrwi(DisasContext *ctx, arg_csrrwi *a)
{
    GEN_RISCV_CSR_TYPE_INSN_HOOK(UC_RISCV_INS_CSRRWI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrw(tcg_ctx, dest, tcg_ctx->cpu_env, rs1_pass, csr_store);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrsi(DisasContext *ctx, arg_csrrsi *a)
{
    GEN_RISCV_CSR_TYPE_INSN_HOOK(UC_RISCV_INS_CSRRSI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrs(tcg_ctx, dest, tcg_ctx->cpu_env, rs1_pass, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}

static bool trans_csrrci(DisasContext *ctx, arg_csrrci *a)
{
    GEN_RISCV_CSR_TYPE_INSN_HOOK(UC_RISCV_INS_CSRRCI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv source1, csr_store, dest, rs1_pass;
    RISCV_OP_CSR_PRE;
    gen_helper_csrrc(tcg_ctx, dest, tcg_ctx->cpu_env, rs1_pass, csr_store, rs1_pass);
    RISCV_OP_CSR_POST;
    return true;
}
