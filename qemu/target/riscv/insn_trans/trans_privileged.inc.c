/*
 * RISC-V translation routines for the RISC-V privileged instructions.
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

// HFENCE and SFENCE instructions are structurally Integer Register-Register instructions 
// These macros are direct binding to R-type instruction hooks
// cf: The RISC-V Instruction Set Manual, Volume I: Unprivileged Architecture - 2.4.2. Integer Register-Register Instructions
#define GEN_RISCV_SHFENCE_INSN_HOOK(insn_id, ...)                     \
    do {                                                                 \
        if (HOOK_EXISTS(ctx->uc, UC_HOOK_INSN)) {                      \
            gen_insn_hook_rtype(ctx, (insn_id), __VA_ARGS__);         \
        }                                                                \
    } while (0)

// Privileged instructions are plain harcoded instructions
#define GEN_RISCV_PRIVILEGED_INSN_HOOK(insn_id)                     \
    do {                                                                 \
        if (HOOK_EXISTS(ctx->uc, UC_HOOK_INSN)) {                      \
            gen_insn_hook_privileged(ctx, (uint32_t)(insn_id));        \
        }                                                                \
    } while (0)


static bool trans_ecall(DisasContext *ctx, arg_ecall *a)
{
    GEN_RISCV_PRIVILEGED_INSN_HOOK(UC_RISCV_INS_ECALL);
    /* always generates U-level ECALL, fixed in do_interrupt handler */
    generate_exception(ctx, RISCV_EXCP_U_ECALL);
    exit_tb(ctx); /* no chaining */
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_ebreak(DisasContext *ctx, arg_ebreak *a)
{
    GEN_RISCV_PRIVILEGED_INSN_HOOK(UC_RISCV_INS_EBREAK);
    // ignore this instruction
    generate_exception(ctx, RISCV_EXCP_BREAKPOINT);
    exit_tb(ctx); /* no chaining */
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_uret(DisasContext *ctx, arg_uret *a)
{
    GEN_RISCV_PRIVILEGED_INSN_HOOK(UC_RISCV_INS_URET);
    return false;
}

static bool trans_sret(DisasContext *ctx, arg_sret *a)
{
    GEN_RISCV_PRIVILEGED_INSN_HOOK(UC_RISCV_INS_SRET);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);

    if (has_ext(ctx, RVS)) {
        gen_helper_sret(tcg_ctx, tcg_ctx->cpu_pc, tcg_ctx->cpu_env, tcg_ctx->cpu_pc);
        exit_tb(ctx); /* no chaining */
        ctx->base.is_jmp = DISAS_NORETURN;
    } else {
        return false;
    }
    return true;
}

static bool trans_mret(DisasContext *ctx, arg_mret *a)
{
    GEN_RISCV_PRIVILEGED_INSN_HOOK(UC_RISCV_INS_MRET);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->base.pc_next);
    gen_helper_mret(tcg_ctx, tcg_ctx->cpu_pc, tcg_ctx->cpu_env, tcg_ctx->cpu_pc);
    exit_tb(ctx); /* no chaining */
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_wfi(DisasContext *ctx, arg_wfi *a)
{
    GEN_RISCV_PRIVILEGED_INSN_HOOK(UC_RISCV_INS_WFI);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->pc_succ_insn);
    gen_helper_wfi(tcg_ctx, tcg_ctx->cpu_env);
    return true;
}

static bool trans_sfence_vma(DisasContext *ctx, arg_sfence_vma *a)
{
    GEN_RISCV_SHFENCE_INSN_HOOK(UC_RISCV_INS_SFENCEVMA, (uint32_t)a->rs1, (uint32_t)a->rs2, 0);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (ctx->priv_ver >= PRIV_VERSION_1_10_0) {
        gen_helper_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
        return true;
    }
    return false;
}

static bool trans_sfence_vm(DisasContext *ctx, arg_sfence_vm *a)
{
    GEN_RISCV_SHFENCE_INSN_HOOK(UC_RISCV_INS_SFENCEVM, (uint32_t)a->rs1, 0, 0); // This one has no rs2
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (ctx->priv_ver <= PRIV_VERSION_1_09_1) {
        gen_helper_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
        return true;
    }
    return false;
}

static bool trans_hfence_gvma(DisasContext *ctx, arg_sfence_vma *a)
{
    GEN_RISCV_SHFENCE_INSN_HOOK(UC_RISCV_INS_HFENCEGVMA, (uint32_t)a->rs1, (uint32_t)a->rs2, 0);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (ctx->priv_ver >= PRIV_VERSION_1_10_0 &&
        has_ext(ctx, RVH)) {
        /* Hpervisor extensions exist */
        /*
         * if (env->priv == PRV_M ||
         *   (env->priv == PRV_S &&
         *    !riscv_cpu_virt_enabled(env) &&
         *    get_field(ctx->mstatus_fs, MSTATUS_TVM))) {
         */
            gen_helper_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
            return true;
        /* } */
    }
    return false;
}

static bool trans_hfence_bvma(DisasContext *ctx, arg_sfence_vma *a)
{
    GEN_RISCV_SHFENCE_INSN_HOOK(UC_RISCV_INS_HFENCEBVMA, (uint32_t)a->rs1, (uint32_t)a->rs2, 0);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    if (ctx->priv_ver >= PRIV_VERSION_1_10_0 &&
        has_ext(ctx, RVH)) {
        /* Hpervisor extensions exist */
        /*
         * if (env->priv == PRV_M ||
         *   (env->priv == PRV_S &&
         *    !riscv_cpu_virt_enabled(env) &&
         *    get_field(ctx->mstatus_fs, MSTATUS_TVM))) {
         */
            gen_helper_tlb_flush(tcg_ctx, tcg_ctx->cpu_env);
            return true;
        /* } */
    }
    return false;
}
