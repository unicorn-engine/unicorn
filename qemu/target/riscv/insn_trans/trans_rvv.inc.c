/*
 * RISC-V translation routines for vector configuration instructions.
 *
 * Copyright (c) 2020 T-Head Semiconductor Co., Ltd. All rights reserved.
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

typedef struct {
    int rd;
    int rs1;
    int zimm;
} arg_vsetvli;

typedef arg_vsetvli arg_vsetivli;
typedef arg_r arg_vsetvl;

typedef struct {
    int rd;
    int rs1;
    int rs2;
    int nf;
    int vm;
} arg_rvv_ldst;

typedef struct {
    int rd;
    int rs1;
    int rs2;
    int vm;
} arg_rvv_arith;

static bool require_rvv(DisasContext *ctx)
{
    return ctx->mstatus_vs != 0 &&
           (has_ext(ctx, RVV) || ctx->ext_zve32f || ctx->ext_zve64f);
}

static bool require_rvv_data(DisasContext *ctx)
{
    return require_rvv(ctx) && !ctx->vill && ctx->sew <= MO_64;
}

static bool require_rvf(DisasContext *ctx)
{
    if (ctx->mstatus_fs == 0) {
        return false;
    }

    switch (ctx->sew) {
    case MO_16:
    case MO_32:
        return has_ext(ctx, RVF);
    case MO_64:
        return has_ext(ctx, RVD);
    default:
        return false;
    }
}

static bool require_scale_rvf(DisasContext *ctx)
{
    if (ctx->mstatus_fs == 0) {
        return false;
    }

    switch (ctx->sew) {
    case MO_8:
    case MO_16:
        return has_ext(ctx, RVF);
    case MO_32:
        return has_ext(ctx, RVD);
    default:
        return false;
    }
}

static bool require_zve32f(DisasContext *ctx)
{
    if (has_ext(ctx, RVV)) {
        return true;
    }

    return ctx->ext_zve32f ? ctx->sew <= MO_32 : true;
}

static bool require_zve64f(DisasContext *ctx)
{
    if (has_ext(ctx, RVV)) {
        return true;
    }

    return ctx->ext_zve64f ? ctx->sew <= MO_32 : true;
}

static bool require_scale_zve32f(DisasContext *ctx)
{
    if (has_ext(ctx, RVV)) {
        return true;
    }

    return ctx->ext_zve32f ? ctx->sew <= MO_16 : true;
}

static bool require_scale_zve64f(DisasContext *ctx)
{
    if (has_ext(ctx, RVV)) {
        return true;
    }

    return ctx->ext_zve64f ? ctx->sew <= MO_16 : true;
}

static bool require_vm(int vm, int vd)
{
    return vm != 0 || vd != 0;
}

static bool require_nf(int vd, int nf, int lmul)
{
    int size = nf << MAX(lmul, 0);

    return size <= 8 && vd + size <= 32;
}

static bool require_align(int val, int8_t lmul)
{
    return lmul <= 0 || extract32(val, 0, lmul) == 0;
}

static inline bool is_overlapped(int8_t astart, int8_t asize,
                                 int8_t bstart, int8_t bsize)
{
    int8_t aend = astart + asize;
    int8_t bend = bstart + bsize;

    return MAX(aend, bend) - MIN(astart, bstart) < asize + bsize;
}

static bool require_noover(int8_t dst, int8_t dst_lmul,
                           int8_t src, int8_t src_lmul)
{
    int8_t dst_size = dst_lmul <= 0 ? 1 : 1 << dst_lmul;
    int8_t src_size = src_lmul <= 0 ? 1 : 1 << src_lmul;

    if (dst_size > src_size &&
        dst < src &&
        src_lmul >= 0 &&
        is_overlapped(dst, dst_size, src, src_size) &&
        !is_overlapped(dst, dst_size, src + src_size, src_size)) {
        return true;
    }

    return !is_overlapped(dst, dst_size, src, src_size);
}

static bool vext_check_store(DisasContext *ctx, int vd, int nf, uint8_t eew)
{
    int8_t emul = eew - ctx->sew + ctx->lmul;

    return emul >= -3 && emul <= 3 &&
           require_align(vd, emul) &&
           require_nf(vd, nf, emul);
}

static bool vext_check_load(DisasContext *ctx, int vd, int nf, int vm,
                            uint8_t eew)
{
    return vext_check_store(ctx, vd, nf, eew) && require_vm(vm, vd);
}

static bool vext_check_st_index(DisasContext *ctx, int vd, int vs2,
                                int nf, uint8_t eew)
{
    int8_t emul = eew - ctx->sew + ctx->lmul;
    bool ret = emul >= -3 && emul <= 3 &&
               require_align(vs2, emul) &&
               require_align(vd, ctx->lmul) &&
               require_nf(vd, nf, ctx->lmul);

#if !defined(TARGET_RISCV64)
    if (!has_ext(ctx, RVV) && ctx->ext_zve64f && eew == MO_64) {
        ret = false;
    }
#endif

    return ret;
}

static bool vext_check_ld_index(DisasContext *ctx, int vd, int vs2,
                                int nf, int vm, uint8_t eew)
{
    int8_t emul = eew - ctx->sew + ctx->lmul;
    int8_t seg_vd;
    int i;
    bool ret = vext_check_st_index(ctx, vd, vs2, nf, eew) &&
               require_vm(vm, vd);

    for (i = 0; i < nf; i++) {
        seg_vd = vd + (1 << MAX(ctx->lmul, 0)) * i;

        if (eew > ctx->sew) {
            if (seg_vd != vs2) {
                ret &= require_noover(seg_vd, ctx->lmul, vs2, emul);
            }
        } else if (eew < ctx->sew) {
            ret &= require_noover(seg_vd, ctx->lmul, vs2, emul);
        }

        if (nf > 1) {
            ret &= !is_overlapped(seg_vd, 1 << MAX(ctx->lmul, 0),
                                  vs2, 1 << MAX(emul, 0));
        }
    }
    return ret;
}

static bool vext_check_ss(DisasContext *ctx, int vd, int vs, int vm)
{
    return require_vm(vm, vd) &&
           require_align(vd, ctx->lmul) &&
           require_align(vs, ctx->lmul);
}

static bool vext_check_sss(DisasContext *ctx, int vd, int vs1, int vs2,
                           int vm)
{
    return vext_check_ss(ctx, vd, vs2, vm) &&
           require_align(vs1, ctx->lmul);
}

static bool vext_check_ms(DisasContext *ctx, int vd, int vs)
{
    bool ret = require_align(vs, ctx->lmul);

    if (vd != vs) {
        ret &= require_noover(vd, 0, vs, ctx->lmul);
    }
    return ret;
}

static bool vext_check_mss(DisasContext *ctx, int vd, int vs1, int vs2)
{
    bool ret = vext_check_ms(ctx, vd, vs2) &&
               require_align(vs1, ctx->lmul);

    if (vd != vs1) {
        ret &= require_noover(vd, 0, vs1, ctx->lmul);
    }
    return ret;
}

static bool vext_wide_check_common(DisasContext *ctx, int vd, int vm)
{
    return ctx->lmul <= 2 &&
           ctx->sew < MO_64 &&
           require_align(vd, ctx->lmul + 1) &&
           require_vm(vm, vd);
}

static bool vext_check_ds(DisasContext *ctx, int vd, int vs, int vm)
{
    return vext_wide_check_common(ctx, vd, vm) &&
           require_align(vs, ctx->lmul) &&
           require_noover(vd, ctx->lmul + 1, vs, ctx->lmul);
}

static bool vext_check_dd(DisasContext *ctx, int vd, int vs, int vm)
{
    return vext_wide_check_common(ctx, vd, vm) &&
           require_align(vs, ctx->lmul + 1);
}

static bool vext_check_dss(DisasContext *ctx, int vd, int vs1, int vs2,
                           int vm)
{
    return vext_check_ds(ctx, vd, vs2, vm) &&
           require_align(vs1, ctx->lmul) &&
           require_noover(vd, ctx->lmul + 1, vs1, ctx->lmul);
}

static bool vext_check_dds(DisasContext *ctx, int vd, int vs1, int vs2,
                           int vm)
{
    return vext_check_ds(ctx, vd, vs1, vm) &&
           require_align(vs2, ctx->lmul + 1);
}

static bool vext_narrow_check_common(DisasContext *ctx, int vd, int vs2,
                                     int vm)
{
    return ctx->lmul <= 2 &&
           ctx->sew < MO_64 &&
           require_align(vs2, ctx->lmul + 1) &&
           require_align(vd, ctx->lmul) &&
           require_vm(vm, vd);
}

static bool vext_check_sd(DisasContext *ctx, int vd, int vs, int vm)
{
    bool ret = vext_narrow_check_common(ctx, vd, vs, vm);

    if (vd != vs) {
        ret &= require_noover(vd, ctx->lmul, vs, ctx->lmul + 1);
    }
    return ret;
}

static bool vext_check_sds(DisasContext *ctx, int vd, int vs1, int vs2,
                           int vm)
{
    return vext_check_sd(ctx, vd, vs2, vm) &&
           require_align(vs1, ctx->lmul);
}

static bool vext_check_reduction(DisasContext *ctx, int vs2)
{
    return require_align(vs2, ctx->lmul);
}

static bool vext_check_slide(DisasContext *ctx, int vd, int vs2, int vm,
                             bool slide_up)
{
    bool ret = require_vm(vm, vd) &&
               require_align(vd, ctx->lmul) &&
               require_align(vs2, ctx->lmul);

    if (slide_up) {
        ret &= vd != vs2;
    }
    return ret;
}

static uint8_t vext_get_emul(DisasContext *ctx, uint8_t eew)
{
    int8_t emul = eew - ctx->sew + ctx->lmul;

    return emul < 0 ? 0 : emul;
}

static uint32_t vreg_ofs(DisasContext *ctx, int reg)
{
    return offsetof(CPURISCVState, vreg) + reg * ctx->vlen / 8;
}

static TCGv_ptr gen_vreg_ptr(DisasContext *ctx, int reg)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr ptr = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, ptr, tcg_ctx->cpu_env, vreg_ofs(ctx, reg));
    return ptr;
}

static TCGv_i32 gen_rvv_desc(DisasContext *ctx, uint32_t data)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    uint32_t vlenb = ctx->vlen >> 3;

    return tcg_const_i32(tcg_ctx, simd_desc(vlenb, vlenb, data));
}

typedef void gen_helper_ldst_us(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv,
                                TCGv_env, TCGv_i32);
typedef void gen_helper_ldst_stride(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv,
                                    TCGv, TCGv_env, TCGv_i32);
typedef void gen_helper_ldst_index(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv,
                                   TCGv_ptr, TCGv_env, TCGv_i32);
typedef void gen_helper_ldst_whole(TCGContext *, TCGv_ptr, TCGv, TCGv_env,
                                   TCGv_i32);
typedef void gen_helper_opivv(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_ptr,
                              TCGv_ptr, TCGv_env, TCGv_i32);
typedef void gen_helper_opivx(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv,
                              TCGv_ptr, TCGv_env, TCGv_i32);
typedef void gen_helper_opfvf(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_i64,
                              TCGv_ptr, TCGv_env, TCGv_i32);
typedef void gen_helper_opivm(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_ptr,
                              TCGv_env, TCGv_i32);
typedef void gen_helper_vmv_vv(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_env,
                               TCGv_i32);
typedef void gen_helper_vmv_vx(TCGContext *, TCGv_ptr, TCGv_i64, TCGv_env,
                               TCGv_i32);
typedef void gen_helper_vid_v(TCGContext *, TCGv_ptr, TCGv_ptr, TCGv_env,
                              TCGv_i32);
typedef void gen_helper_mscalar(TCGContext *, TCGv, TCGv_ptr, TCGv_ptr,
                                TCGv_env, TCGv_i32);

static bool do_vsetvl(DisasContext *ctx, int rd, int rs1, TCGv s2)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv s1;
    TCGv dst;

    if (!require_rvv(ctx)) {
        return false;
    }

    dst = tcg_temp_new(tcg_ctx);
    s1 = tcg_temp_new(tcg_ctx);
    if (rd == 0 && rs1 == 0) {
        tcg_gen_mov_tl(tcg_ctx, s1, cpu_vl);
    } else if (rs1 == 0) {
        tcg_gen_movi_tl(tcg_ctx, s1, RV_VLEN_MAX);
    } else {
        gen_get_gpr(tcg_ctx, s1, rs1);
    }

    gen_helper_vsetvl(tcg_ctx, dst, tcg_ctx->cpu_env, s1, s2);
    gen_set_gpr(tcg_ctx, rd, dst);
    mark_vs_dirty(ctx);
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->pc_succ_insn);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, dst);
    tcg_temp_free(tcg_ctx, s1);
    return true;
}

static bool trans_vsetvl(DisasContext *ctx, arg_vsetvl *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv s2;
    bool ret;

    s2 = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, s2, a->rs2);
    ret = do_vsetvl(ctx, a->rd, a->rs1, s2);
    tcg_temp_free(tcg_ctx, s2);
    return ret;
}

static bool trans_vsetvli(DisasContext *ctx, arg_vsetvli *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv s2;
    bool ret;

    s2 = tcg_const_tl(tcg_ctx, a->zimm);
    ret = do_vsetvl(ctx, a->rd, a->rs1, s2);
    tcg_temp_free(tcg_ctx, s2);
    return ret;
}

static bool trans_vsetivli(DisasContext *ctx, arg_vsetivli *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv s1;
    TCGv s2;
    TCGv dst;

    if (!require_rvv(ctx)) {
        return false;
    }

    dst = tcg_temp_new(tcg_ctx);
    s1 = tcg_const_tl(tcg_ctx, a->rs1);
    s2 = tcg_const_tl(tcg_ctx, a->zimm);

    gen_helper_vsetvl(tcg_ctx, dst, tcg_ctx->cpu_env, s1, s2);
    gen_set_gpr(tcg_ctx, a->rd, dst);
    mark_vs_dirty(ctx);
    tcg_gen_movi_tl(tcg_ctx, tcg_ctx->cpu_pc, ctx->pc_succ_insn);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(tcg_ctx, dst);
    tcg_temp_free(tcg_ctx, s1);
    tcg_temp_free(tcg_ctx, s2);
    return true;
}

static bool ldst_us_trans(DisasContext *ctx, int vd, int rs1, uint32_t data,
                          gen_helper_ldst_us *fn, bool is_store)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv base;
    TCGv_i32 desc;

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    dest = gen_vreg_ptr(ctx, vd);
    mask = gen_vreg_ptr(ctx, 0);
    base = tcg_temp_new(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    gen_get_gpr(tcg_ctx, base, rs1);
    fn(tcg_ctx, dest, mask, base, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free(tcg_ctx, base);
    tcg_temp_free_i32(tcg_ctx, desc);

    if (!is_store) {
        mark_vs_dirty(ctx);
    }

    gen_set_label(tcg_ctx, over);
    return true;
}

static bool ldst_stride_trans(DisasContext *ctx, int vd, int rs1, int rs2,
                              uint32_t data, gen_helper_ldst_stride *fn,
                              bool is_store)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv base;
    TCGv stride;
    TCGv_i32 desc;

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    dest = gen_vreg_ptr(ctx, vd);
    mask = gen_vreg_ptr(ctx, 0);
    base = tcg_temp_new(tcg_ctx);
    stride = tcg_temp_new(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    gen_get_gpr(tcg_ctx, base, rs1);
    gen_get_gpr(tcg_ctx, stride, rs2);
    fn(tcg_ctx, dest, mask, base, stride, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free(tcg_ctx, base);
    tcg_temp_free(tcg_ctx, stride);
    tcg_temp_free_i32(tcg_ctx, desc);

    if (!is_store) {
        mark_vs_dirty(ctx);
    }

    gen_set_label(tcg_ctx, over);
    return true;
}

static bool ldst_index_trans(DisasContext *ctx, int vd, int rs1, int vs2,
                             uint32_t data, gen_helper_ldst_index *fn,
                             bool is_store)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr index;
    TCGv base;
    TCGv_i32 desc;

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    dest = gen_vreg_ptr(ctx, vd);
    mask = gen_vreg_ptr(ctx, 0);
    index = gen_vreg_ptr(ctx, vs2);
    base = tcg_temp_new(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    gen_get_gpr(tcg_ctx, base, rs1);
    fn(tcg_ctx, dest, mask, base, index, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, index);
    tcg_temp_free(tcg_ctx, base);
    tcg_temp_free_i32(tcg_ctx, desc);

    if (!is_store) {
        mark_vs_dirty(ctx);
    }

    gen_set_label(tcg_ctx, over);
    return true;
}

static bool ldst_whole_trans(DisasContext *ctx, int vd, int rs1,
                             uint32_t nf, uint32_t width,
                             gen_helper_ldst_whole *fn, bool is_store)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv base;
    TCGv_i32 desc;
    uint32_t evl = (ctx->vlen >> 3) * nf / width;
    uint32_t data = 0;

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, evl, over);

    dest = gen_vreg_ptr(ctx, vd);
    base = tcg_temp_new(tcg_ctx);
    FIELD_DP32(data, VDATA, NF, nf, data);
    desc = gen_rvv_desc(ctx, data);

    gen_get_gpr(tcg_ctx, base, rs1);
    fn(tcg_ctx, dest, base, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free(tcg_ctx, base);
    tcg_temp_free_i32(tcg_ctx, desc);

    if (!is_store) {
        mark_vs_dirty(ctx);
    }

    gen_set_label(tcg_ctx, over);
    return true;
}

static bool vle_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew,
                      gen_helper_ldst_us *fn)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_load(ctx, a->rd, a->nf, a->vm, eew)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, eew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);
    return ldst_us_trans(ctx, a->rd, a->rs1, data, fn, false);
}

static bool vleff_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew,
                        gen_helper_ldst_us *fn)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_load(ctx, a->rd, a->nf, a->vm, eew)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, eew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);
    return ldst_us_trans(ctx, a->rd, a->rs1, data, fn, false);
}

static bool vse_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew,
                      gen_helper_ldst_us *fn)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_store(ctx, a->rd, a->nf, eew)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, eew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    return ldst_us_trans(ctx, a->rd, a->rs1, data, fn, true);
}

static bool vlse_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew,
                       gen_helper_ldst_stride *fn)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_load(ctx, a->rd, a->nf, a->vm, eew)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, eew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);
    return ldst_stride_trans(ctx, a->rd, a->rs1, a->rs2, data, fn, false);
}

static bool vsse_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew,
                       gen_helper_ldst_stride *fn)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_store(ctx, a->rd, a->nf, eew)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, eew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    return ldst_stride_trans(ctx, a->rd, a->rs1, a->rs2, data, fn, true);
}

static bool vlxei_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew)
{
    uint32_t data = 0;
    gen_helper_ldst_index *fn;
    static gen_helper_ldst_index * const fns[4][4] = {
        { gen_helper_vlxei8_8_v, gen_helper_vlxei8_16_v,
          gen_helper_vlxei8_32_v, gen_helper_vlxei8_64_v },
        { gen_helper_vlxei16_8_v, gen_helper_vlxei16_16_v,
          gen_helper_vlxei16_32_v, gen_helper_vlxei16_64_v },
        { gen_helper_vlxei32_8_v, gen_helper_vlxei32_16_v,
          gen_helper_vlxei32_32_v, gen_helper_vlxei32_64_v },
        { gen_helper_vlxei64_8_v, gen_helper_vlxei64_16_v,
          gen_helper_vlxei64_32_v, gen_helper_vlxei64_64_v },
    };

    if (!require_rvv_data(ctx) ||
        !vext_check_ld_index(ctx, a->rd, a->rs2, a->nf, a->vm, eew)) {
        return false;
    }

    fn = fns[eew][ctx->sew];
    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, ctx->sew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);
    return ldst_index_trans(ctx, a->rd, a->rs1, a->rs2, data, fn, false);
}

static bool vsxei_trans(DisasContext *ctx, arg_rvv_ldst *a, uint8_t eew)
{
    uint32_t data = 0;
    gen_helper_ldst_index *fn;
    static gen_helper_ldst_index * const fns[4][4] = {
        { gen_helper_vsxei8_8_v, gen_helper_vsxei8_16_v,
          gen_helper_vsxei8_32_v, gen_helper_vsxei8_64_v },
        { gen_helper_vsxei16_8_v, gen_helper_vsxei16_16_v,
          gen_helper_vsxei16_32_v, gen_helper_vsxei16_64_v },
        { gen_helper_vsxei32_8_v, gen_helper_vsxei32_16_v,
          gen_helper_vsxei32_32_v, gen_helper_vsxei32_64_v },
        { gen_helper_vsxei64_8_v, gen_helper_vsxei64_16_v,
          gen_helper_vsxei64_32_v, gen_helper_vsxei64_64_v },
    };

    if (!require_rvv_data(ctx) ||
        !vext_check_st_index(ctx, a->rd, a->rs2, a->nf, eew)) {
        return false;
    }

    fn = fns[eew][ctx->sew];
    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, vext_get_emul(ctx, ctx->sew), data);
    FIELD_DP32(data, VDATA, NF, a->nf, data);
    return ldst_index_trans(ctx, a->rd, a->rs1, a->rs2, data, fn, true);
}

static bool trans_vle8_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vle_trans(ctx, a, MO_8, gen_helper_vle8_v);
}

static bool trans_vle16_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vle_trans(ctx, a, MO_16, gen_helper_vle16_v);
}

static bool trans_vle32_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vle_trans(ctx, a, MO_32, gen_helper_vle32_v);
}

static bool trans_vle64_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vle_trans(ctx, a, MO_64, gen_helper_vle64_v);
}

static bool trans_vle8ff_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vleff_trans(ctx, a, MO_8, gen_helper_vle8ff_v);
}

static bool trans_vle16ff_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vleff_trans(ctx, a, MO_16, gen_helper_vle16ff_v);
}

static bool trans_vle32ff_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vleff_trans(ctx, a, MO_32, gen_helper_vle32ff_v);
}

static bool trans_vle64ff_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vleff_trans(ctx, a, MO_64, gen_helper_vle64ff_v);
}

static bool trans_vse8_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vse_trans(ctx, a, MO_8, gen_helper_vse8_v);
}

static bool trans_vse16_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vse_trans(ctx, a, MO_16, gen_helper_vse16_v);
}

static bool trans_vse32_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vse_trans(ctx, a, MO_32, gen_helper_vse32_v);
}

static bool trans_vse64_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vse_trans(ctx, a, MO_64, gen_helper_vse64_v);
}

static bool trans_vlse8_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlse_trans(ctx, a, MO_8, gen_helper_vlse8_v);
}

static bool trans_vlse16_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlse_trans(ctx, a, MO_16, gen_helper_vlse16_v);
}

static bool trans_vlse32_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlse_trans(ctx, a, MO_32, gen_helper_vlse32_v);
}

static bool trans_vlse64_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlse_trans(ctx, a, MO_64, gen_helper_vlse64_v);
}

static bool trans_vsse8_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsse_trans(ctx, a, MO_8, gen_helper_vsse8_v);
}

static bool trans_vsse16_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsse_trans(ctx, a, MO_16, gen_helper_vsse16_v);
}

static bool trans_vsse32_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsse_trans(ctx, a, MO_32, gen_helper_vsse32_v);
}

static bool trans_vsse64_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsse_trans(ctx, a, MO_64, gen_helper_vsse64_v);
}

static bool trans_vlxei8_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlxei_trans(ctx, a, MO_8);
}

static bool trans_vlxei16_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlxei_trans(ctx, a, MO_16);
}

static bool trans_vlxei32_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlxei_trans(ctx, a, MO_32);
}

static bool trans_vlxei64_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vlxei_trans(ctx, a, MO_64);
}

static bool trans_vsxei8_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsxei_trans(ctx, a, MO_8);
}

static bool trans_vsxei16_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsxei_trans(ctx, a, MO_16);
}

static bool trans_vsxei32_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsxei_trans(ctx, a, MO_32);
}

static bool trans_vsxei64_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    return vsxei_trans(ctx, a, MO_64);
}

static bool trans_vlm_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx)) {
        return false;
    }

    FIELD_DP32(data, VDATA, LMUL, 0, data);
    FIELD_DP32(data, VDATA, NF, 1, data);
    FIELD_DP32(data, VDATA, VTA, ctx->rvv_ta_all_1s, data);
    return ldst_us_trans(ctx, a->rd, a->rs1, data, gen_helper_vlm_v, false);
}

static bool trans_vsm_v(DisasContext *ctx, arg_rvv_ldst *a)
{
    uint32_t data = 0;

    if (!require_rvv_data(ctx)) {
        return false;
    }

    FIELD_DP32(data, VDATA, LMUL, 0, data);
    FIELD_DP32(data, VDATA, NF, 1, data);
    return ldst_us_trans(ctx, a->rd, a->rs1, data, gen_helper_vsm_v, true);
}

#define GEN_LDST_WHOLE_TRANS(NAME, NF, WIDTH, IS_STORE)                  \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_ldst *a)             \
{                                                                        \
    if (require_rvv(ctx) && QEMU_IS_ALIGNED(a->rd, NF)) {                \
        return ldst_whole_trans(ctx, a->rd, a->rs1, NF, WIDTH,           \
                                gen_helper_##NAME, IS_STORE);            \
    }                                                                    \
    return false;                                                        \
}

GEN_LDST_WHOLE_TRANS(vl1re8_v, 1, 1, false)
GEN_LDST_WHOLE_TRANS(vl1re16_v, 1, 2, false)
GEN_LDST_WHOLE_TRANS(vl1re32_v, 1, 4, false)
GEN_LDST_WHOLE_TRANS(vl1re64_v, 1, 8, false)
GEN_LDST_WHOLE_TRANS(vl2re8_v, 2, 1, false)
GEN_LDST_WHOLE_TRANS(vl2re16_v, 2, 2, false)
GEN_LDST_WHOLE_TRANS(vl2re32_v, 2, 4, false)
GEN_LDST_WHOLE_TRANS(vl2re64_v, 2, 8, false)
GEN_LDST_WHOLE_TRANS(vl4re8_v, 4, 1, false)
GEN_LDST_WHOLE_TRANS(vl4re16_v, 4, 2, false)
GEN_LDST_WHOLE_TRANS(vl4re32_v, 4, 4, false)
GEN_LDST_WHOLE_TRANS(vl4re64_v, 4, 8, false)
GEN_LDST_WHOLE_TRANS(vl8re8_v, 8, 1, false)
GEN_LDST_WHOLE_TRANS(vl8re16_v, 8, 2, false)
GEN_LDST_WHOLE_TRANS(vl8re32_v, 8, 4, false)
GEN_LDST_WHOLE_TRANS(vl8re64_v, 8, 8, false)
GEN_LDST_WHOLE_TRANS(vs1r_v, 1, 1, true)
GEN_LDST_WHOLE_TRANS(vs2r_v, 2, 1, true)
GEN_LDST_WHOLE_TRANS(vs4r_v, 4, 1, true)
GEN_LDST_WHOLE_TRANS(vs8r_v, 8, 1, true)

static bool opivv_trans(DisasContext *ctx, arg_rvv_arith *a,
                        gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_sss(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                               bool is_imm, target_long imm,
                               gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_ss(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_trans(DisasContext *ctx, arg_rvv_arith *a,
                        gen_helper_opivx *fn)
{
    return opivx_trans_common(ctx, a, false, 0, fn);
}

static bool opivi_trans(DisasContext *ctx, arg_rvv_arith *a,
                        target_long scalar_value, gen_helper_opivx *fn)
{
    return opivx_trans_common(ctx, a, true, scalar_value, fn);
}

static bool opivx_slide_trans(DisasContext *ctx, arg_rvv_arith *a,
                              bool is_imm, target_long imm,
                              gen_helper_opivx *fn, bool slide_up)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_slide(ctx, a->rd, a->rs2, a->vm, slide_up)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivv_widen_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                                     gen_helper_opivv *fn, bool wide_vs2)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx)) {
        return false;
    }
    if (wide_vs2) {
        if (!vext_check_dds(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
            return false;
        }
    } else if (!vext_check_dss(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_widen_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                                     gen_helper_opivx *fn, bool wide_vs2)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx)) {
        return false;
    }
    if (wide_vs2) {
        if (!vext_check_dd(ctx, a->rd, a->rs2, a->vm)) {
            return false;
        }
    } else if (!vext_check_ds(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    scalar = tcg_temp_new(tcg_ctx);
    gen_get_gpr(tcg_ctx, scalar, a->rs1);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivv_reduction_trans(DisasContext *ctx, arg_rvv_arith *a,
                                  gen_helper_opivv *fn, bool widening)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *call;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) ||
        !vext_check_reduction(ctx, a->rs2)) {
        return false;
    }
    if (widening &&
        (ctx->sew >= MO_64 || (ctx->sew + 1) > (ctx->elen >> 4))) {
        return false;
    }

    call = gen_new_label(tcg_ctx);
    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_NE, cpu_vstart, 0, call);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    gen_set_label(tcg_ctx, call);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvv_reduction_trans(DisasContext *ctx, arg_rvv_arith *a,
                                  gen_helper_opivv *fn, bool widening)
{
    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_reduction(ctx, a->rs2)) {
        return false;
    }
    if (widening &&
        (ctx->sew >= MO_64 || (ctx->sew + 1) > (ctx->elen >> 4))) {
        return false;
    }

    gen_set_rm(ctx, 7);
    return opivv_reduction_trans(ctx, a, fn, widening);
}

#define GEN_WIDEN_VV_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)         \
{                                                                     \
    static gen_helper_opivv * const fns[4] = {                        \
        gen_helper_##NAME##_b,                                        \
        gen_helper_##NAME##_h,                                        \
        gen_helper_##NAME##_w,                                        \
        NULL,                                                         \
    };                                                                \
                                                                      \
    return opivv_widen_trans_common(ctx, a, fns[ctx->sew], false);    \
}

#define GEN_WIDEN_VX_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)         \
{                                                                     \
    static gen_helper_opivx * const fns[4] = {                        \
        gen_helper_##NAME##_b,                                        \
        gen_helper_##NAME##_h,                                        \
        gen_helper_##NAME##_w,                                        \
        NULL,                                                         \
    };                                                                \
                                                                      \
    return opivx_widen_trans_common(ctx, a, fns[ctx->sew], false);    \
}

#define GEN_WIDEN_WV_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)         \
{                                                                     \
    static gen_helper_opivv * const fns[4] = {                        \
        gen_helper_##NAME##_b,                                        \
        gen_helper_##NAME##_h,                                        \
        gen_helper_##NAME##_w,                                        \
        NULL,                                                         \
    };                                                                \
                                                                      \
    return opivv_widen_trans_common(ctx, a, fns[ctx->sew], true);     \
}

#define GEN_WIDEN_WX_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)         \
{                                                                     \
    static gen_helper_opivx * const fns[4] = {                        \
        gen_helper_##NAME##_b,                                        \
        gen_helper_##NAME##_h,                                        \
        gen_helper_##NAME##_w,                                        \
        NULL,                                                         \
    };                                                                \
                                                                      \
    return opivx_widen_trans_common(ctx, a, fns[ctx->sew], true);     \
}

GEN_WIDEN_VV_TRANS(vwaddu_vv)
GEN_WIDEN_VV_TRANS(vwadd_vv)
GEN_WIDEN_VV_TRANS(vwsubu_vv)
GEN_WIDEN_VV_TRANS(vwsub_vv)
GEN_WIDEN_VX_TRANS(vwaddu_vx)
GEN_WIDEN_VX_TRANS(vwadd_vx)
GEN_WIDEN_VX_TRANS(vwsubu_vx)
GEN_WIDEN_VX_TRANS(vwsub_vx)
GEN_WIDEN_WV_TRANS(vwaddu_wv)
GEN_WIDEN_WV_TRANS(vwadd_wv)
GEN_WIDEN_WV_TRANS(vwsubu_wv)
GEN_WIDEN_WV_TRANS(vwsub_wv)
GEN_WIDEN_WX_TRANS(vwaddu_wx)
GEN_WIDEN_WX_TRANS(vwadd_wx)
GEN_WIDEN_WX_TRANS(vwsubu_wx)
GEN_WIDEN_WX_TRANS(vwsub_wx)
GEN_WIDEN_VV_TRANS(vwmulu_vv)
GEN_WIDEN_VV_TRANS(vwmulsu_vv)
GEN_WIDEN_VV_TRANS(vwmul_vv)
GEN_WIDEN_VX_TRANS(vwmulu_vx)
GEN_WIDEN_VX_TRANS(vwmulsu_vx)
GEN_WIDEN_VX_TRANS(vwmul_vx)
GEN_WIDEN_VV_TRANS(vwmaccu_vv)
GEN_WIDEN_VV_TRANS(vwmacc_vv)
GEN_WIDEN_VV_TRANS(vwmaccsu_vv)
GEN_WIDEN_VX_TRANS(vwmaccu_vx)
GEN_WIDEN_VX_TRANS(vwmacc_vx)
GEN_WIDEN_VX_TRANS(vwmaccsu_vx)
GEN_WIDEN_VX_TRANS(vwmaccus_vx)

static bool opivv_vadc_trans(DisasContext *ctx, arg_rvv_arith *a,
                             gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || a->rd == 0 ||
        !vext_check_sss(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_vadc_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                                    bool is_imm, target_long imm,
                                    gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || a->rd == 0 ||
        !vext_check_ss(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_vadc_trans(DisasContext *ctx, arg_rvv_arith *a,
                             gen_helper_opivx *fn)
{
    return opivx_vadc_trans_common(ctx, a, false, 0, fn);
}

static bool opivi_vadc_trans(DisasContext *ctx, arg_rvv_arith *a,
                             target_long scalar_value, gen_helper_opivx *fn)
{
    return opivx_vadc_trans_common(ctx, a, true, scalar_value, fn);
}

static bool opivv_vmadc_trans(DisasContext *ctx, arg_rvv_arith *a,
                              gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_mss(ctx, a->rd, a->rs1, a->rs2)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_vmadc_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                                     bool is_imm, target_long imm,
                                     gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || !vext_check_ms(ctx, a->rd, a->rs2)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_vmadc_trans(DisasContext *ctx, arg_rvv_arith *a,
                              gen_helper_opivx *fn)
{
    return opivx_vmadc_trans_common(ctx, a, false, 0, fn);
}

static bool opivi_vmadc_trans(DisasContext *ctx, arg_rvv_arith *a,
                              target_long scalar_value,
                              gen_helper_opivx *fn)
{
    return opivx_vmadc_trans_common(ctx, a, true, scalar_value, fn);
}

static bool trans_vadd_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vadd_vv_b,
        gen_helper_vadd_vv_h,
        gen_helper_vadd_vv_w,
        gen_helper_vadd_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsub_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vsub_vv_b,
        gen_helper_vsub_vv_h,
        gen_helper_vsub_vv_w,
        gen_helper_vsub_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vand_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vand_vv_b,
        gen_helper_vand_vv_h,
        gen_helper_vand_vv_w,
        gen_helper_vand_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vor_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vor_vv_b,
        gen_helper_vor_vv_h,
        gen_helper_vor_vv_w,
        gen_helper_vor_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vxor_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vxor_vv_b,
        gen_helper_vxor_vv_h,
        gen_helper_vxor_vv_w,
        gen_helper_vxor_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vminu_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vminu_vv_b,
        gen_helper_vminu_vv_h,
        gen_helper_vminu_vv_w,
        gen_helper_vminu_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmin_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmin_vv_b,
        gen_helper_vmin_vv_h,
        gen_helper_vmin_vv_w,
        gen_helper_vmin_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmaxu_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmaxu_vv_b,
        gen_helper_vmaxu_vv_h,
        gen_helper_vmaxu_vv_w,
        gen_helper_vmaxu_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmax_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmax_vv_b,
        gen_helper_vmax_vv_h,
        gen_helper_vmax_vv_w,
        gen_helper_vmax_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmul_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmul_vv_b,
        gen_helper_vmul_vv_h,
        gen_helper_vmul_vv_w,
        gen_helper_vmul_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmulh_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmulh_vv_b,
        gen_helper_vmulh_vv_h,
        gen_helper_vmulh_vv_w,
        gen_helper_vmulh_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmulhu_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmulhu_vv_b,
        gen_helper_vmulhu_vv_h,
        gen_helper_vmulhu_vv_w,
        gen_helper_vmulhu_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmulhsu_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmulhsu_vv_b,
        gen_helper_vmulhsu_vv_h,
        gen_helper_vmulhsu_vv_w,
        gen_helper_vmulhsu_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vdivu_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vdivu_vv_b,
        gen_helper_vdivu_vv_h,
        gen_helper_vdivu_vv_w,
        gen_helper_vdivu_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vdiv_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vdiv_vv_b,
        gen_helper_vdiv_vv_h,
        gen_helper_vdiv_vv_w,
        gen_helper_vdiv_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vremu_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vremu_vv_b,
        gen_helper_vremu_vv_h,
        gen_helper_vremu_vv_w,
        gen_helper_vremu_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vrem_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vrem_vv_b,
        gen_helper_vrem_vv_h,
        gen_helper_vrem_vv_w,
        gen_helper_vrem_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

#define GEN_FIXED_VV_TRANS(NAME)                                     \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivv * const fns[4] = {                       \
        gen_helper_##NAME##_b,                                       \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
        gen_helper_##NAME##_d,                                       \
    };                                                               \
                                                                     \
    return opivv_trans(ctx, a, fns[ctx->sew]);                       \
}

#define GEN_FIXED_VX_TRANS(NAME)                                     \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivx * const fns[4] = {                       \
        gen_helper_##NAME##_b,                                       \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
        gen_helper_##NAME##_d,                                       \
    };                                                               \
                                                                     \
    return opivx_trans(ctx, a, fns[ctx->sew]);                       \
}

#define GEN_FIXED_VI_TRANS(NAME, HELPER, IMM)                        \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivx * const fns[4] = {                       \
        gen_helper_##HELPER##_b,                                     \
        gen_helper_##HELPER##_h,                                     \
        gen_helper_##HELPER##_w,                                     \
        gen_helper_##HELPER##_d,                                     \
    };                                                               \
                                                                     \
    return opivi_trans(ctx, a, IMM, fns[ctx->sew]);                  \
}

GEN_FIXED_VV_TRANS(vsaddu_vv)
GEN_FIXED_VV_TRANS(vsadd_vv)
GEN_FIXED_VV_TRANS(vssubu_vv)
GEN_FIXED_VV_TRANS(vssub_vv)
GEN_FIXED_VX_TRANS(vsaddu_vx)
GEN_FIXED_VX_TRANS(vsadd_vx)
GEN_FIXED_VX_TRANS(vssubu_vx)
GEN_FIXED_VX_TRANS(vssub_vx)
GEN_FIXED_VI_TRANS(vsaddu_vi, vsaddu_vx, sextract32(a->rs1, 0, 5))
GEN_FIXED_VI_TRANS(vsadd_vi, vsadd_vx, sextract32(a->rs1, 0, 5))

GEN_FIXED_VV_TRANS(vaadd_vv)
GEN_FIXED_VV_TRANS(vaaddu_vv)
GEN_FIXED_VV_TRANS(vasub_vv)
GEN_FIXED_VV_TRANS(vasubu_vv)
GEN_FIXED_VX_TRANS(vaadd_vx)
GEN_FIXED_VX_TRANS(vaaddu_vx)
GEN_FIXED_VX_TRANS(vasub_vx)
GEN_FIXED_VX_TRANS(vasubu_vx)

GEN_FIXED_VV_TRANS(vsmul_vv)
GEN_FIXED_VX_TRANS(vsmul_vx)

GEN_FIXED_VV_TRANS(vssrl_vv)
GEN_FIXED_VV_TRANS(vssra_vv)
GEN_FIXED_VX_TRANS(vssrl_vx)
GEN_FIXED_VX_TRANS(vssra_vx)
GEN_FIXED_VI_TRANS(vssrl_vi, vssrl_vx, a->rs1)
GEN_FIXED_VI_TRANS(vssra_vi, vssra_vx, a->rs1)

static bool opivv_narrow_shift_trans(DisasContext *ctx, arg_rvv_arith *a,
                                     gen_helper_opivv *fn);
static bool opivx_narrow_shift_trans(DisasContext *ctx, arg_rvv_arith *a,
                                     gen_helper_opivx *fn);
static bool opivi_narrow_shift_trans(DisasContext *ctx, arg_rvv_arith *a,
                                     target_long scalar_value,
                                     gen_helper_opivx *fn);

#define GEN_FIXED_NARROW_WV_TRANS(NAME)                             \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivv * const fns[3] = {                       \
        gen_helper_##NAME##_b,                                       \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
    };                                                               \
                                                                     \
    if (ctx->sew >= MO_64) {                                         \
        return false;                                                \
    }                                                                \
    return opivv_narrow_shift_trans(ctx, a, fns[ctx->sew]);          \
}

#define GEN_FIXED_NARROW_WX_TRANS(NAME)                             \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivx * const fns[3] = {                       \
        gen_helper_##NAME##_b,                                       \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
    };                                                               \
                                                                     \
    if (ctx->sew >= MO_64) {                                         \
        return false;                                                \
    }                                                                \
    return opivx_narrow_shift_trans(ctx, a, fns[ctx->sew]);          \
}

#define GEN_FIXED_NARROW_WI_TRANS(NAME, HELPER)                     \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivx * const fns[3] = {                       \
        gen_helper_##HELPER##_b,                                     \
        gen_helper_##HELPER##_h,                                     \
        gen_helper_##HELPER##_w,                                     \
    };                                                               \
                                                                     \
    if (ctx->sew >= MO_64) {                                         \
        return false;                                                \
    }                                                                \
    return opivi_narrow_shift_trans(ctx, a, a->rs1, fns[ctx->sew]);  \
}

GEN_FIXED_NARROW_WV_TRANS(vnclipu_wv)
GEN_FIXED_NARROW_WV_TRANS(vnclip_wv)
GEN_FIXED_NARROW_WX_TRANS(vnclipu_wx)
GEN_FIXED_NARROW_WX_TRANS(vnclip_wx)
GEN_FIXED_NARROW_WI_TRANS(vnclipu_wi, vnclipu_wx)
GEN_FIXED_NARROW_WI_TRANS(vnclip_wi, vnclip_wx)

#define GEN_REDUCTION_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)          \
{                                                                      \
    static gen_helper_opivv * const fns[4] = {                         \
        gen_helper_##NAME##_b,                                         \
        gen_helper_##NAME##_h,                                         \
        gen_helper_##NAME##_w,                                         \
        gen_helper_##NAME##_d,                                         \
    };                                                                 \
                                                                       \
    return opivv_reduction_trans(ctx, a, fns[ctx->sew], false);        \
}

#define GEN_WIDEN_REDUCTION_TRANS(NAME)                                \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)          \
{                                                                      \
    static gen_helper_opivv * const fns[3] = {                         \
        gen_helper_##NAME##_b,                                         \
        gen_helper_##NAME##_h,                                         \
        gen_helper_##NAME##_w,                                         \
    };                                                                 \
                                                                       \
    if (ctx->sew >= MO_64) {                                           \
        return false;                                                  \
    }                                                                  \
    return opivv_reduction_trans(ctx, a, fns[ctx->sew], true);         \
}

GEN_REDUCTION_TRANS(vredsum_vs)
GEN_REDUCTION_TRANS(vredand_vs)
GEN_REDUCTION_TRANS(vredor_vs)
GEN_REDUCTION_TRANS(vredxor_vs)
GEN_REDUCTION_TRANS(vredminu_vs)
GEN_REDUCTION_TRANS(vredmin_vs)
GEN_REDUCTION_TRANS(vredmaxu_vs)
GEN_REDUCTION_TRANS(vredmax_vs)
GEN_WIDEN_REDUCTION_TRANS(vwredsumu_vs)
GEN_WIDEN_REDUCTION_TRANS(vwredsum_vs)

#define GEN_FP_REDUCTION_TRANS(NAME)                                 \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivv * const fns[4] = {                       \
        NULL,                                                        \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
        gen_helper_##NAME##_d,                                       \
    };                                                               \
                                                                     \
    return opfvv_reduction_trans(ctx, a, fns[ctx->sew], false);      \
}

#define GEN_FP_WIDEN_REDUCTION_TRANS(NAME)                           \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivv * const fns[4] = {                       \
        NULL,                                                        \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
        NULL,                                                        \
    };                                                               \
                                                                     \
    return opfvv_reduction_trans(ctx, a, fns[ctx->sew], true);       \
}

GEN_FP_REDUCTION_TRANS(vfredusum_vs)
GEN_FP_REDUCTION_TRANS(vfredosum_vs)
GEN_FP_REDUCTION_TRANS(vfredmin_vs)
GEN_FP_REDUCTION_TRANS(vfredmax_vs)
GEN_FP_WIDEN_REDUCTION_TRANS(vfwredusum_vs)
GEN_FP_WIDEN_REDUCTION_TRANS(vfwredosum_vs)

#define GEN_MAC_VV_TRANS(NAME)                                       \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivv * const fns[4] = {                       \
        gen_helper_##NAME##_b,                                       \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
        gen_helper_##NAME##_d,                                       \
    };                                                               \
                                                                     \
    return opivv_trans(ctx, a, fns[ctx->sew]);                       \
}

GEN_MAC_VV_TRANS(vmacc_vv)
GEN_MAC_VV_TRANS(vnmsac_vv)
GEN_MAC_VV_TRANS(vmadd_vv)
GEN_MAC_VV_TRANS(vnmsub_vv)

static bool trans_vsll_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vsll_vv_b,
        gen_helper_vsll_vv_h,
        gen_helper_vsll_vv_w,
        gen_helper_vsll_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsrl_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vsrl_vv_b,
        gen_helper_vsrl_vv_h,
        gen_helper_vsrl_vv_w,
        gen_helper_vsrl_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsra_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vsra_vv_b,
        gen_helper_vsra_vv_h,
        gen_helper_vsra_vv_w,
        gen_helper_vsra_vv_d,
    };

    return opivv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vadd_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vadd_vx_b,
        gen_helper_vadd_vx_h,
        gen_helper_vadd_vx_w,
        gen_helper_vadd_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vadd_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vadd_vx_b,
        gen_helper_vadd_vx_h,
        gen_helper_vadd_vx_w,
        gen_helper_vadd_vx_d,
    };

    return opivi_trans(ctx, a, sextract32(a->rs1, 0, 5), fns[ctx->sew]);
}

static bool trans_vsub_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsub_vx_b,
        gen_helper_vsub_vx_h,
        gen_helper_vsub_vx_w,
        gen_helper_vsub_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vrsub_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vrsub_vx_b,
        gen_helper_vrsub_vx_h,
        gen_helper_vrsub_vx_w,
        gen_helper_vrsub_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vrsub_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vrsub_vx_b,
        gen_helper_vrsub_vx_h,
        gen_helper_vrsub_vx_w,
        gen_helper_vrsub_vx_d,
    };

    return opivi_trans(ctx, a, sextract32(a->rs1, 0, 5), fns[ctx->sew]);
}

static bool trans_vslideup_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vslideup_vx_b,
        gen_helper_vslideup_vx_h,
        gen_helper_vslideup_vx_w,
        gen_helper_vslideup_vx_d,
    };

    return opivx_slide_trans(ctx, a, false, 0, fns[ctx->sew], true);
}

static bool trans_vslideup_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vslideup_vx_b,
        gen_helper_vslideup_vx_h,
        gen_helper_vslideup_vx_w,
        gen_helper_vslideup_vx_d,
    };

    return opivx_slide_trans(ctx, a, true, a->rs1, fns[ctx->sew], true);
}

static bool trans_vslide1up_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vslide1up_vx_b,
        gen_helper_vslide1up_vx_h,
        gen_helper_vslide1up_vx_w,
        gen_helper_vslide1up_vx_d,
    };

    return opivx_slide_trans(ctx, a, false, 0, fns[ctx->sew], true);
}

static bool trans_vslidedown_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vslidedown_vx_b,
        gen_helper_vslidedown_vx_h,
        gen_helper_vslidedown_vx_w,
        gen_helper_vslidedown_vx_d,
    };

    return opivx_slide_trans(ctx, a, false, 0, fns[ctx->sew], false);
}

static bool trans_vslidedown_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vslidedown_vx_b,
        gen_helper_vslidedown_vx_h,
        gen_helper_vslidedown_vx_w,
        gen_helper_vslidedown_vx_d,
    };

    return opivx_slide_trans(ctx, a, true, a->rs1, fns[ctx->sew], false);
}

static bool trans_vslide1down_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vslide1down_vx_b,
        gen_helper_vslide1down_vx_h,
        gen_helper_vslide1down_vx_w,
        gen_helper_vslide1down_vx_d,
    };

    return opivx_slide_trans(ctx, a, false, 0, fns[ctx->sew], false);
}

static bool vext_check_gather_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    return require_rvv_data(ctx) &&
           require_align(a->rd, ctx->lmul) &&
           require_align(a->rs1, ctx->lmul) &&
           require_align(a->rs2, ctx->lmul) &&
           a->rd != a->rs2 &&
           a->rd != a->rs1 &&
           require_vm(a->vm, a->rd);
}

static bool vext_check_gatherei16_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    int8_t emul = MO_16 - ctx->sew + ctx->lmul;
    int8_t rd_size = 1 << MAX(ctx->lmul, 0);

    return require_rvv_data(ctx) &&
           emul >= -3 &&
           emul <= 3 &&
           require_align(a->rd, ctx->lmul) &&
           require_align(a->rs1, emul) &&
           require_align(a->rs2, ctx->lmul) &&
           a->rd != a->rs2 &&
           a->rd != a->rs1 &&
           !is_overlapped(a->rd, rd_size, a->rs1, 1 << MAX(emul, 0)) &&
           !is_overlapped(a->rd, rd_size,
                          a->rs2, 1 << MAX(ctx->lmul, 0)) &&
           require_vm(a->vm, a->rd);
}

static bool opivv_gather_trans(DisasContext *ctx, arg_rvv_arith *a,
                               gen_helper_opivv *fn, bool ei16)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL ||
        !(ei16 ? vext_check_gatherei16_vv(ctx, a) :
                 vext_check_gather_vv(ctx, a))) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vrgather_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vrgather_vv_b,
        gen_helper_vrgather_vv_h,
        gen_helper_vrgather_vv_w,
        gen_helper_vrgather_vv_d,
    };

    return opivv_gather_trans(ctx, a, fns[ctx->sew], false);
}

static bool trans_vrgatherei16_vv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vrgatherei16_vv_b,
        gen_helper_vrgatherei16_vv_h,
        gen_helper_vrgatherei16_vv_w,
        gen_helper_vrgatherei16_vv_d,
    };

    return opivv_gather_trans(ctx, a, fns[ctx->sew], true);
}

static bool vext_check_gather_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    return require_rvv_data(ctx) &&
           require_align(a->rd, ctx->lmul) &&
           require_align(a->rs2, ctx->lmul) &&
           a->rd != a->rs2 &&
           require_vm(a->vm, a->rd);
}

static bool opivx_gather_trans(DisasContext *ctx, arg_rvv_arith *a,
                               bool is_imm, target_long imm,
                               gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !vext_check_gather_vx(ctx, a)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vrgather_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vrgather_vx_b,
        gen_helper_vrgather_vx_h,
        gen_helper_vrgather_vx_w,
        gen_helper_vrgather_vx_d,
    };

    return opivx_gather_trans(ctx, a, false, 0, fns[ctx->sew]);
}

static bool trans_vrgather_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vrgather_vx_b,
        gen_helper_vrgather_vx_h,
        gen_helper_vrgather_vx_w,
        gen_helper_vrgather_vx_d,
    };

    return opivx_gather_trans(ctx, a, true, a->rs1, fns[ctx->sew]);
}

static bool trans_vcompress_vm(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vcompress_vm_b,
        gen_helper_vcompress_vm_h,
        gen_helper_vcompress_vm_w,
        gen_helper_vcompress_vm_d,
    };
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    TCGLabel *call;
    uint32_t data = 0;
    int8_t rd_size = 1 << MAX(ctx->lmul, 0);

    if (!require_rvv_data(ctx) ||
        !require_align(a->rd, ctx->lmul) ||
        !require_align(a->rs2, ctx->lmul) ||
        a->rd == a->rs2 ||
        is_overlapped(a->rd, rd_size, a->rs1, 1)) {
        return false;
    }

    call = gen_new_label(tcg_ctx);
    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_NE, cpu_vstart, 0, call);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    gen_set_label(tcg_ctx, call);

    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fns[ctx->sew](tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool vmv_whole_trans(DisasContext *ctx, arg_rvv_arith *a,
                            uint32_t len)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t vlenb = ctx->vlen >> 3;
    uint32_t maxsz = (ctx->vlen >> 3) * len;

    if (!require_rvv(ctx) ||
        !QEMU_IS_ALIGNED(a->rd, len) ||
        !QEMU_IS_ALIGNED(a->rs2, len)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, maxsz, over);

    dest = gen_vreg_ptr(ctx, a->rd);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = tcg_const_i32(tcg_ctx, simd_desc(vlenb, maxsz, 0));

    gen_helper_vmvr_v(tcg_ctx, dest, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vmv1r_v(DisasContext *ctx, arg_rvv_arith *a)
{
    return vmv_whole_trans(ctx, a, 1);
}

static bool trans_vmv2r_v(DisasContext *ctx, arg_rvv_arith *a)
{
    return vmv_whole_trans(ctx, a, 2);
}

static bool trans_vmv4r_v(DisasContext *ctx, arg_rvv_arith *a)
{
    return vmv_whole_trans(ctx, a, 4);
}

static bool trans_vmv8r_v(DisasContext *ctx, arg_rvv_arith *a)
{
    return vmv_whole_trans(ctx, a, 8);
}

static bool trans_vadc_vvm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vadc_vvm_b,
        gen_helper_vadc_vvm_h,
        gen_helper_vadc_vvm_w,
        gen_helper_vadc_vvm_d,
    };

    return opivv_vadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vadc_vxm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vadc_vxm_b,
        gen_helper_vadc_vxm_h,
        gen_helper_vadc_vxm_w,
        gen_helper_vadc_vxm_d,
    };

    return opivx_vadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vadc_vim(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vadc_vxm_b,
        gen_helper_vadc_vxm_h,
        gen_helper_vadc_vxm_w,
        gen_helper_vadc_vxm_d,
    };

    return opivi_vadc_trans(ctx, a, sextract32(a->rs1, 0, 5),
                            fns[ctx->sew]);
}

static bool trans_vmadc_vvm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmadc_vvm_b,
        gen_helper_vmadc_vvm_h,
        gen_helper_vmadc_vvm_w,
        gen_helper_vmadc_vvm_d,
    };

    return opivv_vmadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmadc_vxm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmadc_vxm_b,
        gen_helper_vmadc_vxm_h,
        gen_helper_vmadc_vxm_w,
        gen_helper_vmadc_vxm_d,
    };

    return opivx_vmadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmadc_vim(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmadc_vxm_b,
        gen_helper_vmadc_vxm_h,
        gen_helper_vmadc_vxm_w,
        gen_helper_vmadc_vxm_d,
    };

    return opivi_vmadc_trans(ctx, a, sextract32(a->rs1, 0, 5),
                             fns[ctx->sew]);
}

static bool trans_vsbc_vvm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vsbc_vvm_b,
        gen_helper_vsbc_vvm_h,
        gen_helper_vsbc_vvm_w,
        gen_helper_vsbc_vvm_d,
    };

    return opivv_vadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsbc_vxm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsbc_vxm_b,
        gen_helper_vsbc_vxm_h,
        gen_helper_vsbc_vxm_w,
        gen_helper_vsbc_vxm_d,
    };

    return opivx_vadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmsbc_vvm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmsbc_vvm_b,
        gen_helper_vmsbc_vvm_h,
        gen_helper_vmsbc_vvm_w,
        gen_helper_vmsbc_vvm_d,
    };

    return opivv_vmadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmsbc_vxm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmsbc_vxm_b,
        gen_helper_vmsbc_vxm_h,
        gen_helper_vmsbc_vxm_w,
        gen_helper_vmsbc_vxm_d,
    };

    return opivx_vmadc_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vand_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vand_vx_b,
        gen_helper_vand_vx_h,
        gen_helper_vand_vx_w,
        gen_helper_vand_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vand_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vand_vx_b,
        gen_helper_vand_vx_h,
        gen_helper_vand_vx_w,
        gen_helper_vand_vx_d,
    };

    return opivi_trans(ctx, a, sextract32(a->rs1, 0, 5), fns[ctx->sew]);
}

static bool trans_vor_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vor_vx_b,
        gen_helper_vor_vx_h,
        gen_helper_vor_vx_w,
        gen_helper_vor_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vor_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vor_vx_b,
        gen_helper_vor_vx_h,
        gen_helper_vor_vx_w,
        gen_helper_vor_vx_d,
    };

    return opivi_trans(ctx, a, sextract32(a->rs1, 0, 5), fns[ctx->sew]);
}

static bool trans_vxor_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vxor_vx_b,
        gen_helper_vxor_vx_h,
        gen_helper_vxor_vx_w,
        gen_helper_vxor_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vxor_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vxor_vx_b,
        gen_helper_vxor_vx_h,
        gen_helper_vxor_vx_w,
        gen_helper_vxor_vx_d,
    };

    return opivi_trans(ctx, a, sextract32(a->rs1, 0, 5), fns[ctx->sew]);
}

static bool trans_vminu_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vminu_vx_b,
        gen_helper_vminu_vx_h,
        gen_helper_vminu_vx_w,
        gen_helper_vminu_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmin_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmin_vx_b,
        gen_helper_vmin_vx_h,
        gen_helper_vmin_vx_w,
        gen_helper_vmin_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmaxu_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmaxu_vx_b,
        gen_helper_vmaxu_vx_h,
        gen_helper_vmaxu_vx_w,
        gen_helper_vmaxu_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmax_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmax_vx_b,
        gen_helper_vmax_vx_h,
        gen_helper_vmax_vx_w,
        gen_helper_vmax_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmul_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmul_vx_b,
        gen_helper_vmul_vx_h,
        gen_helper_vmul_vx_w,
        gen_helper_vmul_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmulh_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmulh_vx_b,
        gen_helper_vmulh_vx_h,
        gen_helper_vmulh_vx_w,
        gen_helper_vmulh_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmulhu_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmulhu_vx_b,
        gen_helper_vmulhu_vx_h,
        gen_helper_vmulhu_vx_w,
        gen_helper_vmulhu_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmulhsu_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmulhsu_vx_b,
        gen_helper_vmulhsu_vx_h,
        gen_helper_vmulhsu_vx_w,
        gen_helper_vmulhsu_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vdivu_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vdivu_vx_b,
        gen_helper_vdivu_vx_h,
        gen_helper_vdivu_vx_w,
        gen_helper_vdivu_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vdiv_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vdiv_vx_b,
        gen_helper_vdiv_vx_h,
        gen_helper_vdiv_vx_w,
        gen_helper_vdiv_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vremu_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vremu_vx_b,
        gen_helper_vremu_vx_h,
        gen_helper_vremu_vx_w,
        gen_helper_vremu_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vrem_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vrem_vx_b,
        gen_helper_vrem_vx_h,
        gen_helper_vrem_vx_w,
        gen_helper_vrem_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

#define GEN_MAC_VX_TRANS(NAME)                                       \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    static gen_helper_opivx * const fns[4] = {                       \
        gen_helper_##NAME##_b,                                       \
        gen_helper_##NAME##_h,                                       \
        gen_helper_##NAME##_w,                                       \
        gen_helper_##NAME##_d,                                       \
    };                                                               \
                                                                     \
    return opivx_trans(ctx, a, fns[ctx->sew]);                       \
}

GEN_MAC_VX_TRANS(vmacc_vx)
GEN_MAC_VX_TRANS(vnmsac_vx)
GEN_MAC_VX_TRANS(vmadd_vx)
GEN_MAC_VX_TRANS(vnmsub_vx)

static bool trans_vsll_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsll_vx_b,
        gen_helper_vsll_vx_h,
        gen_helper_vsll_vx_w,
        gen_helper_vsll_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsll_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsll_vx_b,
        gen_helper_vsll_vx_h,
        gen_helper_vsll_vx_w,
        gen_helper_vsll_vx_d,
    };

    return opivi_trans(ctx, a, a->rs1, fns[ctx->sew]);
}

static bool trans_vsrl_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsrl_vx_b,
        gen_helper_vsrl_vx_h,
        gen_helper_vsrl_vx_w,
        gen_helper_vsrl_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsrl_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsrl_vx_b,
        gen_helper_vsrl_vx_h,
        gen_helper_vsrl_vx_w,
        gen_helper_vsrl_vx_d,
    };

    return opivi_trans(ctx, a, a->rs1, fns[ctx->sew]);
}

static bool trans_vsra_vx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsra_vx_b,
        gen_helper_vsra_vx_h,
        gen_helper_vsra_vx_w,
        gen_helper_vsra_vx_d,
    };

    return opivx_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsra_vi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vsra_vx_b,
        gen_helper_vsra_vx_h,
        gen_helper_vsra_vx_w,
        gen_helper_vsra_vx_d,
    };

    return opivi_trans(ctx, a, a->rs1, fns[ctx->sew]);
}

static bool opivv_narrow_shift_trans(DisasContext *ctx, arg_rvv_arith *a,
                                     gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_sds(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_narrow_shift_trans_common(DisasContext *ctx,
                                            arg_rvv_arith *a,
                                            bool is_imm,
                                            target_long imm,
                                            gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !vext_check_sd(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_narrow_shift_trans(DisasContext *ctx, arg_rvv_arith *a,
                                     gen_helper_opivx *fn)
{
    return opivx_narrow_shift_trans_common(ctx, a, false, 0, fn);
}

static bool opivi_narrow_shift_trans(DisasContext *ctx, arg_rvv_arith *a,
                                     target_long scalar_value,
                                     gen_helper_opivx *fn)
{
    return opivx_narrow_shift_trans_common(ctx, a, true, scalar_value, fn);
}

static bool trans_vnsrl_wv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[3] = {
        gen_helper_vnsrl_wv_b,
        gen_helper_vnsrl_wv_h,
        gen_helper_vnsrl_wv_w,
    };

    if (ctx->sew >= MO_64) {
        return false;
    }
    return opivv_narrow_shift_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vnsrl_wx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[3] = {
        gen_helper_vnsrl_wx_b,
        gen_helper_vnsrl_wx_h,
        gen_helper_vnsrl_wx_w,
    };

    if (ctx->sew >= MO_64) {
        return false;
    }
    return opivx_narrow_shift_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vnsrl_wi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[3] = {
        gen_helper_vnsrl_wx_b,
        gen_helper_vnsrl_wx_h,
        gen_helper_vnsrl_wx_w,
    };

    if (ctx->sew >= MO_64) {
        return false;
    }
    return opivi_narrow_shift_trans(ctx, a, a->rs1, fns[ctx->sew]);
}

static bool trans_vnsra_wv(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[3] = {
        gen_helper_vnsra_wv_b,
        gen_helper_vnsra_wv_h,
        gen_helper_vnsra_wv_w,
    };

    if (ctx->sew >= MO_64) {
        return false;
    }
    return opivv_narrow_shift_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vnsra_wx(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[3] = {
        gen_helper_vnsra_wx_b,
        gen_helper_vnsra_wx_h,
        gen_helper_vnsra_wx_w,
    };

    if (ctx->sew >= MO_64) {
        return false;
    }
    return opivx_narrow_shift_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vnsra_wi(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[3] = {
        gen_helper_vnsra_wx_b,
        gen_helper_vnsra_wx_h,
        gen_helper_vnsra_wx_w,
    };

    if (ctx->sew >= MO_64) {
        return false;
    }
    return opivi_narrow_shift_trans(ctx, a, a->rs1, fns[ctx->sew]);
}

static bool int_ext_check(DisasContext *ctx, arg_rvv_arith *a, uint8_t div)
{
    uint8_t from = (ctx->sew + 3) - div;

    return require_rvv_data(ctx) &&
           from >= 3 && from <= 8 &&
           a->rd != a->rs2 &&
           require_align(a->rd, ctx->lmul) &&
           require_align(a->rs2, ctx->lmul - div) &&
           require_vm(a->vm, a->rd) &&
           require_noover(a->rd, ctx->lmul, a->rs2, ctx->lmul - div);
}

static bool int_ext_trans(DisasContext *ctx, arg_rvv_arith *a,
                          gen_helper_opivm *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vzext_vf2(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivm * const fns[4] = {
        NULL,
        gen_helper_vzext_vf2_h,
        gen_helper_vzext_vf2_w,
        gen_helper_vzext_vf2_d,
    };

    if (!int_ext_check(ctx, a, 1)) {
        return false;
    }
    return int_ext_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vzext_vf4(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivm * const fns[4] = {
        NULL,
        NULL,
        gen_helper_vzext_vf4_w,
        gen_helper_vzext_vf4_d,
    };

    if (!int_ext_check(ctx, a, 2)) {
        return false;
    }
    return int_ext_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vzext_vf8(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivm * const fns[4] = {
        NULL,
        NULL,
        NULL,
        gen_helper_vzext_vf8_d,
    };

    if (!int_ext_check(ctx, a, 3)) {
        return false;
    }
    return int_ext_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsext_vf2(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivm * const fns[4] = {
        NULL,
        gen_helper_vsext_vf2_h,
        gen_helper_vsext_vf2_w,
        gen_helper_vsext_vf2_d,
    };

    if (!int_ext_check(ctx, a, 1)) {
        return false;
    }
    return int_ext_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsext_vf4(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivm * const fns[4] = {
        NULL,
        NULL,
        gen_helper_vsext_vf4_w,
        gen_helper_vsext_vf4_d,
    };

    if (!int_ext_check(ctx, a, 2)) {
        return false;
    }
    return int_ext_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vsext_vf8(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivm * const fns[4] = {
        NULL,
        NULL,
        NULL,
        gen_helper_vsext_vf8_d,
    };

    if (!int_ext_check(ctx, a, 3)) {
        return false;
    }
    return int_ext_trans(ctx, a, fns[ctx->sew]);
}

static bool vmerge_vv_trans(DisasContext *ctx, arg_rvv_arith *a,
                            gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || a->vm != 0 || a->rd == 0 ||
        !vext_check_sss(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool vmerge_vx_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                                   bool is_imm, target_long imm,
                                   gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || a->vm != 0 || a->rd == 0 ||
        !vext_check_ss(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vmerge_vvm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivv * const fns[4] = {
        gen_helper_vmerge_vvm_b,
        gen_helper_vmerge_vvm_h,
        gen_helper_vmerge_vvm_w,
        gen_helper_vmerge_vvm_d,
    };

    return vmerge_vv_trans(ctx, a, fns[ctx->sew]);
}

static bool trans_vmerge_vxm(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmerge_vxm_b,
        gen_helper_vmerge_vxm_h,
        gen_helper_vmerge_vxm_w,
        gen_helper_vmerge_vxm_d,
    };

    return vmerge_vx_trans_common(ctx, a, false, 0, fns[ctx->sew]);
}

static bool trans_vmerge_vim(DisasContext *ctx, arg_rvv_arith *a)
{
    static gen_helper_opivx * const fns[4] = {
        gen_helper_vmerge_vxm_b,
        gen_helper_vmerge_vxm_h,
        gen_helper_vmerge_vxm_w,
        gen_helper_vmerge_vxm_d,
    };

    return vmerge_vx_trans_common(ctx, a, true, sextract32(a->rs1, 0, 5),
                                  fns[ctx->sew]);
}

static bool opivv_cmp_trans(DisasContext *ctx, arg_rvv_arith *a,
                            gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || a->vm != 1 ||
        !vext_check_mss(ctx, a->rd, a->rs1, a->rs2)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_cmp_trans_common(DisasContext *ctx, arg_rvv_arith *a,
                                   bool is_imm, target_long imm,
                                   gen_helper_opivx *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) || a->vm != 1 ||
        !vext_check_ms(ctx, a->rd, a->rs2)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    if (is_imm) {
        scalar = tcg_const_tl(tcg_ctx, imm);
    } else {
        scalar = tcg_temp_new(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar, a->rs1);
    }

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opivx_cmp_trans(DisasContext *ctx, arg_rvv_arith *a,
                            gen_helper_opivx *fn)
{
    return opivx_cmp_trans_common(ctx, a, false, 0, fn);
}

static bool opivi_cmp_trans(DisasContext *ctx, arg_rvv_arith *a,
                            target_long scalar_value, gen_helper_opivx *fn)
{
    return opivx_cmp_trans_common(ctx, a, true, scalar_value, fn);
}

#define GEN_CMP_VV_TRANS(NAME)                                      \
static bool trans_##NAME##_vv(DisasContext *ctx, arg_rvv_arith *a)  \
{                                                                   \
    static gen_helper_opivv * const fns[4] = {                      \
        gen_helper_##NAME##_vv_b,                                   \
        gen_helper_##NAME##_vv_h,                                   \
        gen_helper_##NAME##_vv_w,                                   \
        gen_helper_##NAME##_vv_d,                                   \
    };                                                              \
                                                                    \
    return opivv_cmp_trans(ctx, a, fns[ctx->sew]);                  \
}

#define GEN_CMP_VX_TRANS(NAME)                                      \
static bool trans_##NAME##_vx(DisasContext *ctx, arg_rvv_arith *a)  \
{                                                                   \
    static gen_helper_opivx * const fns[4] = {                      \
        gen_helper_##NAME##_vx_b,                                   \
        gen_helper_##NAME##_vx_h,                                   \
        gen_helper_##NAME##_vx_w,                                   \
        gen_helper_##NAME##_vx_d,                                   \
    };                                                              \
                                                                    \
    return opivx_cmp_trans(ctx, a, fns[ctx->sew]);                  \
}

#define GEN_CMP_VI_TRANS(NAME)                                      \
static bool trans_##NAME##_vi(DisasContext *ctx, arg_rvv_arith *a)  \
{                                                                   \
    static gen_helper_opivx * const fns[4] = {                      \
        gen_helper_##NAME##_vx_b,                                   \
        gen_helper_##NAME##_vx_h,                                   \
        gen_helper_##NAME##_vx_w,                                   \
        gen_helper_##NAME##_vx_d,                                   \
    };                                                              \
                                                                    \
    return opivi_cmp_trans(ctx, a, sextract32(a->rs1, 0, 5),        \
                           fns[ctx->sew]);                         \
}

GEN_CMP_VV_TRANS(vmseq)
GEN_CMP_VV_TRANS(vmsne)
GEN_CMP_VV_TRANS(vmsltu)
GEN_CMP_VV_TRANS(vmslt)
GEN_CMP_VV_TRANS(vmsleu)
GEN_CMP_VV_TRANS(vmsle)
GEN_CMP_VX_TRANS(vmseq)
GEN_CMP_VX_TRANS(vmsne)
GEN_CMP_VX_TRANS(vmsltu)
GEN_CMP_VX_TRANS(vmslt)
GEN_CMP_VX_TRANS(vmsleu)
GEN_CMP_VX_TRANS(vmsle)
GEN_CMP_VX_TRANS(vmsgtu)
GEN_CMP_VX_TRANS(vmsgt)
GEN_CMP_VI_TRANS(vmseq)
GEN_CMP_VI_TRANS(vmsne)
GEN_CMP_VI_TRANS(vmsleu)
GEN_CMP_VI_TRANS(vmsle)
GEN_CMP_VI_TRANS(vmsgtu)
GEN_CMP_VI_TRANS(vmsgt)

static bool mask_mm_trans(DisasContext *ctx, arg_rvv_arith *a,
                          gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

#define GEN_MM_TRANS(NAME)                                           \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    return mask_mm_trans(ctx, a, gen_helper_##NAME);                 \
}

GEN_MM_TRANS(vmand_mm)
GEN_MM_TRANS(vmnand_mm)
GEN_MM_TRANS(vmandn_mm)
GEN_MM_TRANS(vmxor_mm)
GEN_MM_TRANS(vmor_mm)
GEN_MM_TRANS(vmnor_mm)
GEN_MM_TRANS(vmorn_mm)
GEN_MM_TRANS(vmxnor_mm)

static bool mask_scalar_trans(DisasContext *ctx, arg_rvv_arith *a,
                              gen_helper_mscalar *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv dest;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);

    dest = tcg_temp_new(tcg_ctx);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);
    gen_set_gpr(tcg_ctx, a->rd, dest);

    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);
    return true;
}

static bool trans_vcpop_m(DisasContext *ctx, arg_rvv_arith *a)
{
    return mask_scalar_trans(ctx, a, gen_helper_vcpop_m);
}

static bool trans_vfirst_m(DisasContext *ctx, arg_rvv_arith *a)
{
    return mask_scalar_trans(ctx, a, gen_helper_vfirst_m);
}

static bool mask_m_trans(DisasContext *ctx, arg_rvv_arith *a,
                         gen_helper_opivm *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (!require_rvv_data(ctx) ||
        !require_vm(a->vm, a->rd) ||
        a->rd == a->rs2) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    return true;
}

#define GEN_M_TRANS(NAME)                                            \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)        \
{                                                                    \
    return mask_m_trans(ctx, a, gen_helper_##NAME);                  \
}

GEN_M_TRANS(vmsbf_m)
GEN_M_TRANS(vmsif_m)
GEN_M_TRANS(vmsof_m)

static bool trans_viota_m(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;
    static gen_helper_opivm * const fns[4] = {
        gen_helper_viota_m_b,
        gen_helper_viota_m_h,
        gen_helper_viota_m_w,
        gen_helper_viota_m_d,
    };

    if (!require_rvv_data(ctx) ||
        !require_vm(a->vm, a->rd) ||
        !require_align(a->rd, ctx->lmul) ||
        is_overlapped(a->rd, 1 << MAX(ctx->lmul, 0), a->rs2, 1)) {
        return false;
    }

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fns[ctx->sew](tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    return true;
}

static bool trans_vid_v(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_i32 desc;
    uint32_t data = 0;
    static gen_helper_vid_v * const fns[4] = {
        gen_helper_vid_v_b,
        gen_helper_vid_v_h,
        gen_helper_vid_v_w,
        gen_helper_vid_v_d,
    };

    if (!require_rvv_data(ctx) ||
        !require_align(a->rd, ctx->lmul) ||
        !require_vm(a->vm, a->rd)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    desc = gen_rvv_desc(ctx, data);

    fns[ctx->sew](tcg_ctx, dest, mask, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool vmv_vx_trans(DisasContext *ctx, int rd, int rs1,
                         bool is_imm, target_long imm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv scalar_tl;
    TCGv_i64 scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    static gen_helper_vmv_vx * const fns[4] = {
        gen_helper_vmv_v_x_b,
        gen_helper_vmv_v_x_h,
        gen_helper_vmv_v_x_w,
        gen_helper_vmv_v_x_d,
    };

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    if (is_imm) {
        scalar_tl = NULL;
        scalar = tcg_const_i64(tcg_ctx, imm);
    } else {
        scalar_tl = tcg_temp_new(tcg_ctx);
        scalar = tcg_temp_new_i64(tcg_ctx);
        gen_get_gpr(tcg_ctx, scalar_tl, rs1);
        tcg_gen_ext_tl_i64(tcg_ctx, scalar, scalar_tl);
    }

    dest = gen_vreg_ptr(ctx, rd);
    desc = gen_rvv_desc(ctx, data);

    fns[ctx->sew](tcg_ctx, dest, scalar, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_i64(tcg_ctx, scalar);
    if (!is_imm) {
        tcg_temp_free(tcg_ctx, scalar_tl);
    }
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vmv_v_v(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr src1;
    TCGv_i32 desc;
    uint32_t data = 0;

    static gen_helper_vmv_vv * const fns[4] = {
        gen_helper_vmv_v_v_b,
        gen_helper_vmv_v_v_h,
        gen_helper_vmv_v_v_w,
        gen_helper_vmv_v_v_d,
    };

    if (!require_rvv_data(ctx) || a->vm != 1 || a->rs2 != 0 ||
        !vext_check_sss(ctx, a->rd, a->rs1, 0, 1)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    desc = gen_rvv_desc(ctx, data);

    fns[ctx->sew](tcg_ctx, dest, src1, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vmv_v_x(DisasContext *ctx, arg_rvv_arith *a)
{
    if (!require_rvv_data(ctx) || a->vm != 1 || a->rs2 != 0 ||
        !vext_check_ss(ctx, a->rd, 0, 1)) {
        return false;
    }

    return vmv_vx_trans(ctx, a->rd, a->rs1, false, 0);
}

static bool trans_vmv_v_i(DisasContext *ctx, arg_rvv_arith *a)
{
    if (!require_rvv_data(ctx) || a->vm != 1 || a->rs2 != 0 ||
        !vext_check_ss(ctx, a->rd, 0, 1)) {
        return false;
    }

    return vmv_vx_trans(ctx, a->rd, 0, true, sextract32(a->rs1, 0, 5));
}

static void load_element(DisasContext *ctx, TCGv_i64 dest, TCGv_ptr base,
                         int ofs, int sew, bool sign)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    switch (sew) {
    case MO_8:
        if (sign) {
            tcg_gen_ld8s_i64(tcg_ctx, dest, base, ofs);
        } else {
            tcg_gen_ld8u_i64(tcg_ctx, dest, base, ofs);
        }
        break;
    case MO_16:
        if (sign) {
            tcg_gen_ld16s_i64(tcg_ctx, dest, base, ofs);
        } else {
            tcg_gen_ld16u_i64(tcg_ctx, dest, base, ofs);
        }
        break;
    case MO_32:
        if (sign) {
            tcg_gen_ld32s_i64(tcg_ctx, dest, base, ofs);
        } else {
            tcg_gen_ld32u_i64(tcg_ctx, dest, base, ofs);
        }
        break;
    case MO_64:
        tcg_gen_ld_i64(tcg_ctx, dest, base, ofs);
        break;
    default:
        g_assert_not_reached();
    }
}

static uint32_t endian_ofs(DisasContext *ctx, int reg, int idx)
{
#if HOST_BIG_ENDIAN
    return vreg_ofs(ctx, reg) + ((idx ^ (7 >> ctx->sew)) << ctx->sew);
#else
    return vreg_ofs(ctx, reg) + (idx << ctx->sew);
#endif
}

static void vec_element_loadi(DisasContext *ctx, TCGv_i64 dest,
                              int reg, int idx, bool sign)
{
    load_element(ctx, dest, ctx->uc->tcg_ctx->cpu_env,
                 endian_ofs(ctx, reg, idx), ctx->sew, sign);
}

static void store_element(DisasContext *ctx, TCGv_i64 val, TCGv_ptr base,
                          int ofs, int sew)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    switch (sew) {
    case MO_8:
        tcg_gen_st8_i64(tcg_ctx, val, base, ofs);
        break;
    case MO_16:
        tcg_gen_st16_i64(tcg_ctx, val, base, ofs);
        break;
    case MO_32:
        tcg_gen_st32_i64(tcg_ctx, val, base, ofs);
        break;
    case MO_64:
        tcg_gen_st_i64(tcg_ctx, val, base, ofs);
        break;
    default:
        g_assert_not_reached();
    }
}

static void vec_element_storei(DisasContext *ctx, int reg,
                               int idx, TCGv_i64 val)
{
    store_element(ctx, val, ctx->uc->tcg_ctx->cpu_env,
                  endian_ofs(ctx, reg, idx), ctx->sew);
}

static bool trans_vmv_x_s(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 elem;
    TCGv dest;

    if (!require_rvv_data(ctx) || a->vm != 1 || a->rs1 != 0) {
        return false;
    }

    elem = tcg_temp_new_i64(tcg_ctx);
    dest = tcg_temp_new(tcg_ctx);
    vec_element_loadi(ctx, elem, a->rs2, 0, true);
    tcg_gen_trunc_i64_tl(tcg_ctx, dest, elem);
    gen_set_gpr(tcg_ctx, a->rd, dest);
    tcg_temp_free(tcg_ctx, dest);
    tcg_temp_free_i64(tcg_ctx, elem);
    return true;
}

static bool trans_vmv_s_x(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv scalar_tl;
    TCGv_i64 scalar;

    if (!require_rvv_data(ctx) || a->vm != 1 || a->rs2 != 0) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    scalar_tl = tcg_temp_new(tcg_ctx);
    scalar = tcg_temp_new_i64(tcg_ctx);
    gen_get_gpr(tcg_ctx, scalar_tl, a->rs1);
    tcg_gen_ext_tl_i64(tcg_ctx, scalar, scalar_tl);
    vec_element_storei(ctx, a->rd, 0, scalar);
    tcg_temp_free_i64(tcg_ctx, scalar);
    tcg_temp_free(tcg_ctx, scalar_tl);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static void rvv_nanbox_scalar(DisasContext *ctx, TCGv_i64 dest, TCGv_i64 src)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    switch (ctx->sew) {
    case MO_16:
        gen_check_nanbox_h(tcg_ctx, dest, src);
        break;
    case MO_32:
        gen_check_nanbox_s(tcg_ctx, dest, src);
        break;
    case MO_64:
        tcg_gen_mov_i64(tcg_ctx, dest, src);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool trans_vfmv_v_f(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_i64 scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    static gen_helper_vmv_vx * const fns[4] = {
        NULL,
        gen_helper_vmv_v_x_h,
        gen_helper_vmv_v_x_w,
        gen_helper_vmv_v_x_d,
    };

    if (ctx->sew > MO_64 || fns[ctx->sew] == NULL ||
        !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        a->rs2 != 0 || a->vm != 1 || !require_align(a->rd, ctx->lmul)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    scalar = tcg_temp_new_i64(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    rvv_nanbox_scalar(ctx, scalar, tcg_ctx->cpu_fpr[a->rs1]);
    fns[ctx->sew](tcg_ctx, dest, scalar, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_i64(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool trans_vfmv_f_s(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    unsigned int ofs;
    unsigned int len;

    if (!require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        a->rs1 != 0 || a->vm != 1) {
        return false;
    }

    gen_set_rm(ctx, 7);
    vec_element_loadi(ctx, tcg_ctx->cpu_fpr[a->rd], a->rs2, 0, false);

    ofs = 8 << ctx->sew;
    len = 64 - ofs;
    if (len != 0) {
        TCGv_i64 ones = tcg_const_i64(tcg_ctx, UINT64_MAX);

        tcg_gen_deposit_i64(tcg_ctx, tcg_ctx->cpu_fpr[a->rd],
                            tcg_ctx->cpu_fpr[a->rd], ones, ofs, len);
        tcg_temp_free_i64(tcg_ctx, ones);
    }

    mark_fs_dirty(ctx);
    return true;
}

static bool trans_vfmv_s_f(DisasContext *ctx, arg_rvv_arith *a)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_i64 scalar;

    if (!require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        a->rs2 != 0 || a->vm != 1) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    scalar = tcg_temp_new_i64(tcg_ctx);
    rvv_nanbox_scalar(ctx, scalar, tcg_ctx->cpu_fpr[a->rs1]);
    vec_element_storei(ctx, a->rd, 0, scalar);
    tcg_temp_free_i64(tcg_ctx, scalar);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvv_trans(DisasContext *ctx, arg_rvv_arith *a,
                        gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_sss(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvf_trans(DisasContext *ctx, arg_rvv_arith *a,
                        gen_helper_opfvf *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i64 scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_ss(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    scalar = tcg_temp_new_i64(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    rvv_nanbox_scalar(ctx, scalar, tcg_ctx->cpu_fpr[a->rs1]);
    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i64(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvf_slide_trans(DisasContext *ctx, arg_rvv_arith *a,
                              gen_helper_opfvf *fn, bool slide_up)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i64 scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_slide(ctx, a->rd, a->rs2, a->vm, slide_up)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    scalar = tcg_temp_new_i64(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    rvv_nanbox_scalar(ctx, scalar, tcg_ctx->cpu_fpr[a->rs1]);
    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i64(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvv_widen_trans(DisasContext *ctx, arg_rvv_arith *a,
                              gen_helper_opivv *fn, bool wide_vs2)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_scale_rvf(ctx) ||
        !require_scale_zve32f(ctx) || !require_scale_zve64f(ctx)) {
        return false;
    }
    if (wide_vs2) {
        if (!vext_check_dds(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
            return false;
        }
    } else if (!vext_check_dss(ctx, a->rd, a->rs1, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvf_widen_trans(DisasContext *ctx, arg_rvv_arith *a,
                              gen_helper_opfvf *fn, bool wide_vs2)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i64 scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_scale_rvf(ctx) ||
        !require_scale_zve32f(ctx) || !require_scale_zve64f(ctx)) {
        return false;
    }
    if (wide_vs2) {
        if (!vext_check_dd(ctx, a->rd, a->rs2, a->vm)) {
            return false;
        }
    } else if (!vext_check_ds(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    scalar = tcg_temp_new_i64(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    rvv_nanbox_scalar(ctx, scalar, tcg_ctx->cpu_fpr[a->rs1]);
    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i64(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvv_cmp_trans(DisasContext *ctx, arg_rvv_arith *a,
                            gen_helper_opivv *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src1;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_mss(ctx, a->rd, a->rs1, a->rs2)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src1 = gen_vreg_ptr(ctx, a->rs1);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src1, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src1);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfvf_cmp_trans(DisasContext *ctx, arg_rvv_arith *a,
                            gen_helper_opfvf *fn)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i64 scalar;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_ms(ctx, a->rd, a->rs2)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, 7);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VTA_ALL_1S, ctx->rvv_ta_all_1s, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    scalar = tcg_temp_new_i64(tcg_ctx);
    desc = gen_rvv_desc(ctx, data);

    rvv_nanbox_scalar(ctx, scalar, tcg_ctx->cpu_fpr[a->rs1]);
    fn(tcg_ctx, dest, mask, scalar, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i64(tcg_ctx, scalar);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfv_trans(DisasContext *ctx, arg_rvv_arith *a,
                       gen_helper_opivm *fn, int rm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx) || !require_rvf(ctx) ||
        !require_zve32f(ctx) || !require_zve64f(ctx) ||
        !vext_check_ss(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, rm);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfv_widen_cvt_trans(DisasContext *ctx, arg_rvv_arith *a,
                                 gen_helper_opivm *fn,
                                 bool fp_src, bool fp_dest, int rm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx)) {
        return false;
    }
    if (fp_src) {
        if (!require_rvf(ctx) || !require_zve32f(ctx) ||
            !require_zve64f(ctx)) {
            return false;
        }
    }
    if (fp_dest) {
        if (!require_scale_rvf(ctx) || !require_scale_zve32f(ctx) ||
            !require_scale_zve64f(ctx)) {
            return false;
        }
    }
    if (fp_src && fp_dest && ctx->sew == MO_8) {
        return false;
    }
    if (!vext_check_ds(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, rm);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

static bool opfv_narrow_cvt_trans(DisasContext *ctx, arg_rvv_arith *a,
                                  gen_helper_opivm *fn,
                                  bool fp_src, bool fp_dest, int rm)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGLabel *over;
    TCGv_ptr dest;
    TCGv_ptr mask;
    TCGv_ptr src2;
    TCGv_i32 desc;
    uint32_t data = 0;

    if (fn == NULL || !require_rvv_data(ctx)) {
        return false;
    }
    if (fp_src) {
        if (!require_scale_rvf(ctx) || !require_scale_zve32f(ctx) ||
            !require_scale_zve64f(ctx)) {
            return false;
        }
    }
    if (fp_dest) {
        if (!require_rvf(ctx) || !require_zve32f(ctx) ||
            !require_zve64f(ctx)) {
            return false;
        }
    }
    if (fp_src && fp_dest && ctx->sew == MO_8) {
        return false;
    }
    if (!vext_check_sd(ctx, a->rd, a->rs2, a->vm)) {
        return false;
    }

    over = gen_new_label(tcg_ctx);
    gen_set_rm(ctx, rm);
    tcg_gen_brcondi_tl(tcg_ctx, TCG_COND_EQ, cpu_vl, 0, over);
    tcg_gen_brcond_tl(tcg_ctx, TCG_COND_GEU, cpu_vstart, cpu_vl, over);

    FIELD_DP32(data, VDATA, VM, a->vm, data);
    FIELD_DP32(data, VDATA, LMUL, ctx->lmul, data);
    FIELD_DP32(data, VDATA, VTA, ctx->vta, data);
    FIELD_DP32(data, VDATA, VMA, ctx->vma, data);

    dest = gen_vreg_ptr(ctx, a->rd);
    mask = gen_vreg_ptr(ctx, 0);
    src2 = gen_vreg_ptr(ctx, a->rs2);
    desc = gen_rvv_desc(ctx, data);

    fn(tcg_ctx, dest, mask, src2, tcg_ctx->cpu_env, desc);

    tcg_temp_free_ptr(tcg_ctx, dest);
    tcg_temp_free_ptr(tcg_ctx, mask);
    tcg_temp_free_ptr(tcg_ctx, src2);
    tcg_temp_free_i32(tcg_ctx, desc);

    mark_vs_dirty(ctx);
    gen_set_label(tcg_ctx, over);
    return true;
}

#define GEN_OPFVV_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)      \
{                                                                  \
    static gen_helper_opivv * const fns[4] = {                     \
        NULL,                                                      \
        gen_helper_##NAME##_h,                                     \
        gen_helper_##NAME##_w,                                     \
        gen_helper_##NAME##_d,                                     \
    };                                                             \
                                                                   \
    if (ctx->sew > MO_64) {                                        \
        return false;                                              \
    }                                                              \
    return opfvv_trans(ctx, a, fns[ctx->sew]);                     \
}

#define GEN_OPFVF_TRANS(NAME)                                      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)      \
{                                                                  \
    static gen_helper_opfvf * const fns[4] = {                     \
        NULL,                                                      \
        gen_helper_##NAME##_h,                                     \
        gen_helper_##NAME##_w,                                     \
        gen_helper_##NAME##_d,                                     \
    };                                                             \
                                                                   \
    if (ctx->sew > MO_64) {                                        \
        return false;                                              \
    }                                                              \
    return opfvf_trans(ctx, a, fns[ctx->sew]);                     \
}

#define GEN_OPFVF_SLIDE_TRANS(NAME, SLIDE_UP)                       \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)       \
{                                                                   \
    static gen_helper_opfvf * const fns[4] = {                      \
        NULL,                                                       \
        gen_helper_##NAME##_h,                                      \
        gen_helper_##NAME##_w,                                      \
        gen_helper_##NAME##_d,                                      \
    };                                                              \
                                                                    \
    if (ctx->sew > MO_64) {                                         \
        return false;                                               \
    }                                                               \
    return opfvf_slide_trans(ctx, a, fns[ctx->sew], SLIDE_UP);      \
}

#define GEN_OPFVV_WIDEN_TRANS(NAME, WIDE_VS2)                       \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)       \
{                                                                   \
    static gen_helper_opivv * const fns[4] = {                      \
        NULL,                                                       \
        gen_helper_##NAME##_h,                                      \
        gen_helper_##NAME##_w,                                      \
        NULL,                                                       \
    };                                                              \
                                                                    \
    return opfvv_widen_trans(ctx, a, fns[ctx->sew], WIDE_VS2);      \
}

#define GEN_OPFVF_WIDEN_TRANS(NAME, WIDE_VS2)                       \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)       \
{                                                                   \
    static gen_helper_opfvf * const fns[4] = {                      \
        NULL,                                                       \
        gen_helper_##NAME##_h,                                      \
        gen_helper_##NAME##_w,                                      \
        NULL,                                                       \
    };                                                              \
                                                                    \
    return opfvf_widen_trans(ctx, a, fns[ctx->sew], WIDE_VS2);      \
}

#define GEN_OPFVV_CMP_TRANS(NAME)                                  \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)      \
{                                                                  \
    static gen_helper_opivv * const fns[4] = {                     \
        NULL,                                                      \
        gen_helper_##NAME##_h,                                     \
        gen_helper_##NAME##_w,                                     \
        gen_helper_##NAME##_d,                                     \
    };                                                             \
                                                                   \
    if (ctx->sew > MO_64) {                                        \
        return false;                                              \
    }                                                              \
    return opfvv_cmp_trans(ctx, a, fns[ctx->sew]);                 \
}

#define GEN_OPFVF_CMP_TRANS(NAME)                                  \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)      \
{                                                                  \
    static gen_helper_opfvf * const fns[4] = {                     \
        NULL,                                                      \
        gen_helper_##NAME##_h,                                     \
        gen_helper_##NAME##_w,                                     \
        gen_helper_##NAME##_d,                                     \
    };                                                             \
                                                                   \
    if (ctx->sew > MO_64) {                                        \
        return false;                                              \
    }                                                              \
    return opfvf_cmp_trans(ctx, a, fns[ctx->sew]);                 \
}

#define GEN_OPFV_TRANS(NAME)                                             \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)            \
{                                                                        \
    static gen_helper_opivm * const fns[4] = {                           \
        NULL,                                                            \
        gen_helper_##NAME##_h,                                           \
        gen_helper_##NAME##_w,                                           \
        gen_helper_##NAME##_d,                                           \
    };                                                                   \
                                                                         \
    if (ctx->sew > MO_64) {                                              \
        return false;                                                    \
    }                                                                    \
    return opfv_trans(ctx, a, fns[ctx->sew], RISCV_FRM_DYN);             \
}

#define GEN_OPFV_CVT_TRANS(NAME, HELPER, RM)                             \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)            \
{                                                                        \
    static gen_helper_opivm * const fns[4] = {                           \
        NULL,                                                            \
        gen_helper_##HELPER##_h,                                         \
        gen_helper_##HELPER##_w,                                         \
        gen_helper_##HELPER##_d,                                         \
    };                                                                   \
                                                                         \
    if (ctx->sew > MO_64) {                                              \
        return false;                                                    \
    }                                                                    \
    return opfv_trans(ctx, a, fns[ctx->sew], RM);                        \
}

#define GEN_OPFV_WIDEN_CVT_TRANS(NAME, HELPER, FP_SRC, FP_DEST, RM)      \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)            \
{                                                                        \
    static gen_helper_opivm * const fns[4] = {                           \
        gen_helper_##HELPER##_b,                                         \
        gen_helper_##HELPER##_h,                                         \
        gen_helper_##HELPER##_w,                                         \
        NULL,                                                            \
    };                                                                   \
                                                                         \
    return opfv_widen_cvt_trans(ctx, a, fns[ctx->sew], FP_SRC,           \
                                FP_DEST, RM);                            \
}

#define GEN_OPFV_WIDEN_CVT_TRANS_HW(NAME, HELPER, FP_SRC, FP_DEST, RM)   \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)            \
{                                                                        \
    static gen_helper_opivm * const fns[4] = {                           \
        NULL,                                                            \
        gen_helper_##HELPER##_h,                                         \
        gen_helper_##HELPER##_w,                                         \
        NULL,                                                            \
    };                                                                   \
                                                                         \
    return opfv_widen_cvt_trans(ctx, a, fns[ctx->sew], FP_SRC,           \
                                FP_DEST, RM);                            \
}

#define GEN_OPFV_NARROW_CVT_TRANS(NAME, HELPER, FP_SRC, FP_DEST, RM)     \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)            \
{                                                                        \
    static gen_helper_opivm * const fns[4] = {                           \
        gen_helper_##HELPER##_b,                                         \
        gen_helper_##HELPER##_h,                                         \
        gen_helper_##HELPER##_w,                                         \
        NULL,                                                            \
    };                                                                   \
                                                                         \
    return opfv_narrow_cvt_trans(ctx, a, fns[ctx->sew], FP_SRC,          \
                                 FP_DEST, RM);                           \
}

#define GEN_OPFV_NARROW_CVT_TRANS_HW(NAME, HELPER, FP_SRC, FP_DEST, RM)  \
static bool trans_##NAME(DisasContext *ctx, arg_rvv_arith *a)            \
{                                                                        \
    static gen_helper_opivm * const fns[4] = {                           \
        NULL,                                                            \
        gen_helper_##HELPER##_h,                                         \
        gen_helper_##HELPER##_w,                                         \
        NULL,                                                            \
    };                                                                   \
                                                                         \
    return opfv_narrow_cvt_trans(ctx, a, fns[ctx->sew], FP_SRC,          \
                                 FP_DEST, RM);                           \
}

GEN_OPFVV_TRANS(vfadd_vv)
GEN_OPFVV_TRANS(vfsub_vv)
GEN_OPFVV_TRANS(vfmul_vv)
GEN_OPFVV_TRANS(vfdiv_vv)
GEN_OPFVV_TRANS(vfmin_vv)
GEN_OPFVV_TRANS(vfmax_vv)
GEN_OPFVV_TRANS(vfsgnj_vv)
GEN_OPFVV_TRANS(vfsgnjn_vv)
GEN_OPFVV_TRANS(vfsgnjx_vv)
GEN_OPFVF_TRANS(vfadd_vf)
GEN_OPFVF_TRANS(vfsub_vf)
GEN_OPFVF_TRANS(vfrsub_vf)
GEN_OPFVF_TRANS(vfmul_vf)
GEN_OPFVF_TRANS(vfdiv_vf)
GEN_OPFVF_TRANS(vfrdiv_vf)
GEN_OPFVF_TRANS(vfmin_vf)
GEN_OPFVF_TRANS(vfmax_vf)
GEN_OPFVF_TRANS(vfsgnj_vf)
GEN_OPFVF_TRANS(vfsgnjn_vf)
GEN_OPFVF_TRANS(vfsgnjx_vf)
GEN_OPFVV_WIDEN_TRANS(vfwadd_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwadd_vf, false)
GEN_OPFVV_WIDEN_TRANS(vfwsub_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwsub_vf, false)
GEN_OPFVV_WIDEN_TRANS(vfwadd_wv, true)
GEN_OPFVF_WIDEN_TRANS(vfwadd_wf, true)
GEN_OPFVV_WIDEN_TRANS(vfwsub_wv, true)
GEN_OPFVF_WIDEN_TRANS(vfwsub_wf, true)
GEN_OPFVV_WIDEN_TRANS(vfwmul_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwmul_vf, false)
GEN_OPFVV_TRANS(vfmacc_vv)
GEN_OPFVF_TRANS(vfmacc_vf)
GEN_OPFVV_TRANS(vfnmacc_vv)
GEN_OPFVF_TRANS(vfnmacc_vf)
GEN_OPFVV_TRANS(vfmsac_vv)
GEN_OPFVF_TRANS(vfmsac_vf)
GEN_OPFVV_TRANS(vfnmsac_vv)
GEN_OPFVF_TRANS(vfnmsac_vf)
GEN_OPFVV_TRANS(vfmadd_vv)
GEN_OPFVF_TRANS(vfmadd_vf)
GEN_OPFVV_TRANS(vfnmadd_vv)
GEN_OPFVF_TRANS(vfnmadd_vf)
GEN_OPFVV_TRANS(vfmsub_vv)
GEN_OPFVF_TRANS(vfmsub_vf)
GEN_OPFVV_TRANS(vfnmsub_vv)
GEN_OPFVF_TRANS(vfnmsub_vf)
GEN_OPFVV_WIDEN_TRANS(vfwmacc_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwmacc_vf, false)
GEN_OPFVV_WIDEN_TRANS(vfwnmacc_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwnmacc_vf, false)
GEN_OPFVV_WIDEN_TRANS(vfwmsac_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwmsac_vf, false)
GEN_OPFVV_WIDEN_TRANS(vfwnmsac_vv, false)
GEN_OPFVF_WIDEN_TRANS(vfwnmsac_vf, false)
GEN_OPFVV_CMP_TRANS(vmfeq_vv)
GEN_OPFVV_CMP_TRANS(vmfne_vv)
GEN_OPFVV_CMP_TRANS(vmflt_vv)
GEN_OPFVV_CMP_TRANS(vmfle_vv)
GEN_OPFVF_CMP_TRANS(vmfeq_vf)
GEN_OPFVF_CMP_TRANS(vmfne_vf)
GEN_OPFVF_CMP_TRANS(vmflt_vf)
GEN_OPFVF_CMP_TRANS(vmfle_vf)
GEN_OPFVF_CMP_TRANS(vmfgt_vf)
GEN_OPFVF_CMP_TRANS(vmfge_vf)
GEN_OPFV_TRANS(vfsqrt_v)
GEN_OPFV_TRANS(vfrsqrt7_v)
GEN_OPFV_TRANS(vfrec7_v)
GEN_OPFV_CVT_TRANS(vfcvt_xu_f_v, vfcvt_xu_f_v, RISCV_FRM_DYN)
GEN_OPFV_CVT_TRANS(vfcvt_x_f_v, vfcvt_x_f_v, RISCV_FRM_DYN)
GEN_OPFV_CVT_TRANS(vfcvt_f_xu_v, vfcvt_f_xu_v, RISCV_FRM_DYN)
GEN_OPFV_CVT_TRANS(vfcvt_f_x_v, vfcvt_f_x_v, RISCV_FRM_DYN)
GEN_OPFV_CVT_TRANS(vfcvt_rtz_xu_f_v, vfcvt_xu_f_v, RISCV_FRM_RTZ)
GEN_OPFV_CVT_TRANS(vfcvt_rtz_x_f_v, vfcvt_x_f_v, RISCV_FRM_RTZ)
GEN_OPFV_WIDEN_CVT_TRANS_HW(vfwcvt_xu_f_v, vfwcvt_xu_f_v, true, false,
                            RISCV_FRM_DYN)
GEN_OPFV_WIDEN_CVT_TRANS_HW(vfwcvt_x_f_v, vfwcvt_x_f_v, true, false,
                            RISCV_FRM_DYN)
GEN_OPFV_WIDEN_CVT_TRANS_HW(vfwcvt_rtz_xu_f_v, vfwcvt_xu_f_v, true, false,
                            RISCV_FRM_RTZ)
GEN_OPFV_WIDEN_CVT_TRANS_HW(vfwcvt_rtz_x_f_v, vfwcvt_x_f_v, true, false,
                            RISCV_FRM_RTZ)
GEN_OPFV_WIDEN_CVT_TRANS(vfwcvt_f_xu_v, vfwcvt_f_xu_v, false, true,
                         RISCV_FRM_DYN)
GEN_OPFV_WIDEN_CVT_TRANS(vfwcvt_f_x_v, vfwcvt_f_x_v, false, true,
                         RISCV_FRM_DYN)
GEN_OPFV_WIDEN_CVT_TRANS_HW(vfwcvt_f_f_v, vfwcvt_f_f_v, true, true,
                            RISCV_FRM_DYN)
GEN_OPFV_NARROW_CVT_TRANS(vfncvt_xu_f_w, vfncvt_xu_f_w, true, false,
                          RISCV_FRM_DYN)
GEN_OPFV_NARROW_CVT_TRANS(vfncvt_x_f_w, vfncvt_x_f_w, true, false,
                          RISCV_FRM_DYN)
GEN_OPFV_NARROW_CVT_TRANS(vfncvt_rtz_xu_f_w, vfncvt_xu_f_w, true, false,
                          RISCV_FRM_RTZ)
GEN_OPFV_NARROW_CVT_TRANS(vfncvt_rtz_x_f_w, vfncvt_x_f_w, true, false,
                          RISCV_FRM_RTZ)
GEN_OPFV_NARROW_CVT_TRANS_HW(vfncvt_f_xu_w, vfncvt_f_xu_w, false, true,
                             RISCV_FRM_DYN)
GEN_OPFV_NARROW_CVT_TRANS_HW(vfncvt_f_x_w, vfncvt_f_x_w, false, true,
                             RISCV_FRM_DYN)
GEN_OPFV_NARROW_CVT_TRANS_HW(vfncvt_f_f_w, vfncvt_f_f_w, true, true,
                             RISCV_FRM_DYN)
GEN_OPFV_NARROW_CVT_TRANS_HW(vfncvt_rod_f_f_w, vfncvt_f_f_w, true, true,
                             RISCV_FRM_ROD)
GEN_OPFV_TRANS(vfclass_v)
GEN_OPFVF_TRANS(vfmerge_vfm)
GEN_OPFVF_SLIDE_TRANS(vfslide1up_vf, true)
GEN_OPFVF_SLIDE_TRANS(vfslide1down_vf, false)

static bool decode_rvv_config(DisasContext *ctx, uint32_t insn)
{
    if ((insn & 0x0000707f) != 0x00007057) {
        return false;
    }

    if ((insn & 0xfe00707f) == 0x80007057) {
        arg_vsetvl a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vsetvl(ctx, &a);
    }

    if ((insn & 0xc000707f) == 0xc0007057) {
        arg_vsetivli a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .zimm = extract32(insn, 20, 10),
        };

        return trans_vsetivli(ctx, &a);
    }

    if ((insn & 0x8000707f) == 0x00007057) {
        arg_vsetvli a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .zimm = extract32(insn, 20, 11),
        };

        return trans_vsetvli(ctx, &a);
    }

    return false;
}

static bool decode_rvv_data(DisasContext *ctx, uint32_t insn)
{
    static const struct {
        uint32_t value;
        bool (*trans)(DisasContext *, arg_rvv_ldst *);
    } whole[] = {
        { 0x02800007, trans_vl1re8_v },
        { 0x02805007, trans_vl1re16_v },
        { 0x02806007, trans_vl1re32_v },
        { 0x02807007, trans_vl1re64_v },
        { 0x22800007, trans_vl2re8_v },
        { 0x22805007, trans_vl2re16_v },
        { 0x22806007, trans_vl2re32_v },
        { 0x22807007, trans_vl2re64_v },
        { 0x62800007, trans_vl4re8_v },
        { 0x62805007, trans_vl4re16_v },
        { 0x62806007, trans_vl4re32_v },
        { 0x62807007, trans_vl4re64_v },
        { 0xe2800007, trans_vl8re8_v },
        { 0xe2805007, trans_vl8re16_v },
        { 0xe2806007, trans_vl8re32_v },
        { 0xe2807007, trans_vl8re64_v },
        { 0x02800027, trans_vs1r_v },
        { 0x22800027, trans_vs2r_v },
        { 0x62800027, trans_vs4r_v },
        { 0xe2800027, trans_vs8r_v },
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(whole); i++) {
        if ((insn & 0xfff0707f) == whole[i].value) {
            arg_rvv_ldst a = {
                .rd = extract32(insn, 7, 5),
                .rs1 = extract32(insn, 15, 5),
            };

            return whole[i].trans(ctx, &a);
        }
    }

    {
        static const struct {
            uint32_t value;
            bool (*trans)(DisasContext *, arg_rvv_arith *);
        } fp_arith[] = {
            { 0x00001057, trans_vfadd_vv },
            { 0x00005057, trans_vfadd_vf },
            { 0x08001057, trans_vfsub_vv },
            { 0x08005057, trans_vfsub_vf },
            { 0x10001057, trans_vfmin_vv },
            { 0x10005057, trans_vfmin_vf },
            { 0x18001057, trans_vfmax_vv },
            { 0x18005057, trans_vfmax_vf },
            { 0x20001057, trans_vfsgnj_vv },
            { 0x20005057, trans_vfsgnj_vf },
            { 0x24001057, trans_vfsgnjn_vv },
            { 0x24005057, trans_vfsgnjn_vf },
            { 0x28001057, trans_vfsgnjx_vv },
            { 0x28005057, trans_vfsgnjx_vf },
            { 0x38005057, trans_vfslide1up_vf },
            { 0x3c005057, trans_vfslide1down_vf },
            { 0x60001057, trans_vmfeq_vv },
            { 0x60005057, trans_vmfeq_vf },
            { 0x64001057, trans_vmfle_vv },
            { 0x64005057, trans_vmfle_vf },
            { 0x6c001057, trans_vmflt_vv },
            { 0x6c005057, trans_vmflt_vf },
            { 0x70001057, trans_vmfne_vv },
            { 0x70005057, trans_vmfne_vf },
            { 0x74005057, trans_vmfgt_vf },
            { 0x7c005057, trans_vmfge_vf },
            { 0x80001057, trans_vfdiv_vv },
            { 0x80005057, trans_vfdiv_vf },
            { 0x84005057, trans_vfrdiv_vf },
            { 0x90001057, trans_vfmul_vv },
            { 0x90005057, trans_vfmul_vf },
            { 0x9c005057, trans_vfrsub_vf },
            { 0xa0001057, trans_vfmadd_vv },
            { 0xa0005057, trans_vfmadd_vf },
            { 0xa4001057, trans_vfnmadd_vv },
            { 0xa4005057, trans_vfnmadd_vf },
            { 0xa8001057, trans_vfmsub_vv },
            { 0xa8005057, trans_vfmsub_vf },
            { 0xac001057, trans_vfnmsub_vv },
            { 0xac005057, trans_vfnmsub_vf },
            { 0xb0001057, trans_vfmacc_vv },
            { 0xb0005057, trans_vfmacc_vf },
            { 0xb4001057, trans_vfnmacc_vv },
            { 0xb4005057, trans_vfnmacc_vf },
            { 0xb8001057, trans_vfmsac_vv },
            { 0xb8005057, trans_vfmsac_vf },
            { 0xbc001057, trans_vfnmsac_vv },
            { 0xbc005057, trans_vfnmsac_vf },
            { 0xc0001057, trans_vfwadd_vv },
            { 0xc0005057, trans_vfwadd_vf },
            { 0xc8001057, trans_vfwsub_vv },
            { 0xc8005057, trans_vfwsub_vf },
            { 0xd0001057, trans_vfwadd_wv },
            { 0xd0005057, trans_vfwadd_wf },
            { 0xd8001057, trans_vfwsub_wv },
            { 0xd8005057, trans_vfwsub_wf },
            { 0xe0001057, trans_vfwmul_vv },
            { 0xe0005057, trans_vfwmul_vf },
            { 0xf0001057, trans_vfwmacc_vv },
            { 0xf0005057, trans_vfwmacc_vf },
            { 0xf4001057, trans_vfwnmacc_vv },
            { 0xf4005057, trans_vfwnmacc_vf },
            { 0xf8001057, trans_vfwmsac_vv },
            { 0xf8005057, trans_vfwmsac_vf },
            { 0xfc001057, trans_vfwnmsac_vv },
            { 0xfc005057, trans_vfwnmsac_vf },
        };

        for (i = 0; i < ARRAY_SIZE(fp_arith); i++) {
            if ((insn & 0xfc00707f) == fp_arith[i].value) {
                arg_rvv_arith a = {
                    .rd = extract32(insn, 7, 5),
                    .rs1 = extract32(insn, 15, 5),
                    .rs2 = extract32(insn, 20, 5),
                    .vm = extract32(insn, 25, 1),
                };

                return fp_arith[i].trans(ctx, &a);
            }
        }
    }

    {
        static const struct {
            uint32_t value;
            bool (*trans)(DisasContext *, arg_rvv_arith *);
        } fp_red[] = {
            { 0x04001057, trans_vfredusum_vs },
            { 0x0c001057, trans_vfredosum_vs },
            { 0x14001057, trans_vfredmin_vs },
            { 0x1c001057, trans_vfredmax_vs },
            { 0xc4001057, trans_vfwredusum_vs },
            { 0xcc001057, trans_vfwredosum_vs },
        };

        for (i = 0; i < ARRAY_SIZE(fp_red); i++) {
            if ((insn & 0xfc00707f) == fp_red[i].value) {
                arg_rvv_arith a = {
                    .rd = extract32(insn, 7, 5),
                    .rs1 = extract32(insn, 15, 5),
                    .rs2 = extract32(insn, 20, 5),
                    .vm = extract32(insn, 25, 1),
                };

                return fp_red[i].trans(ctx, &a);
            }
        }
    }

    {
        static const struct {
            uint32_t value;
            bool (*trans)(DisasContext *, arg_rvv_arith *);
        } fp_unary[] = {
            { 0x48001057, trans_vfcvt_xu_f_v },
            { 0x48009057, trans_vfcvt_x_f_v },
            { 0x48011057, trans_vfcvt_f_xu_v },
            { 0x48019057, trans_vfcvt_f_x_v },
            { 0x48031057, trans_vfcvt_rtz_xu_f_v },
            { 0x48039057, trans_vfcvt_rtz_x_f_v },
            { 0x48041057, trans_vfwcvt_xu_f_v },
            { 0x48049057, trans_vfwcvt_x_f_v },
            { 0x48051057, trans_vfwcvt_f_xu_v },
            { 0x48059057, trans_vfwcvt_f_x_v },
            { 0x48061057, trans_vfwcvt_f_f_v },
            { 0x48071057, trans_vfwcvt_rtz_xu_f_v },
            { 0x48079057, trans_vfwcvt_rtz_x_f_v },
            { 0x48081057, trans_vfncvt_xu_f_w },
            { 0x48089057, trans_vfncvt_x_f_w },
            { 0x48091057, trans_vfncvt_f_xu_w },
            { 0x48099057, trans_vfncvt_f_x_w },
            { 0x480a1057, trans_vfncvt_f_f_w },
            { 0x480a9057, trans_vfncvt_rod_f_f_w },
            { 0x480b1057, trans_vfncvt_rtz_xu_f_w },
            { 0x480b9057, trans_vfncvt_rtz_x_f_w },
            { 0x4c001057, trans_vfsqrt_v },
            { 0x4c021057, trans_vfrsqrt7_v },
            { 0x4c029057, trans_vfrec7_v },
        };

        for (i = 0; i < ARRAY_SIZE(fp_unary); i++) {
            if ((insn & 0xfc0ff07f) == fp_unary[i].value) {
                arg_rvv_arith a = {
                    .rd = extract32(insn, 7, 5),
                    .rs2 = extract32(insn, 20, 5),
                    .vm = extract32(insn, 25, 1),
                };

                return fp_unary[i].trans(ctx, &a);
            }
        }
    }

    if ((insn & 0xfc0ff07f) == 0x4c081057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vfclass_v(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x5c005057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = 0,
        };

        return trans_vfmerge_vfm(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x5e005057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vfmv_v_f(ctx, &a);
    }

    if ((insn & 0xfe0ff07f) == 0x42001057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vfmv_f_s(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x42005057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vfmv_s_f(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x02b00007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
        };

        return trans_vlm_v(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x02b00027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
        };

        return trans_vsm_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x01000007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle8ff_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x01005007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle16ff_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x01006007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle32ff_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x01007007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle64ff_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00000007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle8_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00005007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle16_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00006007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle32_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00007007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vle64_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00000027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vse8_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00005027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vse16_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00006027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vse32_v(ctx, &a);
    }

    if ((insn & 0x1df0707f) == 0x00007027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vse64_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08000007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlse8_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08005007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlse16_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08006007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlse32_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08007007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlse64_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08000027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsse8_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08005027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsse16_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08006027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsse32_v(ctx, &a);
    }

    if ((insn & 0x1c00707f) == 0x08007027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsse64_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04000007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlxei8_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04005007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlxei16_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04006007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlxei32_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04007007) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vlxei64_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04000027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsxei8_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04005027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsxei16_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04006027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsxei32_v(ctx, &a);
    }

    if ((insn & 0x1400707f) == 0x04007027) {
        arg_rvv_ldst a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .nf = extract32(insn, 29, 3) + 1,
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsxei64_v(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x5e000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmv_v_v(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x5e004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmv_v_x(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x5e003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmv_v_i(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x5c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmerge_vvm(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x5c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmerge_vxm(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x5c003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmerge_vim(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x60002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmandn_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x64002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmand_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x68002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmor_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x6c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmxor_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x70002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmorn_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x74002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmnand_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x78002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmnor_mm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x7c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
        };

        return trans_vmxnor_mm(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x40082057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vcpop_m(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x4008a057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vfirst_m(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x5000a057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsbf_m(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x5001a057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsif_m(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x50012057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsof_m(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x50082057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_viota_m(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x5008a057 && extract32(insn, 20, 5) == 0) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vid_v(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x00002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredsum_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x04002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredand_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x08002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredor_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x0c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredxor_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x10002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredminu_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x14002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredmin_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x18002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredmaxu_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x1c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vredmax_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc0000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwredsumu_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc4000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwredsum_vs(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x80000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsaddu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x84000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsadd_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x88000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssubu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x8c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssub_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x80004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsaddu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x84004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsadd_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x88004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssubu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x8c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssub_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x80003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsaddu_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x84003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsadd_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x20002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vaaddu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x24002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vaadd_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x28002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vasubu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x2c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vasub_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x20006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vaaddu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x24006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vaadd_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x28006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vasubu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x2c006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vasub_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x9c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsmul_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x9c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsmul_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa8000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssrl_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xac000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssra_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa8004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssrl_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xac004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssra_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa8003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssrl_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xac003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vssra_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb8000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnclipu_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xbc000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnclip_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb8004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnclipu_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xbc004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnclip_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb8003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnclipu_wi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xbc003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnclip_wi(ctx, &a);
    }

    if ((insn & 0xfe0ff07f) == 0x42002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmv_x_s(ctx, &a);
    }

    if ((insn & 0xfff0707f) == 0x42006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmv_s_x(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x00000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vadd_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x00004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vadd_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x00003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vadd_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x08000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsub_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x08004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsub_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x0c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrsub_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x0c003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrsub_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x38004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vslideup_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x38003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vslideup_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x38006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vslide1up_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x3c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vslidedown_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x3c003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vslidedown_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x3c006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vslide1down_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x30000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrgather_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x38000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrgatherei16_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x30004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrgather_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x30003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrgather_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x5c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vcompress_vm(ctx, &a);
    }

    if ((insn & 0xfe0ff07f) == 0x9e003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = 0,
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vmv1r_v(ctx, &a);
    }

    if ((insn & 0xfe0ff07f) == 0x9e00b057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = 1,
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vmv2r_v(ctx, &a);
    }

    if ((insn & 0xfe0ff07f) == 0x9e01b057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = 3,
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vmv4r_v(ctx, &a);
    }

    if ((insn & 0xfe0ff07f) == 0x9e03b057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = 7,
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vmv8r_v(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x40000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vadc_vvm(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x40004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vadc_vxm(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x40003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vadc_vim(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x44000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmadc_vvm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x44004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmadc_vxm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x44003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmadc_vim(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x48000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vsbc_vvm(ctx, &a);
    }

    if ((insn & 0xfe00707f) == 0x48004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = 1,
        };

        return trans_vsbc_vxm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x4c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsbc_vvm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x4c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsbc_vxm(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x10000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vminu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x10004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vminu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x14000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmin_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x14004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmin_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x18000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmaxu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x18004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmaxu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x1c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmax_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x1c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmax_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc0002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwaddu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc0006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwaddu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc4002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwadd_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc4006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwadd_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc8002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsubu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xc8006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsubu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xcc002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsub_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xcc006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsub_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xd0002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwaddu_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xd0006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwaddu_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xd4002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwadd_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xd4006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwadd_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xd8002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsubu_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xd8006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsubu_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xdc002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsub_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xdc006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwsub_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa4002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmadd_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa4006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmadd_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xac002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnmsub_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xac006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnmsub_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb4002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmacc_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb4006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmacc_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xbc002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnmsac_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xbc006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnmsac_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xe0002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmulu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xe0006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmulu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xe8002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmulsu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xe8006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmulsu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xec002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmul_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xec006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmul_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xf0002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmaccu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xf0006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmaccu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xf4002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmacc_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xf4006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmacc_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xf8006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmaccus_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xfc002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmaccsu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xfc006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vwmaccsu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x80002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vdivu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x80006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vdivu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x84002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vdiv_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x84006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vdiv_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x88002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vremu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x88006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vremu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x8c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrem_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x8c006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vrem_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x94002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmul_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x94006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmul_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x9c002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmulh_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x9c006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmulh_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x90002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmulhu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x90006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmulhu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x98002057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmulhsu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x98006057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmulhsu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x94000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsll_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x94004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsll_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x94003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsll_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa0000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsrl_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa0004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsrl_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa0003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsrl_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa4000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsra_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa4004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsra_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xa4003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsra_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb0000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnsrl_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb0004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnsrl_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb0003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnsrl_wi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb4000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnsra_wv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb4004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnsra_wx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0xb4003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vnsra_wi(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x48032057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vzext_vf2(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x48022057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vzext_vf4(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x48012057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vzext_vf8(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x4803a057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsext_vf2(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x4802a057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsext_vf4(ctx, &a);
    }

    if ((insn & 0xfc0ff07f) == 0x4801a057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vsext_vf8(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x24000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vand_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x24004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vand_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x24003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vand_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x28000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vor_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x28004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vor_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x28003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vor_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x2c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vxor_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x2c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vxor_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x2c003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vxor_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x60000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmseq_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x60004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmseq_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x60003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmseq_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x64000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsne_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x64004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsne_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x64003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsne_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x68000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsltu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x68004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsltu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x6c000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmslt_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x6c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmslt_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x70000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsleu_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x70004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsleu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x70003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsleu_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x74000057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsle_vv(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x74004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsle_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x74003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsle_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x78004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsgtu_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x78003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsgtu_vi(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x7c004057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsgt_vx(ctx, &a);
    }

    if ((insn & 0xfc00707f) == 0x7c003057) {
        arg_rvv_arith a = {
            .rd = extract32(insn, 7, 5),
            .rs1 = extract32(insn, 15, 5),
            .rs2 = extract32(insn, 20, 5),
            .vm = extract32(insn, 25, 1),
        };

        return trans_vmsgt_vi(ctx, &a);
    }

    return false;
}

static bool decode_rvv(DisasContext *ctx, uint32_t insn)
{
    return decode_rvv_config(ctx, insn) || decode_rvv_data(ctx, insn);
}
