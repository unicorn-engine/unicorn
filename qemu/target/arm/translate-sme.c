/*
 * AArch64 SME translation.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "tcg/tcg-gvec-desc.h"
#include "translate.h"
#include "internals.h"
#include "exec/helper-gen.h"
#include "translate-a64.h"

typedef struct arg_ZERO {
    int imm;
} arg_ZERO;

typedef struct arg_MOVA {
    int esz;
    int rs;
    int pg;
    int zr;
    int za_imm;
    bool v;
    bool to_vec;
} arg_MOVA;

typedef struct arg_ADDA {
    int esz;
    int zad;
    int zn;
    int pm;
    int pn;
    bool vertical;
} arg_ADDA;

typedef struct arg_LDSTR {
    int rv;
    int rn;
    int imm;
    bool store;
} arg_LDSTR;

typedef struct arg_LDST1 {
    int esz;
    int rs;
    int pg;
    int rn;
    int rm;
    int za_imm;
    bool vertical;
    bool store;
} arg_LDST1;

typedef struct arg_OP {
    int esz;
    int zad;
    int zn;
    int zm;
    int pm;
    int pn;
    int kind;
    bool sub;
} arg_OP;

enum {
    SME_FP_OP_FMOPA_S,
    SME_FP_OP_FMOPA_D,
    SME_FP_OP_BFMOPA,
    SME_FP_OP_FMOPA_H,
};

static inline int pred_full_reg_offset(DisasContext *s, int regno)
{
    return offsetof(CPUARMState, vfp.pregs[regno]);
}

static inline TCGv_ptr pred_full_reg_ptr(DisasContext *s, int regno)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr ret = tcg_temp_new_ptr(tcg_ctx);

    tcg_gen_addi_ptr(tcg_ctx, ret, tcg_ctx->cpu_env,
                     pred_full_reg_offset(s, regno));
    return ret;
}

static TCGv_i64 sme_clean_data_tbi(DisasContext *s, TCGv_i64 addr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 clean = tcg_temp_new_i64(tcg_ctx);

    if (s->tbid == 0) {
        tcg_gen_mov_i64(tcg_ctx, clean, addr);
    } else if (!regime_has_2_ranges(s->mmu_idx)) {
        tcg_gen_extract_i64(tcg_ctx, clean, addr, 0, 56);
    } else {
        tcg_gen_sextract_i64(tcg_ctx, clean, addr, 0, 56);

        if (s->tbid != 3) {
            TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

            tcg_gen_movcond_i64(tcg_ctx,
                                s->tbid == 1 ? TCG_COND_GE : TCG_COND_LT,
                                clean, clean, zero, clean, addr);
            tcg_temp_free_i64(tcg_ctx, zero);
        }
    }
    return clean;
}

static inline int streaming_vec_reg_size(DisasContext *s)
{
    return s->svl;
}

static inline int streaming_pred_reg_size(DisasContext *s)
{
    return s->svl >> 3;
}

static inline bool sme_za_enabled_check(DisasContext *s)
{
    return sme_enabled_check_with_svcr(s, R_SVCR_ZA_MASK);
}

static inline bool sme_smza_enabled_check(DisasContext *s)
{
    return sme_enabled_check_with_svcr(s, (unsigned)R_SVCR_SM_MASK |
                                          (unsigned)R_SVCR_ZA_MASK);
}

static TCGv_ptr get_tile_rowcol(DisasContext *s, int esz, int rs,
                                int tile_index, bool vertical)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int tile = tile_index >> (4 - esz);
    int index = esz == MO_128 ? 0 : extract32(tile_index, 0, 4 - esz);
    int pos, len, offset;
    TCGv_i32 tmp;
    TCGv_ptr addr;

    tmp = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_extrl_i64_i32(tcg_ctx, tmp, cpu_reg(s, rs));
    tcg_gen_addi_i32(tcg_ctx, tmp, tmp, index);

    len = ctz32(streaming_vec_reg_size(s)) - esz;
    if (!len) {
        tcg_gen_movi_i32(tcg_ctx, tmp, 0);
    } else if (vertical) {
        pos = esz;
        tcg_gen_deposit_z_i32(tcg_ctx, tmp, tmp, pos, len);
#ifdef HOST_WORDS_BIGENDIAN
        if (esz < MO_64) {
            tcg_gen_xori_i32(tcg_ctx, tmp, tmp, 8 - (1 << esz));
        }
#endif
    } else {
        pos = esz + ctz32(sizeof(ARMVectorReg));
        tcg_gen_deposit_z_i32(tcg_ctx, tmp, tmp, pos, len);
    }

    offset = tile * sizeof(ARMVectorReg) + offsetof(CPUARMState, zarray);
    tcg_gen_addi_i32(tcg_ctx, tmp, tmp, offset);

    addr = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_ext_i32_ptr(tcg_ctx, addr, tmp);
    tcg_temp_free_i32(tcg_ctx, tmp);
    tcg_gen_add_ptr(tcg_ctx, addr, addr, tcg_ctx->cpu_env);

    return addr;
}

static TCGv_ptr get_tile(DisasContext *s, int tile_index)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr addr = tcg_temp_new_ptr(tcg_ctx);
    int offset;

    offset = tile_index * sizeof(ARMVectorReg) + offsetof(CPUARMState, zarray);
    tcg_gen_addi_ptr(tcg_ctx, addr, tcg_ctx->cpu_env, offset);
    return addr;
}

static bool trans_ZERO(DisasContext *s, arg_ZERO *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 imm;
    TCGv_i32 svl;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (sme_za_enabled_check(s)) {
        imm = tcg_const_i32(tcg_ctx, a->imm);
        svl = tcg_const_i32(tcg_ctx, streaming_vec_reg_size(s));
        gen_helper_sme_zero(tcg_ctx, tcg_ctx->cpu_env, imm, svl);
        tcg_temp_free_i32(tcg_ctx, imm);
        tcg_temp_free_i32(tcg_ctx, svl);
    }
    return true;
}

static bool trans_MOVA(DisasContext *s, arg_MOVA *a)
{
    static gen_helper_gvec_4 * const h_fns[5] = {
        gen_helper_sve_sel_zpzz_b, gen_helper_sve_sel_zpzz_h,
        gen_helper_sve_sel_zpzz_s, gen_helper_sve_sel_zpzz_d,
        gen_helper_sve_sel_zpzz_q
    };
    static gen_helper_gvec_3 * const cz_fns[5] = {
        gen_helper_sme_mova_cz_b, gen_helper_sme_mova_cz_h,
        gen_helper_sme_mova_cz_s, gen_helper_sme_mova_cz_d,
        gen_helper_sme_mova_cz_q,
    };
    static gen_helper_gvec_3 * const zc_fns[5] = {
        gen_helper_sme_mova_zc_b, gen_helper_sme_mova_zc_h,
        gen_helper_sme_mova_zc_s, gen_helper_sme_mova_zc_d,
        gen_helper_sme_mova_zc_q,
    };
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr t_za, t_zr, t_pg;
    TCGv_i32 t_desc;
    int svl;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (!sme_smza_enabled_check(s)) {
        return true;
    }

    t_za = get_tile_rowcol(s, a->esz, a->rs, a->za_imm, a->v);
    t_zr = vec_full_reg_ptr(s, a->zr);
    t_pg = pred_full_reg_ptr(s, a->pg);
    svl = streaming_vec_reg_size(s);
    t_desc = tcg_const_i32(tcg_ctx, simd_desc(svl, svl, 0));

    if (a->v) {
        if (a->to_vec) {
            zc_fns[a->esz](tcg_ctx, t_zr, t_za, t_pg, t_desc);
        } else {
            cz_fns[a->esz](tcg_ctx, t_za, t_zr, t_pg, t_desc);
        }
    } else {
        if (a->to_vec) {
            h_fns[a->esz](tcg_ctx, t_zr, t_za, t_zr, t_pg, t_desc);
        } else {
            h_fns[a->esz](tcg_ctx, t_za, t_zr, t_za, t_pg, t_desc);
        }
    }

    tcg_temp_free_i32(tcg_ctx, t_desc);
    tcg_temp_free_ptr(tcg_ctx, t_za);
    tcg_temp_free_ptr(tcg_ctx, t_zr);
    tcg_temp_free_ptr(tcg_ctx, t_pg);
    return true;
}

static bool trans_ADDA(DisasContext *s, arg_ADDA *a)
{
    static gen_helper_gvec_4 * const h_fns[2] = {
        gen_helper_sme_addha_s, gen_helper_sme_addha_d
    };
    static gen_helper_gvec_4 * const v_fns[2] = {
        gen_helper_sme_addva_s, gen_helper_sme_addva_d
    };
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr za, zn, pn, pm;
    TCGv_i32 desc;
    int svl = streaming_vec_reg_size(s);
    int size_index = a->esz == MO_64;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (a->esz == MO_64 && !dc_isar_feature(aa64_sme_i16i64, s)) {
        return false;
    }
    if (!sme_smza_enabled_check(s)) {
        return true;
    }

    za = get_tile(s, a->zad);
    zn = vec_full_reg_ptr(s, a->zn);
    pn = pred_full_reg_ptr(s, a->pn);
    pm = pred_full_reg_ptr(s, a->pm);
    desc = tcg_const_i32(tcg_ctx, simd_desc(svl, svl, 0));

    if (a->vertical) {
        v_fns[size_index](tcg_ctx, za, zn, pn, pm, desc);
    } else {
        h_fns[size_index](tcg_ctx, za, zn, pn, pm, desc);
    }

    tcg_temp_free_i32(tcg_ctx, desc);
    tcg_temp_free_ptr(tcg_ctx, za);
    tcg_temp_free_ptr(tcg_ctx, zn);
    tcg_temp_free_ptr(tcg_ctx, pn);
    tcg_temp_free_ptr(tcg_ctx, pm);
    return true;
}

static bool trans_LDST1(DisasContext *s, arg_LDST1 *a)
{
    typedef void GenLdSt1(TCGContext *, TCGv_env, TCGv_ptr, TCGv_ptr,
                          TCGv_i64, TCGv_i32);

    static GenLdSt1 * const fns[5][2][2][2][2] = {
        {
            {
                {
                    { gen_helper_sme_ld1b_h, gen_helper_sme_st1b_h },
                    { gen_helper_sme_ld1b_h_mte,
                      gen_helper_sme_st1b_h_mte },
                },
                {
                    { gen_helper_sme_ld1b_v, gen_helper_sme_st1b_v },
                    { gen_helper_sme_ld1b_v_mte,
                      gen_helper_sme_st1b_v_mte },
                },
            },
            {
                {
                    { gen_helper_sme_ld1b_h, gen_helper_sme_st1b_h },
                    { gen_helper_sme_ld1b_h_mte,
                      gen_helper_sme_st1b_h_mte },
                },
                {
                    { gen_helper_sme_ld1b_v, gen_helper_sme_st1b_v },
                    { gen_helper_sme_ld1b_v_mte,
                      gen_helper_sme_st1b_v_mte },
                },
            },
        },
        {
            {
                {
                    { gen_helper_sme_ld1h_le_h, gen_helper_sme_st1h_le_h },
                    { gen_helper_sme_ld1h_le_h_mte,
                      gen_helper_sme_st1h_le_h_mte },
                },
                {
                    { gen_helper_sme_ld1h_le_v, gen_helper_sme_st1h_le_v },
                    { gen_helper_sme_ld1h_le_v_mte,
                      gen_helper_sme_st1h_le_v_mte },
                },
            },
            {
                {
                    { gen_helper_sme_ld1h_be_h, gen_helper_sme_st1h_be_h },
                    { gen_helper_sme_ld1h_be_h_mte,
                      gen_helper_sme_st1h_be_h_mte },
                },
                {
                    { gen_helper_sme_ld1h_be_v, gen_helper_sme_st1h_be_v },
                    { gen_helper_sme_ld1h_be_v_mte,
                      gen_helper_sme_st1h_be_v_mte },
                },
            },
        },
        {
            {
                {
                    { gen_helper_sme_ld1s_le_h, gen_helper_sme_st1s_le_h },
                    { gen_helper_sme_ld1s_le_h_mte,
                      gen_helper_sme_st1s_le_h_mte },
                },
                {
                    { gen_helper_sme_ld1s_le_v, gen_helper_sme_st1s_le_v },
                    { gen_helper_sme_ld1s_le_v_mte,
                      gen_helper_sme_st1s_le_v_mte },
                },
            },
            {
                {
                    { gen_helper_sme_ld1s_be_h, gen_helper_sme_st1s_be_h },
                    { gen_helper_sme_ld1s_be_h_mte,
                      gen_helper_sme_st1s_be_h_mte },
                },
                {
                    { gen_helper_sme_ld1s_be_v, gen_helper_sme_st1s_be_v },
                    { gen_helper_sme_ld1s_be_v_mte,
                      gen_helper_sme_st1s_be_v_mte },
                },
            },
        },
        {
            {
                {
                    { gen_helper_sme_ld1d_le_h, gen_helper_sme_st1d_le_h },
                    { gen_helper_sme_ld1d_le_h_mte,
                      gen_helper_sme_st1d_le_h_mte },
                },
                {
                    { gen_helper_sme_ld1d_le_v, gen_helper_sme_st1d_le_v },
                    { gen_helper_sme_ld1d_le_v_mte,
                      gen_helper_sme_st1d_le_v_mte },
                },
            },
            {
                {
                    { gen_helper_sme_ld1d_be_h, gen_helper_sme_st1d_be_h },
                    { gen_helper_sme_ld1d_be_h_mte,
                      gen_helper_sme_st1d_be_h_mte },
                },
                {
                    { gen_helper_sme_ld1d_be_v, gen_helper_sme_st1d_be_v },
                    { gen_helper_sme_ld1d_be_v_mte,
                      gen_helper_sme_st1d_be_v_mte },
                },
            },
        },
        {
            {
                {
                    { gen_helper_sme_ld1q_le_h, gen_helper_sme_st1q_le_h },
                    { gen_helper_sme_ld1q_le_h_mte,
                      gen_helper_sme_st1q_le_h_mte },
                },
                {
                    { gen_helper_sme_ld1q_le_v, gen_helper_sme_st1q_le_v },
                    { gen_helper_sme_ld1q_le_v_mte,
                      gen_helper_sme_st1q_le_v_mte },
                },
            },
            {
                {
                    { gen_helper_sme_ld1q_be_h, gen_helper_sme_st1q_be_h },
                    { gen_helper_sme_ld1q_be_h_mte,
                      gen_helper_sme_st1q_be_h_mte },
                },
                {
                    { gen_helper_sme_ld1q_be_v, gen_helper_sme_st1q_be_v },
                    { gen_helper_sme_ld1q_be_v_mte,
                      gen_helper_sme_st1q_be_v_mte },
                },
            },
        },
    };
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr za, pg;
    TCGv_i64 addr;
    TCGv_i64 clean_addr;
    TCGv_i32 desc;
    uint32_t desc_data = 0;
    int svl = streaming_vec_reg_size(s);
    int be = s->be_data == MO_BE;
    int mte = s->mte_active[0];

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (!sme_smza_enabled_check(s)) {
        return true;
    }

    za = get_tile_rowcol(s, a->esz, a->rs, a->za_imm, a->vertical);
    pg = pred_full_reg_ptr(s, a->pg);
    addr = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_shli_i64(tcg_ctx, addr, cpu_reg(s, a->rm), a->esz);
    tcg_gen_add_i64(tcg_ctx, addr, addr, cpu_reg_sp(s, a->rn));
    if (mte) {
        desc_data = deposit32(desc_data, R_MTEDESC_MIDX_SHIFT,
                              R_MTEDESC_MIDX_LENGTH, get_mem_index(s));
        desc_data = deposit32(desc_data, R_MTEDESC_TBI_SHIFT,
                              R_MTEDESC_TBI_LENGTH, s->tbid);
        desc_data = deposit32(desc_data, R_MTEDESC_TCMA_SHIFT,
                              R_MTEDESC_TCMA_LENGTH, s->tcma);
        desc_data = deposit32(desc_data, R_MTEDESC_WRITE_SHIFT,
                              R_MTEDESC_WRITE_LENGTH, a->store);
        desc_data = deposit32(desc_data, R_MTEDESC_SIZEM1_SHIFT,
                              R_MTEDESC_SIZEM1_LENGTH,
                              (1 << a->esz) - 1);
        clean_addr = addr;
    } else {
        desc_data = get_mem_index(s);
        clean_addr = sme_clean_data_tbi(s, addr);
        tcg_temp_free_i64(tcg_ctx, addr);
    }
    desc = tcg_const_i32(tcg_ctx, simd_desc(svl, svl, desc_data));

    fns[a->esz][be][a->vertical][mte][a->store](tcg_ctx, tcg_ctx->cpu_env,
                                                za, pg, clean_addr, desc);

    tcg_temp_free_i32(tcg_ctx, desc);
    tcg_temp_free_i64(tcg_ctx, clean_addr);
    tcg_temp_free_ptr(tcg_ctx, za);
    tcg_temp_free_ptr(tcg_ctx, pg);
    return true;
}

static bool trans_LDSTR(DisasContext *s, arg_LDSTR *a)
{
    TCGv_ptr base;
    int svl = streaming_vec_reg_size(s);

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (!sme_za_enabled_check(s)) {
        return true;
    }

    base = get_tile_rowcol(s, MO_8, a->rv, a->imm, false);
    if (a->store) {
        gen_sve_str(s, base, 0, svl, a->rn, a->imm * svl);
    } else {
        gen_sve_ldr(s, base, 0, svl, a->rn, a->imm * svl);
    }
    tcg_temp_free_ptr(s->uc->tcg_ctx, base);
    return true;
}

static bool trans_OUTPROD(DisasContext *s, arg_OP *a)
{
    static gen_helper_gvec_5 * const fns_s[4] = {
        gen_helper_sme_smopa_s, gen_helper_sme_sumopa_s,
        gen_helper_sme_usmopa_s, gen_helper_sme_umopa_s,
    };
    static gen_helper_gvec_5 * const fns_d[4] = {
        gen_helper_sme_smopa_d, gen_helper_sme_sumopa_d,
        gen_helper_sme_usmopa_d, gen_helper_sme_umopa_d,
    };
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr za, zn, zm, pn, pm;
    TCGv_i32 desc;
    int svl = streaming_vec_reg_size(s);
    gen_helper_gvec_5 *fn;

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (a->esz == MO_64 && !dc_isar_feature(aa64_sme_i16i64, s)) {
        return false;
    }
    if (!sme_smza_enabled_check(s)) {
        return true;
    }

    fn = a->esz == MO_64 ? fns_d[a->kind] : fns_s[a->kind];
    za = get_tile(s, a->zad);
    zn = vec_full_reg_ptr(s, a->zn);
    zm = vec_full_reg_ptr(s, a->zm);
    pn = pred_full_reg_ptr(s, a->pn);
    pm = pred_full_reg_ptr(s, a->pm);
    desc = tcg_const_i32(tcg_ctx, simd_desc(svl, svl, a->sub));

    fn(tcg_ctx, za, zn, zm, pn, pm, desc);

    tcg_temp_free_i32(tcg_ctx, desc);
    tcg_temp_free_ptr(tcg_ctx, za);
    tcg_temp_free_ptr(tcg_ctx, zn);
    tcg_temp_free_ptr(tcg_ctx, zm);
    tcg_temp_free_ptr(tcg_ctx, pn);
    tcg_temp_free_ptr(tcg_ctx, pm);
    return true;
}

static bool trans_FPOUTPROD(DisasContext *s, arg_OP *a)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_ptr za, zn, zm, pn, pm;
    TCGv_i32 desc;
    int svl = streaming_vec_reg_size(s);

    if (!dc_isar_feature(aa64_sme, s)) {
        return false;
    }
    if (a->kind == SME_FP_OP_FMOPA_D &&
        !dc_isar_feature(aa64_sme_f64f64, s)) {
        return false;
    }
    if (!sme_smza_enabled_check(s)) {
        return true;
    }

    za = get_tile(s, a->zad);
    zn = vec_full_reg_ptr(s, a->zn);
    zm = vec_full_reg_ptr(s, a->zm);
    pn = pred_full_reg_ptr(s, a->pn);
    pm = pred_full_reg_ptr(s, a->pm);
    desc = tcg_const_i32(tcg_ctx, simd_desc(svl, svl, a->sub));

    switch (a->kind) {
    case SME_FP_OP_FMOPA_S:
    {
        TCGv_ptr fpst = get_fpstatus_ptr(tcg_ctx, false);

        gen_helper_sme_fmopa_s(tcg_ctx, za, zn, zm, pn, pm, fpst, desc);
        tcg_temp_free_ptr(tcg_ctx, fpst);
        break;
    }
    case SME_FP_OP_FMOPA_D:
    {
        TCGv_ptr fpst = get_fpstatus_ptr(tcg_ctx, false);

        gen_helper_sme_fmopa_d(tcg_ctx, za, zn, zm, pn, pm, fpst, desc);
        tcg_temp_free_ptr(tcg_ctx, fpst);
        break;
    }
    case SME_FP_OP_FMOPA_H:
        gen_helper_sme_fmopa_h(tcg_ctx, za, zn, zm, pn, pm,
                               tcg_ctx->cpu_env, desc);
        break;
    case SME_FP_OP_BFMOPA:
        gen_helper_sme_bfmopa(tcg_ctx, za, zn, zm, pn, pm, desc);
        break;
    }

    tcg_temp_free_i32(tcg_ctx, desc);
    tcg_temp_free_ptr(tcg_ctx, za);
    tcg_temp_free_ptr(tcg_ctx, zn);
    tcg_temp_free_ptr(tcg_ctx, zm);
    tcg_temp_free_ptr(tcg_ctx, pn);
    tcg_temp_free_ptr(tcg_ctx, pm);
    return true;
}

static bool decode_mova(uint32_t insn, arg_MOVA *a)
{
    int group;
    int qbit;

    if (extract32(insn, 24, 8) != 0xc0) {
        return false;
    }
    group = extract32(insn, 17, 5);
    if (group != 0 && group != 1) {
        return false;
    }

    a->esz = extract32(insn, 22, 2);
    qbit = extract32(insn, 16, 1);
    if (qbit) {
        if (a->esz != MO_64) {
            return false;
        }
        a->esz = MO_128;
    }

    a->v = extract32(insn, 15, 1);
    a->rs = extract32(insn, 13, 2) + 12;
    a->pg = extract32(insn, 10, 3);
    a->to_vec = group == 1;
    if (a->to_vec) {
        if (extract32(insn, 9, 1)) {
            return false;
        }
        a->za_imm = extract32(insn, 5, 4);
        a->zr = extract32(insn, 0, 5);
    } else {
        if (extract32(insn, 4, 1)) {
            return false;
        }
        a->zr = extract32(insn, 5, 5);
        a->za_imm = extract32(insn, 0, 4);
    }
    return true;
}

static bool decode_adda(uint32_t insn, arg_ADDA *a)
{
    if ((insn & 0xfffe001c) == 0xc0900000) {
        a->esz = MO_32;
        a->zad = extract32(insn, 0, 2);
    } else if ((insn & 0xfffe0018) == 0xc0d00000) {
        a->esz = MO_64;
        a->zad = extract32(insn, 0, 3);
    } else {
        return false;
    }

    a->vertical = extract32(insn, 16, 1);
    a->pm = extract32(insn, 13, 3);
    a->pn = extract32(insn, 10, 3);
    a->zn = extract32(insn, 5, 5);
    return true;
}

static bool decode_ldst1(uint32_t insn, arg_LDST1 *a)
{
    if ((insn & 0xff000010) == 0xe0000000) {
        a->esz = extract32(insn, 22, 2);
    } else if ((insn & 0xffc00010) == 0xe1c00000) {
        a->esz = MO_128;
    } else {
        return false;
    }

    a->store = extract32(insn, 21, 1);
    a->rm = extract32(insn, 16, 5);
    a->vertical = extract32(insn, 15, 1);
    a->pg = extract32(insn, 10, 3);
    a->rn = extract32(insn, 5, 5);
    a->rs = extract32(insn, 13, 2) + 12;
    a->za_imm = extract32(insn, 0, 4);
    return true;
}

static bool decode_ldstr(uint32_t insn, arg_LDSTR *a)
{
    if ((insn & 0xffff9c10) != 0xe1000000 &&
        (insn & 0xffff9c10) != 0xe1200000) {
        return false;
    }

    a->rv = extract32(insn, 13, 2) + 12;
    a->rn = extract32(insn, 5, 5);
    a->imm = extract32(insn, 0, 4);
    a->store = extract32(insn, 21, 1);
    return true;
}

static bool decode_fp_op(uint32_t insn, arg_OP *a)
{
    if ((insn & 0xffe0000c) == 0x80800000) {
        a->kind = SME_FP_OP_FMOPA_S;
        a->esz = MO_32;
        a->zad = extract32(insn, 0, 2);
    } else if ((insn & 0xffe00008) == 0x80c00000) {
        a->kind = SME_FP_OP_FMOPA_D;
        a->esz = MO_64;
        a->zad = extract32(insn, 0, 3);
    } else if ((insn & 0xffe0000c) == 0x81800000) {
        a->kind = SME_FP_OP_BFMOPA;
        a->esz = MO_32;
        a->zad = extract32(insn, 0, 2);
    } else if ((insn & 0xffe0000c) == 0x81a00000) {
        a->kind = SME_FP_OP_FMOPA_H;
        a->esz = MO_32;
        a->zad = extract32(insn, 0, 2);
    } else {
        return false;
    }

    a->zm = extract32(insn, 16, 5);
    a->pm = extract32(insn, 13, 3);
    a->pn = extract32(insn, 10, 3);
    a->zn = extract32(insn, 5, 5);
    a->sub = extract32(insn, 4, 1);
    return true;
}

static bool decode_int_op(uint32_t insn, arg_OP *a)
{
    if ((insn & 0xfec0000c) == 0xa0800000) {
        a->esz = MO_32;
        a->zad = extract32(insn, 0, 2);
    } else if ((insn & 0xfec00008) == 0xa0c00000) {
        a->esz = MO_64;
        a->zad = extract32(insn, 0, 3);
    } else {
        return false;
    }

    a->kind = (extract32(insn, 24, 1) << 1) | extract32(insn, 21, 1);
    a->zm = extract32(insn, 16, 5);
    a->pm = extract32(insn, 13, 3);
    a->pn = extract32(insn, 10, 3);
    a->zn = extract32(insn, 5, 5);
    a->sub = extract32(insn, 4, 1);
    return true;
}

bool disas_sme(DisasContext *s, uint32_t insn)
{
    if ((insn & 0xffffff00) == 0xc0080000) {
        arg_ZERO a = { .imm = extract32(insn, 0, 8) };
        return trans_ZERO(s, &a);
    }

    {
        arg_MOVA a;

        if (decode_mova(insn, &a)) {
            return trans_MOVA(s, &a);
        }
    }

    {
        arg_ADDA a;

        if (decode_adda(insn, &a)) {
            return trans_ADDA(s, &a);
        }
    }

    {
        arg_LDST1 a;

        if (decode_ldst1(insn, &a)) {
            return trans_LDST1(s, &a);
        }
    }

    {
        arg_LDSTR a;

        if (decode_ldstr(insn, &a)) {
            return trans_LDSTR(s, &a);
        }
    }

    {
        arg_OP a;

        if (decode_fp_op(insn, &a)) {
            return trans_FPOUTPROD(s, &a);
        }
    }

    {
        arg_OP a;

        if (decode_int_op(insn, &a)) {
            return trans_OUTPROD(s, &a);
        }
    }

    return false;
}
