/* This file is autogenerated by scripts/decodetree.py.  */

typedef struct {
    int align;
    int itype;
    int l;
    int rm;
    int rn;
    int size;
    int vd;
} arg_disas_neon_ls0;

typedef struct {
    int a;
    int n;
    int rm;
    int rn;
    int size;
    int t;
    int vd;
} arg_disas_neon_ls1;

typedef struct {
    int align;
    int l;
    int n;
    int reg_idx;
    int rm;
    int rn;
    int size;
    int stride;
    int vd;
} arg_disas_neon_ls2;

typedef arg_disas_neon_ls0 arg_VLDST_multiple;
static bool trans_VLDST_multiple(DisasContext *ctx, arg_VLDST_multiple *a);
typedef arg_disas_neon_ls1 arg_VLD_all_lanes;
static bool trans_VLD_all_lanes(DisasContext *ctx, arg_VLD_all_lanes *a);
typedef arg_disas_neon_ls2 arg_VLDST_single;
static bool trans_VLDST_single(DisasContext *ctx, arg_VLDST_single *a);

static void disas_neon_ls_extract_disas_neon_ls_Fmt_0(DisasContext *ctx, arg_disas_neon_ls0 *a, uint32_t insn)
{
    a->l = extract32(insn, 21, 1);
    a->rn = extract32(insn, 16, 4);
    a->itype = extract32(insn, 8, 4);
    a->size = extract32(insn, 6, 2);
    a->align = extract32(insn, 4, 2);
    a->rm = extract32(insn, 0, 4);
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
}

static void disas_neon_ls_extract_disas_neon_ls_Fmt_1(DisasContext *ctx, arg_disas_neon_ls1 *a, uint32_t insn)
{
    a->rn = extract32(insn, 16, 4);
    a->n = extract32(insn, 8, 2);
    a->size = extract32(insn, 6, 2);
    a->t = extract32(insn, 5, 1);
    a->a = extract32(insn, 4, 1);
    a->rm = extract32(insn, 0, 4);
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
}

static void disas_neon_ls_extract_disas_neon_ls_Fmt_2(DisasContext *ctx, arg_disas_neon_ls2 *a, uint32_t insn)
{
    a->l = extract32(insn, 21, 1);
    a->rn = extract32(insn, 16, 4);
    a->n = extract32(insn, 8, 2);
    a->reg_idx = extract32(insn, 5, 3);
    a->align = extract32(insn, 4, 1);
    a->rm = extract32(insn, 0, 4);
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->size = 0;
    a->stride = 1;
}

static void disas_neon_ls_extract_disas_neon_ls_Fmt_3(DisasContext *ctx, arg_disas_neon_ls2 *a, uint32_t insn)
{
    a->l = extract32(insn, 21, 1);
    a->rn = extract32(insn, 16, 4);
    a->n = extract32(insn, 8, 2);
    a->reg_idx = extract32(insn, 6, 2);
    a->align = extract32(insn, 4, 2);
    a->rm = extract32(insn, 0, 4);
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->size = 1;
    a->stride = plus1(ctx, extract32(insn, 5, 1));
}

static void disas_neon_ls_extract_disas_neon_ls_Fmt_4(DisasContext *ctx, arg_disas_neon_ls2 *a, uint32_t insn)
{
    a->l = extract32(insn, 21, 1);
    a->rn = extract32(insn, 16, 4);
    a->n = extract32(insn, 8, 2);
    a->reg_idx = extract32(insn, 7, 1);
    a->align = extract32(insn, 4, 3);
    a->rm = extract32(insn, 0, 4);
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->size = 2;
    a->stride = plus1(ctx, extract32(insn, 6, 1));
}

static bool disas_neon_ls(DisasContext *ctx, uint32_t insn)
{
    union {
        arg_disas_neon_ls0 f_disas_neon_ls0;
        arg_disas_neon_ls1 f_disas_neon_ls1;
        arg_disas_neon_ls2 f_disas_neon_ls2;
    } u;

    switch (insn & 0xff900000) {
    case 0xf4000000:
        /* 11110100 0..0.... ........ ........ */
        disas_neon_ls_extract_disas_neon_ls_Fmt_0(ctx, &u.f_disas_neon_ls0, insn);
        if (trans_VLDST_multiple(ctx, &u.f_disas_neon_ls0)) return true;
        return false;
    case 0xf4800000:
        /* 11110100 1..0.... ........ ........ */
        switch ((insn >> 10) & 0x3) {
        case 0x0:
            /* 11110100 1..0.... ....00.. ........ */
            disas_neon_ls_extract_disas_neon_ls_Fmt_2(ctx, &u.f_disas_neon_ls2, insn);
            if (trans_VLDST_single(ctx, &u.f_disas_neon_ls2)) return true;
            return false;
        case 0x1:
            /* 11110100 1..0.... ....01.. ........ */
            disas_neon_ls_extract_disas_neon_ls_Fmt_3(ctx, &u.f_disas_neon_ls2, insn);
            if (trans_VLDST_single(ctx, &u.f_disas_neon_ls2)) return true;
            return false;
        case 0x2:
            /* 11110100 1..0.... ....10.. ........ */
            disas_neon_ls_extract_disas_neon_ls_Fmt_4(ctx, &u.f_disas_neon_ls2, insn);
            if (trans_VLDST_single(ctx, &u.f_disas_neon_ls2)) return true;
            return false;
        case 0x3:
            /* 11110100 1..0.... ....11.. ........ */
            disas_neon_ls_extract_disas_neon_ls_Fmt_1(ctx, &u.f_disas_neon_ls1, insn);
            switch ((insn >> 21) & 0x1) {
            case 0x1:
                /* 11110100 1.10.... ....11.. ........ */
                if (trans_VLD_all_lanes(ctx, &u.f_disas_neon_ls1)) return true;
                return false;
            }
            return false;
        }
        return false;
    }
    return false;
}
