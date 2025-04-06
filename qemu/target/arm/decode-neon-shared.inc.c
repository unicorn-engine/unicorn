/* This file is autogenerated by scripts/decodetree.py.  */

typedef struct {
    int q;
    int rot;
    int size;
    int vd;
    int vm;
    int vn;
} arg_disas_neon_shared0;

typedef struct {
    int q;
    int u;
    int vd;
    int vm;
    int vn;
} arg_disas_neon_shared1;

typedef struct {
    int q;
    int s;
    int vd;
    int vm;
    int vn;
} arg_disas_neon_shared2;

typedef struct {
    int index;
    int q;
    int rot;
    int size;
    int vd;
    int vm;
    int vn;
} arg_disas_neon_shared3;

typedef struct {
    int index;
    int q;
    int rm;
    int u;
    int vd;
    int vm;
    int vn;
} arg_disas_neon_shared4;

typedef struct {
    int index;
    int q;
    int rm;
    int s;
    int vd;
    int vn;
} arg_disas_neon_shared5;

typedef arg_disas_neon_shared0 arg_VCMLA;
static bool trans_VCMLA(DisasContext *ctx, arg_VCMLA *a);
typedef arg_disas_neon_shared0 arg_VCADD;
static bool trans_VCADD(DisasContext *ctx, arg_VCADD *a);
typedef arg_disas_neon_shared1 arg_VDOT;
static bool trans_VDOT(DisasContext *ctx, arg_VDOT *a);
typedef arg_disas_neon_shared2 arg_VFML;
static bool trans_VFML(DisasContext *ctx, arg_VFML *a);
typedef arg_disas_neon_shared3 arg_VCMLA_scalar;
static bool trans_VCMLA_scalar(DisasContext *ctx, arg_VCMLA_scalar *a);
typedef arg_disas_neon_shared4 arg_VDOT_scalar;
static bool trans_VDOT_scalar(DisasContext *ctx, arg_VDOT_scalar *a);
typedef arg_disas_neon_shared5 arg_VFML_scalar;
static bool trans_VFML_scalar(DisasContext *ctx, arg_VFML_scalar *a);

static void disas_neon_shared_extract_disas_neon_shared_Fmt_0(DisasContext *ctx, arg_disas_neon_shared0 *a, uint32_t insn)
{
    a->rot = extract32(insn, 23, 2);
    a->size = extract32(insn, 20, 1);
    a->q = extract32(insn, 6, 1);
    a->vm = deposit32(extract32(insn, 0, 4), 4, 28, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_1(DisasContext *ctx, arg_disas_neon_shared0 *a, uint32_t insn)
{
    a->rot = extract32(insn, 24, 1);
    a->size = extract32(insn, 20, 1);
    a->q = extract32(insn, 6, 1);
    a->vm = deposit32(extract32(insn, 0, 4), 4, 28, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_2(DisasContext *ctx, arg_disas_neon_shared1 *a, uint32_t insn)
{
    a->q = extract32(insn, 6, 1);
    a->u = extract32(insn, 4, 1);
    a->vm = deposit32(extract32(insn, 0, 4), 4, 28, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_3(DisasContext *ctx, arg_disas_neon_shared2 *a, uint32_t insn)
{
    a->s = extract32(insn, 23, 1);
    a->vm = deposit32(extract32(insn, 5, 1), 1, 31, extract32(insn, 0, 4));
    a->vn = deposit32(extract32(insn, 7, 1), 1, 31, extract32(insn, 16, 4));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->q = 0;
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_4(DisasContext *ctx, arg_disas_neon_shared2 *a, uint32_t insn)
{
    a->s = extract32(insn, 23, 1);
    a->vm = deposit32(extract32(insn, 0, 4), 4, 28, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->q = 1;
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_5(DisasContext *ctx, arg_disas_neon_shared3 *a, uint32_t insn)
{
    a->rot = extract32(insn, 20, 2);
    a->q = extract32(insn, 6, 1);
    a->index = extract32(insn, 5, 1);
    a->vm = extract32(insn, 0, 4);
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->size = 0;
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_6(DisasContext *ctx, arg_disas_neon_shared3 *a, uint32_t insn)
{
    a->rot = extract32(insn, 20, 2);
    a->q = extract32(insn, 6, 1);
    a->vm = deposit32(extract32(insn, 0, 4), 4, 28, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->size = 1;
    a->index = 0;
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_7(DisasContext *ctx, arg_disas_neon_shared4 *a, uint32_t insn)
{
    a->q = extract32(insn, 6, 1);
    a->index = extract32(insn, 5, 1);
    a->u = extract32(insn, 4, 1);
    a->rm = extract32(insn, 0, 4);
    a->vm = deposit32(extract32(insn, 0, 4), 4, 28, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_8(DisasContext *ctx, arg_disas_neon_shared5 *a, uint32_t insn)
{
    a->s = extract32(insn, 20, 1);
    a->index = extract32(insn, 3, 1);
    a->rm = deposit32(extract32(insn, 5, 1), 1, 31, extract32(insn, 0, 3));
    a->vn = deposit32(extract32(insn, 7, 1), 1, 31, extract32(insn, 16, 4));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->q = 0;
}

static void disas_neon_shared_extract_disas_neon_shared_Fmt_9(DisasContext *ctx, arg_disas_neon_shared5 *a, uint32_t insn)
{
    a->s = extract32(insn, 20, 1);
    a->rm = extract32(insn, 0, 3);
    a->index = deposit32(extract32(insn, 3, 1), 1, 31, extract32(insn, 5, 1));
    a->vn = deposit32(extract32(insn, 16, 4), 4, 28, extract32(insn, 7, 1));
    a->vd = deposit32(extract32(insn, 12, 4), 4, 28, extract32(insn, 22, 1));
    a->q = 1;
}

static bool disas_neon_shared(DisasContext *ctx, uint32_t insn)
{
    union {
        arg_disas_neon_shared0 f_disas_neon_shared0;
        arg_disas_neon_shared1 f_disas_neon_shared1;
        arg_disas_neon_shared2 f_disas_neon_shared2;
        arg_disas_neon_shared3 f_disas_neon_shared3;
        arg_disas_neon_shared4 f_disas_neon_shared4;
        arg_disas_neon_shared5 f_disas_neon_shared5;
    } u;

    switch (insn & 0xfe000f00) {
    case 0xfc000800:
        /* 1111110. ........ ....1000 ........ */
        switch (insn & 0x00200010) {
        case 0x00000000:
            /* 1111110. ..0..... ....1000 ...0.... */
            disas_neon_shared_extract_disas_neon_shared_Fmt_1(ctx, &u.f_disas_neon_shared0, insn);
            switch ((insn >> 23) & 0x1) {
            case 0x1:
                /* 1111110. 1.0..... ....1000 ...0.... */
                if (trans_VCADD(ctx, &u.f_disas_neon_shared0)) return true;
                return false;
            }
            return false;
        case 0x00200000:
            /* 1111110. ..1..... ....1000 ...0.... */
            disas_neon_shared_extract_disas_neon_shared_Fmt_0(ctx, &u.f_disas_neon_shared0, insn);
            if (trans_VCMLA(ctx, &u.f_disas_neon_shared0)) return true;
            return false;
        case 0x00200010:
            /* 1111110. ..1..... ....1000 ...1.... */
            switch (insn & 0x01100040) {
            case 0x00000000:
                /* 11111100 ..10.... ....1000 .0.1.... */
                disas_neon_shared_extract_disas_neon_shared_Fmt_3(ctx, &u.f_disas_neon_shared2, insn);
                if (trans_VFML(ctx, &u.f_disas_neon_shared2)) return true;
                return false;
            case 0x00000040:
                /* 11111100 ..10.... ....1000 .1.1.... */
                disas_neon_shared_extract_disas_neon_shared_Fmt_4(ctx, &u.f_disas_neon_shared2, insn);
                if (trans_VFML(ctx, &u.f_disas_neon_shared2)) return true;
                return false;
            }
            return false;
        }
        return false;
    case 0xfc000d00:
        /* 1111110. ........ ....1101 ........ */
        disas_neon_shared_extract_disas_neon_shared_Fmt_2(ctx, &u.f_disas_neon_shared1, insn);
        switch (insn & 0x01b00000) {
        case 0x00200000:
            /* 11111100 0.10.... ....1101 ........ */
            if (trans_VDOT(ctx, &u.f_disas_neon_shared1)) return true;
            return false;
        }
        return false;
    case 0xfe000800:
        /* 1111111. ........ ....1000 ........ */
        switch (insn & 0x01800010) {
        case 0x00000000:
            /* 11111110 0....... ....1000 ...0.... */
            disas_neon_shared_extract_disas_neon_shared_Fmt_5(ctx, &u.f_disas_neon_shared3, insn);
            if (trans_VCMLA_scalar(ctx, &u.f_disas_neon_shared3)) return true;
            return false;
        case 0x00000010:
            /* 11111110 0....... ....1000 ...1.... */
            switch (insn & 0x00200040) {
            case 0x00000000:
                /* 11111110 0.0..... ....1000 .0.1.... */
                disas_neon_shared_extract_disas_neon_shared_Fmt_8(ctx, &u.f_disas_neon_shared5, insn);
                if (trans_VFML_scalar(ctx, &u.f_disas_neon_shared5)) return true;
                return false;
            case 0x00000040:
                /* 11111110 0.0..... ....1000 .1.1.... */
                disas_neon_shared_extract_disas_neon_shared_Fmt_9(ctx, &u.f_disas_neon_shared5, insn);
                if (trans_VFML_scalar(ctx, &u.f_disas_neon_shared5)) return true;
                return false;
            }
            return false;
        case 0x00800000:
            /* 11111110 1....... ....1000 ...0.... */
            disas_neon_shared_extract_disas_neon_shared_Fmt_6(ctx, &u.f_disas_neon_shared3, insn);
            if (trans_VCMLA_scalar(ctx, &u.f_disas_neon_shared3)) return true;
            return false;
        }
        return false;
    case 0xfe000d00:
        /* 1111111. ........ ....1101 ........ */
        disas_neon_shared_extract_disas_neon_shared_Fmt_7(ctx, &u.f_disas_neon_shared4, insn);
        switch (insn & 0x01b00000) {
        case 0x00200000:
            /* 11111110 0.10.... ....1101 ........ */
            if (trans_VDOT_scalar(ctx, &u.f_disas_neon_shared4)) return true;
            return false;
        }
        return false;
    }
    return false;
}
