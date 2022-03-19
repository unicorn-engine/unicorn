/*
 * QEMU TCG support -- s390x vector instruction translation functions
 *
 * Copyright (C) 2019 Red Hat Inc
 *
 * Authors:
 *   David Hildenbrand <david@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

/*
 * For most instructions that use the same element size for reads and
 * writes, we can use real gvec vector expansion, which potantially uses
 * real host vector instructions. As they only work up to 64 bit elements,
 * 128 bit elements (vector is a single element) have to be handled
 * differently. Operations that are too complicated to encode via TCG ops
 * are handled via gvec ool (out-of-line) handlers.
 *
 * As soon as instructions use different element sizes for reads and writes
 * or access elements "out of their element scope" we expand them manually
 * in fancy loops, as gvec expansion does not deal with actual element
 * numbers and does also not support access to other elements.
 *
 * 128 bit elements:
 *  As we only have i32/i64, such elements have to be loaded into two
 *  i64 values and can then be processed e.g. by tcg_gen_add2_i64.
 *
 * Sizes:
 *  On s390x, the operand size (oprsz) and the maximum size (maxsz) are
 *  always 16 (128 bit). What gvec code calls "vece", s390x calls "es",
 *  a.k.a. "element size". These values nicely map to MO_8 ... MO_64. Only
 *  128 bit element size has to be treated in a special way (MO_64 + 1).
 *  We will use ES_* instead of MO_* for this reason in this file.
 *
 * CC handling:
 *  As gvec ool-helpers can currently not return values (besides via
 *  pointers like vectors or cpu_env), whenever we have to set the CC and
 *  can't conclude the value from the result vector, we will directly
 *  set it in "env->cc_op" and mark it as static via set_cc_static()".
 *  Whenever this is done, the helper writes globals (cc_op).
 */

#define NUM_VEC_ELEMENT_BYTES(es) (1 << (es))
#define NUM_VEC_ELEMENTS(es) (16 / NUM_VEC_ELEMENT_BYTES(es))
#define NUM_VEC_ELEMENT_BITS(es) (NUM_VEC_ELEMENT_BYTES(es) * BITS_PER_BYTE)

#define ES_8    MO_8
#define ES_16   MO_16
#define ES_32   MO_32
#define ES_64   MO_64
#define ES_128  4

/* Floating-Point Format */
#define FPF_SHORT       2
#define FPF_LONG        3
#define FPF_EXT         4

static inline bool valid_vec_element(uint8_t enr, MemOp es)
{
    return !(enr & ~(NUM_VEC_ELEMENTS(es) - 1));
}

static void read_vec_element_i64(TCGContext *tcg_ctx, TCGv_i64 dst, uint8_t reg, uint8_t enr,
                                 MemOp memop)
{
    const int offs = vec_reg_offset(reg, enr, memop & MO_SIZE);

    switch (memop) {
    case ES_8:
        tcg_gen_ld8u_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_16:
        tcg_gen_ld16u_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_32:
        tcg_gen_ld32u_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_8 | MO_SIGN:
        tcg_gen_ld8s_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_16 | MO_SIGN:
        tcg_gen_ld16s_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_32 | MO_SIGN:
        tcg_gen_ld32s_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_64:
    case ES_64 | MO_SIGN:
        tcg_gen_ld_i64(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    default:
        g_assert_not_reached();
    }
}

static void read_vec_element_i32(TCGContext *tcg_ctx, TCGv_i32 dst, uint8_t reg, uint8_t enr,
                                 MemOp memop)
{
    const int offs = vec_reg_offset(reg, enr, memop & MO_SIZE);

    switch (memop) {
    case ES_8:
        tcg_gen_ld8u_i32(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_16:
        tcg_gen_ld16u_i32(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_8 | MO_SIGN:
        tcg_gen_ld8s_i32(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_16 | MO_SIGN:
        tcg_gen_ld16s_i32(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    case ES_32:
    case ES_32 | MO_SIGN:
        tcg_gen_ld_i32(tcg_ctx, dst, tcg_ctx->cpu_env, offs);
        break;
    default:
        // g_assert_not_reached();
        break;
    }
}

static void write_vec_element_i64(TCGContext *tcg_ctx, TCGv_i64 src, int reg, uint8_t enr,
                                  MemOp memop)
{
    const int offs = vec_reg_offset(reg, enr, memop & MO_SIZE);

    switch (memop) {
    case ES_8:
        tcg_gen_st8_i64(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    case ES_16:
        tcg_gen_st16_i64(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    case ES_32:
        tcg_gen_st32_i64(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    case ES_64:
        tcg_gen_st_i64(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    default:
        g_assert_not_reached();
    }
}

static void write_vec_element_i32(TCGContext *tcg_ctx, TCGv_i32 src, int reg, uint8_t enr,
                                  MemOp memop)
{
    const int offs = vec_reg_offset(reg, enr, memop & MO_SIZE);

    switch (memop) {
    case ES_8:
        tcg_gen_st8_i32(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    case ES_16:
        tcg_gen_st16_i32(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    case ES_32:
        tcg_gen_st_i32(tcg_ctx, src, tcg_ctx->cpu_env, offs);
        break;
    default:
        // g_assert_not_reached();
        break;
    }
}

static void get_vec_element_ptr_i64(TCGContext *tcg_ctx, TCGv_ptr ptr, uint8_t reg, TCGv_i64 enr,
                                    uint8_t es)
{
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);

    /* mask off invalid parts from the element nr */
    tcg_gen_andi_i64(tcg_ctx, tmp, enr, NUM_VEC_ELEMENTS(es) - 1);

    /* convert it to an element offset relative to cpu_env (vec_reg_offset() */
    tcg_gen_shli_i64(tcg_ctx, tmp, tmp, es);
#ifndef HOST_WORDS_BIGENDIAN
    tcg_gen_xori_i64(tcg_ctx, tmp, tmp, 8 - NUM_VEC_ELEMENT_BYTES(es));
#endif
    tcg_gen_addi_i64(tcg_ctx, tmp, tmp, vec_full_reg_offset(reg));

    /* generate the final ptr by adding cpu_env */
    tcg_gen_trunc_i64_ptr(tcg_ctx, ptr, tmp);
    tcg_gen_add_ptr(tcg_ctx, ptr, ptr, tcg_ctx->cpu_env);

    tcg_temp_free_i64(tcg_ctx, tmp);
}

#define gen_gvec_2(tcg_ctx, v1, v2, gen) \
    tcg_gen_gvec_2(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                   16, 16, gen)
#define gen_gvec_2s(tcg_ctx, v1, v2, c, gen) \
    tcg_gen_gvec_2s(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                    16, 16, c, gen)
#define gen_gvec_2_ool(tcg_ctx, v1, v2, data, fn) \
    tcg_gen_gvec_2_ool(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                       16, 16, data, fn)
#define gen_gvec_2i_ool(tcg_ctx, v1, v2, c, data, fn) \
    tcg_gen_gvec_2i_ool(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                        c, 16, 16, data, fn)
#define gen_gvec_2_ptr(tcg_ctx, v1, v2, ptr, data, fn) \
    tcg_gen_gvec_2_ptr(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                       ptr, 16, 16, data, fn)
#define gen_gvec_3(tcg_ctx, v1, v2, v3, gen) \
    tcg_gen_gvec_3(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                   vec_full_reg_offset(v3), 16, 16, gen)
#define gen_gvec_3_ool(tcg_ctx, v1, v2, v3, data, fn) \
    tcg_gen_gvec_3_ool(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                       vec_full_reg_offset(v3), 16, 16, data, fn)
#define gen_gvec_3_ptr(tcg_ctx, v1, v2, v3, ptr, data, fn) \
    tcg_gen_gvec_3_ptr(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                       vec_full_reg_offset(v3), ptr, 16, 16, data, fn)
#define gen_gvec_3i(tcg_ctx, v1, v2, v3, c, gen) \
    tcg_gen_gvec_3i(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                    vec_full_reg_offset(v3), 16, 16, c, gen)
#define gen_gvec_4(tcg_ctx, v1, v2, v3, v4, gen) \
    tcg_gen_gvec_4(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                   vec_full_reg_offset(v3), vec_full_reg_offset(v4), \
                   16, 16, gen)
#define gen_gvec_4_ool(tcg_ctx, v1, v2, v3, v4, data, fn) \
    tcg_gen_gvec_4_ool(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                       vec_full_reg_offset(v3), vec_full_reg_offset(v4), \
                       16, 16, data, fn)
#define gen_gvec_4_ptr(tcg_ctx, v1, v2, v3, v4, ptr, data, fn) \
    tcg_gen_gvec_4_ptr(tcg_ctx, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                       vec_full_reg_offset(v3), vec_full_reg_offset(v4), \
                       ptr, 16, 16, data, fn)
#define gen_gvec_dup_i64(tcg_ctx, es, v1, c) \
    tcg_gen_gvec_dup_i64(tcg_ctx, es, vec_full_reg_offset(v1), 16, 16, c)
#define gen_gvec_mov(tcg_ctx, v1, v2) \
    tcg_gen_gvec_mov(tcg_ctx, 0, vec_full_reg_offset(v1), vec_full_reg_offset(v2), 16, \
                     16)
#define gen_gvec_dup64i(tcg_ctx, v1, c) \
    tcg_gen_gvec_dup64i(tcg_ctx, vec_full_reg_offset(v1), 16, 16, c)
#define gen_gvec_fn_2(tcg_ctx, fn, es, v1, v2) \
    tcg_gen_gvec_##fn(tcg_ctx, es, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                      16, 16)
#define gen_gvec_fn_2i(tcg_ctx, fn, es, v1, v2, c) \
    tcg_gen_gvec_##fn(tcg_ctx, es, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                      c, 16, 16)
#define gen_gvec_fn_2s(tcg_ctx, fn, es, v1, v2, s) \
    tcg_gen_gvec_##fn(tcg_ctx, es, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                      s, 16, 16)
#define gen_gvec_fn_3(tcg_ctx, fn, es, v1, v2, v3) \
    tcg_gen_gvec_##fn(tcg_ctx, es, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                      vec_full_reg_offset(v3), 16, 16)
#define gen_gvec_fn_4(tcg_ctx, fn, es, v1, v2, v3, v4) \
    tcg_gen_gvec_##fn(tcg_ctx, es, vec_full_reg_offset(v1), vec_full_reg_offset(v2), \
                      vec_full_reg_offset(v3), vec_full_reg_offset(v4), 16, 16)

/*
 * Helper to carry out a 128 bit vector computation using 2 i64 values per
 * vector.
 */
typedef void (*gen_gvec128_3_i64_fn)(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al,
                                     TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh);
static void gen_gvec128_3_i64(TCGContext *tcg_ctx, gen_gvec128_3_i64_fn fn, uint8_t d, uint8_t a,
                              uint8_t b)
{
        TCGv_i64 dh = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 dl = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 ah = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 al = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 bh = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 bl = tcg_temp_new_i64(tcg_ctx);

        read_vec_element_i64(tcg_ctx, ah, a, 0, ES_64);
        read_vec_element_i64(tcg_ctx, al, a, 1, ES_64);
        read_vec_element_i64(tcg_ctx, bh, b, 0, ES_64);
        read_vec_element_i64(tcg_ctx, bl, b, 1, ES_64);
        fn(tcg_ctx, dl, dh, al, ah, bl, bh);
        write_vec_element_i64(tcg_ctx, dh, d, 0, ES_64);
        write_vec_element_i64(tcg_ctx, dl, d, 1, ES_64);

        tcg_temp_free_i64(tcg_ctx, dh);
        tcg_temp_free_i64(tcg_ctx, dl);
        tcg_temp_free_i64(tcg_ctx, ah);
        tcg_temp_free_i64(tcg_ctx, al);
        tcg_temp_free_i64(tcg_ctx, bh);
        tcg_temp_free_i64(tcg_ctx, bl);
}

typedef void (*gen_gvec128_4_i64_fn)(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al,
                                     TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh,
                                     TCGv_i64 cl, TCGv_i64 ch);
static void gen_gvec128_4_i64(TCGContext *tcg_ctx, gen_gvec128_4_i64_fn fn, uint8_t d, uint8_t a,
                              uint8_t b, uint8_t c)
{
        TCGv_i64 dh = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 dl = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 ah = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 al = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 bh = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 bl = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 ch = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 cl = tcg_temp_new_i64(tcg_ctx);

        read_vec_element_i64(tcg_ctx, ah, a, 0, ES_64);
        read_vec_element_i64(tcg_ctx, al, a, 1, ES_64);
        read_vec_element_i64(tcg_ctx, bh, b, 0, ES_64);
        read_vec_element_i64(tcg_ctx, bl, b, 1, ES_64);
        read_vec_element_i64(tcg_ctx, ch, c, 0, ES_64);
        read_vec_element_i64(tcg_ctx, cl, c, 1, ES_64);
        fn(tcg_ctx, dl, dh, al, ah, bl, bh, cl, ch);
        write_vec_element_i64(tcg_ctx, dh, d, 0, ES_64);
        write_vec_element_i64(tcg_ctx, dl, d, 1, ES_64);

        tcg_temp_free_i64(tcg_ctx, dh);
        tcg_temp_free_i64(tcg_ctx, dl);
        tcg_temp_free_i64(tcg_ctx, ah);
        tcg_temp_free_i64(tcg_ctx, al);
        tcg_temp_free_i64(tcg_ctx, bh);
        tcg_temp_free_i64(tcg_ctx, bl);
        tcg_temp_free_i64(tcg_ctx, ch);
        tcg_temp_free_i64(tcg_ctx, cl);
}

static void gen_gvec_dupi(TCGContext *tcg_ctx, uint8_t es, uint8_t reg, uint64_t c)
{
    switch (es) {
    case ES_8:
        tcg_gen_gvec_dup8i(tcg_ctx, vec_full_reg_offset(reg), 16, 16, c);
        break;
    case ES_16:
        tcg_gen_gvec_dup16i(tcg_ctx, vec_full_reg_offset(reg), 16, 16, c);
        break;
    case ES_32:
        tcg_gen_gvec_dup32i(tcg_ctx, vec_full_reg_offset(reg), 16, 16, c);
        break;
    case ES_64:
        gen_gvec_dup64i(tcg_ctx, reg, c);
        break;
    default:
        g_assert_not_reached();
    }
}

static void zero_vec(TCGContext *tcg_ctx, uint8_t reg)
{
    tcg_gen_gvec_dup8i(tcg_ctx, vec_full_reg_offset(reg), 16, 16, 0);
}

static void gen_addi2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al, TCGv_i64 ah,
                          uint64_t b)
{
    TCGv_i64 bl = tcg_const_i64(tcg_ctx, b);
    TCGv_i64 bh = tcg_const_i64(tcg_ctx, 0);

    tcg_gen_add2_i64(tcg_ctx, dl, dh, al, ah, bl, bh);
    tcg_temp_free_i64(tcg_ctx, bl);
    tcg_temp_free_i64(tcg_ctx, bh);
}

static DisasJumpType op_vge(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = s->insn->data;
    const uint8_t enr = get_field(s, m3);
    TCGv_i64 tmp;

    if (!valid_vec_element(enr, es)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    read_vec_element_i64(tcg_ctx, tmp, get_field(s, v2), enr, es);
    tcg_gen_add_i64(tcg_ctx, o->addr1, o->addr1, tmp);
    gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 0);

    tcg_gen_qemu_ld_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TE | es);
    write_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), enr, es);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static uint64_t generate_byte_mask(uint8_t mask)
{
    uint64_t r = 0;
    int i;

    for (i = 0; i < 8; i++) {
        if ((mask >> i) & 1) {
            r |= 0xffull << (i * 8);
        }
    }
    return r;
}

static DisasJumpType op_vgbm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint16_t i2 = get_field(s, i2);

    if (i2 == (i2 & 0xff) * 0x0101) {
        /*
         * Masks for both 64 bit elements of the vector are the same.
         * Trust tcg to produce a good constant loading.
         */
        gen_gvec_dup64i(tcg_ctx, get_field(s, v1),
                        generate_byte_mask(i2 & 0xff));
    } else {
        TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

        tcg_gen_movi_i64(tcg_ctx, t, generate_byte_mask(i2 >> 8));
        write_vec_element_i64(tcg_ctx, t, get_field(s, v1), 0, ES_64);
        tcg_gen_movi_i64(tcg_ctx, t, generate_byte_mask(i2));
        write_vec_element_i64(tcg_ctx, t, get_field(s, v1), 1, ES_64);
        tcg_temp_free_i64(tcg_ctx, t);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vgm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t bits = NUM_VEC_ELEMENT_BITS(es);
    const uint8_t i2 = get_field(s, i2) & (bits - 1);
    const uint8_t i3 = get_field(s, i3) & (bits - 1);
    uint64_t mask = 0;
    int i;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    /* generate the mask - take care of wrapping */
    for (i = i2; ; i = (i + 1) % bits) {
        mask |= 1ull << (bits - i - 1);
        if (i == i3) {
            break;
        }
    }

    gen_gvec_dupi(tcg_ctx, es, get_field(s, v1), mask);
    return DISAS_NEXT;
}

static DisasJumpType op_vl(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_qemu_ld_i64(tcg_ctx, t0, o->addr1, get_mem_index(s), MO_TEQ);
    gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, t1, o->addr1, get_mem_index(s), MO_TEQ);
    write_vec_element_i64(tcg_ctx, t0, get_field(s, v1), 0, ES_64);
    write_vec_element_i64(tcg_ctx, t1, get_field(s, v1), 1, ES_64);
    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    return DISAS_NEXT;
}

static DisasJumpType op_vlr(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_mov(tcg_ctx, get_field(s, v1), get_field(s, v2));
    return DISAS_NEXT;
}

static DisasJumpType op_vlrep(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);
    TCGv_i64 tmp;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_qemu_ld_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TE | es);
    gen_gvec_dup_i64(tcg_ctx, es, get_field(s, v1), tmp);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vle(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = s->insn->data;
    const uint8_t enr = get_field(s, m3);
    TCGv_i64 tmp;

    if (!valid_vec_element(enr, es)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_qemu_ld_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TE | es);
    write_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), enr, es);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vlei(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = s->insn->data;
    const uint8_t enr = get_field(s, m3);
    TCGv_i64 tmp;

    if (!valid_vec_element(enr, es)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_const_i64(tcg_ctx, (int16_t)get_field(s, i2));
    write_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), enr, es);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vlgv(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    TCGv_ptr ptr;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    /* fast path if we don't need the register content */
    if (!get_field(s, b2)) {
        uint8_t enr = get_field(s, d2) & (NUM_VEC_ELEMENTS(es) - 1);

        read_vec_element_i64(tcg_ctx, o->out, get_field(s, v3), enr, es);
        return DISAS_NEXT;
    }

    ptr = tcg_temp_new_ptr(tcg_ctx);
    get_vec_element_ptr_i64(tcg_ctx, ptr, get_field(s, v3), o->addr1, es);
    switch (es) {
    case ES_8:
        tcg_gen_ld8u_i64(tcg_ctx, o->out, ptr, 0);
        break;
    case ES_16:
        tcg_gen_ld16u_i64(tcg_ctx, o->out, ptr, 0);
        break;
    case ES_32:
        tcg_gen_ld32u_i64(tcg_ctx, o->out, ptr, 0);
        break;
    case ES_64:
        tcg_gen_ld_i64(tcg_ctx, o->out, ptr, 0);
        break;
    default:
        // g_assert_not_reached();
        break;
    }
    tcg_temp_free_ptr(tcg_ctx, ptr);

    return DISAS_NEXT;
}

static DisasJumpType op_vllez(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint8_t es = get_field(s, m3);
    uint8_t enr;
    TCGv_i64 t;

    switch (es) {
    /* rightmost sub-element of leftmost doubleword */
    case ES_8:
        enr = 7;
        break;
    case ES_16:
        enr = 3;
        break;
    case ES_32:
        enr = 1;
        break;
    case ES_64:
        enr = 0;
        break;
    /* leftmost sub-element of leftmost doubleword */
    case 6:
        if (s390_has_feat(s->uc, S390_FEAT_VECTOR_ENH)) {
            es = ES_32;
            enr = 0;
            break;
        }
        /* fallthrough */
    default:
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    t = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_qemu_ld_i64(tcg_ctx, t, o->addr1, get_mem_index(s), MO_TE | es);
    zero_vec(tcg_ctx, get_field(s, v1));
    write_vec_element_i64(tcg_ctx, t, get_field(s, v1), enr, es);
    tcg_temp_free_i64(tcg_ctx, t);
    return DISAS_NEXT;
}

static DisasJumpType op_vlm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t v3 = get_field(s, v3);
    uint8_t v1 = get_field(s, v1);
    TCGv_i64 t0, t1;

    if (v3 < v1 || (v3 - v1 + 1) > 16) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    /*
     * Check for possible access exceptions by trying to load the last
     * element. The first element will be checked first next.
     */
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    gen_addi_and_wrap_i64(s, t0, o->addr1, (v3 - v1) * 16 + 8);
    tcg_gen_qemu_ld_i64(tcg_ctx, t0, t0, get_mem_index(s), MO_TEQ);

    for (;; v1++) {
        tcg_gen_qemu_ld_i64(tcg_ctx, t1, o->addr1, get_mem_index(s), MO_TEQ);
        write_vec_element_i64(tcg_ctx, t1, v1, 0, ES_64);
        if (v1 == v3) {
            break;
        }
        gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 8);
        tcg_gen_qemu_ld_i64(tcg_ctx, t1, o->addr1, get_mem_index(s), MO_TEQ);
        write_vec_element_i64(tcg_ctx, t1, v1, 1, ES_64);
        gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 8);
    }

    /* Store the last element, loaded first */
    write_vec_element_i64(tcg_ctx, t0, v1, 1, ES_64);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    return DISAS_NEXT;
}

static DisasJumpType op_vlbb(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int64_t block_size = (1ull << (get_field(s, m3) + 6));
    const int v1_offs = vec_full_reg_offset(get_field(s, v1));
    TCGv_ptr a0;
    TCGv_i64 bytes;

    if (get_field(s, m3) > 6) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    bytes = tcg_temp_new_i64(tcg_ctx);
    a0 = tcg_temp_new_ptr(tcg_ctx);
    /* calculate the number of bytes until the next block boundary */
    tcg_gen_ori_i64(tcg_ctx, bytes, o->addr1, -block_size);
    tcg_gen_neg_i64(tcg_ctx, bytes, bytes);

    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, v1_offs);
    gen_helper_vll(tcg_ctx, tcg_ctx->cpu_env, a0, o->addr1, bytes);
    tcg_temp_free_i64(tcg_ctx, bytes);
    tcg_temp_free_ptr(tcg_ctx, a0);
    return DISAS_NEXT;
}

static DisasJumpType op_vlvg(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    TCGv_ptr ptr;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    /* fast path if we don't need the register content */
    if (!get_field(s, b2)) {
        uint8_t enr = get_field(s, d2) & (NUM_VEC_ELEMENTS(es) - 1);

        write_vec_element_i64(tcg_ctx, o->in2, get_field(s, v1), enr, es);
        return DISAS_NEXT;
    }

    ptr = tcg_temp_new_ptr(tcg_ctx);
    get_vec_element_ptr_i64(tcg_ctx, ptr, get_field(s, v1), o->addr1, es);
    switch (es) {
    case ES_8:
        tcg_gen_st8_i64(tcg_ctx, o->in2, ptr, 0);
        break;
    case ES_16:
        tcg_gen_st16_i64(tcg_ctx, o->in2, ptr, 0);
        break;
    case ES_32:
        tcg_gen_st32_i64(tcg_ctx, o->in2, ptr, 0);
        break;
    case ES_64:
        tcg_gen_st_i64(tcg_ctx, o->in2, ptr, 0);
        break;
    default:
        // g_assert_not_reached();
        break;
    }
    tcg_temp_free_ptr(tcg_ctx, ptr);

    return DISAS_NEXT;
}

static DisasJumpType op_vlvgp(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    write_vec_element_i64(tcg_ctx, o->in1, get_field(s, v1), 0, ES_64);
    write_vec_element_i64(tcg_ctx, o->in2, get_field(s, v1), 1, ES_64);
    return DISAS_NEXT;
}

static DisasJumpType op_vll(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int v1_offs = vec_full_reg_offset(get_field(s, v1));
    TCGv_ptr a0 = tcg_temp_new_ptr(tcg_ctx);

    /* convert highest index into an actual length */
    tcg_gen_addi_i64(tcg_ctx, o->in2, o->in2, 1);
    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, v1_offs);
    gen_helper_vll(tcg_ctx, tcg_ctx->cpu_env, a0, o->addr1, o->in2);
    tcg_temp_free_ptr(tcg_ctx, a0);
    return DISAS_NEXT;
}

static DisasJumpType op_vmr(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v2 = get_field(s, v2);
    const uint8_t v3 = get_field(s, v3);
    const uint8_t es = get_field(s, m4);
    int dst_idx, src_idx;
    TCGv_i64 tmp;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    if (s->fields.op2 == 0x61) {
        /* iterate backwards to avoid overwriting data we might need later */
        for (dst_idx = NUM_VEC_ELEMENTS(es) - 1; dst_idx >= 0; dst_idx--) {
            src_idx = dst_idx / 2;
            if (dst_idx % 2 == 0) {
                read_vec_element_i64(tcg_ctx, tmp, v2, src_idx, es);
            } else {
                read_vec_element_i64(tcg_ctx, tmp, v3, src_idx, es);
            }
            write_vec_element_i64(tcg_ctx, tmp, v1, dst_idx, es);
        }
    } else {
        /* iterate forward to avoid overwriting data we might need later */
        for (dst_idx = 0; dst_idx < NUM_VEC_ELEMENTS(es); dst_idx++) {
            src_idx = (dst_idx + NUM_VEC_ELEMENTS(es)) / 2;
            if (dst_idx % 2 == 0) {
                read_vec_element_i64(tcg_ctx, tmp, v2, src_idx, es);
            } else {
                read_vec_element_i64(tcg_ctx, tmp, v3, src_idx, es);
            }
            write_vec_element_i64(tcg_ctx, tmp, v1, dst_idx, es);
        }
    }
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vpk(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v2 = get_field(s, v2);
    const uint8_t v3 = get_field(s, v3);
    const uint8_t es = get_field(s, m4);
    static gen_helper_gvec_3 * const vpk[3] = {
        gen_helper_gvec_vpk16,
        gen_helper_gvec_vpk32,
        gen_helper_gvec_vpk64,
    };
     static gen_helper_gvec_3 * const vpks[3] = {
        gen_helper_gvec_vpks16,
        gen_helper_gvec_vpks32,
        gen_helper_gvec_vpks64,
    };
    static gen_helper_gvec_3_ptr * const vpks_cc[3] = {
        gen_helper_gvec_vpks_cc16,
        gen_helper_gvec_vpks_cc32,
        gen_helper_gvec_vpks_cc64,
    };
    static gen_helper_gvec_3 * const vpkls[3] = {
        gen_helper_gvec_vpkls16,
        gen_helper_gvec_vpkls32,
        gen_helper_gvec_vpkls64,
    };
    static gen_helper_gvec_3_ptr * const vpkls_cc[3] = {
        gen_helper_gvec_vpkls_cc16,
        gen_helper_gvec_vpkls_cc32,
        gen_helper_gvec_vpkls_cc64,
    };

    if (es == ES_8 || es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0x97:
        if (get_field(s, m5) & 0x1) {
            gen_gvec_3_ptr(tcg_ctx, v1, v2, v3, tcg_ctx->cpu_env, 0, vpks_cc[es - 1]);
            set_cc_static(s);
        } else {
            gen_gvec_3_ool(tcg_ctx, v1, v2, v3, 0, vpks[es - 1]);
        }
        break;
    case 0x95:
        if (get_field(s, m5) & 0x1) {
            gen_gvec_3_ptr(tcg_ctx, v1, v2, v3, tcg_ctx->cpu_env, 0, vpkls_cc[es - 1]);
            set_cc_static(s);
        } else {
            gen_gvec_3_ool(tcg_ctx, v1, v2, v3, 0, vpkls[es - 1]);
        }
        break;
    case 0x94:
        /* If sources and destination dont't overlap -> fast path */
        if (v1 != v2 && v1 != v3) {
            const uint8_t src_es = get_field(s, m4);
            const uint8_t dst_es = src_es - 1;
            TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
            int dst_idx, src_idx;

            for (dst_idx = 0; dst_idx < NUM_VEC_ELEMENTS(dst_es); dst_idx++) {
                src_idx = dst_idx;
                if (src_idx < NUM_VEC_ELEMENTS(src_es)) {
                    read_vec_element_i64(tcg_ctx, tmp, v2, src_idx, src_es);
                } else {
                    src_idx -= NUM_VEC_ELEMENTS(src_es);
                    read_vec_element_i64(tcg_ctx, tmp, v3, src_idx, src_es);
                }
                write_vec_element_i64(tcg_ctx, tmp, v1, dst_idx, dst_es);
            }
            tcg_temp_free_i64(tcg_ctx, tmp);
        } else {
            gen_gvec_3_ool(tcg_ctx, v1, v2, v3, 0, vpk[es - 1]);
        }
        break;
    default:
        g_assert_not_reached();
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vperm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_4_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                   get_field(s, v3), get_field(s, v4),
                   0, gen_helper_gvec_vperm);
    return DISAS_NEXT;
}

static DisasJumpType op_vpdi(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t i2 = extract32(get_field(s, m4), 2, 1);
    const uint8_t i3 = extract32(get_field(s, m4), 0, 1);
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

    read_vec_element_i64(tcg_ctx, t0, get_field(s, v2), i2, ES_64);
    read_vec_element_i64(tcg_ctx, t1, get_field(s, v3), i3, ES_64);
    write_vec_element_i64(tcg_ctx, t0, get_field(s, v1), 0, ES_64);
    write_vec_element_i64(tcg_ctx, t1, get_field(s, v1), 1, ES_64);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    return DISAS_NEXT;
}

static DisasJumpType op_vrep(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t enr = get_field(s, i2);
    const uint8_t es = get_field(s, m4);

    if (es > ES_64 || !valid_vec_element(enr, es)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tcg_gen_gvec_dup_mem(tcg_ctx, es, vec_full_reg_offset(get_field(s, v1)),
                         vec_reg_offset(get_field(s, v3), enr, es),
                         16, 16);
    return DISAS_NEXT;
}

static DisasJumpType op_vrepi(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int64_t data = (int16_t)get_field(s, i2);
    const uint8_t es = get_field(s, m3);

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec_dupi(tcg_ctx, es, get_field(s, v1), data);
    return DISAS_NEXT;
}

static DisasJumpType op_vsce(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = s->insn->data;
    const uint8_t enr = get_field(s, m3);
    TCGv_i64 tmp;

    if (!valid_vec_element(enr, es)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    read_vec_element_i64(tcg_ctx, tmp, get_field(s, v2), enr, es);
    tcg_gen_add_i64(tcg_ctx, o->addr1, o->addr1, tmp);
    gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 0);

    read_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), enr, es);
    tcg_gen_qemu_st_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TE | es);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vsel(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_4(tcg_ctx, bitsel, ES_8, get_field(s, v1),
                  get_field(s, v4), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vseg(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);
    int idx1, idx2;
    TCGv_i64 tmp;

    switch (es) {
    case ES_8:
        idx1 = 7;
        idx2 = 15;
        break;
    case ES_16:
        idx1 = 3;
        idx2 = 7;
        break;
    case ES_32:
        idx1 = 1;
        idx2 = 3;
        break;
    default:
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    read_vec_element_i64(tcg_ctx, tmp, get_field(s, v2), idx1, es | MO_SIGN);
    write_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), 0, ES_64);
    read_vec_element_i64(tcg_ctx, tmp, get_field(s, v2), idx2, es | MO_SIGN);
    write_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), 1, ES_64);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vst(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 tmp = tcg_const_i64(tcg_ctx, 16);

    /* Probe write access before actually modifying memory */
    gen_helper_probe_write_access(tcg_ctx, tcg_ctx->cpu_env, o->addr1, tmp);

    read_vec_element_i64(tcg_ctx, tmp,  get_field(s, v1), 0, ES_64);
    tcg_gen_qemu_st_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TEQ);
    gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 8);
    read_vec_element_i64(tcg_ctx, tmp,  get_field(s, v1), 1, ES_64);
    tcg_gen_qemu_st_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TEQ);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vste(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = s->insn->data;
    const uint8_t enr = get_field(s, m3);
    TCGv_i64 tmp;

    if (!valid_vec_element(enr, es)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    read_vec_element_i64(tcg_ctx, tmp, get_field(s, v1), enr, es);
    tcg_gen_qemu_st_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TE | es);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vstm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t v3 = get_field(s, v3);
    uint8_t v1 = get_field(s, v1);
    TCGv_i64 tmp;

    while (v3 < v1 || (v3 - v1 + 1) > 16) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    /* Probe write access before actually modifying memory */
    tmp = tcg_const_i64(tcg_ctx, (v3 - v1 + 1) * 16);
    gen_helper_probe_write_access(tcg_ctx, tcg_ctx->cpu_env, o->addr1, tmp);

    for (;; v1++) {
        read_vec_element_i64(tcg_ctx, tmp, v1, 0, ES_64);
        tcg_gen_qemu_st_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TEQ);
        gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 8);
        read_vec_element_i64(tcg_ctx, tmp, v1, 1, ES_64);
        tcg_gen_qemu_st_i64(tcg_ctx, tmp, o->addr1, get_mem_index(s), MO_TEQ);
        if (v1 == v3) {
            break;
        }
        gen_addi_and_wrap_i64(s, o->addr1, o->addr1, 8);
    }
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vstl(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const int v1_offs = vec_full_reg_offset(get_field(s, v1));
    TCGv_ptr a0 = tcg_temp_new_ptr(tcg_ctx);

    /* convert highest index into an actual length */
    tcg_gen_addi_i64(tcg_ctx, o->in2, o->in2, 1);
    tcg_gen_addi_ptr(tcg_ctx, a0, tcg_ctx->cpu_env, v1_offs);
    gen_helper_vstl(tcg_ctx, tcg_ctx->cpu_env, a0, o->addr1, o->in2);
    tcg_temp_free_ptr(tcg_ctx, a0);
    return DISAS_NEXT;
}

static DisasJumpType op_vup(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const bool logical = s->fields.op2 == 0xd4 || s->fields.op2 == 0xd5;
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v2 = get_field(s, v2);
    const uint8_t src_es = get_field(s, m3);
    const uint8_t dst_es = src_es + 1;
    int dst_idx, src_idx;
    TCGv_i64 tmp;

    if (src_es > ES_32) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);
    if (s->fields.op2 == 0xd7 || s->fields.op2 == 0xd5) {
        /* iterate backwards to avoid overwriting data we might need later */
        for (dst_idx = NUM_VEC_ELEMENTS(dst_es) - 1; dst_idx >= 0; dst_idx--) {
            src_idx = dst_idx;
            read_vec_element_i64(tcg_ctx, tmp, v2, src_idx,
                                 src_es | (logical ? 0 : MO_SIGN));
            write_vec_element_i64(tcg_ctx, tmp, v1, dst_idx, dst_es);
        }

    } else {
        /* iterate forward to avoid overwriting data we might need later */
        for (dst_idx = 0; dst_idx < NUM_VEC_ELEMENTS(dst_es); dst_idx++) {
            src_idx = dst_idx + NUM_VEC_ELEMENTS(src_es) / 2;
            read_vec_element_i64(tcg_ctx, tmp, v2, src_idx,
                                 src_es | (logical ? 0 : MO_SIGN));
            write_vec_element_i64(tcg_ctx, tmp, v1, dst_idx, dst_es);
        }
    }
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_va(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);

    if (es > ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    } else if (es == ES_128) {
        gen_gvec128_3_i64(tcg_ctx, tcg_gen_add2_i64, get_field(s, v1),
                          get_field(s, v2), get_field(s, v3));
        return DISAS_NEXT;
    }
    gen_gvec_fn_3(tcg_ctx, add, es, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static void gen_acc(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b, uint8_t es)
{
    const uint8_t msb_bit_nr = NUM_VEC_ELEMENT_BITS(es) - 1;
    TCGv_i64 msb_mask = tcg_const_i64(tcg_ctx, dup_const(es, 1ull << msb_bit_nr));
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t3 = tcg_temp_new_i64(tcg_ctx);

    /* Calculate the carry into the MSB, ignoring the old MSBs */
    tcg_gen_andc_i64(tcg_ctx, t1, a, msb_mask);
    tcg_gen_andc_i64(tcg_ctx, t2, b, msb_mask);
    tcg_gen_add_i64(tcg_ctx, t1, t1, t2);
    /* Calculate the MSB without any carry into it */
    tcg_gen_xor_i64(tcg_ctx, t3, a, b);
    /* Calculate the carry out of the MSB in the MSB bit position */
    tcg_gen_and_i64(tcg_ctx, d, a, b);
    tcg_gen_and_i64(tcg_ctx, t1, t1, t3);
    tcg_gen_or_i64(tcg_ctx, d, d, t1);
    /* Isolate and shift the carry into position */
    tcg_gen_and_i64(tcg_ctx, d, d, msb_mask);
    tcg_gen_shri_i64(tcg_ctx, d, d, msb_bit_nr);

    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, t3);
}

static void gen_acc8_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    gen_acc(tcg_ctx, d, a, b, ES_8);
}

static void gen_acc16_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    gen_acc(tcg_ctx, d, a, b, ES_16);
}

static void gen_acc_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_add_i32(tcg_ctx, t, a, b);
    tcg_gen_setcond_i32(tcg_ctx, TCG_COND_LTU, d, t, b);
    tcg_temp_free_i32(tcg_ctx, t);
}

static void gen_acc_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_add_i64(tcg_ctx, t, a, b);
    tcg_gen_setcond_i64(tcg_ctx, TCG_COND_LTU, d, t, b);
    tcg_temp_free_i64(tcg_ctx, t);
}

static void gen_acc2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al,
                         TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh)
{
    TCGv_i64 th = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

    tcg_gen_add2_i64(tcg_ctx, tl, th, al, zero, bl, zero);
    tcg_gen_add2_i64(tcg_ctx, tl, th, th, zero, ah, zero);
    tcg_gen_add2_i64(tcg_ctx, tl, dl, tl, th, bh, zero);
    tcg_gen_mov_i64(tcg_ctx, dh, zero);

    tcg_temp_free_i64(tcg_ctx, th);
    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static DisasJumpType op_vacc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g[4] = {
        { .fni8 = gen_acc8_i64, },
        { .fni8 = gen_acc16_i64, },
        { .fni4 = gen_acc_i32, },
        { .fni8 = gen_acc_i64, },
    };

    if (es > ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    } else if (es == ES_128) {
        gen_gvec128_3_i64(tcg_ctx, gen_acc2_i64, get_field(s, v1),
                          get_field(s, v2), get_field(s, v3));
        return DISAS_NEXT;
    }
    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), &g[es]);
    return DISAS_NEXT;
}

static void gen_ac2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al, TCGv_i64 ah,
                        TCGv_i64 bl, TCGv_i64 bh, TCGv_i64 cl, TCGv_i64 ch)
{
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 th = tcg_const_i64(tcg_ctx, 0);

    /* extract the carry only */
    tcg_gen_extract_i64(tcg_ctx, tl, cl, 0, 1);
    tcg_gen_add2_i64(tcg_ctx, dl, dh, al, ah, bl, bh);
    tcg_gen_add2_i64(tcg_ctx, dl, dh, dl, dh, tl, th);

    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, th);
}

static DisasJumpType op_vac(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (get_field(s, m5) != ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec128_4_i64(tcg_ctx, gen_ac2_i64, get_field(s, v1),
                      get_field(s, v2), get_field(s, v3),
                      get_field(s, v4));
    return DISAS_NEXT;
}

static void gen_accc2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al, TCGv_i64 ah,
                          TCGv_i64 bl, TCGv_i64 bh, TCGv_i64 cl, TCGv_i64 ch)
{
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 th = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

    tcg_gen_andi_i64(tcg_ctx, tl, cl, 1);
    tcg_gen_add2_i64(tcg_ctx, tl, th, tl, zero, al, zero);
    tcg_gen_add2_i64(tcg_ctx, tl, th, tl, th, bl, zero);
    tcg_gen_add2_i64(tcg_ctx, tl, th, th, zero, ah, zero);
    tcg_gen_add2_i64(tcg_ctx, tl, dl, tl, th, bh, zero);
    tcg_gen_mov_i64(tcg_ctx, dh, zero);

    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, th);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static DisasJumpType op_vaccc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (get_field(s, m5) != ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec128_4_i64(tcg_ctx, gen_accc2_i64, get_field(s, v1),
                      get_field(s, v2), get_field(s, v3),
                      get_field(s, v4));
    return DISAS_NEXT;
}

static DisasJumpType op_vn(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, and, ES_8, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vnc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, andc, ES_8, get_field(s, v1),
                  get_field(s, v2), get_field(s, v3));
    return DISAS_NEXT;
}

static void gen_avg_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ext_i32_i64(tcg_ctx, t0, a);
    tcg_gen_ext_i32_i64(tcg_ctx, t1, b);
    tcg_gen_add_i64(tcg_ctx, t0, t0, t1);
    tcg_gen_addi_i64(tcg_ctx, t0, t0, 1);
    tcg_gen_shri_i64(tcg_ctx, t0, t0, 1);
    tcg_gen_extrl_i64_i32(tcg_ctx, d, t0);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
}

static void gen_avg_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 al, TCGv_i64 bl)
{
    TCGv_i64 dh = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 ah = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 bh = tcg_temp_new_i64(tcg_ctx);

    /* extending the sign by one bit is sufficient */
    tcg_gen_extract_i64(tcg_ctx, ah, al, 63, 1);
    tcg_gen_extract_i64(tcg_ctx, bh, bl, 63, 1);
    tcg_gen_add2_i64(tcg_ctx, dl, dh, al, ah, bl, bh);
    gen_addi2_i64(tcg_ctx, dl, dh, dl, dh, 1);
    tcg_gen_extract2_i64(tcg_ctx, dl, dl, dh, 1);

    tcg_temp_free_i64(tcg_ctx, dh);
    tcg_temp_free_i64(tcg_ctx, ah);
    tcg_temp_free_i64(tcg_ctx, bh);
}

static DisasJumpType op_vavg(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g[4] = {
        { .fno = gen_helper_gvec_vavg8, },
        { .fno = gen_helper_gvec_vavg16, },
        { .fni4 = gen_avg_i32, },
        { .fni8 = gen_avg_i64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), &g[es]);
    return DISAS_NEXT;
}

static void gen_avgl_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_extu_i32_i64(tcg_ctx, t0, a);
    tcg_gen_extu_i32_i64(tcg_ctx, t1, b);
    tcg_gen_add_i64(tcg_ctx, t0, t0, t1);
    tcg_gen_addi_i64(tcg_ctx, t0, t0, 1);
    tcg_gen_shri_i64(tcg_ctx, t0, t0, 1);
    tcg_gen_extrl_i64_i32(tcg_ctx, d, t0);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
}

static void gen_avgl_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 al, TCGv_i64 bl)
{
    TCGv_i64 dh = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

    tcg_gen_add2_i64(tcg_ctx, dl, dh, al, zero, bl, zero);
    gen_addi2_i64(tcg_ctx, dl, dh, dl, dh, 1);
    tcg_gen_extract2_i64(tcg_ctx, dl, dl, dh, 1);

    tcg_temp_free_i64(tcg_ctx, dh);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static DisasJumpType op_vavgl(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g[4] = {
        { .fno = gen_helper_gvec_vavgl8, },
        { .fno = gen_helper_gvec_vavgl16, },
        { .fni4 = gen_avgl_i32, },
        { .fni8 = gen_avgl_i64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), &g[es]);
    return DISAS_NEXT;
}

static DisasJumpType op_vcksm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 tmp = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 sum = tcg_temp_new_i32(tcg_ctx);
    int i;

    read_vec_element_i32(tcg_ctx, sum, get_field(s, v3), 1, ES_32);
    for (i = 0; i < 4; i++) {
        read_vec_element_i32(tcg_ctx, tmp, get_field(s, v2), i, ES_32);
        tcg_gen_add2_i32(tcg_ctx, tmp, sum, sum, sum, tmp, tmp);
    }
    zero_vec(tcg_ctx, get_field(s, v1));
    write_vec_element_i32(tcg_ctx, sum, get_field(s, v1), 1, ES_32);

    tcg_temp_free_i32(tcg_ctx, tmp);
    tcg_temp_free_i32(tcg_ctx, sum);
    return DISAS_NEXT;
}

static DisasJumpType op_vec(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint8_t es = get_field(s, m3);
    const uint8_t enr = NUM_VEC_ELEMENTS(es) / 2 - 1;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    if (s->fields.op2 == 0xdb) {
        es |= MO_SIGN;
    }

    o->in1 = tcg_temp_new_i64(tcg_ctx);
    o->in2 = tcg_temp_new_i64(tcg_ctx);
    read_vec_element_i64(tcg_ctx, o->in1, get_field(s, v1), enr, es);
    read_vec_element_i64(tcg_ctx, o->in2, get_field(s, v2), enr, es);
    return DISAS_NEXT;
}

static DisasJumpType op_vc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    TCGCond cond = s->insn->data;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    tcg_gen_gvec_cmp(tcg_ctx, cond, es,
                     vec_full_reg_offset(get_field(s, v1)),
                     vec_full_reg_offset(get_field(s, v2)),
                     vec_full_reg_offset(get_field(s, v3)), 16, 16);
    if (get_field(s, m5) & 0x1) {
        TCGv_i64 low = tcg_temp_new_i64(tcg_ctx);
        TCGv_i64 high = tcg_temp_new_i64(tcg_ctx);

        read_vec_element_i64(tcg_ctx, high, get_field(s, v1), 0, ES_64);
        read_vec_element_i64(tcg_ctx, low, get_field(s, v1), 1, ES_64);
        gen_op_update2_cc_i64(s, CC_OP_VC, low, high);

        tcg_temp_free_i64(tcg_ctx, low);
        tcg_temp_free_i64(tcg_ctx, high);
    }
    return DISAS_NEXT;
}

static void gen_clz_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a)
{
    tcg_gen_clzi_i32(tcg_ctx, d, a, 32);
}

static void gen_clz_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a)
{
    tcg_gen_clzi_i64(tcg_ctx, d, a, 64);
}

static DisasJumpType op_vclz(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);
    static const GVecGen2 g[4] = {
        { .fno = gen_helper_gvec_vclz8, },
        { .fno = gen_helper_gvec_vclz16, },
        { .fni4 = gen_clz_i32, },
        { .fni8 = gen_clz_i64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_2(tcg_ctx, get_field(s, v1), get_field(s, v2), &g[es]);
    return DISAS_NEXT;
}

static void gen_ctz_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a)
{
    tcg_gen_ctzi_i32(tcg_ctx, d, a, 32);
}

static void gen_ctz_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a)
{
    tcg_gen_ctzi_i64(tcg_ctx, d, a, 64);
}

static DisasJumpType op_vctz(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);
    static const GVecGen2 g[4] = {
        { .fno = gen_helper_gvec_vctz8, },
        { .fno = gen_helper_gvec_vctz16, },
        { .fni4 = gen_ctz_i32, },
        { .fni8 = gen_ctz_i64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_2(tcg_ctx, get_field(s, v1), get_field(s, v2), &g[es]);
    return DISAS_NEXT;
}

static DisasJumpType op_vx(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, xor, ES_8, get_field(s, v1), get_field(s, v2),
                 get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vgfm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g[4] = {
        { .fno = gen_helper_gvec_vgfm8, },
        { .fno = gen_helper_gvec_vgfm16, },
        { .fno = gen_helper_gvec_vgfm32, },
        { .fno = gen_helper_gvec_vgfm64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), &g[es]);
    return DISAS_NEXT;
}

static DisasJumpType op_vgfma(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m5);
    static const GVecGen4 g[4] = {
        { .fno = gen_helper_gvec_vgfma8, },
        { .fno = gen_helper_gvec_vgfma16, },
        { .fno = gen_helper_gvec_vgfma32, },
        { .fno = gen_helper_gvec_vgfma64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_4(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), get_field(s, v4), &g[es]);
    return DISAS_NEXT;
}

static DisasJumpType op_vlc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec_fn_2(tcg_ctx, neg, es, get_field(s, v1), get_field(s, v2));
    return DISAS_NEXT;
}

static DisasJumpType op_vlp(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec_fn_2(tcg_ctx, abs, es, get_field(s, v1), get_field(s, v2));
    return DISAS_NEXT;
}

static DisasJumpType op_vmx(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v2 = get_field(s, v2);
    const uint8_t v3 = get_field(s, v3);
    const uint8_t es = get_field(s, m4);

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0xff:
        gen_gvec_fn_3(tcg_ctx, smax, es, v1, v2, v3);
        break;
    case 0xfd:
        gen_gvec_fn_3(tcg_ctx, umax, es, v1, v2, v3);
        break;
    case 0xfe:
        gen_gvec_fn_3(tcg_ctx, smin, es, v1, v2, v3);
        break;
    case 0xfc:
        gen_gvec_fn_3(tcg_ctx, umin, es, v1, v2, v3);
        break;
    default:
        g_assert_not_reached();
    }
    return DISAS_NEXT;
}

static void gen_mal_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_mul_i32(tcg_ctx, t0, a, b);
    tcg_gen_add_i32(tcg_ctx, d, t0, c);

    tcg_temp_free_i32(tcg_ctx, t0);
}

static void gen_mah_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ext_i32_i64(tcg_ctx, t0, a);
    tcg_gen_ext_i32_i64(tcg_ctx, t1, b);
    tcg_gen_ext_i32_i64(tcg_ctx, t2, c);
    tcg_gen_mul_i64(tcg_ctx, t0, t0, t1);
    tcg_gen_add_i64(tcg_ctx, t0, t0, t2);
    tcg_gen_extrh_i64_i32(tcg_ctx, d, t0);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t2);
}

static void gen_malh_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_extu_i32_i64(tcg_ctx, t0, a);
    tcg_gen_extu_i32_i64(tcg_ctx, t1, b);
    tcg_gen_extu_i32_i64(tcg_ctx, t2, c);
    tcg_gen_mul_i64(tcg_ctx, t0, t0, t1);
    tcg_gen_add_i64(tcg_ctx, t0, t0, t2);
    tcg_gen_extrh_i64_i32(tcg_ctx, d, t0);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t2);
}

static DisasJumpType op_vma(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m5);
    static const GVecGen4 g_vmal[3] = {
        { .fno = gen_helper_gvec_vmal8, },
        { .fno = gen_helper_gvec_vmal16, },
        { .fni4 = gen_mal_i32, },
    };
    static const GVecGen4 g_vmah[3] = {
        { .fno = gen_helper_gvec_vmah8, },
        { .fno = gen_helper_gvec_vmah16, },
        { .fni4 = gen_mah_i32, },
    };
    static const GVecGen4 g_vmalh[3] = {
        { .fno = gen_helper_gvec_vmalh8, },
        { .fno = gen_helper_gvec_vmalh16, },
        { .fni4 = gen_malh_i32, },
    };
    static const GVecGen4 g_vmae[3] = {
        { .fno = gen_helper_gvec_vmae8, },
        { .fno = gen_helper_gvec_vmae16, },
        { .fno = gen_helper_gvec_vmae32, },
    };
    static const GVecGen4 g_vmale[3] = {
        { .fno = gen_helper_gvec_vmale8, },
        { .fno = gen_helper_gvec_vmale16, },
        { .fno = gen_helper_gvec_vmale32, },
    };
    static const GVecGen4 g_vmao[3] = {
        { .fno = gen_helper_gvec_vmao8, },
        { .fno = gen_helper_gvec_vmao16, },
        { .fno = gen_helper_gvec_vmao32, },
    };
    static const GVecGen4 g_vmalo[3] = {
        { .fno = gen_helper_gvec_vmalo8, },
        { .fno = gen_helper_gvec_vmalo16, },
        { .fno = gen_helper_gvec_vmalo32, },
    };
    const GVecGen4 *fn;

    if (es > ES_32) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0xaa:
        fn = &g_vmal[es];
        break;
    case 0xab:
        fn = &g_vmah[es];
        break;
    case 0xa9:
        fn = &g_vmalh[es];
        break;
    case 0xae:
        fn = &g_vmae[es];
        break;
    case 0xac:
        fn = &g_vmale[es];
        break;
    case 0xaf:
        fn = &g_vmao[es];
        break;
    case 0xad:
        fn = &g_vmalo[es];
        break;
    default:
        g_assert_not_reached();
    }

    gen_gvec_4(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), get_field(s, v4), fn);
    return DISAS_NEXT;
}

static void gen_mh_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_muls2_i32(tcg_ctx, t, d, a, b);
    tcg_temp_free_i32(tcg_ctx, t);
}

static void gen_mlh_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_mulu2_i32(tcg_ctx, t, d, a, b);
    tcg_temp_free_i32(tcg_ctx, t);
}

static DisasJumpType op_vm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g_vmh[3] = {
        { .fno = gen_helper_gvec_vmh8, },
        { .fno = gen_helper_gvec_vmh16, },
        { .fni4 = gen_mh_i32, },
    };
    static const GVecGen3 g_vmlh[3] = {
        { .fno = gen_helper_gvec_vmlh8, },
        { .fno = gen_helper_gvec_vmlh16, },
        { .fni4 = gen_mlh_i32, },
    };
    static const GVecGen3 g_vme[3] = {
        { .fno = gen_helper_gvec_vme8, },
        { .fno = gen_helper_gvec_vme16, },
        { .fno = gen_helper_gvec_vme32, },
    };
    static const GVecGen3 g_vmle[3] = {
        { .fno = gen_helper_gvec_vmle8, },
        { .fno = gen_helper_gvec_vmle16, },
        { .fno = gen_helper_gvec_vmle32, },
    };
    static const GVecGen3 g_vmo[3] = {
        { .fno = gen_helper_gvec_vmo8, },
        { .fno = gen_helper_gvec_vmo16, },
        { .fno = gen_helper_gvec_vmo32, },
    };
    static const GVecGen3 g_vmlo[3] = {
        { .fno = gen_helper_gvec_vmlo8, },
        { .fno = gen_helper_gvec_vmlo16, },
        { .fno = gen_helper_gvec_vmlo32, },
    };
    const GVecGen3 *fn;

    if (es > ES_32) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0xa2:
        gen_gvec_fn_3(tcg_ctx, mul, es, get_field(s, v1),
                      get_field(s, v2), get_field(s, v3));
        return DISAS_NEXT;
    case 0xa3:
        fn = &g_vmh[es];
        break;
    case 0xa1:
        fn = &g_vmlh[es];
        break;
    case 0xa6:
        fn = &g_vme[es];
        break;
    case 0xa4:
        fn = &g_vmle[es];
        break;
    case 0xa7:
        fn = &g_vmo[es];
        break;
    case 0xa5:
        fn = &g_vmlo[es];
        break;
    default:
        g_assert_not_reached();
    }

    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), fn);
    return DISAS_NEXT;
}

static DisasJumpType op_vnn(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, nand, ES_8, get_field(s, v1),
                  get_field(s, v2), get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vno(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, nor, ES_8, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vnx(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, eqv, ES_8, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vo(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, or, ES_8, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_voc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_fn_3(tcg_ctx, orc, ES_8, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static DisasJumpType op_vpopct(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m3);
    static const GVecGen2 g[4] = {
        { .fno = gen_helper_gvec_vpopct8, },
        { .fno = gen_helper_gvec_vpopct16, },
        { .fni4 = tcg_gen_ctpop_i32, },
        { .fni8 = tcg_gen_ctpop_i64, },
    };

    if (es > ES_64 || (es != ES_8 && !s390_has_feat(s->uc, S390_FEAT_VECTOR_ENH))) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec_2(tcg_ctx, get_field(s, v1), get_field(s, v2), &g[es]);
    return DISAS_NEXT;
}

static void gen_rll_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_andi_i32(tcg_ctx, t0, b, 31);
    tcg_gen_rotl_i32(tcg_ctx, d, a, t0);
    tcg_temp_free_i32(tcg_ctx, t0);
}

static void gen_rll_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_andi_i64(tcg_ctx, t0, b, 63);
    tcg_gen_rotl_i64(tcg_ctx, d, a, t0);
    tcg_temp_free_i64(tcg_ctx, t0);
}

static DisasJumpType op_verllv(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g[4] = {
        { .fno = gen_helper_gvec_verllv8, },
        { .fno = gen_helper_gvec_verllv16, },
        { .fni4 = gen_rll_i32, },
        { .fni8 = gen_rll_i64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), &g[es]);
    return DISAS_NEXT;
}

static DisasJumpType op_verll(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen2s g[4] = {
        { .fno = gen_helper_gvec_verll8, },
        { .fno = gen_helper_gvec_verll16, },
        { .fni4 = gen_rll_i32, },
        { .fni8 = gen_rll_i64, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }
    gen_gvec_2s(tcg_ctx, get_field(s, v1), get_field(s, v3), o->addr1,
                &g[es]);
    return DISAS_NEXT;
}

static void gen_rim_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b, int32_t c)
{
    TCGv_i32 t = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_rotli_i32(tcg_ctx, t, a, c & 31);
    tcg_gen_and_i32(tcg_ctx, t, t, b);
    tcg_gen_andc_i32(tcg_ctx, d, d, b);
    tcg_gen_or_i32(tcg_ctx, d, d, t);

    tcg_temp_free_i32(tcg_ctx, t);
}

static void gen_rim_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b, int64_t c)
{
    TCGv_i64 t = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_rotli_i64(tcg_ctx, t, a, c & 63);
    tcg_gen_and_i64(tcg_ctx, t, t, b);
    tcg_gen_andc_i64(tcg_ctx, d, d, b);
    tcg_gen_or_i64(tcg_ctx, d, d, t);

    tcg_temp_free_i64(tcg_ctx, t);
}

static DisasJumpType op_verim(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m5);
    const uint8_t i4 = get_field(s, i4) &
                       (NUM_VEC_ELEMENT_BITS(es) - 1);
    static const GVecGen3i g[4] = {
        { .fno = gen_helper_gvec_verim8, },
        { .fno = gen_helper_gvec_verim16, },
        { .fni4 = gen_rim_i32,
          .load_dest = true, },
        { .fni8 = gen_rim_i64,
          .load_dest = true, },
    };

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec_3i(tcg_ctx, get_field(s, v1), get_field(s, v2),
                get_field(s, v3), i4, &g[es]);
    return DISAS_NEXT;
}

static DisasJumpType op_vesv(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v2 = get_field(s, v2);
    const uint8_t v3 = get_field(s, v3);

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0x70:
        gen_gvec_fn_3(tcg_ctx, shlv, es, v1, v2, v3);
        break;
    case 0x7a:
        gen_gvec_fn_3(tcg_ctx, sarv, es, v1, v2, v3);
        break;
    case 0x78:
        gen_gvec_fn_3(tcg_ctx, shrv, es, v1, v2, v3);
        break;
    default:
        g_assert_not_reached();
    }
    return DISAS_NEXT;
}

static DisasJumpType op_ves(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t d2 = get_field(s, d2) &
                       (NUM_VEC_ELEMENT_BITS(es) - 1);
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v3 = get_field(s, v3);
    TCGv_i32 shift;

    if (es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (likely(!get_field(s, b2))) {
        switch (s->fields.op2) {
        case 0x30:
            gen_gvec_fn_2i(tcg_ctx, shli, es, v1, v3, d2);
            break;
        case 0x3a:
            gen_gvec_fn_2i(tcg_ctx, sari, es, v1, v3, d2);
            break;
        case 0x38:
            gen_gvec_fn_2i(tcg_ctx, shri, es, v1, v3, d2);
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        shift = tcg_temp_new_i32(tcg_ctx);
        tcg_gen_extrl_i64_i32(tcg_ctx, shift, o->addr1);
        tcg_gen_andi_i32(tcg_ctx, shift, shift, NUM_VEC_ELEMENT_BITS(es) - 1);
        switch (s->fields.op2) {
        case 0x30:
            gen_gvec_fn_2s(tcg_ctx, shls, es, v1, v3, shift);
            break;
        case 0x3a:
            gen_gvec_fn_2s(tcg_ctx, sars, es, v1, v3, shift);
            break;
        case 0x38:
            gen_gvec_fn_2s(tcg_ctx, shrs, es, v1, v3, shift);
            break;
        default:
            g_assert_not_reached();
        }
        tcg_temp_free_i32(tcg_ctx, shift);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vsl(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 shift = tcg_temp_new_i64(tcg_ctx);

    read_vec_element_i64(tcg_ctx, shift, get_field(s, v3), 7, ES_8);
    if (s->fields.op2 == 0x74) {
        tcg_gen_andi_i64(tcg_ctx, shift, shift, 0x7);
    } else {
        tcg_gen_andi_i64(tcg_ctx, shift, shift, 0x78);
    }

    gen_gvec_2i_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                    shift, 0, gen_helper_gvec_vsl);
    tcg_temp_free_i64(tcg_ctx, shift);
    return DISAS_NEXT;
}

static DisasJumpType op_vsldb(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t i4 = get_field(s, i4) & 0xf;
    const int left_shift = (i4 & 7) * 8;
    const int right_shift = 64 - left_shift;
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t2 = tcg_temp_new_i64(tcg_ctx);

    if ((i4 & 8) == 0) {
        read_vec_element_i64(tcg_ctx, t0, get_field(s, v2), 0, ES_64);
        read_vec_element_i64(tcg_ctx, t1, get_field(s, v2), 1, ES_64);
        read_vec_element_i64(tcg_ctx, t2, get_field(s, v3), 0, ES_64);
    } else {
        read_vec_element_i64(tcg_ctx, t0, get_field(s, v2), 1, ES_64);
        read_vec_element_i64(tcg_ctx, t1, get_field(s, v3), 0, ES_64);
        read_vec_element_i64(tcg_ctx, t2, get_field(s, v3), 1, ES_64);
    }
    tcg_gen_extract2_i64(tcg_ctx, t0, t1, t0, right_shift);
    tcg_gen_extract2_i64(tcg_ctx, t1, t2, t1, right_shift);
    write_vec_element_i64(tcg_ctx, t0, get_field(s, v1), 0, ES_64);
    write_vec_element_i64(tcg_ctx, t1, get_field(s, v1), 1, ES_64);

    tcg_temp_free(tcg_ctx, t0);
    tcg_temp_free(tcg_ctx, t1);
    tcg_temp_free(tcg_ctx, t2);
    return DISAS_NEXT;
}

static DisasJumpType op_vsra(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 shift = tcg_temp_new_i64(tcg_ctx);

    read_vec_element_i64(tcg_ctx, shift, get_field(s, v3), 7, ES_8);
    if (s->fields.op2 == 0x7e) {
        tcg_gen_andi_i64(tcg_ctx, shift, shift, 0x7);
    } else {
        tcg_gen_andi_i64(tcg_ctx, shift, shift, 0x78);
    }

    gen_gvec_2i_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                    shift, 0, gen_helper_gvec_vsra);
    tcg_temp_free_i64(tcg_ctx, shift);
    return DISAS_NEXT;
}

static DisasJumpType op_vsrl(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 shift = tcg_temp_new_i64(tcg_ctx);

    read_vec_element_i64(tcg_ctx, shift, get_field(s, v3), 7, ES_8);
    if (s->fields.op2 == 0x7c) {
        tcg_gen_andi_i64(tcg_ctx, shift, shift, 0x7);
    } else {
        tcg_gen_andi_i64(tcg_ctx, shift, shift, 0x78);
    }

    gen_gvec_2i_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                    shift, 0, gen_helper_gvec_vsrl);
    tcg_temp_free_i64(tcg_ctx, shift);
    return DISAS_NEXT;
}

static DisasJumpType op_vs(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);

    if (es > ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    } else if (es == ES_128) {
        gen_gvec128_3_i64(tcg_ctx, tcg_gen_sub2_i64, get_field(s, v1),
                          get_field(s, v2), get_field(s, v3));
        return DISAS_NEXT;
    }
    gen_gvec_fn_3(tcg_ctx, sub, es, get_field(s, v1), get_field(s, v2),
                  get_field(s, v3));
    return DISAS_NEXT;
}

static void gen_scbi_i32(TCGContext *tcg_ctx, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b)
{
    tcg_gen_setcond_i32(tcg_ctx, TCG_COND_GEU, d, a, b);
}

static void gen_scbi_i64(TCGContext *tcg_ctx, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b)
{
    tcg_gen_setcond_i64(tcg_ctx, TCG_COND_GEU, d, a, b);
}

static void gen_scbi2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al,
                          TCGv_i64 ah, TCGv_i64 bl, TCGv_i64 bh)
{
    TCGv_i64 th = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);

    tcg_gen_sub2_i64(tcg_ctx, tl, th, al, zero, bl, zero);
    tcg_gen_andi_i64(tcg_ctx, th, th, 1);
    tcg_gen_sub2_i64(tcg_ctx, tl, th, ah, zero, th, zero);
    tcg_gen_sub2_i64(tcg_ctx, tl, th, tl, th, bh, zero);
    /* "invert" the result: -1 -> 0; 0 -> 1 */
    tcg_gen_addi_i64(tcg_ctx, dl, th, 1);
    tcg_gen_mov_i64(tcg_ctx, dh, zero);

    tcg_temp_free_i64(tcg_ctx, th);
    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static DisasJumpType op_vscbi(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    static const GVecGen3 g[4] = {
        { .fno = gen_helper_gvec_vscbi8, },
        { .fno = gen_helper_gvec_vscbi16, },
        { .fni4 = gen_scbi_i32, },
        { .fni8 = gen_scbi_i64, },
    };

    if (es > ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    } else if (es == ES_128) {
        gen_gvec128_3_i64(tcg_ctx, gen_scbi2_i64, get_field(s, v1),
                          get_field(s, v2), get_field(s, v3));
        return DISAS_NEXT;
    }
    gen_gvec_3(tcg_ctx, get_field(s, v1), get_field(s, v2),
               get_field(s, v3), &g[es]);
    return DISAS_NEXT;
}

static void gen_sbi2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al, TCGv_i64 ah,
                         TCGv_i64 bl, TCGv_i64 bh, TCGv_i64 cl, TCGv_i64 ch)
{
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 th = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_not_i64(tcg_ctx, tl, bl);
    tcg_gen_not_i64(tcg_ctx, th, bh);
    gen_ac2_i64(tcg_ctx, dl, dh, al, ah, tl, th, cl, ch);
    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, th);
}

static DisasJumpType op_vsbi(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (get_field(s, m5) != ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec128_4_i64(tcg_ctx, gen_sbi2_i64, get_field(s, v1),
                      get_field(s, v2), get_field(s, v3),
                      get_field(s, v4));
    return DISAS_NEXT;
}

static void gen_sbcbi2_i64(TCGContext *tcg_ctx, TCGv_i64 dl, TCGv_i64 dh, TCGv_i64 al, TCGv_i64 ah,
                           TCGv_i64 bl, TCGv_i64 bh, TCGv_i64 cl, TCGv_i64 ch)
{
    TCGv_i64 th = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_not_i64(tcg_ctx, tl, bl);
    tcg_gen_not_i64(tcg_ctx, th, bh);
    gen_accc2_i64(tcg_ctx, dl, dh, al, ah, tl, th, cl, ch);

    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, th);
}

static DisasJumpType op_vsbcbi(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (get_field(s, m5) != ES_128) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    gen_gvec128_4_i64(tcg_ctx, gen_sbcbi2_i64, get_field(s, v1),
                      get_field(s, v2), get_field(s, v3),
                      get_field(s, v4));
    return DISAS_NEXT;
}

static DisasJumpType op_vsumg(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    TCGv_i64 sum, tmp;
    uint8_t dst_idx;

    if (es == ES_8 || es > ES_32) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    sum = tcg_temp_new_i64(tcg_ctx);
    tmp = tcg_temp_new_i64(tcg_ctx);
    for (dst_idx = 0; dst_idx < 2; dst_idx++) {
        uint8_t idx = dst_idx * NUM_VEC_ELEMENTS(es) / 2;
        const uint8_t max_idx = idx + NUM_VEC_ELEMENTS(es) / 2 - 1;

        read_vec_element_i64(tcg_ctx, sum, get_field(s, v3), max_idx, es);
        for (; idx <= max_idx; idx++) {
            read_vec_element_i64(tcg_ctx, tmp, get_field(s, v2), idx, es);
            tcg_gen_add_i64(tcg_ctx, sum, sum, tmp);
        }
        write_vec_element_i64(tcg_ctx, sum, get_field(s, v1), dst_idx, ES_64);
    }
    tcg_temp_free_i64(tcg_ctx, sum);
    tcg_temp_free_i64(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vsumq(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t max_idx = NUM_VEC_ELEMENTS(es) - 1;
    TCGv_i64 sumh, suml, zero, tmpl;
    uint8_t idx;

    if (es < ES_32 || es > ES_64) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    sumh = tcg_const_i64(tcg_ctx, 0);
    suml = tcg_temp_new_i64(tcg_ctx);
    zero = tcg_const_i64(tcg_ctx, 0);
    tmpl = tcg_temp_new_i64(tcg_ctx);

    read_vec_element_i64(tcg_ctx, suml, get_field(s, v3), max_idx, es);
    for (idx = 0; idx <= max_idx; idx++) {
        read_vec_element_i64(tcg_ctx, tmpl, get_field(s, v2), idx, es);
        tcg_gen_add2_i64(tcg_ctx, suml, sumh, suml, sumh, tmpl, zero);
    }
    write_vec_element_i64(tcg_ctx, sumh, get_field(s, v1), 0, ES_64);
    write_vec_element_i64(tcg_ctx, suml, get_field(s, v1), 1, ES_64);

    tcg_temp_free_i64(tcg_ctx, sumh);
    tcg_temp_free_i64(tcg_ctx, suml);
    tcg_temp_free_i64(tcg_ctx, zero);
    tcg_temp_free_i64(tcg_ctx, tmpl);
    return DISAS_NEXT;
}

static DisasJumpType op_vsum(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    TCGv_i32 sum, tmp;
    uint8_t dst_idx;

    if (es > ES_16) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    sum = tcg_temp_new_i32(tcg_ctx);
    tmp = tcg_temp_new_i32(tcg_ctx);
    for (dst_idx = 0; dst_idx < 4; dst_idx++) {
        uint8_t idx = dst_idx * NUM_VEC_ELEMENTS(es) / 4;
        const uint8_t max_idx = idx + NUM_VEC_ELEMENTS(es) / 4 - 1;

        read_vec_element_i32(tcg_ctx, sum, get_field(s, v3), max_idx, es);
        for (; idx <= max_idx; idx++) {
            read_vec_element_i32(tcg_ctx, tmp, get_field(s, v2), idx, es);
            tcg_gen_add_i32(tcg_ctx, sum, sum, tmp);
        }
        write_vec_element_i32(tcg_ctx, sum, get_field(s, v1), dst_idx, ES_32);
    }
    tcg_temp_free_i32(tcg_ctx, sum);
    tcg_temp_free_i32(tcg_ctx, tmp);
    return DISAS_NEXT;
}

static DisasJumpType op_vtm(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                   tcg_ctx->cpu_env, 0, gen_helper_gvec_vtm);
    set_cc_static(s);
    return DISAS_NEXT;
}

static DisasJumpType op_vfae(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    static gen_helper_gvec_3 * const g[3] = {
        gen_helper_gvec_vfae8,
        gen_helper_gvec_vfae16,
        gen_helper_gvec_vfae32,
    };
    static gen_helper_gvec_3_ptr * const g_cc[3] = {
        gen_helper_gvec_vfae_cc8,
        gen_helper_gvec_vfae_cc16,
        gen_helper_gvec_vfae_cc32,
    };
    if (es > ES_32) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m5, 0, 1)) {
        gen_gvec_3_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       get_field(s, v3), tcg_ctx->cpu_env, m5, g_cc[es]);
        set_cc_static(s);
    } else {
        gen_gvec_3_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       get_field(s, v3), m5, g[es]);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vfee(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    static gen_helper_gvec_3 * const g[3] = {
        gen_helper_gvec_vfee8,
        gen_helper_gvec_vfee16,
        gen_helper_gvec_vfee32,
    };
    static gen_helper_gvec_3_ptr * const g_cc[3] = {
        gen_helper_gvec_vfee_cc8,
        gen_helper_gvec_vfee_cc16,
        gen_helper_gvec_vfee_cc32,
    };

    if (es > ES_32 || m5 & ~0x3) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m5, 0, 1)) {
        gen_gvec_3_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       get_field(s, v3), tcg_ctx->cpu_env, m5, g_cc[es]);
        set_cc_static(s);
    } else {
        gen_gvec_3_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       get_field(s, v3), m5, g[es]);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vfene(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    static gen_helper_gvec_3 * const g[3] = {
        gen_helper_gvec_vfene8,
        gen_helper_gvec_vfene16,
        gen_helper_gvec_vfene32,
    };
    static gen_helper_gvec_3_ptr * const g_cc[3] = {
        gen_helper_gvec_vfene_cc8,
        gen_helper_gvec_vfene_cc16,
        gen_helper_gvec_vfene_cc32,
    };

    if (es > ES_32 || m5 & ~0x3) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m5, 0, 1)) {
        gen_gvec_3_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       get_field(s, v3), tcg_ctx->cpu_env, m5, g_cc[es]);
        set_cc_static(s);
    } else {
        gen_gvec_3_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       get_field(s, v3), m5, g[es]);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vistr(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    static gen_helper_gvec_2 * const g[3] = {
        gen_helper_gvec_vistr8,
        gen_helper_gvec_vistr16,
        gen_helper_gvec_vistr32,
    };
    static gen_helper_gvec_2_ptr * const g_cc[3] = {
        gen_helper_gvec_vistr_cc8,
        gen_helper_gvec_vistr_cc16,
        gen_helper_gvec_vistr_cc32,
    };

    if (es > ES_32 || m5 & ~0x1) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m5, 0, 1)) {
        gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       tcg_ctx->cpu_env, 0, g_cc[es]);
        set_cc_static(s);
    } else {
        gen_gvec_2_ool(tcg_ctx, get_field(s, v1), get_field(s, v2), 0,
                       g[es]);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vstrc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t es = get_field(s, m5);
    const uint8_t m6 = get_field(s, m6);
    static gen_helper_gvec_4 * const g[3] = {
        gen_helper_gvec_vstrc8,
        gen_helper_gvec_vstrc16,
        gen_helper_gvec_vstrc32,
    };
    static gen_helper_gvec_4 * const g_rt[3] = {
        gen_helper_gvec_vstrc_rt8,
        gen_helper_gvec_vstrc_rt16,
        gen_helper_gvec_vstrc_rt32,
    };
    static gen_helper_gvec_4_ptr * const g_cc[3] = {
        gen_helper_gvec_vstrc_cc8,
        gen_helper_gvec_vstrc_cc16,
        gen_helper_gvec_vstrc_cc32,
    };
    static gen_helper_gvec_4_ptr * const g_cc_rt[3] = {
        gen_helper_gvec_vstrc_cc_rt8,
        gen_helper_gvec_vstrc_cc_rt16,
        gen_helper_gvec_vstrc_cc_rt32,
    };

    if (es > ES_32) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m6, 0, 1)) {
        if (extract32(m6, 2, 1)) {
            gen_gvec_4_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                           get_field(s, v3), get_field(s, v4),
                           tcg_ctx->cpu_env, m6, g_cc_rt[es]);
        } else {
            gen_gvec_4_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                           get_field(s, v3), get_field(s, v4),
                           tcg_ctx->cpu_env, m6, g_cc[es]);
        }
        set_cc_static(s);
    } else {
        if (extract32(m6, 2, 1)) {
            gen_gvec_4_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                           get_field(s, v3), get_field(s, v4),
                           m6, g_rt[es]);
        } else {
            gen_gvec_4_ool(tcg_ctx, get_field(s, v1), get_field(s, v2),
                           get_field(s, v3), get_field(s, v4),
                           m6, g[es]);
        }
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vfa(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t fpf = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    const bool se = extract32(m5, 3, 1);
    gen_helper_gvec_3_ptr *fn;

    if (fpf != FPF_LONG || extract32(m5, 0, 3)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0xe3:
        fn = se ? gen_helper_gvec_vfa64s : gen_helper_gvec_vfa64;
        break;
    case 0xe5:
        fn = se ? gen_helper_gvec_vfd64s : gen_helper_gvec_vfd64;
        break;
    case 0xe7:
        fn = se ? gen_helper_gvec_vfm64s : gen_helper_gvec_vfm64;
        break;
    case 0xe2:
        fn = se ? gen_helper_gvec_vfs64s : gen_helper_gvec_vfs64;
        break;
    default:
        g_assert_not_reached();
    }
    gen_gvec_3_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                   get_field(s, v3), tcg_ctx->cpu_env, 0, fn);
    return DISAS_NEXT;
}

static DisasJumpType op_wfc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t fpf = get_field(s, m3);
    const uint8_t m4 = get_field(s, m4);

    if (fpf != FPF_LONG || m4) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (s->fields.op2 == 0xcb) {
        gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       tcg_ctx->cpu_env, 0, gen_helper_gvec_wfc64);
    } else {
        gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                       tcg_ctx->cpu_env, 0, gen_helper_gvec_wfk64);
    }
    set_cc_static(s);
    return DISAS_NEXT;
}

static DisasJumpType op_vfc(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t fpf = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    const uint8_t m6 = get_field(s, m6);
    const bool se = extract32(m5, 3, 1);
    const bool cs = extract32(m6, 0, 1);
    gen_helper_gvec_3_ptr *fn;

    if (fpf != FPF_LONG || extract32(m5, 0, 3) || extract32(m6, 1, 3)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (cs) {
        switch (s->fields.op2) {
        case 0xe8:
            fn = se ? gen_helper_gvec_vfce64s_cc : gen_helper_gvec_vfce64_cc;
            break;
        case 0xeb:
            fn = se ? gen_helper_gvec_vfch64s_cc : gen_helper_gvec_vfch64_cc;
            break;
        case 0xea:
            fn = se ? gen_helper_gvec_vfche64s_cc : gen_helper_gvec_vfche64_cc;
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        switch (s->fields.op2) {
        case 0xe8:
            fn = se ? gen_helper_gvec_vfce64s : gen_helper_gvec_vfce64;
            break;
        case 0xeb:
            fn = se ? gen_helper_gvec_vfch64s : gen_helper_gvec_vfch64;
            break;
        case 0xea:
            fn = se ? gen_helper_gvec_vfche64s : gen_helper_gvec_vfche64;
            break;
        default:
            g_assert_not_reached();
        }
    }
    gen_gvec_3_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                   get_field(s, v3), tcg_ctx->cpu_env, 0, fn);
    if (cs) {
        set_cc_static(s);
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vcdg(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t fpf = get_field(s, m3);
    const uint8_t m4 = get_field(s, m4);
    const uint8_t erm = get_field(s, m5);
    const bool se = extract32(m4, 3, 1);
    gen_helper_gvec_2_ptr *fn;

    if (fpf != FPF_LONG || extract32(m4, 0, 2) || erm > 7 || erm == 2) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    switch (s->fields.op2) {
    case 0xc3:
        fn = se ? gen_helper_gvec_vcdg64s : gen_helper_gvec_vcdg64;
        break;
    case 0xc1:
        fn = se ? gen_helper_gvec_vcdlg64s : gen_helper_gvec_vcdlg64;
        break;
    case 0xc2:
        fn = se ? gen_helper_gvec_vcgd64s : gen_helper_gvec_vcgd64;
        break;
    case 0xc0:
        fn = se ? gen_helper_gvec_vclgd64s : gen_helper_gvec_vclgd64;
        break;
    case 0xc7:
        fn = se ? gen_helper_gvec_vfi64s : gen_helper_gvec_vfi64;
        break;
    case 0xc5:
        fn = se ? gen_helper_gvec_vflr64s : gen_helper_gvec_vflr64;
        break;
    default:
        g_assert_not_reached();
    }
    gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2), tcg_ctx->cpu_env,
                   deposit32(m4, 4, 4, erm), fn);
    return DISAS_NEXT;
}

static DisasJumpType op_vfll(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t fpf = get_field(s, m3);
    const uint8_t m4 = get_field(s, m4);
    gen_helper_gvec_2_ptr *fn = gen_helper_gvec_vfll32;

    if (fpf != FPF_SHORT || extract32(m4, 0, 3)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m4, 3, 1)) {
        fn = gen_helper_gvec_vfll32s;
    }
    gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2), tcg_ctx->cpu_env,
                   0, fn);
    return DISAS_NEXT;
}

static DisasJumpType op_vfma(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t m5 = get_field(s, m5);
    const uint8_t fpf = get_field(s, m6);
    const bool se = extract32(m5, 3, 1);
    gen_helper_gvec_4_ptr *fn;

    if (fpf != FPF_LONG || extract32(m5, 0, 3)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (s->fields.op2 == 0x8f) {
        fn = se ? gen_helper_gvec_vfma64s : gen_helper_gvec_vfma64;
    } else {
        fn = se ? gen_helper_gvec_vfms64s : gen_helper_gvec_vfms64;
    }
    gen_gvec_4_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2),
                   get_field(s, v3), get_field(s, v4), tcg_ctx->cpu_env,
                   0, fn);
    return DISAS_NEXT;
}

static DisasJumpType op_vfpso(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t v1 = get_field(s, v1);
    const uint8_t v2 = get_field(s, v2);
    const uint8_t fpf = get_field(s, m3);
    const uint8_t m4 = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    TCGv_i64 tmp;

    if (fpf != FPF_LONG || extract32(m4, 0, 3) || m5 > 2) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m4, 3, 1)) {
        tmp = tcg_temp_new_i64(tcg_ctx);
        read_vec_element_i64(tcg_ctx, tmp, v2, 0, ES_64);
        switch (m5) {
        case 0:
            /* sign bit is inverted (complement) */
            tcg_gen_xori_i64(tcg_ctx, tmp, tmp, 1ull << 63);
            break;
        case 1:
            /* sign bit is set to one (negative) */
            tcg_gen_ori_i64(tcg_ctx, tmp, tmp, 1ull << 63);
            break;
        case 2:
            /* sign bit is set to zero (positive) */
            tcg_gen_andi_i64(tcg_ctx, tmp, tmp, (1ull << 63) - 1);
            break;
        }
        write_vec_element_i64(tcg_ctx, tmp, v1, 0, ES_64);
        tcg_temp_free_i64(tcg_ctx, tmp);
    } else {
        switch (m5) {
        case 0:
            /* sign bit is inverted (complement) */
            gen_gvec_fn_2i(tcg_ctx, xori, ES_64, v1, v2, 1ull << 63);
            break;
        case 1:
            /* sign bit is set to one (negative) */
            gen_gvec_fn_2i(tcg_ctx, ori, ES_64, v1, v2, 1ull << 63);
            break;
        case 2:
            /* sign bit is set to zero (positive) */
            gen_gvec_fn_2i(tcg_ctx, andi, ES_64, v1, v2, (1ull << 63) - 1);
            break;
        }
    }
    return DISAS_NEXT;
}

static DisasJumpType op_vfsq(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint8_t fpf = get_field(s, m3);
    const uint8_t m4 = get_field(s, m4);
    gen_helper_gvec_2_ptr *fn = gen_helper_gvec_vfsq64;

    if (fpf != FPF_LONG || extract32(m4, 0, 3)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m4, 3, 1)) {
        fn = gen_helper_gvec_vfsq64s;
    }
    gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2), tcg_ctx->cpu_env,
                   0, fn);
    return DISAS_NEXT;
}

static DisasJumpType op_vftci(DisasContext *s, DisasOps *o)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    const uint16_t i3 = get_field(s, i3);
    const uint8_t fpf = get_field(s, m4);
    const uint8_t m5 = get_field(s, m5);
    gen_helper_gvec_2_ptr *fn = gen_helper_gvec_vftci64;

    if (fpf != FPF_LONG || extract32(m5, 0, 3)) {
        gen_program_exception(s, PGM_SPECIFICATION);
        return DISAS_NORETURN;
    }

    if (extract32(m5, 3, 1)) {
        fn = gen_helper_gvec_vftci64s;
    }
    gen_gvec_2_ptr(tcg_ctx, get_field(s, v1), get_field(s, v2), tcg_ctx->cpu_env, i3, fn);
    set_cc_static(s);
    return DISAS_NEXT;
}
