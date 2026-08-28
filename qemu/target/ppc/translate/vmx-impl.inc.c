/*
 * translate/vmx-impl.c
 *
 * Altivec/VMX translation
 */

/***                      Altivec vector extension                         ***/
/* Altivec registers moves */

static inline TCGv_ptr gen_avr_ptr(TCGContext *tcg_ctx, int reg)
{
    TCGv_ptr r = tcg_temp_new_ptr(tcg_ctx);
    tcg_gen_addi_ptr(tcg_ctx, r, tcg_ctx->cpu_env, avr_full_offset(reg));
    return r;
}

#define GEN_VR_LDX(name, opc2, opc3)                                          \
static void glue(gen_, name)(DisasContext *ctx)                               \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                                   \
    TCGv EA;                                                                  \
    TCGv_i64 avr;                                                             \
    if (unlikely(!ctx->altivec_enabled)) {                                    \
        gen_exception(ctx, POWERPC_EXCP_VPU);                                 \
        return;                                                               \
    }                                                                         \
    gen_set_access_type(ctx, ACCESS_INT);                                     \
    avr = tcg_temp_new_i64(tcg_ctx);                                          \
    EA = tcg_temp_new(tcg_ctx);                                                      \
    gen_addr_reg_index(ctx, EA);                                              \
    tcg_gen_andi_tl(tcg_ctx, EA, EA, ~0xf);                                            \
    /*                                                                        \
     * We only need to swap high and low halves. gen_qemu_ld64_i64            \
     * does necessary 64-bit byteswap already.                                \
     */                                                                       \
    if (ctx->le_mode) {                                                       \
        gen_qemu_ld64_i64(ctx, avr, EA);                                      \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, false);                               \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                                           \
        gen_qemu_ld64_i64(ctx, avr, EA);                                      \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, true);                                \
    } else {                                                                  \
        gen_qemu_ld64_i64(ctx, avr, EA);                                      \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, true);                                \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                                           \
        gen_qemu_ld64_i64(ctx, avr, EA);                                      \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, false);                               \
    }                                                                         \
    tcg_temp_free(tcg_ctx, EA);                                                        \
    tcg_temp_free_i64(tcg_ctx, avr);                                                   \
}

#define GEN_VR_STX(name, opc2, opc3)                                          \
static void gen_st##name(DisasContext *ctx)                                   \
{                                                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                                   \
    TCGv EA;                                                                  \
    TCGv_i64 avr;                                                             \
    if (unlikely(!ctx->altivec_enabled)) {                                    \
        gen_exception(ctx, POWERPC_EXCP_VPU);                                 \
        return;                                                               \
    }                                                                         \
    gen_set_access_type(ctx, ACCESS_INT);                                     \
    avr = tcg_temp_new_i64(tcg_ctx);                                          \
    EA = tcg_temp_new(tcg_ctx);                                                      \
    gen_addr_reg_index(ctx, EA);                                              \
    tcg_gen_andi_tl(tcg_ctx, EA, EA, ~0xf);                                            \
    /*                                                                        \
     * We only need to swap high and low halves. gen_qemu_st64_i64            \
     * does necessary 64-bit byteswap already.                                \
     */                                                                       \
    if (ctx->le_mode) {                                                       \
        get_avr64(tcg_ctx, avr, rD(ctx->opcode), false);                               \
        gen_qemu_st64_i64(ctx, avr, EA);                                      \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                                           \
        get_avr64(tcg_ctx, avr, rD(ctx->opcode), true);                                \
        gen_qemu_st64_i64(ctx, avr, EA);                                      \
    } else {                                                                  \
        get_avr64(tcg_ctx, avr, rD(ctx->opcode), true);                                \
        gen_qemu_st64_i64(ctx, avr, EA);                                      \
        tcg_gen_addi_tl(tcg_ctx, EA, EA, 8);                                           \
        get_avr64(tcg_ctx, avr, rD(ctx->opcode), false);                               \
        gen_qemu_st64_i64(ctx, avr, EA);                                      \
    }                                                                         \
    tcg_temp_free(tcg_ctx, EA);                                                        \
    tcg_temp_free_i64(tcg_ctx, avr);                                                   \
}

#define GEN_VR_LVE(name, opc2, opc3, size)                              \
static void gen_lve##name(DisasContext *ctx)                            \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv EA;                                                        \
        TCGv_ptr rs;                                                    \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        gen_set_access_type(ctx, ACCESS_INT);                           \
        EA = tcg_temp_new(tcg_ctx);                                            \
        gen_addr_reg_index(ctx, EA);                                    \
        if (size > 1) {                                                 \
            tcg_gen_andi_tl(tcg_ctx, EA, EA, ~(size - 1));                       \
        }                                                               \
        rs = gen_avr_ptr(tcg_ctx, rS(ctx->opcode));                     \
        gen_helper_lve##name(tcg_ctx, tcg_ctx->cpu_env, rs, EA);                 \
        tcg_temp_free(tcg_ctx, EA);                                              \
        tcg_temp_free_ptr(tcg_ctx, rs);                                          \
    }

#define GEN_VR_STVE(name, opc2, opc3, size)                             \
static void gen_stve##name(DisasContext *ctx)                           \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv EA;                                                        \
        TCGv_ptr rs;                                                    \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        gen_set_access_type(ctx, ACCESS_INT);                           \
        EA = tcg_temp_new(tcg_ctx);                                            \
        gen_addr_reg_index(ctx, EA);                                    \
        if (size > 1) {                                                 \
            tcg_gen_andi_tl(tcg_ctx, EA, EA, ~(size - 1));                       \
        }                                                               \
        rs = gen_avr_ptr(tcg_ctx, rS(ctx->opcode));                     \
        gen_helper_stve##name(tcg_ctx, tcg_ctx->cpu_env, rs, EA);                \
        tcg_temp_free(tcg_ctx, EA);                                              \
        tcg_temp_free_ptr(tcg_ctx, rs);                                          \
    }

GEN_VR_LDX(lvx, 0x07, 0x03);
/* As we don't emulate the cache, lvxl is stricly equivalent to lvx */
GEN_VR_LDX(lvxl, 0x07, 0x0B);

GEN_VR_LVE(bx, 0x07, 0x00, 1);
GEN_VR_LVE(hx, 0x07, 0x01, 2);
GEN_VR_LVE(wx, 0x07, 0x02, 4);

GEN_VR_STX(svx, 0x07, 0x07);
/* As we don't emulate the cache, stvxl is stricly equivalent to stvx */
GEN_VR_STX(svxl, 0x07, 0x0F);

GEN_VR_STVE(bx, 0x07, 0x04, 1);
GEN_VR_STVE(hx, 0x07, 0x05, 2);
GEN_VR_STVE(wx, 0x07, 0x06, 4);

static void gen_mfvscr(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 t;
    TCGv_i64 avr;
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }
    avr = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_movi_i64(tcg_ctx, avr, 0);
    set_avr64(tcg_ctx, rD(ctx->opcode), avr, true);
    t = tcg_temp_new_i32(tcg_ctx);
    gen_helper_mfvscr(tcg_ctx, t, tcg_ctx->cpu_env);
    tcg_gen_extu_i32_i64(tcg_ctx, avr, t);
    set_avr64(tcg_ctx, rD(ctx->opcode), avr, false);
    tcg_temp_free_i32(tcg_ctx, t);
    tcg_temp_free_i64(tcg_ctx, avr);
}

static void gen_mtvscr(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i32 val;
    int bofs;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    val = tcg_temp_new_i32(tcg_ctx);
    bofs = avr_full_offset(rB(ctx->opcode));
#ifdef HOST_WORDS_BIGENDIAN
    bofs += 3 * 4;
#endif

    tcg_gen_ld_i32(tcg_ctx, val, tcg_ctx->cpu_env, bofs);
    gen_helper_mtvscr(tcg_ctx, tcg_ctx->cpu_env, val);
    tcg_temp_free_i32(tcg_ctx, val);
}

#define GEN_VX_VMUL10(name, add_cin, ret_carry)                         \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    TCGv_i64 t0;                                                        \
    TCGv_i64 t1;                                                        \
    TCGv_i64 t2;                                                        \
    TCGv_i64 avr;                                                       \
    TCGv_i64 ten, z;                                                    \
                                                                        \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
                                                                        \
    t0 = tcg_temp_new_i64(tcg_ctx);                                     \
    t1 = tcg_temp_new_i64(tcg_ctx);                                     \
    t2 = tcg_temp_new_i64(tcg_ctx);                                     \
    avr = tcg_temp_new_i64(tcg_ctx);                                    \
    ten = tcg_const_i64(tcg_ctx, 10);                                   \
    z = tcg_const_i64(tcg_ctx, 0);                                      \
                                                                        \
    if (add_cin) {                                                      \
        get_avr64(tcg_ctx, avr, rA(ctx->opcode), false);                \
        tcg_gen_mulu2_i64(tcg_ctx, t0, t1, avr, ten);                            \
        get_avr64(tcg_ctx, avr, rB(ctx->opcode), false);                \
        tcg_gen_andi_i64(tcg_ctx, t2, avr, 0xF);                                 \
        tcg_gen_add2_i64(tcg_ctx, avr, t2, t0, t1, t2, z);                       \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, false);                \
    } else {                                                            \
        get_avr64(tcg_ctx, avr, rA(ctx->opcode), false);                \
        tcg_gen_mulu2_i64(tcg_ctx, avr, t2, avr, ten);                           \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, false);                \
    }                                                                   \
                                                                        \
    if (ret_carry) {                                                    \
        get_avr64(tcg_ctx, avr, rA(ctx->opcode), true);                 \
        tcg_gen_mulu2_i64(tcg_ctx, t0, t1, avr, ten);                            \
        tcg_gen_add2_i64(tcg_ctx, t0, avr, t0, t1, t2, z);                       \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, false);                \
        set_avr64(tcg_ctx, rD(ctx->opcode), z, true);                   \
    } else {                                                            \
        get_avr64(tcg_ctx, avr, rA(ctx->opcode), true);                 \
        tcg_gen_mul_i64(tcg_ctx, t0, avr, ten);                                  \
        tcg_gen_add_i64(tcg_ctx, avr, t0, t2);                                   \
        set_avr64(tcg_ctx, rD(ctx->opcode), avr, true);                 \
    }                                                                   \
                                                                        \
    tcg_temp_free_i64(tcg_ctx, t0);                                     \
    tcg_temp_free_i64(tcg_ctx, t1);                                     \
    tcg_temp_free_i64(tcg_ctx, t2);                                     \
    tcg_temp_free_i64(tcg_ctx, avr);                                    \
    tcg_temp_free_i64(tcg_ctx, ten);                                    \
    tcg_temp_free_i64(tcg_ctx, z);                                      \
}                                                                       \

GEN_VX_VMUL10(vmul10uq, 0, 0);
GEN_VX_VMUL10(vmul10euq, 1, 0);
GEN_VX_VMUL10(vmul10cuq, 0, 1);
GEN_VX_VMUL10(vmul10ecuq, 1, 1);

#define GEN_VXFORM_V(name, vece, tcg_op, opc2, opc3)                    \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
                                                                        \
    tcg_op(tcg_ctx, vece,                                               \
           avr_full_offset(rD(ctx->opcode)),                            \
           avr_full_offset(rA(ctx->opcode)),                            \
           avr_full_offset(rB(ctx->opcode)),                            \
           16, 16);                                                     \
}

/* Logical operations */
GEN_VXFORM_V(vand, MO_64, tcg_gen_gvec_and, 2, 16);
GEN_VXFORM_V(vandc, MO_64, tcg_gen_gvec_andc, 2, 17);
GEN_VXFORM_V(vor, MO_64, tcg_gen_gvec_or, 2, 18);
GEN_VXFORM_V(vxor, MO_64, tcg_gen_gvec_xor, 2, 19);
GEN_VXFORM_V(vnor, MO_64, tcg_gen_gvec_nor, 2, 20);
GEN_VXFORM_V(veqv, MO_64, tcg_gen_gvec_eqv, 2, 26);
GEN_VXFORM_V(vnand, MO_64, tcg_gen_gvec_nand, 2, 22);
GEN_VXFORM_V(vorc, MO_64, tcg_gen_gvec_orc, 2, 21);

#define GEN_VXFORM(name, opc2, opc3)                                    \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    TCGv_ptr ra, rb, rd;                                                \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));                         \
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                         \
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                         \
    gen_helper_##name(tcg_ctx, rd, ra, rb);                             \
    tcg_temp_free_ptr(tcg_ctx, ra);                                     \
    tcg_temp_free_ptr(tcg_ctx, rb);                                     \
    tcg_temp_free_ptr(tcg_ctx, rd);                                     \
}

#define GEN_VXFORM_TRANS(name, opc2, opc3)                              \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
    trans_##name(ctx);                                                  \
}

#define GEN_VXFORM_ENV(name, opc2, opc3)                                \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    TCGv_ptr ra, rb, rd;                                                \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));                         \
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                         \
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                         \
    gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rd, ra, rb);           \
    tcg_temp_free_ptr(tcg_ctx, ra);                                     \
    tcg_temp_free_ptr(tcg_ctx, rb);                                     \
    tcg_temp_free_ptr(tcg_ctx, rd);                                     \
}

#define GEN_VXFORM3(name, opc2, opc3)                                   \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    TCGv_ptr ra, rb, rc, rd;                                            \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));                         \
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                         \
    rc = gen_avr_ptr(tcg_ctx, rC(ctx->opcode));                         \
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                         \
    gen_helper_##name(tcg_ctx, rd, ra, rb, rc);                         \
    tcg_temp_free_ptr(tcg_ctx, ra);                                     \
    tcg_temp_free_ptr(tcg_ctx, rb);                                     \
    tcg_temp_free_ptr(tcg_ctx, rc);                                     \
    tcg_temp_free_ptr(tcg_ctx, rd);                                     \
}

/*
 * Support for Altivec instruction pairs that use bit 31 (Rc) as
 * an opcode bit.  In general, these pairs come from different
 * versions of the ISA, so we must also support a pair of flags for
 * each instruction.
 */
#define GEN_VXFORM_DUAL(name0, flg0, flg2_0, name1, flg1, flg2_1)      \
static void glue(gen_, name0##_##name1)(DisasContext *ctx)             \
{                                                                      \
    if ((Rc(ctx->opcode) == 0) &&                                      \
        ((ctx->insns_flags & flg0) || (ctx->insns_flags2 & flg2_0))) { \
        gen_##name0(ctx);                                              \
    } else if ((Rc(ctx->opcode) == 1) &&                               \
        ((ctx->insns_flags & flg1) || (ctx->insns_flags2 & flg2_1))) { \
        gen_##name1(ctx);                                              \
    } else {                                                           \
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);            \
    }                                                                  \
}

/*
 * We use this macro if one instruction is realized with direct
 * translation, and second one with helper.
 */
#define GEN_VXFORM_TRANS_DUAL(name0, flg0, flg2_0, name1, flg1, flg2_1)\
static void glue(gen_, name0##_##name1)(DisasContext *ctx)             \
{                                                                      \
    if ((Rc(ctx->opcode) == 0) &&                                      \
        ((ctx->insns_flags & flg0) || (ctx->insns_flags2 & flg2_0))) { \
        if (unlikely(!ctx->altivec_enabled)) {                         \
            gen_exception(ctx, POWERPC_EXCP_VPU);                      \
            return;                                                    \
        }                                                              \
        trans_##name0(ctx);                                            \
    } else if ((Rc(ctx->opcode) == 1) &&                               \
        ((ctx->insns_flags & flg1) || (ctx->insns_flags2 & flg2_1))) { \
        gen_##name1(ctx);                                              \
    } else {                                                           \
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);            \
    }                                                                  \
}

/* Adds support to provide invalid mask */
#define GEN_VXFORM_DUAL_EXT(name0, flg0, flg2_0, inval0,                \
                            name1, flg1, flg2_1, inval1)                \
static void glue(gen_, name0##_##name1)(DisasContext *ctx)              \
{                                                                       \
    if ((Rc(ctx->opcode) == 0) &&                                       \
        ((ctx->insns_flags & flg0) || (ctx->insns_flags2 & flg2_0)) &&  \
        !(ctx->opcode & inval0)) {                                      \
        gen_##name0(ctx);                                               \
    } else if ((Rc(ctx->opcode) == 1) &&                                \
               ((ctx->insns_flags & flg1) || (ctx->insns_flags2 & flg2_1)) && \
               !(ctx->opcode & inval1)) {                               \
        gen_##name1(ctx);                                               \
    } else {                                                            \
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);             \
    }                                                                   \
}

#define GEN_VXFORM_HETRO(name, opc2, opc3)                              \
static void glue(gen_, name)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    TCGv_ptr rb;                                                        \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                         \
    gen_helper_##name(tcg_ctx, cpu_gpr[rD(ctx->opcode)], cpu_gpr[rA(ctx->opcode)], rb); \
    tcg_temp_free_ptr(tcg_ctx, rb);                                     \
}

GEN_VXFORM_V(vaddubm, MO_8, tcg_gen_gvec_add, 0, 0);
GEN_VXFORM_DUAL_EXT(vaddubm, PPC_ALTIVEC, PPC_NONE, 0,       \
                    vmul10cuq, PPC_NONE, PPC2_ISA300, 0x0000F800)
GEN_VXFORM_V(vadduhm, MO_16, tcg_gen_gvec_add, 0, 1);
GEN_VXFORM_DUAL(vadduhm, PPC_ALTIVEC, PPC_NONE,  \
                vmul10ecuq, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_V(vadduwm, MO_32, tcg_gen_gvec_add, 0, 2);
GEN_VXFORM_V(vaddudm, MO_64, tcg_gen_gvec_add, 0, 3);
GEN_VXFORM_V(vsububm, MO_8, tcg_gen_gvec_sub, 0, 16);
GEN_VXFORM_V(vsubuhm, MO_16, tcg_gen_gvec_sub, 0, 17);
GEN_VXFORM_V(vsubuwm, MO_32, tcg_gen_gvec_sub, 0, 18);
GEN_VXFORM_V(vsubudm, MO_64, tcg_gen_gvec_sub, 0, 19);
GEN_VXFORM_V(vmaxub, MO_8, tcg_gen_gvec_umax, 1, 0);
GEN_VXFORM_V(vmaxuh, MO_16, tcg_gen_gvec_umax, 1, 1);
GEN_VXFORM_V(vmaxuw, MO_32, tcg_gen_gvec_umax, 1, 2);
GEN_VXFORM_V(vmaxud, MO_64, tcg_gen_gvec_umax, 1, 3);
GEN_VXFORM_V(vmaxsb, MO_8, tcg_gen_gvec_smax, 1, 4);
GEN_VXFORM_V(vmaxsh, MO_16, tcg_gen_gvec_smax, 1, 5);
GEN_VXFORM_V(vmaxsw, MO_32, tcg_gen_gvec_smax, 1, 6);
GEN_VXFORM_V(vmaxsd, MO_64, tcg_gen_gvec_smax, 1, 7);
GEN_VXFORM_V(vminub, MO_8, tcg_gen_gvec_umin, 1, 8);
GEN_VXFORM_V(vminuh, MO_16, tcg_gen_gvec_umin, 1, 9);
GEN_VXFORM_V(vminuw, MO_32, tcg_gen_gvec_umin, 1, 10);
GEN_VXFORM_V(vminud, MO_64, tcg_gen_gvec_umin, 1, 11);
GEN_VXFORM_V(vminsb, MO_8, tcg_gen_gvec_smin, 1, 12);
GEN_VXFORM_V(vminsh, MO_16, tcg_gen_gvec_smin, 1, 13);
GEN_VXFORM_V(vminsw, MO_32, tcg_gen_gvec_smin, 1, 14);
GEN_VXFORM_V(vminsd, MO_64, tcg_gen_gvec_smin, 1, 15);
GEN_VXFORM(vavgub, 1, 16);
GEN_VXFORM(vabsdub, 1, 16);
GEN_VXFORM_DUAL(vavgub, PPC_ALTIVEC, PPC_NONE, \
                vabsdub, PPC_NONE, PPC2_ISA300)
GEN_VXFORM(vavguh, 1, 17);
GEN_VXFORM(vabsduh, 1, 17);
GEN_VXFORM_DUAL(vavguh, PPC_ALTIVEC, PPC_NONE, \
                vabsduh, PPC_NONE, PPC2_ISA300)
GEN_VXFORM(vavguw, 1, 18);
GEN_VXFORM(vabsduw, 1, 18);
GEN_VXFORM_DUAL(vavguw, PPC_ALTIVEC, PPC_NONE, \
                vabsduw, PPC_NONE, PPC2_ISA300)
GEN_VXFORM(vavgsb, 1, 20);
GEN_VXFORM(vavgsh, 1, 21);
GEN_VXFORM(vavgsw, 1, 22);
GEN_VXFORM(vmrghb, 6, 0);
GEN_VXFORM(vmrghh, 6, 1);
GEN_VXFORM(vmrghw, 6, 2);
GEN_VXFORM(vmrglb, 6, 4);
GEN_VXFORM(vmrglh, 6, 5);
GEN_VXFORM(vmrglw, 6, 6);

static void trans_vmrgew(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VA = rA(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 avr = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, avr, VB, true);
    tcg_gen_shri_i64(tcg_ctx, tmp, avr, 32);
    get_avr64(tcg_ctx, avr, VA, true);
    tcg_gen_deposit_i64(tcg_ctx, avr, avr, tmp, 0, 32);
    set_avr64(tcg_ctx, VT, avr, true);

    get_avr64(tcg_ctx, avr, VB, false);
    tcg_gen_shri_i64(tcg_ctx, tmp, avr, 32);
    get_avr64(tcg_ctx, avr, VA, false);
    tcg_gen_deposit_i64(tcg_ctx, avr, avr, tmp, 0, 32);
    set_avr64(tcg_ctx, VT, avr, false);

    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, avr);
}

static void trans_vmrgow(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VA = rA(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 avr = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, t0, VB, true);
    get_avr64(tcg_ctx, t1, VA, true);
    tcg_gen_deposit_i64(tcg_ctx, avr, t0, t1, 32, 32);
    set_avr64(tcg_ctx, VT, avr, true);

    get_avr64(tcg_ctx, t0, VB, false);
    get_avr64(tcg_ctx, t1, VA, false);
    tcg_gen_deposit_i64(tcg_ctx, avr, t0, t1, 32, 32);
    set_avr64(tcg_ctx, VT, avr, false);

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, avr);
}

/*
 * lvsl VRT,RA,RB - Load Vector for Shift Left
 *
 * Let the EA be the sum (rA|0)+(rB). Let sh=EA[28-31].
 * Let X be the 32-byte value 0x00 || 0x01 || 0x02 || ... || 0x1E || 0x1F.
 * Bytes sh:sh+15 of X are placed into vD.
 */
static void trans_lvsl(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    TCGv_i64 result = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sh = tcg_temp_new_i64(tcg_ctx);
    TCGv EA = tcg_temp_new(tcg_ctx);

    /* Get sh(from description) by anding EA with 0xf. */
    gen_addr_reg_index(ctx, EA);
    tcg_gen_extu_tl_i64(tcg_ctx, sh, EA);
    tcg_gen_andi_i64(tcg_ctx, sh, sh, 0xfULL);

    /*
     * Create bytes sh:sh+7 of X(from description) and place them in
     * higher doubleword of vD.
     */
    tcg_gen_muli_i64(tcg_ctx, sh, sh, 0x0101010101010101ULL);
    tcg_gen_addi_i64(tcg_ctx, result, sh, 0x0001020304050607ull);
    set_avr64(tcg_ctx, VT, result, true);
    /*
     * Create bytes sh+8:sh+15 of X(from description) and place them in
     * lower doubleword of vD.
     */
    tcg_gen_addi_i64(tcg_ctx, result, sh, 0x08090a0b0c0d0e0fULL);
    set_avr64(tcg_ctx, VT, result, false);

    tcg_temp_free_i64(tcg_ctx, result);
    tcg_temp_free_i64(tcg_ctx, sh);
    tcg_temp_free(tcg_ctx, EA);
}

/*
 * lvsr VRT,RA,RB - Load Vector for Shift Right
 *
 * Let the EA be the sum (rA|0)+(rB). Let sh=EA[28-31].
 * Let X be the 32-byte value 0x00 || 0x01 || 0x02 || ... || 0x1E || 0x1F.
 * Bytes (16-sh):(31-sh) of X are placed into vD.
 */
static void trans_lvsr(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    TCGv_i64 result = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sh = tcg_temp_new_i64(tcg_ctx);
    TCGv EA = tcg_temp_new(tcg_ctx);


    /* Get sh(from description) by anding EA with 0xf. */
    gen_addr_reg_index(ctx, EA);
    tcg_gen_extu_tl_i64(tcg_ctx, sh, EA);
    tcg_gen_andi_i64(tcg_ctx, sh, sh, 0xfULL);

    /*
     * Create bytes (16-sh):(23-sh) of X(from description) and place them in
     * higher doubleword of vD.
     */
    tcg_gen_muli_i64(tcg_ctx, sh, sh, 0x0101010101010101ULL);
    tcg_gen_subfi_i64(tcg_ctx, result, 0x1011121314151617ULL, sh);
    set_avr64(tcg_ctx, VT, result, true);
    /*
     * Create bytes (24-sh):(32-sh) of X(from description) and place them in
     * lower doubleword of vD.
     */
    tcg_gen_subfi_i64(tcg_ctx, result, 0x18191a1b1c1d1e1fULL, sh);
    set_avr64(tcg_ctx, VT, result, false);

    tcg_temp_free_i64(tcg_ctx, result);
    tcg_temp_free_i64(tcg_ctx, sh);
    tcg_temp_free(tcg_ctx, EA);
}

/*
 * vsl VRT,VRA,VRB - Vector Shift Left
 *
 * Shifting left 128 bit value of vA by value specified in bits 125-127 of vB.
 * Lowest 3 bits in each byte element of register vB must be identical or
 * result is undefined.
 */
static void trans_vsl(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VA = rA(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i64 avr = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sh = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 carry = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);

    /* Place bits 125-127 of vB in 'sh'. */
    get_avr64(tcg_ctx, avr, VB, false);
    tcg_gen_andi_i64(tcg_ctx, sh, avr, 0x07ULL);

    /*
     * Save highest 'sh' bits of lower doubleword element of vA in variable
     * 'carry' and perform shift on lower doubleword.
     */
    get_avr64(tcg_ctx, avr, VA, false);
    tcg_gen_subfi_i64(tcg_ctx, tmp, 32, sh);
    tcg_gen_shri_i64(tcg_ctx, carry, avr, 32);
    tcg_gen_shr_i64(tcg_ctx, carry, carry, tmp);
    tcg_gen_shl_i64(tcg_ctx, avr, avr, sh);
    set_avr64(tcg_ctx, VT, avr, false);

    /*
     * Perform shift on higher doubleword element of vA and replace lowest
     * 'sh' bits with 'carry'.
     */
    get_avr64(tcg_ctx, avr, VA, true);
    tcg_gen_shl_i64(tcg_ctx, avr, avr, sh);
    tcg_gen_or_i64(tcg_ctx, avr, avr, carry);
    set_avr64(tcg_ctx, VT, avr, true);

    tcg_temp_free_i64(tcg_ctx, avr);
    tcg_temp_free_i64(tcg_ctx, sh);
    tcg_temp_free_i64(tcg_ctx, carry);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

/*
 * vsr VRT,VRA,VRB - Vector Shift Right
 *
 * Shifting right 128 bit value of vA by value specified in bits 125-127 of vB.
 * Lowest 3 bits in each byte element of register vB must be identical or
 * result is undefined.
 */
static void trans_vsr(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VA = rA(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i64 avr = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 sh = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 carry = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);

    /* Place bits 125-127 of vB in 'sh'. */
    get_avr64(tcg_ctx, avr, VB, false);
    tcg_gen_andi_i64(tcg_ctx, sh, avr, 0x07ULL);

    /*
     * Save lowest 'sh' bits of higher doubleword element of vA in variable
     * 'carry' and perform shift on higher doubleword.
     */
    get_avr64(tcg_ctx, avr, VA, true);
    tcg_gen_subfi_i64(tcg_ctx, tmp, 32, sh);
    tcg_gen_shli_i64(tcg_ctx, carry, avr, 32);
    tcg_gen_shl_i64(tcg_ctx, carry, carry, tmp);
    tcg_gen_shr_i64(tcg_ctx, avr, avr, sh);
    set_avr64(tcg_ctx, VT, avr, true);
    /*
     * Perform shift on lower doubleword element of vA and replace highest
     * 'sh' bits with 'carry'.
     */
    get_avr64(tcg_ctx, avr, VA, false);
    tcg_gen_shr_i64(tcg_ctx, avr, avr, sh);
    tcg_gen_or_i64(tcg_ctx, avr, avr, carry);
    set_avr64(tcg_ctx, VT, avr, false);

    tcg_temp_free_i64(tcg_ctx, avr);
    tcg_temp_free_i64(tcg_ctx, sh);
    tcg_temp_free_i64(tcg_ctx, carry);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

/*
 * vgbbd VRT,VRB - Vector Gather Bits by Bytes by Doubleword
 *
 * All ith bits (i in range 1 to 8) of each byte of doubleword element in source
 * register are concatenated and placed into ith byte of appropriate doubleword
 * element in destination register.
 *
 * Following solution is done for both doubleword elements of source register
 * in parallel, in order to reduce the number of instructions needed(that's why
 * arrays are used):
 * First, both doubleword elements of source register vB are placed in
 * appropriate element of array avr. Bits are gathered in 2x8 iterations(2 for
 * loops). In first iteration bit 1 of byte 1, bit 2 of byte 2,... bit 8 of
 * byte 8 are in their final spots so avr[i], i={0,1} can be and-ed with
 * tcg_mask. For every following iteration, both avr[i] and tcg_mask variables
 * have to be shifted right for 7 and 8 places, respectively, in order to get
 * bit 1 of byte 2, bit 2 of byte 3.. bit 7 of byte 8 in their final spots so
 * shifted avr values(saved in tmp) can be and-ed with new value of tcg_mask...
 * After first 8 iteration(first loop), all the first bits are in their final
 * places, all second bits but second bit from eight byte are in their places...
 * only 1 eight bit from eight byte is in it's place). In second loop we do all
 * operations symmetrically, in order to get other half of bits in their final
 * spots. Results for first and second doubleword elements are saved in
 * result[0] and result[1] respectively. In the end those results are saved in
 * appropriate doubleword element of destination register vD.
 */
static void trans_vgbbd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);
    uint64_t mask = 0x8040201008040201ULL;
    int i, j;

    TCGv_i64 result[2];
    result[0] = tcg_temp_new_i64(tcg_ctx);
    result[1] = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 avr[2];
    avr[0] = tcg_temp_new_i64(tcg_ctx);
    avr[1] = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tcg_mask = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_movi_i64(tcg_ctx, tcg_mask, mask);
    for (j = 0; j < 2; j++) {
        get_avr64(tcg_ctx, avr[j], VB, j);
        tcg_gen_and_i64(tcg_ctx, result[j], avr[j], tcg_mask);
    }
    for (i = 1; i < 8; i++) {
        tcg_gen_movi_i64(tcg_ctx, tcg_mask, mask >> (i * 8));
        for (j = 0; j < 2; j++) {
            tcg_gen_shri_i64(tcg_ctx, tmp, avr[j], i * 7);
            tcg_gen_and_i64(tcg_ctx, tmp, tmp, tcg_mask);
            tcg_gen_or_i64(tcg_ctx, result[j], result[j], tmp);
        }
    }
    for (i = 1; i < 8; i++) {
        tcg_gen_movi_i64(tcg_ctx, tcg_mask, mask << (i * 8));
        for (j = 0; j < 2; j++) {
            tcg_gen_shli_i64(tcg_ctx, tmp, avr[j], i * 7);
            tcg_gen_and_i64(tcg_ctx, tmp, tmp, tcg_mask);
            tcg_gen_or_i64(tcg_ctx, result[j], result[j], tmp);
        }
    }
    for (j = 0; j < 2; j++) {
        set_avr64(tcg_ctx, VT, result[j], j);
    }

    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, tcg_mask);
    tcg_temp_free_i64(tcg_ctx, result[0]);
    tcg_temp_free_i64(tcg_ctx, result[1]);
    tcg_temp_free_i64(tcg_ctx, avr[0]);
    tcg_temp_free_i64(tcg_ctx, avr[1]);
}

/*
 * vclzw VRT,VRB - Vector Count Leading Zeros Word
 *
 * Counting the number of leading zero bits of each word element in source
 * register and placing result in appropriate word element of destination
 * register.
 */
static void trans_vclzw(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i32 tmp = tcg_temp_new_i32(tcg_ctx);
    int i;

    /* Perform count for every word element using tcg_gen_clzi_i32. */
    for (i = 0; i < 4; i++) {
        tcg_gen_ld_i32(tcg_ctx, tmp, tcg_ctx->cpu_env,
            offsetof(CPUPPCState, vsr[32 + VB].u64[0]) + i * 4);
        tcg_gen_clzi_i32(tcg_ctx, tmp, tmp, 32);
        tcg_gen_st_i32(tcg_ctx, tmp, tcg_ctx->cpu_env,
            offsetof(CPUPPCState, vsr[32 + VT].u64[0]) + i * 4);
    }

    tcg_temp_free_i32(tcg_ctx, tmp);
}

/*
 * vclzd VRT,VRB - Vector Count Leading Zeros Doubleword
 *
 * Counting the number of leading zero bits of each doubleword element in source
 * register and placing result in appropriate doubleword element of destination
 * register.
 */
static void trans_vclzd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int VT = rD(ctx->opcode);
    int VB = rB(ctx->opcode);
    TCGv_i64 avr = tcg_temp_new_i64(tcg_ctx);

    /* high doubleword */
    get_avr64(tcg_ctx, avr, VB, true);
    tcg_gen_clzi_i64(tcg_ctx, avr, avr, 64);
    set_avr64(tcg_ctx, VT, avr, true);

    /* low doubleword */
    get_avr64(tcg_ctx, avr, VB, false);
    tcg_gen_clzi_i64(tcg_ctx, avr, avr, 64);
    set_avr64(tcg_ctx, VT, avr, false);

    tcg_temp_free_i64(tcg_ctx, avr);
}

GEN_VXFORM(vmuloub, 4, 0);
GEN_VXFORM(vmulouh, 4, 1);
GEN_VXFORM(vmulouw, 4, 2);
GEN_VXFORM(vmuluwm, 4, 2);
GEN_VXFORM_DUAL(vmulouw, PPC_ALTIVEC, PPC_NONE,
                vmuluwm, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM(vmulosb, 4, 4);
GEN_VXFORM(vmulosh, 4, 5);
GEN_VXFORM(vmulosw, 4, 6);
GEN_VXFORM(vmuleub, 4, 8);
GEN_VXFORM(vmuleuh, 4, 9);
GEN_VXFORM(vmuleuw, 4, 10);
GEN_VXFORM(vmulesb, 4, 12);
GEN_VXFORM(vmulesh, 4, 13);
GEN_VXFORM(vmulesw, 4, 14);

static void gen_vmuleo_dword(DisasContext *ctx, bool even, bool sign)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 vra;
    TCGv_i64 vrb;
    TCGv_i64 lo;
    TCGv_i64 hi;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    vra = tcg_temp_new_i64(tcg_ctx);
    vrb = tcg_temp_new_i64(tcg_ctx);
    lo = tcg_temp_new_i64(tcg_ctx);
    hi = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, vra, rA(ctx->opcode), even);
    get_avr64(tcg_ctx, vrb, rB(ctx->opcode), even);
    if (sign) {
        tcg_gen_muls2_i64(tcg_ctx, lo, hi, vra, vrb);
    } else {
        tcg_gen_mulu2_i64(tcg_ctx, lo, hi, vra, vrb);
    }
    set_avr64(tcg_ctx, rD(ctx->opcode), lo, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), hi, true);

    tcg_temp_free_i64(tcg_ctx, vra);
    tcg_temp_free_i64(tcg_ctx, vrb);
    tcg_temp_free_i64(tcg_ctx, lo);
    tcg_temp_free_i64(tcg_ctx, hi);
}

static void gen_vmulesd(DisasContext *ctx)
{
    gen_vmuleo_dword(ctx, true, true);
}

static void gen_vmulosd(DisasContext *ctx)
{
    gen_vmuleo_dword(ctx, false, true);
}

static void gen_vmuleud(DisasContext *ctx)
{
    gen_vmuleo_dword(ctx, true, false);
}

static void gen_vmuloud(DisasContext *ctx)
{
    gen_vmuleo_dword(ctx, false, false);
}

static void gen_vmulld(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tcg_gen_gvec_mul(tcg_ctx, MO_64, avr_full_offset(rD(ctx->opcode)),
                     avr_full_offset(rA(ctx->opcode)),
                     avr_full_offset(rB(ctx->opcode)), 16, 16);
}

static void gen_vmulhw_i64(TCGContext *tcg_ctx, TCGv_i64 t, TCGv_i64 a,
                           TCGv_i64 b, bool sign)
{
    TCGv_i64 hh = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 lh = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tmp = tcg_temp_new_i64(tcg_ctx);

    if (sign) {
        tcg_gen_ext32s_i64(tcg_ctx, lh, a);
        tcg_gen_ext32s_i64(tcg_ctx, tmp, b);
    } else {
        tcg_gen_ext32u_i64(tcg_ctx, lh, a);
        tcg_gen_ext32u_i64(tcg_ctx, tmp, b);
    }
    tcg_gen_mul_i64(tcg_ctx, lh, lh, tmp);

    if (sign) {
        tcg_gen_sari_i64(tcg_ctx, hh, a, 32);
        tcg_gen_sari_i64(tcg_ctx, tmp, b, 32);
    } else {
        tcg_gen_shri_i64(tcg_ctx, hh, a, 32);
        tcg_gen_shri_i64(tcg_ctx, tmp, b, 32);
    }
    tcg_gen_mul_i64(tcg_ctx, hh, hh, tmp);

    tcg_gen_shri_i64(tcg_ctx, lh, lh, 32);
    tcg_gen_deposit_i64(tcg_ctx, t, hh, lh, 0, 32);

    tcg_temp_free_i64(tcg_ctx, hh);
    tcg_temp_free_i64(tcg_ctx, lh);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

static void gen_vmulhd_i64(TCGContext *tcg_ctx, TCGv_i64 t, TCGv_i64 a,
                           TCGv_i64 b, bool sign)
{
    TCGv_i64 lo = tcg_temp_new_i64(tcg_ctx);

    if (sign) {
        tcg_gen_muls2_i64(tcg_ctx, lo, t, a, b);
    } else {
        tcg_gen_mulu2_i64(tcg_ctx, lo, t, a, b);
    }

    tcg_temp_free_i64(tcg_ctx, lo);
}

static void gen_vmulh(DisasContext *ctx, bool sign, bool dword)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 vra;
    TCGv_i64 vrb;
    TCGv_i64 vrt;
    int i;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    vra = tcg_temp_new_i64(tcg_ctx);
    vrb = tcg_temp_new_i64(tcg_ctx);
    vrt = tcg_temp_new_i64(tcg_ctx);

    for (i = 0; i < 2; i++) {
        get_avr64(tcg_ctx, vra, rA(ctx->opcode), i);
        get_avr64(tcg_ctx, vrb, rB(ctx->opcode), i);
        if (dword) {
            gen_vmulhd_i64(tcg_ctx, vrt, vra, vrb, sign);
        } else {
            gen_vmulhw_i64(tcg_ctx, vrt, vra, vrb, sign);
        }
        set_avr64(tcg_ctx, rD(ctx->opcode), vrt, i);
    }

    tcg_temp_free_i64(tcg_ctx, vra);
    tcg_temp_free_i64(tcg_ctx, vrb);
    tcg_temp_free_i64(tcg_ctx, vrt);
}

static void gen_vmulhsw(DisasContext *ctx)
{
    gen_vmulh(ctx, true, false);
}

static void gen_vmulhuw(DisasContext *ctx)
{
    gen_vmulh(ctx, false, false);
}

static void gen_vmulhsd(DisasContext *ctx)
{
    gen_vmulh(ctx, true, true);
}

static void gen_vmulhud(DisasContext *ctx)
{
    gen_vmulh(ctx, false, true);
}

GEN_VXFORM_DUAL(vmuleuw, PPC_NONE, PPC2_ALTIVEC_207, \
                vmulhuw, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vmulesw, PPC_NONE, PPC2_ALTIVEC_207, \
                vmulhsw, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vmulosd, PPC_NONE, PPC2_ISA310, \
                vmulld, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vmuleud, PPC_NONE, PPC2_ISA310, \
                vmulhud, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vmulesd, PPC_NONE, PPC2_ISA310, \
                vmulhsd, PPC_NONE, PPC2_ISA310)

static void gen_vector_shift_quad(DisasContext *ctx, bool right, bool alg)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 hi;
    TCGv_i64 lo;
    TCGv_i64 t0;
    TCGv_i64 t1;
    TCGv_i64 n;
    TCGv_i64 zero;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    hi = tcg_temp_new_i64(tcg_ctx);
    lo = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    n = tcg_temp_new_i64(tcg_ctx);
    zero = tcg_const_i64(tcg_ctx, 0);

    get_avr64(tcg_ctx, lo, rA(ctx->opcode), false);
    get_avr64(tcg_ctx, hi, rA(ctx->opcode), true);
    get_avr64(tcg_ctx, n, rB(ctx->opcode), true);

    tcg_gen_andi_i64(tcg_ctx, t0, n, 64);
    if (right) {
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, lo, t0, zero, hi, lo);
        tcg_gen_movi_i64(tcg_ctx, t1, 0);
        if (alg) {
            tcg_gen_sari_i64(tcg_ctx, t1, lo, 63);
        }
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, hi, t0, zero, t1, hi);
    } else {
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, hi, t0, zero, lo, hi);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, lo, t0, zero, zero, lo);
    }
    tcg_gen_andi_i64(tcg_ctx, n, n, 0x3f);

    if (right) {
        if (alg) {
            tcg_gen_sar_i64(tcg_ctx, t0, hi, n);
        } else {
            tcg_gen_shr_i64(tcg_ctx, t0, hi, n);
        }
    } else {
        tcg_gen_shl_i64(tcg_ctx, t0, lo, n);
    }
    set_avr64(tcg_ctx, rD(ctx->opcode), t0, right);

    if (right) {
        tcg_gen_shr_i64(tcg_ctx, lo, lo, n);
    } else {
        tcg_gen_shl_i64(tcg_ctx, hi, hi, n);
    }
    tcg_gen_xori_i64(tcg_ctx, n, n, 63);
    if (right) {
        tcg_gen_shl_i64(tcg_ctx, hi, hi, n);
        tcg_gen_shli_i64(tcg_ctx, hi, hi, 1);
    } else {
        tcg_gen_shr_i64(tcg_ctx, lo, lo, n);
        tcg_gen_shri_i64(tcg_ctx, lo, lo, 1);
    }
    tcg_gen_or_i64(tcg_ctx, hi, hi, lo);
    set_avr64(tcg_ctx, rD(ctx->opcode), hi, !right);

    tcg_temp_free_i64(tcg_ctx, hi);
    tcg_temp_free_i64(tcg_ctx, lo);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, n);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static void gen_vrlq_mask(TCGContext *tcg_ctx, TCGv_i64 mh, TCGv_i64 ml,
                          TCGv_i64 b, TCGv_i64 e)
{
    TCGv_i64 th = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 tl = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);
    TCGv_i64 ones = tcg_const_i64(tcg_ctx, -1);

    tcg_gen_andi_i64(tcg_ctx, t0, b, 64);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, t1, t0, zero, zero, ones);
    tcg_gen_andi_i64(tcg_ctx, t0, b, 0x3f);
    tcg_gen_shr_i64(tcg_ctx, mh, t1, t0);
    tcg_gen_shr_i64(tcg_ctx, ml, ones, t0);
    tcg_gen_xori_i64(tcg_ctx, t0, t0, 63);
    tcg_gen_shl_i64(tcg_ctx, t1, t1, t0);
    tcg_gen_shli_i64(tcg_ctx, t1, t1, 1);
    tcg_gen_or_i64(tcg_ctx, ml, t1, ml);

    tcg_gen_andi_i64(tcg_ctx, t0, e, 64);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, t1, t0, zero, zero, ones);
    tcg_gen_andi_i64(tcg_ctx, t0, e, 0x3f);
    tcg_gen_shr_i64(tcg_ctx, th, t1, t0);
    tcg_gen_shr_i64(tcg_ctx, tl, ones, t0);
    tcg_gen_xori_i64(tcg_ctx, t0, t0, 63);
    tcg_gen_shl_i64(tcg_ctx, t1, t1, t0);
    tcg_gen_shli_i64(tcg_ctx, t1, t1, 1);
    tcg_gen_or_i64(tcg_ctx, tl, t1, tl);

    tcg_gen_extract2_i64(tcg_ctx, tl, tl, th, 1);
    tcg_gen_shri_i64(tcg_ctx, th, th, 1);

    tcg_gen_xor_i64(tcg_ctx, mh, mh, th);
    tcg_gen_xor_i64(tcg_ctx, ml, ml, tl);

    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_GT, t0, b, e, ones, zero);
    tcg_gen_xor_i64(tcg_ctx, mh, mh, t0);
    tcg_gen_xor_i64(tcg_ctx, ml, ml, t0);

    tcg_temp_free_i64(tcg_ctx, th);
    tcg_temp_free_i64(tcg_ctx, tl);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, zero);
    tcg_temp_free_i64(tcg_ctx, ones);
}

static void gen_vector_rotl_quad(DisasContext *ctx, bool mask, bool insert)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 ah;
    TCGv_i64 al;
    TCGv_i64 vrb;
    TCGv_i64 n;
    TCGv_i64 t0;
    TCGv_i64 t1;
    TCGv_i64 zero;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    ah = tcg_temp_new_i64(tcg_ctx);
    al = tcg_temp_new_i64(tcg_ctx);
    vrb = tcg_temp_new_i64(tcg_ctx);
    n = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    zero = tcg_const_i64(tcg_ctx, 0);

    get_avr64(tcg_ctx, ah, rA(ctx->opcode), true);
    get_avr64(tcg_ctx, al, rA(ctx->opcode), false);
    get_avr64(tcg_ctx, vrb, rB(ctx->opcode), true);

    tcg_gen_mov_i64(tcg_ctx, t0, ah);
    tcg_gen_andi_i64(tcg_ctx, t1, vrb, 64);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, ah, t1, zero, al, ah);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, al, t1, zero, t0, al);
    tcg_gen_andi_i64(tcg_ctx, n, vrb, 0x3f);

    tcg_gen_shl_i64(tcg_ctx, t0, ah, n);
    tcg_gen_shl_i64(tcg_ctx, t1, al, n);

    tcg_gen_xori_i64(tcg_ctx, n, n, 63);

    tcg_gen_shr_i64(tcg_ctx, al, al, n);
    tcg_gen_shri_i64(tcg_ctx, al, al, 1);
    tcg_gen_or_i64(tcg_ctx, t0, al, t0);

    tcg_gen_shr_i64(tcg_ctx, ah, ah, n);
    tcg_gen_shri_i64(tcg_ctx, ah, ah, 1);
    tcg_gen_or_i64(tcg_ctx, t1, ah, t1);

    if (mask || insert) {
        tcg_gen_extract_i64(tcg_ctx, n, vrb, 8, 7);
        tcg_gen_extract_i64(tcg_ctx, vrb, vrb, 16, 7);

        gen_vrlq_mask(tcg_ctx, ah, al, vrb, n);

        tcg_gen_and_i64(tcg_ctx, t0, t0, ah);
        tcg_gen_and_i64(tcg_ctx, t1, t1, al);

        if (insert) {
            get_avr64(tcg_ctx, n, rD(ctx->opcode), true);
            get_avr64(tcg_ctx, vrb, rD(ctx->opcode), false);
            tcg_gen_andc_i64(tcg_ctx, n, n, ah);
            tcg_gen_andc_i64(tcg_ctx, vrb, vrb, al);
            tcg_gen_or_i64(tcg_ctx, t0, t0, n);
            tcg_gen_or_i64(tcg_ctx, t1, t1, vrb);
        }
    }

    set_avr64(tcg_ctx, rD(ctx->opcode), t0, true);
    set_avr64(tcg_ctx, rD(ctx->opcode), t1, false);

    tcg_temp_free_i64(tcg_ctx, ah);
    tcg_temp_free_i64(tcg_ctx, al);
    tcg_temp_free_i64(tcg_ctx, vrb);
    tcg_temp_free_i64(tcg_ctx, n);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static void gen_vslq(DisasContext *ctx)
{
    gen_vector_shift_quad(ctx, false, false);
}

static void gen_vsrq(DisasContext *ctx)
{
    gen_vector_shift_quad(ctx, true, false);
}

static void gen_vsraq(DisasContext *ctx)
{
    gen_vector_shift_quad(ctx, true, true);
}

static void gen_vrlq(DisasContext *ctx)
{
    gen_vector_rotl_quad(ctx, false, false);
}

static void gen_vrlqnm(DisasContext *ctx)
{
    gen_vector_rotl_quad(ctx, true, false);
}

static void gen_vrlqmi(DisasContext *ctx)
{
    gen_vector_rotl_quad(ctx, false, true);
}

static void gen_vmsumcud(DisasContext *ctx);

static void gen_vsldbi_vsrdbi(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    TCGv_i64 t1;
    TCGv_i64 t2;
    int opc = opc3(ctx->opcode);
    int sh = opc & 7;

    if (Rc(ctx->opcode)) {
        gen_vmsumcud(ctx);
        return;
    }
    if (opc >= 16) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);

    if (opc & 8) {
        get_avr64(tcg_ctx, t0, rB(ctx->opcode), false);
        get_avr64(tcg_ctx, t1, rB(ctx->opcode), true);

        if (sh != 0) {
            t2 = tcg_temp_new_i64(tcg_ctx);

            get_avr64(tcg_ctx, t2, rA(ctx->opcode), false);

            tcg_gen_extract2_i64(tcg_ctx, t0, t0, t1, sh);
            tcg_gen_extract2_i64(tcg_ctx, t1, t1, t2, sh);

            tcg_temp_free_i64(tcg_ctx, t2);
        }

        set_avr64(tcg_ctx, rD(ctx->opcode), t0, false);
        set_avr64(tcg_ctx, rD(ctx->opcode), t1, true);
    } else {
        get_avr64(tcg_ctx, t0, rA(ctx->opcode), true);
        get_avr64(tcg_ctx, t1, rA(ctx->opcode), false);

        if (sh != 0) {
            t2 = tcg_temp_new_i64(tcg_ctx);

            get_avr64(tcg_ctx, t2, rB(ctx->opcode), true);

            tcg_gen_extract2_i64(tcg_ctx, t0, t1, t0, 64 - sh);
            tcg_gen_extract2_i64(tcg_ctx, t1, t2, t1, 64 - sh);

            tcg_temp_free_i64(tcg_ctx, t2);
        }

        set_avr64(tcg_ctx, rD(ctx->opcode), t0, true);
        set_avr64(tcg_ctx, rD(ctx->opcode), t1, false);
    }

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

GEN_VXFORM_V(vslb, MO_8, tcg_gen_gvec_shlv, 2, 4);
GEN_VXFORM_V(vslh, MO_16, tcg_gen_gvec_shlv, 2, 5);
GEN_VXFORM_DUAL(vslb, PPC_ALTIVEC, PPC_NONE, \
                vslq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vslh, PPC_ALTIVEC, PPC_NONE, \
                vrlqnm, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_V(vslw, MO_32, tcg_gen_gvec_shlv, 2, 6);
GEN_VXFORM(vrlwnm, 2, 6);
GEN_VXFORM_DUAL(vslw, PPC_ALTIVEC, PPC_NONE, \
                vrlwnm, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_V(vsld, MO_64, tcg_gen_gvec_shlv, 2, 23);
GEN_VXFORM_V(vsrb, MO_8, tcg_gen_gvec_shrv, 2, 8);
GEN_VXFORM_DUAL(vsrb, PPC_ALTIVEC, PPC_NONE, \
                vsrq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_V(vsrh, MO_16, tcg_gen_gvec_shrv, 2, 9);
GEN_VXFORM_V(vsrw, MO_32, tcg_gen_gvec_shrv, 2, 10);
GEN_VXFORM_V(vsrd, MO_64, tcg_gen_gvec_shrv, 2, 27);
GEN_VXFORM_V(vsrab, MO_8, tcg_gen_gvec_sarv, 2, 12);
GEN_VXFORM_DUAL(vsrab, PPC_ALTIVEC, PPC_NONE, \
                vsraq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_V(vsrah, MO_16, tcg_gen_gvec_sarv, 2, 13);
GEN_VXFORM_V(vsraw, MO_32, tcg_gen_gvec_sarv, 2, 14);
GEN_VXFORM_V(vsrad, MO_64, tcg_gen_gvec_sarv, 2, 15);
GEN_VXFORM(vsrv, 2, 28);
GEN_VXFORM(vslv, 2, 29);
GEN_VXFORM(vslo, 6, 16);
GEN_VXFORM(vsro, 6, 17);
GEN_VXFORM(vaddcuw, 0, 6);
GEN_VXFORM(vsubcuw, 0, 22);

#define GEN_VXFORM_SAT(NAME, VECE, NORM, SAT, OPC2, OPC3)               \
static void glue(glue(gen_, NAME), _vec)(TCGContext *tcg_ctx, unsigned vece, TCGv_vec t,     \
                                         TCGv_vec sat, TCGv_vec a,      \
                                         TCGv_vec b)                    \
{                                                                       \
    TCGv_vec x = tcg_temp_new_vec_matching(tcg_ctx, t);                 \
    glue(glue(tcg_gen_, NORM), _vec)(tcg_ctx, VECE, x, a, b);                    \
    glue(glue(tcg_gen_, SAT), _vec)(tcg_ctx, VECE, t, a, b);                     \
    tcg_gen_cmp_vec(tcg_ctx, TCG_COND_NE, VECE, x, x, t);               \
    tcg_gen_or_vec(tcg_ctx, VECE, sat, sat, x);                         \
    tcg_temp_free_vec(tcg_ctx, x);                                      \
}                                                                       \
static void glue(gen_, NAME)(DisasContext *ctx)                         \
{                                                                       \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                             \
    static const TCGOpcode vecop_list[] = {                             \
        glue(glue(INDEX_op_, NORM), _vec),                              \
        glue(glue(INDEX_op_, SAT), _vec),                               \
        INDEX_op_cmp_vec, 0                                             \
    };                                                                  \
    static const GVecGen4 g = {                                         \
        .fniv = glue(glue(gen_, NAME), _vec),                           \
        .fno = glue(gen_helper_, NAME),                                 \
        .opt_opc = vecop_list,                                          \
        .write_aofs = true,                                             \
        .vece = VECE,                                                   \
    };                                                                  \
    if (unlikely(!ctx->altivec_enabled)) {                              \
        gen_exception(ctx, POWERPC_EXCP_VPU);                           \
        return;                                                         \
    }                                                                   \
    tcg_gen_gvec_4(tcg_ctx, avr_full_offset(rD(ctx->opcode)),           \
                   offsetof(CPUPPCState, vscr_sat),                     \
                   avr_full_offset(rA(ctx->opcode)),                    \
                   avr_full_offset(rB(ctx->opcode)),                    \
                   16, 16, &g);                                         \
}

GEN_VXFORM_SAT(vaddubs, MO_8, add, usadd, 0, 8);
GEN_VXFORM_DUAL_EXT(vaddubs, PPC_ALTIVEC, PPC_NONE, 0,       \
                    vmul10uq, PPC_NONE, PPC2_ISA300, 0x0000F800)
GEN_VXFORM_SAT(vadduhs, MO_16, add, usadd, 0, 9);
GEN_VXFORM_DUAL(vadduhs, PPC_ALTIVEC, PPC_NONE, \
                vmul10euq, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_SAT(vadduws, MO_32, add, usadd, 0, 10);
GEN_VXFORM_SAT(vaddsbs, MO_8, add, ssadd, 0, 12);
GEN_VXFORM_SAT(vaddshs, MO_16, add, ssadd, 0, 13);
GEN_VXFORM_SAT(vaddsws, MO_32, add, ssadd, 0, 14);
GEN_VXFORM_SAT(vsububs, MO_8, sub, ussub, 0, 24);
GEN_VXFORM_SAT(vsubuhs, MO_16, sub, ussub, 0, 25);
GEN_VXFORM_SAT(vsubuws, MO_32, sub, ussub, 0, 26);
GEN_VXFORM_SAT(vsubsbs, MO_8, sub, sssub, 0, 28);
GEN_VXFORM_SAT(vsubshs, MO_16, sub, sssub, 0, 29);
GEN_VXFORM_SAT(vsubsws, MO_32, sub, sssub, 0, 30);

static void gen_vcmpq_cr(DisasContext *ctx, bool sign)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 ah;
    TCGv_i64 al;
    TCGv_i64 bh;
    TCGv_i64 bl;
    TCGv_i64 gt;
    TCGv_i64 lt;
    TCGv_i64 eq;
    TCGv_i64 tmp;
    TCGv_i64 crf;
    TCGv_i64 zero;
    TCGv_i64 cr_gt;
    TCGv_i64 cr_lt;

    if (unlikely(ctx->opcode & 0x00600000)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    ah = tcg_temp_new_i64(tcg_ctx);
    al = tcg_temp_new_i64(tcg_ctx);
    bh = tcg_temp_new_i64(tcg_ctx);
    bl = tcg_temp_new_i64(tcg_ctx);
    gt = tcg_temp_new_i64(tcg_ctx);
    lt = tcg_temp_new_i64(tcg_ctx);
    eq = tcg_temp_new_i64(tcg_ctx);
    tmp = tcg_temp_new_i64(tcg_ctx);
    crf = tcg_const_i64(tcg_ctx, CRF_EQ);
    zero = tcg_const_i64(tcg_ctx, 0);
    cr_gt = tcg_const_i64(tcg_ctx, CRF_GT);
    cr_lt = tcg_const_i64(tcg_ctx, CRF_LT);

    get_avr64(tcg_ctx, ah, rA(ctx->opcode), true);
    get_avr64(tcg_ctx, al, rA(ctx->opcode), false);
    get_avr64(tcg_ctx, bh, rB(ctx->opcode), true);
    get_avr64(tcg_ctx, bl, rB(ctx->opcode), false);

    tcg_gen_setcond_i64(tcg_ctx, sign ? TCG_COND_GT : TCG_COND_GTU,
                        gt, ah, bh);
    tcg_gen_setcond_i64(tcg_ctx, sign ? TCG_COND_LT : TCG_COND_LTU,
                        lt, ah, bh);
    tcg_gen_setcond_i64(tcg_ctx, TCG_COND_EQ, eq, ah, bh);

    tcg_gen_setcond_i64(tcg_ctx, TCG_COND_GTU, tmp, al, bl);
    tcg_gen_and_i64(tcg_ctx, tmp, tmp, eq);
    tcg_gen_or_i64(tcg_ctx, gt, gt, tmp);

    tcg_gen_setcond_i64(tcg_ctx, TCG_COND_LTU, tmp, al, bl);
    tcg_gen_and_i64(tcg_ctx, tmp, tmp, eq);
    tcg_gen_or_i64(tcg_ctx, lt, lt, tmp);

    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, crf, gt, zero, cr_gt, crf);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, crf, lt, zero, cr_lt, crf);
    tcg_gen_extrl_i64_i32(tcg_ctx, cpu_crf[BF(ctx->opcode)], crf);

    tcg_temp_free_i64(tcg_ctx, ah);
    tcg_temp_free_i64(tcg_ctx, al);
    tcg_temp_free_i64(tcg_ctx, bh);
    tcg_temp_free_i64(tcg_ctx, bl);
    tcg_temp_free_i64(tcg_ctx, gt);
    tcg_temp_free_i64(tcg_ctx, lt);
    tcg_temp_free_i64(tcg_ctx, eq);
    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, crf);
    tcg_temp_free_i64(tcg_ctx, zero);
    tcg_temp_free_i64(tcg_ctx, cr_gt);
    tcg_temp_free_i64(tcg_ctx, cr_lt);
}

static void gen_vcmpuq(DisasContext *ctx)
{
    gen_vcmpq_cr(ctx, false);
}

static void gen_vcmpsq(DisasContext *ctx)
{
    gen_vcmpq_cr(ctx, true);
}

GEN_VXFORM(vadduqm, 0, 4);
GEN_VXFORM(vaddcuq, 0, 5);
GEN_VXFORM_DUAL(vadduqm, PPC_NONE, PPC2_ALTIVEC_207, \
                vcmpuq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vaddcuq, PPC_NONE, PPC2_ALTIVEC_207, \
                vcmpsq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM3(vaddeuqm, 30, 0);
GEN_VXFORM3(vaddecuq, 30, 0);
GEN_VXFORM_DUAL(vaddeuqm, PPC_NONE, PPC2_ALTIVEC_207, \
            vaddecuq, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM(vsubuqm, 0, 20);
GEN_VXFORM(vsubcuq, 0, 21);
GEN_VXFORM3(vsubeuqm, 31, 0);
GEN_VXFORM3(vsubecuq, 31, 0);
GEN_VXFORM_DUAL(vsubeuqm, PPC_NONE, PPC2_ALTIVEC_207, \
            vsubecuq, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM(vrlb, 2, 0);
GEN_VXFORM_DUAL(vrlb, PPC_ALTIVEC, PPC_NONE, \
                vrlq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM(vrlh, 2, 1);
GEN_VXFORM_DUAL(vrlh, PPC_ALTIVEC, PPC_NONE, \
                vrlqmi, PPC_NONE, PPC2_ISA310)
GEN_VXFORM(vrlw, 2, 2);
GEN_VXFORM(vrlwmi, 2, 2);
GEN_VXFORM_DUAL(vrlw, PPC_ALTIVEC, PPC_NONE, \
                vrlwmi, PPC_NONE, PPC2_ISA300)
GEN_VXFORM(vrld, 2, 3);
GEN_VXFORM(vrldmi, 2, 3);
GEN_VXFORM_DUAL(vrld, PPC_NONE, PPC2_ALTIVEC_207, \
                vrldmi, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_TRANS(vsl, 2, 7);
GEN_VXFORM(vrldnm, 2, 7);
GEN_VXFORM_DUAL(vsl, PPC_ALTIVEC, PPC_NONE, \
                vrldnm, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_TRANS(vsr, 2, 11);
GEN_VXFORM_ENV(vpkuhum, 7, 0);
GEN_VXFORM_ENV(vpkuwum, 7, 1);
GEN_VXFORM_ENV(vpkudum, 7, 17);
GEN_VXFORM_ENV(vpkuhus, 7, 2);
GEN_VXFORM_ENV(vpkuwus, 7, 3);
GEN_VXFORM_ENV(vpkudus, 7, 19);
GEN_VXFORM_ENV(vpkshus, 7, 4);
GEN_VXFORM_ENV(vpkswus, 7, 5);
GEN_VXFORM_ENV(vpksdus, 7, 21);
GEN_VXFORM_ENV(vpkshss, 7, 6);
GEN_VXFORM_ENV(vpkswss, 7, 7);
GEN_VXFORM_ENV(vpksdss, 7, 23);
GEN_VXFORM(vpkpx, 7, 12);
GEN_VXFORM_ENV(vsum4ubs, 4, 24);
GEN_VXFORM_ENV(vsum4sbs, 4, 28);
GEN_VXFORM_ENV(vsum4shs, 4, 25);
GEN_VXFORM_ENV(vsum2sws, 4, 26);
GEN_VXFORM_ENV(vsumsws, 4, 30);
GEN_VXFORM_ENV(vaddfp, 5, 0);
GEN_VXFORM_ENV(vsubfp, 5, 1);
GEN_VXFORM_ENV(vmaxfp, 5, 16);
GEN_VXFORM_ENV(vminfp, 5, 17);
GEN_VXFORM_HETRO(vextublx, 6, 24)
GEN_VXFORM_HETRO(vextuhlx, 6, 25)
GEN_VXFORM_HETRO(vextuwlx, 6, 26)
GEN_VXFORM_TRANS_DUAL(vmrgow, PPC_NONE, PPC2_ALTIVEC_207,
                vextuwlx, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_HETRO(vextubrx, 6, 28)
GEN_VXFORM_HETRO(vextuhrx, 6, 29)
GEN_VXFORM_HETRO(vextuwrx, 6, 30)
GEN_VXFORM_TRANS(lvsl, 6, 31)
GEN_VXFORM_TRANS(lvsr, 6, 32)
GEN_VXFORM_TRANS_DUAL(vmrgew, PPC_NONE, PPC2_ALTIVEC_207,
                vextuwrx, PPC_NONE, PPC2_ISA300)

#define GEN_VXRFORM1(opname, name, str, opc2, opc3)                     \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr ra, rb, rd;                                            \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));                     \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        gen_helper_##opname(tcg_ctx, tcg_ctx->cpu_env, rd, ra, rb);     \
        tcg_temp_free_ptr(tcg_ctx, ra);                                 \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

#define GEN_VXRFORM(name, opc2, opc3)                                \
    GEN_VXRFORM1(name, name, #name, opc2, opc3)                      \
    GEN_VXRFORM1(name##_dot, name##_, #name ".", opc2, (opc3 | (0x1 << 4)))

/*
 * Support for Altivec instructions that use bit 31 (Rc) as an opcode
 * bit but also use bit 21 as an actual Rc bit.  In general, thse pairs
 * come from different versions of the ISA, so we must also support a
 * pair of flags for each instruction.
 */
#define GEN_VXRFORM_DUAL(name0, flg0, flg2_0, name1, flg1, flg2_1)     \
static void glue(gen_, name0##_##name1)(DisasContext *ctx)             \
{                                                                      \
    if ((Rc(ctx->opcode) == 0) &&                                      \
        ((ctx->insns_flags & flg0) || (ctx->insns_flags2 & flg2_0))) { \
        if (Rc21(ctx->opcode) == 0) {                                  \
            gen_##name0(ctx);                                          \
        } else {                                                       \
            gen_##name0##_(ctx);                                       \
        }                                                              \
    } else if ((Rc(ctx->opcode) == 1) &&                               \
        ((ctx->insns_flags & flg1) || (ctx->insns_flags2 & flg2_1))) { \
        if (Rc21(ctx->opcode) == 0) {                                  \
            gen_##name1(ctx);                                          \
        } else {                                                       \
            gen_##name1##_(ctx);                                       \
        }                                                              \
    } else {                                                           \
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);            \
    }                                                                  \
}

GEN_VXRFORM(vcmpequb, 3, 0)
GEN_VXRFORM(vcmpequh, 3, 1)
GEN_VXRFORM(vcmpequw, 3, 2)
GEN_VXRFORM(vcmpequd, 3, 3)
GEN_VXRFORM(vcmpnezb, 3, 4)
GEN_VXRFORM(vcmpnezh, 3, 5)
GEN_VXRFORM(vcmpnezw, 3, 6)
GEN_VXRFORM(vcmpgtsb, 3, 12)
GEN_VXRFORM(vcmpgtsh, 3, 13)
GEN_VXRFORM(vcmpgtsw, 3, 14)
GEN_VXRFORM(vcmpgtsd, 3, 15)
GEN_VXRFORM(vcmpgtub, 3, 8)
GEN_VXRFORM(vcmpgtuh, 3, 9)
GEN_VXRFORM(vcmpgtuw, 3, 10)
GEN_VXRFORM(vcmpgtud, 3, 11)
GEN_VXRFORM(vcmpeqfp, 3, 3)
GEN_VXRFORM(vcmpgefp, 3, 7)
GEN_VXRFORM(vcmpgtfp, 3, 11)
GEN_VXRFORM(vcmpbfp, 3, 15)
GEN_VXRFORM(vcmpneb, 3, 0)
GEN_VXRFORM(vcmpneh, 3, 1)
GEN_VXRFORM(vcmpnew, 3, 2)

static void gen_vcmpq_record(TCGContext *tcg_ctx, TCGv_i64 result)
{
    tcg_gen_extrl_i64_i32(tcg_ctx, cpu_crf[6], result);
    tcg_gen_andi_i32(tcg_ctx, cpu_crf[6], cpu_crf[6], 0xa);
    tcg_gen_xori_i32(tcg_ctx, cpu_crf[6], cpu_crf[6], 0x2);
}

static void gen_vcmpequq_common(DisasContext *ctx, bool record)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    TCGv_i64 t1;
    TCGv_i64 t2;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    t2 = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, t0, rA(ctx->opcode), true);
    get_avr64(tcg_ctx, t1, rB(ctx->opcode), true);
    tcg_gen_xor_i64(tcg_ctx, t2, t0, t1);

    get_avr64(tcg_ctx, t0, rA(ctx->opcode), false);
    get_avr64(tcg_ctx, t1, rB(ctx->opcode), false);
    tcg_gen_xor_i64(tcg_ctx, t1, t0, t1);

    tcg_gen_or_i64(tcg_ctx, t1, t1, t2);
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, t1, t1, 0);
    tcg_gen_neg_i64(tcg_ctx, t1, t1);

    set_avr64(tcg_ctx, rD(ctx->opcode), t1, true);
    set_avr64(tcg_ctx, rD(ctx->opcode), t1, false);

    if (record) {
        gen_vcmpq_record(tcg_ctx, t1);
    }

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
}

static void gen_vcmpgtq_common(DisasContext *ctx, bool sign, bool record)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 t0;
    TCGv_i64 t1;
    TCGv_i64 t2;
    TCGv_i64 zero;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);
    t2 = tcg_temp_new_i64(tcg_ctx);
    zero = tcg_const_i64(tcg_ctx, 0);

    get_avr64(tcg_ctx, t0, rA(ctx->opcode), false);
    get_avr64(tcg_ctx, t1, rB(ctx->opcode), false);
    tcg_gen_setcond_i64(tcg_ctx, TCG_COND_GTU, t2, t0, t1);

    get_avr64(tcg_ctx, t0, rA(ctx->opcode), true);
    get_avr64(tcg_ctx, t1, rB(ctx->opcode), true);
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, t2, t0, t1, t2, zero);
    tcg_gen_setcond_i64(tcg_ctx, sign ? TCG_COND_GT : TCG_COND_GTU,
                        t1, t0, t1);

    tcg_gen_or_i64(tcg_ctx, t1, t1, t2);
    tcg_gen_neg_i64(tcg_ctx, t1, t1);

    set_avr64(tcg_ctx, rD(ctx->opcode), t1, true);
    set_avr64(tcg_ctx, rD(ctx->opcode), t1, false);

    if (record) {
        gen_vcmpq_record(tcg_ctx, t1);
    }

    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
    tcg_temp_free_i64(tcg_ctx, t2);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static void gen_vcmpequq(DisasContext *ctx)
{
    gen_vcmpequq_common(ctx, false);
}

static void gen_vcmpequq_(DisasContext *ctx)
{
    gen_vcmpequq_common(ctx, true);
}

static void gen_vcmpgtsq(DisasContext *ctx)
{
    gen_vcmpgtq_common(ctx, true, false);
}

static void gen_vcmpgtsq_(DisasContext *ctx)
{
    gen_vcmpgtq_common(ctx, true, true);
}

static void gen_vcmpgtuq(DisasContext *ctx)
{
    gen_vcmpgtq_common(ctx, false, false);
}

static void gen_vcmpgtuq_(DisasContext *ctx)
{
    gen_vcmpgtq_common(ctx, false, true);
}

GEN_VXRFORM_DUAL(vcmpequb, PPC_ALTIVEC, PPC_NONE, \
                 vcmpneb, PPC_NONE, PPC2_ISA300)
GEN_VXRFORM_DUAL(vcmpequh, PPC_ALTIVEC, PPC_NONE, \
                 vcmpneh, PPC_NONE, PPC2_ISA300)
GEN_VXRFORM_DUAL(vcmpequw, PPC_ALTIVEC, PPC_NONE, \
                 vcmpnew, PPC_NONE, PPC2_ISA300)
GEN_VXRFORM_DUAL(vcmpeqfp, PPC_ALTIVEC, PPC_NONE, \
                 vcmpequd, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXRFORM_DUAL(vcmpgefp, PPC_ALTIVEC, PPC_NONE, \
                 vcmpequq, PPC_NONE, PPC2_ISA310)
GEN_VXRFORM_DUAL(vcmpbfp, PPC_ALTIVEC, PPC_NONE, \
                 vcmpgtsd, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXRFORM_DUAL(vcmpgtsw, PPC_ALTIVEC, PPC_NONE, \
                 vcmpgtsq, PPC_NONE, PPC2_ISA310)
GEN_VXRFORM_DUAL(vcmpgtuw, PPC_ALTIVEC, PPC_NONE, \
                 vcmpgtuq, PPC_NONE, PPC2_ISA310)
GEN_VXRFORM_DUAL(vcmpgtfp, PPC_ALTIVEC, PPC_NONE, \
                 vcmpgtud, PPC_NONE, PPC2_ALTIVEC_207)

#define GEN_VXFORM_DUPI(name, tcg_op, opc2, opc3)                       \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        int simm;                                                       \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        simm = SIMM5(ctx->opcode);                                      \
        tcg_op(tcg_ctx, avr_full_offset(rD(ctx->opcode)), 16, 16, simm);\
    }

GEN_VXFORM_DUPI(vspltisb, tcg_gen_gvec_dup8i, 6, 12);
GEN_VXFORM_DUPI(vspltish, tcg_gen_gvec_dup16i, 6, 13);
GEN_VXFORM_DUPI(vspltisw, tcg_gen_gvec_dup32i, 6, 14);

#define GEN_VXFORM_NOA(name, opc2, opc3)                                \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr rb, rd;                                                \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        gen_helper_##name(tcg_ctx, rd, rb);                             \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

#define GEN_VXFORM_NOA_ENV(name, opc2, opc3)                            \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr rb, rd;                                                \
                                                                        \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rd, rb);           \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

#define GEN_VXFORM_NOA_2(name, opc2, opc3, opc4)                        \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr rb, rd;                                                \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        gen_helper_##name(tcg_ctx, rd, rb);                             \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

#define GEN_VXFORM_NOA_3(name, opc2, opc3, opc4)                        \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr rb;                                                    \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        gen_helper_##name(tcg_ctx, cpu_gpr[rD(ctx->opcode)], rb);       \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
    }
GEN_VXFORM_NOA(vupkhsb, 7, 8);
GEN_VXFORM_NOA(vupkhsh, 7, 9);
GEN_VXFORM_NOA(vupkhsw, 7, 25);
GEN_VXFORM_NOA(vupklsb, 7, 10);
GEN_VXFORM_NOA(vupklsh, 7, 11);
GEN_VXFORM_NOA(vupklsw, 7, 27);
GEN_VXFORM_NOA(vupkhpx, 7, 13);
GEN_VXFORM_NOA(vupklpx, 7, 15);
GEN_VXFORM_NOA_ENV(vrefp, 5, 4);
GEN_VXFORM_NOA_ENV(vrsqrtefp, 5, 5);
GEN_VXFORM_NOA_ENV(vexptefp, 5, 6);
GEN_VXFORM_NOA_ENV(vlogefp, 5, 7);
GEN_VXFORM_NOA_ENV(vrfim, 5, 11);
GEN_VXFORM_NOA_ENV(vrfin, 5, 8);
GEN_VXFORM_NOA_ENV(vrfip, 5, 10);
GEN_VXFORM_NOA_ENV(vrfiz, 5, 9);
GEN_VXFORM_NOA(vprtybw, 1, 24);
GEN_VXFORM_NOA(vprtybd, 1, 24);
GEN_VXFORM_NOA(vprtybq, 1, 24);

static void gen_vsplt(DisasContext *ctx, int vece)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    int uimm, dofs, bofs;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    uimm = UIMM5(ctx->opcode);
    bofs = avr_full_offset(rB(ctx->opcode));
    dofs = avr_full_offset(rD(ctx->opcode));

    /* Experimental testing shows that hardware masks the immediate.  */
    bofs += (uimm << vece) & 15;
#ifndef HOST_WORDS_BIGENDIAN
    bofs ^= 15;
    bofs &= ~((1 << vece) - 1);
#endif

    tcg_gen_gvec_dup_mem(tcg_ctx, vece, dofs, bofs, 16, 16);
}

#define GEN_VXFORM_VSPLT(name, vece, opc2, opc3) \
static void glue(gen_, name)(DisasContext *ctx) { gen_vsplt(ctx, vece); }

#define GEN_VXFORM_UIMM_ENV(name, opc2, opc3)                           \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr rb, rd;                                                \
        TCGv_i32 uimm;                                                  \
                                                                        \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        uimm = tcg_const_i32(tcg_ctx, UIMM5(ctx->opcode));                       \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        gen_helper_##name(tcg_ctx, tcg_ctx->cpu_env, rd, rb, uimm);     \
        tcg_temp_free_i32(tcg_ctx, uimm);                               \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

#define GEN_VXFORM_UIMM_SPLAT(name, opc2, opc3, splat_max)              \
static void glue(gen_, name)(DisasContext *ctx)                         \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr rb, rd;                                                \
        uint8_t uimm = UIMM4(ctx->opcode);                              \
        TCGv_i32 t0;                                                    \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        if (uimm > splat_max) {                                         \
            uimm = 0;                                                   \
        }                                                               \
        t0 = tcg_temp_new_i32(tcg_ctx);                                 \
        tcg_gen_movi_i32(tcg_ctx, t0, uimm);                            \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        gen_helper_##name(tcg_ctx, rd, rb, t0);                         \
        tcg_temp_free_i32(tcg_ctx, t0);                                 \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

GEN_VXFORM_VSPLT(vspltb, MO_8, 6, 8);
GEN_VXFORM_VSPLT(vsplth, MO_16, 6, 9);
GEN_VXFORM_VSPLT(vspltw, MO_32, 6, 10);
GEN_VXFORM_UIMM_SPLAT(vextractub, 6, 8, 15);
GEN_VXFORM_UIMM_SPLAT(vextractuh, 6, 9, 14);
GEN_VXFORM_UIMM_SPLAT(vextractuw, 6, 10, 12);
GEN_VXFORM_UIMM_SPLAT(vextractd, 6, 11, 8);
GEN_VXFORM_UIMM_SPLAT(vinsertb, 6, 12, 15);
GEN_VXFORM_UIMM_SPLAT(vinserth, 6, 13, 14);
GEN_VXFORM_UIMM_SPLAT(vinsertw, 6, 14, 12);
GEN_VXFORM_UIMM_SPLAT(vinsertd, 6, 15, 8);
GEN_VXFORM_UIMM_ENV(vcfux, 5, 12);
GEN_VXFORM_UIMM_ENV(vcfsx, 5, 13);
GEN_VXFORM_UIMM_ENV(vctuxs, 5, 14);
GEN_VXFORM_UIMM_ENV(vctsxs, 5, 15);

static void gen_vgnb(DisasContext *ctx)
{
    static const uint64_t mask[6][5] = {
        {
            0xAAAAAAAAAAAAAAAAULL, 0xccccccccccccccccULL,
            0xf0f0f0f0f0f0f0f0ULL, 0xff00ff00ff00ff00ULL,
            0xffff0000ffff0000ULL
        },
        {
            0x9249249249249249ULL, 0xC30C30C30C30C30CULL,
            0xF00F00F00F00F00FULL, 0xFF0000FF0000FF00ULL,
            0xFFFF00000000FFFFULL
        },
        {
            0x8888888888888888ULL, 0,
            0xf000f000f000f000ULL, 0, 0xFFFF000000000000ULL
        },
        {
            0x8421084210842108ULL, 0, 0xF0000F0000F0000FULL, 0, 0
        },
        {
            0x8208208208208208ULL, 0, 0xF00000F00000F000ULL, 0, 0
        },
        {
            0x8102040810204081ULL, 0, 0xF000000F000000F0ULL, 0, 0
        }
    };
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 hi;
    TCGv_i64 lo;
    TCGv_i64 t0;
    TCGv_i64 t1;
    uint64_t m;
    int i;
    int n = rA(ctx->opcode) & 7;
    int nbits;
    int sh;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    if (n < 2) {
        return;
    }

    nbits = (64 + n - 1) / n;
    hi = tcg_temp_new_i64(tcg_ctx);
    lo = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, hi, rB(ctx->opcode), true);
    get_avr64(tcg_ctx, lo, rB(ctx->opcode), false);

    tcg_gen_shli_i64(tcg_ctx, lo, lo, n * nbits - 64);

    for (i = 0, sh = n - 1; i < 5; i++, sh <<= 1) {
        m = mask[n - 2][i];
        if (m) {
            tcg_gen_andi_i64(tcg_ctx, hi, hi, m);
            tcg_gen_andi_i64(tcg_ctx, lo, lo, m);
        }
        if (sh < 64) {
            tcg_gen_shli_i64(tcg_ctx, t0, hi, sh);
            tcg_gen_shli_i64(tcg_ctx, t1, lo, sh);
            tcg_gen_or_i64(tcg_ctx, hi, t0, hi);
            tcg_gen_or_i64(tcg_ctx, lo, t1, lo);
        }
    }

    m = ~(~0ULL >> nbits);
    tcg_gen_andi_i64(tcg_ctx, hi, hi, m);
    tcg_gen_andi_i64(tcg_ctx, lo, lo, m);
    tcg_gen_shri_i64(tcg_ctx, lo, lo, nbits);
    tcg_gen_or_i64(tcg_ctx, hi, hi, lo);
    tcg_gen_trunc_i64_tl(tcg_ctx, cpu_gpr[rD(ctx->opcode)], hi);

    tcg_temp_free_i64(tcg_ctx, hi);
    tcg_temp_free_i64(tcg_ctx, lo);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

static void gen_vdiv_vmod(DisasContext *ctx, int vece,
                          void (*func_32)(TCGContext *, TCGv_i32,
                                          TCGv_i32, TCGv_i32),
                          void (*func_64)(TCGContext *, TCGv_i64,
                                          TCGv_i64, TCGv_i64))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    const GVecGen3 op = {
        .fni4 = func_32,
        .fni8 = func_64,
        .vece = vece,
    };

    if (!Rc(ctx->opcode)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tcg_gen_gvec_3(tcg_ctx, avr_full_offset(rD(ctx->opcode)),
                   avr_full_offset(rA(ctx->opcode)),
                   avr_full_offset(rB(ctx->opcode)), 16, 16, &op);
}

#define DIVU32(NAME, DIV)                                               \
static void NAME(TCGContext *tcg_ctx, TCGv_i32 t, TCGv_i32 a,           \
                 TCGv_i32 b)                                            \
{                                                                       \
    TCGv_i32 zero = tcg_const_i32(tcg_ctx, 0);                          \
    TCGv_i32 one = tcg_const_i32(tcg_ctx, 1);                           \
                                                                        \
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_EQ, b, b, zero, one, b);      \
    DIV(tcg_ctx, t, a, b);                                              \
                                                                        \
    tcg_temp_free_i32(tcg_ctx, one);                                    \
    tcg_temp_free_i32(tcg_ctx, zero);                                   \
}

#define DIVS32(NAME, DIV)                                               \
static void NAME(TCGContext *tcg_ctx, TCGv_i32 t, TCGv_i32 a,           \
                 TCGv_i32 b)                                            \
{                                                                       \
    TCGv_i32 t0 = tcg_temp_new_i32(tcg_ctx);                            \
    TCGv_i32 t1 = tcg_temp_new_i32(tcg_ctx);                            \
                                                                        \
    tcg_gen_setcondi_i32(tcg_ctx, TCG_COND_EQ, t0, a, INT32_MIN);       \
    tcg_gen_setcondi_i32(tcg_ctx, TCG_COND_EQ, t1, b, -1);              \
    tcg_gen_and_i32(tcg_ctx, t0, t0, t1);                               \
    tcg_gen_setcondi_i32(tcg_ctx, TCG_COND_EQ, t1, b, 0);               \
    tcg_gen_or_i32(tcg_ctx, t0, t0, t1);                                \
    tcg_gen_movi_i32(tcg_ctx, t1, 0);                                   \
    tcg_gen_movcond_i32(tcg_ctx, TCG_COND_NE, b, t0, t1, t0, b);        \
    DIV(tcg_ctx, t, a, b);                                              \
                                                                        \
    tcg_temp_free_i32(tcg_ctx, t1);                                     \
    tcg_temp_free_i32(tcg_ctx, t0);                                     \
}

#define DIVU64(NAME, DIV)                                               \
static void NAME(TCGContext *tcg_ctx, TCGv_i64 t, TCGv_i64 a,           \
                 TCGv_i64 b)                                            \
{                                                                       \
    TCGv_i64 zero = tcg_const_i64(tcg_ctx, 0);                          \
    TCGv_i64 one = tcg_const_i64(tcg_ctx, 1);                           \
                                                                        \
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_EQ, b, b, zero, one, b);      \
    DIV(tcg_ctx, t, a, b);                                              \
                                                                        \
    tcg_temp_free_i64(tcg_ctx, one);                                    \
    tcg_temp_free_i64(tcg_ctx, zero);                                   \
}

#define DIVS64(NAME, DIV)                                               \
static void NAME(TCGContext *tcg_ctx, TCGv_i64 t, TCGv_i64 a,           \
                 TCGv_i64 b)                                            \
{                                                                       \
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);                            \
    TCGv_i64 t1 = tcg_temp_new_i64(tcg_ctx);                            \
                                                                        \
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, t0, a, INT64_MIN);       \
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, t1, b, -1);              \
    tcg_gen_and_i64(tcg_ctx, t0, t0, t1);                               \
    tcg_gen_setcondi_i64(tcg_ctx, TCG_COND_EQ, t1, b, 0);               \
    tcg_gen_or_i64(tcg_ctx, t0, t0, t1);                                \
    tcg_gen_movi_i64(tcg_ctx, t1, 0);                                   \
    tcg_gen_movcond_i64(tcg_ctx, TCG_COND_NE, b, t0, t1, t0, b);        \
    DIV(tcg_ctx, t, a, b);                                              \
                                                                        \
    tcg_temp_free_i64(tcg_ctx, t1);                                     \
    tcg_temp_free_i64(tcg_ctx, t0);                                     \
}

DIVS32(do_vdivsw, tcg_gen_div_i32)
DIVU32(do_vdivuw, tcg_gen_divu_i32)
DIVS64(do_vdivsd, tcg_gen_div_i64)
DIVU64(do_vdivud, tcg_gen_divu_i64)

static void gen_vdivsw(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_32, do_vdivsw, NULL);
}

static void gen_vdivuw(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_32, do_vdivuw, NULL);
}

static void gen_vdivsd(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_64, NULL, do_vdivsd);
}

static void gen_vdivud(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_64, NULL, do_vdivud);
}

static void gen_vx_helper_rc1(DisasContext *ctx,
                              void (*gen_helper)(TCGContext *, TCGv_ptr,
                                                 TCGv_ptr, TCGv_ptr))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr ra;
    TCGv_ptr rb;
    TCGv_ptr rd;

    if (!Rc(ctx->opcode)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    gen_helper(tcg_ctx, rd, ra, rb);
    tcg_temp_free_ptr(tcg_ctx, rd);
    tcg_temp_free_ptr(tcg_ctx, rb);
    tcg_temp_free_ptr(tcg_ctx, ra);
}

static void gen_vdivsq(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VDIVSQ);
}

static void gen_vdivuq(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VDIVUQ);
}

static void do_vdives_i32(TCGContext *tcg_ctx, TCGv_i32 t, TCGv_i32 a,
                          TCGv_i32 b)
{
    TCGv_i64 val1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 val2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ext_i32_i64(tcg_ctx, val1, a);
    tcg_gen_ext_i32_i64(tcg_ctx, val2, b);
    tcg_gen_shli_i64(tcg_ctx, val1, val1, 32);
    tcg_gen_div_i64(tcg_ctx, val1, val1, val2);
    tcg_gen_extrl_i64_i32(tcg_ctx, t, val1);

    tcg_temp_free_i64(tcg_ctx, val2);
    tcg_temp_free_i64(tcg_ctx, val1);
}

static void do_vdiveu_i32(TCGContext *tcg_ctx, TCGv_i32 t, TCGv_i32 a,
                          TCGv_i32 b)
{
    TCGv_i64 val1 = tcg_temp_new_i64(tcg_ctx);
    TCGv_i64 val2 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_extu_i32_i64(tcg_ctx, val1, a);
    tcg_gen_extu_i32_i64(tcg_ctx, val2, b);
    tcg_gen_shli_i64(tcg_ctx, val1, val1, 32);
    tcg_gen_divu_i64(tcg_ctx, val1, val1, val2);
    tcg_gen_extrl_i64_i32(tcg_ctx, t, val1);

    tcg_temp_free_i64(tcg_ctx, val2);
    tcg_temp_free_i64(tcg_ctx, val1);
}

DIVS32(do_vdivesw, do_vdives_i32)
DIVU32(do_vdiveuw, do_vdiveu_i32)
DIVS32(do_vmodsw, tcg_gen_rem_i32)
DIVU32(do_vmoduw, tcg_gen_remu_i32)
DIVS64(do_vmodsd, tcg_gen_rem_i64)
DIVU64(do_vmodud, tcg_gen_remu_i64)

static void gen_vdivesw(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_32, do_vdivesw, NULL);
}

static void gen_vdiveuw(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_32, do_vdiveuw, NULL);
}

static void gen_vdivesd(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VDIVESD);
}

static void gen_vdiveud(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VDIVEUD);
}

static void gen_vdivesq(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VDIVESQ);
}

static void gen_vdiveuq(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VDIVEUQ);
}

static void gen_vmodsw(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_32, do_vmodsw, NULL);
}

static void gen_vmoduw(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_32, do_vmoduw, NULL);
}

static void gen_vmodsd(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_64, NULL, do_vmodsd);
}

static void gen_vmodud(DisasContext *ctx)
{
    gen_vdiv_vmod(ctx, MO_64, NULL, do_vmodud);
}

static void gen_vmodsq(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VMODSQ);
}

static void gen_vmoduq(DisasContext *ctx)
{
    gen_vx_helper_rc1(ctx, gen_helper_VMODUQ);
}

GEN_VXFORM_DUAL(vaddfp, PPC_ALTIVEC, PPC_NONE,
                vdivuq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL_EXT(vrefp, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vdivsq, PPC_NONE, PPC2_ISA310, 0)
GEN_VXFORM_DUAL_EXT(vexptefp, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vdivsw, PPC_NONE, PPC2_ISA310, 0)
GEN_VXFORM_DUAL_EXT(vlogefp, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vdivsd, PPC_NONE, PPC2_ISA310, 0)
GEN_VXFORM_DUAL_EXT(vrfin, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vdiveuq, PPC_NONE, PPC2_ISA310, 0)
GEN_VXFORM_DUAL_EXT(vrfip, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vdiveuw, PPC_NONE, PPC2_ISA310, 0)
GEN_VXFORM_DUAL_EXT(vrfim, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vdiveud, PPC_NONE, PPC2_ISA310, 0)
GEN_VXFORM_DUAL(vcfux, PPC_ALTIVEC, PPC_NONE,
                vdivesq, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vctuxs, PPC_ALTIVEC, PPC_NONE,
                vdivesw, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vctsxs, PPC_ALTIVEC, PPC_NONE,
                vdivesd, PPC_NONE, PPC2_ISA310)

#undef DIVS32
#undef DIVU32
#undef DIVS64
#undef DIVU64

GEN_VXFORM_DUAL(vspltb, PPC_ALTIVEC, PPC_NONE,
                vextractub, PPC_NONE, PPC2_ISA300);
GEN_VXFORM_DUAL(vsplth, PPC_ALTIVEC, PPC_NONE,
                vextractuh, PPC_NONE, PPC2_ISA300);
GEN_VXFORM_DUAL(vspltw, PPC_ALTIVEC, PPC_NONE,
                vextractuw, PPC_NONE, PPC2_ISA300);
GEN_VXFORM_DUAL(vspltisb, PPC_ALTIVEC, PPC_NONE,
                vinsertb, PPC_NONE, PPC2_ISA300);
GEN_VXFORM_DUAL(vspltish, PPC_ALTIVEC, PPC_NONE,
                vinserth, PPC_NONE, PPC2_ISA300);
GEN_VXFORM_DUAL(vspltisw, PPC_ALTIVEC, PPC_NONE,
                vinsertw, PPC_NONE, PPC2_ISA300);

static void gen_vextdx(DisasContext *ctx, int size, bool right,
                       void (*gen_helper)(TCGContext *, TCGv_ptr,
                                          TCGv_ptr, TCGv_ptr,
                                          TCGv_ptr, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr vrt;
    TCGv_ptr vra;
    TCGv_ptr vrb;
    TCGv rc;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    vrt = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    vra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));
    vrb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));
    rc = tcg_temp_new(tcg_ctx);

    tcg_gen_andi_tl(tcg_ctx, rc, cpu_gpr[rC(ctx->opcode)], 0x1f);
    if (right) {
        tcg_gen_subfi_tl(tcg_ctx, rc, 32 - size, rc);
    }
    gen_helper(tcg_ctx, tcg_ctx->cpu_env, vrt, vra, vrb, rc);

    tcg_temp_free_ptr(tcg_ctx, vrt);
    tcg_temp_free_ptr(tcg_ctx, vra);
    tcg_temp_free_ptr(tcg_ctx, vrb);
    tcg_temp_free(tcg_ctx, rc);
}

static void gen_vextdubvlx(DisasContext *ctx)
{
    gen_vextdx(ctx, 1, false, gen_helper_VEXTDUBVLX);
}

static void gen_vextduhvlx(DisasContext *ctx)
{
    gen_vextdx(ctx, 2, false, gen_helper_VEXTDUHVLX);
}

static void gen_vextduwvlx(DisasContext *ctx)
{
    gen_vextdx(ctx, 4, false, gen_helper_VEXTDUWVLX);
}

static void gen_vextddvlx(DisasContext *ctx)
{
    gen_vextdx(ctx, 8, false, gen_helper_VEXTDDVLX);
}

static void gen_vextdubvrx(DisasContext *ctx)
{
    gen_vextdx(ctx, 1, true, gen_helper_VEXTDUBVLX);
}

static void gen_vextduhvrx(DisasContext *ctx)
{
    gen_vextdx(ctx, 2, true, gen_helper_VEXTDUHVLX);
}

static void gen_vextduwvrx(DisasContext *ctx)
{
    gen_vextdx(ctx, 4, true, gen_helper_VEXTDUWVLX);
}

static void gen_vextddvrx(DisasContext *ctx)
{
    gen_vextdx(ctx, 8, true, gen_helper_VEXTDDVLX);
}

static void gen_vextdubv(DisasContext *ctx)
{
    if (Rc(ctx->opcode)) {
        gen_vextdubvrx(ctx);
    } else {
        gen_vextdubvlx(ctx);
    }
}

static void gen_vextduhv(DisasContext *ctx)
{
    if (Rc(ctx->opcode)) {
        gen_vextduhvrx(ctx);
    } else {
        gen_vextduhvlx(ctx);
    }
}

static void gen_vextduwv(DisasContext *ctx)
{
    if (Rc(ctx->opcode)) {
        gen_vextduwvrx(ctx);
    } else {
        gen_vextduwvlx(ctx);
    }
}

static void gen_vextddv(DisasContext *ctx)
{
    if (Rc(ctx->opcode)) {
        gen_vextddvrx(ctx);
    } else {
        gen_vextddvlx(ctx);
    }
}

static void gen_vstri(DisasContext *ctx,
                      void (*gen_helper)(TCGContext *, TCGv_i32,
                                         TCGv_ptr, TCGv_ptr))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr vrt;
    TCGv_ptr vrb;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    vrt = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    vrb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));

    if (Rc21(ctx->opcode)) {
        gen_helper(tcg_ctx, cpu_crf[6], vrt, vrb);
    } else {
        TCGv_i32 discard = tcg_temp_new_i32(tcg_ctx);
        gen_helper(tcg_ctx, discard, vrt, vrb);
        tcg_temp_free_i32(tcg_ctx, discard);
    }

    tcg_temp_free_ptr(tcg_ctx, vrt);
    tcg_temp_free_ptr(tcg_ctx, vrb);
}

static void gen_vstri_isa310(DisasContext *ctx)
{
    switch (rA(ctx->opcode)) {
    case 0:
        gen_vstri(ctx, gen_helper_VSTRIBL);
        return;
    case 1:
        gen_vstri(ctx, gen_helper_VSTRIBR);
        return;
    case 2:
        gen_vstri(ctx, gen_helper_VSTRIHL);
        return;
    case 3:
        gen_vstri(ctx, gen_helper_VSTRIHR);
        return;
    default:
        gen_invalid(ctx);
        return;
    }
}

static void gen_vmrghb_vstri(DisasContext *ctx)
{
    if (!Rc(ctx->opcode) && (ctx->insns_flags & PPC_ALTIVEC)) {
        gen_vmrghb(ctx);
    } else if (Rc(ctx->opcode) && (ctx->insns_flags2 & PPC2_ISA310)) {
        gen_vstri_isa310(ctx);
    } else {
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);
    }
}

static void gen_vslo_vstri(DisasContext *ctx)
{
    if (!Rc(ctx->opcode) && (ctx->insns_flags & PPC_ALTIVEC)) {
        gen_vslo(ctx);
    } else if (Rc(ctx->opcode) && (ctx->insns_flags2 & PPC2_ISA310)) {
        gen_vstri_isa310(ctx);
    } else {
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);
    }
}

static void gen_vclrb(DisasContext *ctx, bool right)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 rb;
    TCGv_i64 mh;
    TCGv_i64 ml;
    TCGv_i64 tmp;
    TCGv_i64 ones;
    TCGv_i64 zero;
    TCGv_i64 eight;
    TCGv_i64 sixteen;

    if (!Rc(ctx->opcode) || !(ctx->insns_flags2 & PPC2_ISA310)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    rb = tcg_temp_new_i64(tcg_ctx);
    mh = tcg_temp_new_i64(tcg_ctx);
    ml = tcg_temp_new_i64(tcg_ctx);
    tmp = tcg_temp_new_i64(tcg_ctx);
    ones = tcg_const_i64(tcg_ctx, -1);
    zero = tcg_const_i64(tcg_ctx, 0);
    eight = tcg_const_i64(tcg_ctx, 8);
    sixteen = tcg_const_i64(tcg_ctx, 16);

    tcg_gen_extu_tl_i64(tcg_ctx, rb, cpu_gpr[rB(ctx->opcode)]);
    tcg_gen_andi_i64(tcg_ctx, tmp, rb, 7);
    tcg_gen_shli_i64(tcg_ctx, tmp, tmp, 3);
    if (right) {
        tcg_gen_shr_i64(tcg_ctx, tmp, ones, tmp);
    } else {
        tcg_gen_shl_i64(tcg_ctx, tmp, ones, tmp);
    }
    tcg_gen_not_i64(tcg_ctx, tmp, tmp);

    if (right) {
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, mh, rb, eight, tmp, ones);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, ml, rb, eight, zero, tmp);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, ml, rb, sixteen, ml, ones);
    } else {
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, ml, rb, eight, tmp, ones);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, mh, rb, eight, zero, tmp);
        tcg_gen_movcond_i64(tcg_ctx, TCG_COND_LTU, mh, rb, sixteen, mh, ones);
    }

    get_avr64(tcg_ctx, tmp, rA(ctx->opcode), true);
    tcg_gen_and_i64(tcg_ctx, tmp, tmp, mh);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, true);

    get_avr64(tcg_ctx, tmp, rA(ctx->opcode), false);
    tcg_gen_and_i64(tcg_ctx, tmp, tmp, ml);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, false);

    tcg_temp_free_i64(tcg_ctx, rb);
    tcg_temp_free_i64(tcg_ctx, mh);
    tcg_temp_free_i64(tcg_ctx, ml);
    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, ones);
    tcg_temp_free_i64(tcg_ctx, zero);
    tcg_temp_free_i64(tcg_ctx, eight);
    tcg_temp_free_i64(tcg_ctx, sixteen);
}

static void gen_vmrglw_vclrlb(DisasContext *ctx)
{
    if (!Rc(ctx->opcode) && (ctx->insns_flags & PPC_ALTIVEC)) {
        gen_vmrglw(ctx);
    } else if (Rc(ctx->opcode) && (ctx->insns_flags2 & PPC2_ISA310)) {
        gen_vclrb(ctx, false);
    } else {
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);
    }
}

static void gen_vclrrb(DisasContext *ctx)
{
    gen_vclrb(ctx, true);
}

static void gen_vinsx(DisasContext *ctx, int vrt, int size, bool right,
                      TCGv ra, TCGv_i64 rb,
                      void (*gen_helper)(TCGContext *, TCGv_ptr,
                                         TCGv_ptr, TCGv_i64, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr t;
    TCGv idx;

    t = gen_avr_ptr(tcg_ctx, vrt);
    idx = tcg_temp_new(tcg_ctx);

    tcg_gen_andi_tl(tcg_ctx, idx, ra, 0xf);
    if (right) {
        tcg_gen_subfi_tl(tcg_ctx, idx, 16 - size, idx);
    }
    gen_helper(tcg_ctx, tcg_ctx->cpu_env, t, rb, idx);

    tcg_temp_free_ptr(tcg_ctx, t);
    tcg_temp_free(tcg_ctx, idx);
}

static void gen_vinsvx(DisasContext *ctx, int vrt, int size, bool right,
                       TCGv ra, int vrb,
                       void (*gen_helper)(TCGContext *, TCGv_ptr,
                                          TCGv_ptr, TCGv_i64, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 val;

    val = tcg_temp_new_i64(tcg_ctx);
    get_avr64(tcg_ctx, val, vrb, true);
    gen_vinsx(ctx, vrt, size, right, ra, val, gen_helper);
    tcg_temp_free_i64(tcg_ctx, val);
}

static void gen_vinsx_vx(DisasContext *ctx, int size, bool right,
                         void (*gen_helper)(TCGContext *, TCGv_ptr,
                                            TCGv_ptr, TCGv_i64, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 val;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    val = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_extu_tl_i64(tcg_ctx, val, cpu_gpr[rB(ctx->opcode)]);
    gen_vinsx(ctx, rD(ctx->opcode), size, right, cpu_gpr[rA(ctx->opcode)],
              val, gen_helper);
    tcg_temp_free_i64(tcg_ctx, val);
}

static void gen_vinsvx_vx(DisasContext *ctx, int size, bool right,
                          void (*gen_helper)(TCGContext *, TCGv_ptr,
                                             TCGv_ptr, TCGv_i64, TCGv))
{
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    gen_vinsvx(ctx, rD(ctx->opcode), size, right, cpu_gpr[rA(ctx->opcode)],
               rB(ctx->opcode), gen_helper);
}

static void gen_vins_uim4(DisasContext *ctx, int size,
                          void (*gen_helper)(TCGContext *, TCGv_ptr,
                                             TCGv_ptr, TCGv_i64, TCGv))
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 val;
    TCGv uim;
    uint8_t uimm = UIMM4(ctx->opcode);

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    if (uimm > (16 - size)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "Invalid index for VINS* at 0x" TARGET_FMT_lx
                      ", UIM = %d > %d\n", ctx->cia, uimm, 16 - size);
        return;
    }

    val = tcg_temp_new_i64(tcg_ctx);
    uim = tcg_const_tl(tcg_ctx, uimm);
    tcg_gen_extu_tl_i64(tcg_ctx, val, cpu_gpr[rB(ctx->opcode)]);
    gen_vinsx(ctx, rD(ctx->opcode), size, false, uim, val, gen_helper);
    tcg_temp_free(tcg_ctx, uim);
    tcg_temp_free_i64(tcg_ctx, val);
}

static void gen_vinsblx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 1, false, gen_helper_VINSBLX);
}

static void gen_vinshlx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 2, false, gen_helper_VINSHLX);
}

static void gen_vinswlx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 4, false, gen_helper_VINSWLX);
}

static void gen_vinsdlx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 8, false, gen_helper_VINSDLX);
}

static void gen_vinsbrx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 1, true, gen_helper_VINSBLX);
}

static void gen_vinshrx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 2, true, gen_helper_VINSHLX);
}

static void gen_vinswrx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 4, true, gen_helper_VINSWLX);
}

static void gen_vinsdrx(DisasContext *ctx)
{
    gen_vinsx_vx(ctx, 8, true, gen_helper_VINSDLX);
}

static void gen_vinsw(DisasContext *ctx)
{
    gen_vins_uim4(ctx, 4, gen_helper_VINSWLX);
}

static void gen_vinsd(DisasContext *ctx)
{
    gen_vins_uim4(ctx, 8, gen_helper_VINSDLX);
}

static void gen_vinsbvlx(DisasContext *ctx)
{
    gen_vinsvx_vx(ctx, 1, false, gen_helper_VINSBLX);
}

static void gen_vinshvlx(DisasContext *ctx)
{
    gen_vinsvx_vx(ctx, 2, false, gen_helper_VINSHLX);
}

static void gen_vinswvlx(DisasContext *ctx)
{
    gen_vinsvx_vx(ctx, 4, false, gen_helper_VINSWLX);
}

static void gen_vinsbvrx(DisasContext *ctx)
{
    gen_vinsvx_vx(ctx, 1, true, gen_helper_VINSBLX);
}

static void gen_vinshvrx(DisasContext *ctx)
{
    gen_vinsvx_vx(ctx, 2, true, gen_helper_VINSHLX);
}

static void gen_vinswvrx(DisasContext *ctx)
{
    gen_vinsvx_vx(ctx, 4, true, gen_helper_VINSWLX);
}

GEN_VXFORM_DUAL(vpkuhum, PPC_ALTIVEC, PPC_NONE,
                vinsbvlx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkuwum, PPC_ALTIVEC, PPC_NONE,
                vinshvlx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkuhus, PPC_ALTIVEC, PPC_NONE,
                vinswvlx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkuwus, PPC_ALTIVEC, PPC_NONE,
                vinsw, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkshus, PPC_ALTIVEC, PPC_NONE,
                vinsbvrx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkswus, PPC_ALTIVEC, PPC_NONE,
                vinshvrx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkshss, PPC_ALTIVEC, PPC_NONE,
                vinswvrx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vpkswss, PPC_ALTIVEC, PPC_NONE,
                vinsd, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL_EXT(vupkhsb, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vinsblx, PPC_NONE, PPC2_ISA310, 0x00000000)
GEN_VXFORM_DUAL_EXT(vupkhsh, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vinshlx, PPC_NONE, PPC2_ISA310, 0x00000000)
GEN_VXFORM_DUAL_EXT(vupklsb, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vinswlx, PPC_NONE, PPC2_ISA310, 0x00000000)
GEN_VXFORM_DUAL_EXT(vupklsh, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vinsdlx, PPC_NONE, PPC2_ISA310, 0x00000000)
GEN_VXFORM_DUAL(vpkpx, PPC_ALTIVEC, PPC_NONE,
                vinsbrx, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL_EXT(vupkhpx, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vinshrx, PPC_NONE, PPC2_ISA310, 0x00000000)
GEN_VXFORM_DUAL_EXT(vupklpx, PPC_ALTIVEC, PPC_NONE, 0x001f0000,
                    vinsdrx, PPC_NONE, PPC2_ISA310, 0x00000000)

static void gen_vsldoi(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr ra, rb, rd;
    TCGv_i32 sh;
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    sh = tcg_const_i32(tcg_ctx, VSH(ctx->opcode));
    gen_helper_vsldoi(tcg_ctx, rd, ra, rb, sh);
    tcg_temp_free_ptr(tcg_ctx, ra);
    tcg_temp_free_ptr(tcg_ctx, rb);
    tcg_temp_free_ptr(tcg_ctx, rd);
    tcg_temp_free_i32(tcg_ctx, sh);
}

#define GEN_VAFORM_PAIRED(name0, name1, opc2)                           \
static void glue(gen_, name0##_##name1)(DisasContext *ctx)              \
    {                                                                   \
        TCGContext *tcg_ctx = ctx->uc->tcg_ctx;                         \
        TCGv_ptr ra, rb, rc, rd;                                        \
        if (unlikely(!ctx->altivec_enabled)) {                          \
            gen_exception(ctx, POWERPC_EXCP_VPU);                       \
            return;                                                     \
        }                                                               \
        ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));                     \
        rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));                     \
        rc = gen_avr_ptr(tcg_ctx, rC(ctx->opcode));                     \
        rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));                     \
        if (Rc(ctx->opcode)) {                                          \
            gen_helper_##name1(tcg_ctx, tcg_ctx->cpu_env, rd, ra, rb, rc);       \
        } else {                                                        \
            gen_helper_##name0(tcg_ctx, tcg_ctx->cpu_env, rd, ra, rb, rc);       \
        }                                                               \
        tcg_temp_free_ptr(tcg_ctx, ra);                                 \
        tcg_temp_free_ptr(tcg_ctx, rb);                                 \
        tcg_temp_free_ptr(tcg_ctx, rc);                                 \
        tcg_temp_free_ptr(tcg_ctx, rd);                                 \
    }

GEN_VAFORM_PAIRED(vmhaddshs, vmhraddshs, 16)

static void gen_vmladduhm(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr ra, rb, rc, rd;
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));
    rc = gen_avr_ptr(tcg_ctx, rC(ctx->opcode));
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    gen_helper_vmladduhm(tcg_ctx, rd, ra, rb, rc);
    tcg_temp_free_ptr(tcg_ctx, ra);
    tcg_temp_free_ptr(tcg_ctx, rb);
    tcg_temp_free_ptr(tcg_ctx, rc);
    tcg_temp_free_ptr(tcg_ctx, rd);
}

static void gen_vmsumudm(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 rl;
    TCGv_i64 rh;
    TCGv_i64 src1;
    TCGv_i64 src2;
    int dw;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    rh = tcg_temp_new_i64(tcg_ctx);
    rl = tcg_temp_new_i64(tcg_ctx);
    src1 = tcg_temp_new_i64(tcg_ctx);
    src2 = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, rl, rC(ctx->opcode), false);
    get_avr64(tcg_ctx, rh, rC(ctx->opcode), true);

    for (dw = 0; dw < 2; dw++) {
        get_avr64(tcg_ctx, src1, rA(ctx->opcode), dw);
        get_avr64(tcg_ctx, src2, rB(ctx->opcode), dw);
        tcg_gen_mulu2_i64(tcg_ctx, src1, src2, src1, src2);
        tcg_gen_add2_i64(tcg_ctx, rl, rh, rl, rh, src1, src2);
    }

    set_avr64(tcg_ctx, rD(ctx->opcode), rl, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), rh, true);

    tcg_temp_free_i64(tcg_ctx, rl);
    tcg_temp_free_i64(tcg_ctx, rh);
    tcg_temp_free_i64(tcg_ctx, src1);
    tcg_temp_free_i64(tcg_ctx, src2);
}

static void gen_vmsumcud(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 tmp0;
    TCGv_i64 tmp1;
    TCGv_i64 prod1h;
    TCGv_i64 prod1l;
    TCGv_i64 prod0h;
    TCGv_i64 prod0l;
    TCGv_i64 zero;

    if (!Rc(ctx->opcode) || !(ctx->insns_flags2 & PPC2_ISA310)) {
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tmp0 = tcg_temp_new_i64(tcg_ctx);
    tmp1 = tcg_temp_new_i64(tcg_ctx);
    prod1h = tcg_temp_new_i64(tcg_ctx);
    prod1l = tcg_temp_new_i64(tcg_ctx);
    prod0h = tcg_temp_new_i64(tcg_ctx);
    prod0l = tcg_temp_new_i64(tcg_ctx);
    zero = tcg_const_i64(tcg_ctx, 0);

    get_avr64(tcg_ctx, tmp0, rA(ctx->opcode), false);
    get_avr64(tcg_ctx, tmp1, rB(ctx->opcode), false);
    tcg_gen_mulu2_i64(tcg_ctx, prod1l, prod1h, tmp0, tmp1);

    get_avr64(tcg_ctx, tmp0, rA(ctx->opcode), true);
    get_avr64(tcg_ctx, tmp1, rB(ctx->opcode), true);
    tcg_gen_mulu2_i64(tcg_ctx, prod0l, prod0h, tmp0, tmp1);

    get_avr64(tcg_ctx, tmp1, rC(ctx->opcode), false);
    tcg_gen_add2_i64(tcg_ctx, tmp1, tmp0, tmp1, zero, prod1l, zero);
    tcg_gen_add2_i64(tcg_ctx, tmp1, tmp0, tmp1, tmp0, prod0l, zero);

    get_avr64(tcg_ctx, tmp1, rC(ctx->opcode), true);
    tcg_gen_add2_i64(tcg_ctx, tmp1, tmp0, tmp0, zero, tmp1, zero);
    tcg_gen_add2_i64(tcg_ctx, tmp1, tmp0, tmp1, tmp0, prod1h, zero);
    tcg_gen_add2_i64(tcg_ctx, tmp1, tmp0, tmp1, tmp0, prod0h, zero);

    set_avr64(tcg_ctx, rD(ctx->opcode), tmp0, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), zero, true);

    tcg_temp_free_i64(tcg_ctx, tmp0);
    tcg_temp_free_i64(tcg_ctx, tmp1);
    tcg_temp_free_i64(tcg_ctx, prod1h);
    tcg_temp_free_i64(tcg_ctx, prod1l);
    tcg_temp_free_i64(tcg_ctx, prod0h);
    tcg_temp_free_i64(tcg_ctx, prod0l);
    tcg_temp_free_i64(tcg_ctx, zero);
}

static void gen_vmladduhm_vmsumudm(DisasContext *ctx)
{
    if (!Rc(ctx->opcode) && (ctx->insns_flags & PPC_ALTIVEC)) {
        gen_vmladduhm(ctx);
    } else if (Rc(ctx->opcode) && (ctx->insns_flags2 & PPC2_ISA300)) {
        gen_vmsumudm(ctx);
    } else {
        gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);
    }
}

static void gen_vpermr(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr ra, rb, rc, rd;
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));
    rc = gen_avr_ptr(tcg_ctx, rC(ctx->opcode));
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    gen_helper_vpermr(tcg_ctx, tcg_ctx->cpu_env, rd, ra, rb, rc);
    tcg_temp_free_ptr(tcg_ctx, ra);
    tcg_temp_free_ptr(tcg_ctx, rb);
    tcg_temp_free_ptr(tcg_ctx, rc);
    tcg_temp_free_ptr(tcg_ctx, rd);
}

GEN_VAFORM_PAIRED(vmsumubm, vmsummbm, 18)
GEN_VAFORM_PAIRED(vmsumuhm, vmsumuhs, 19)
GEN_VAFORM_PAIRED(vmsumshm, vmsumshs, 20)
GEN_VAFORM_PAIRED(vsel, vperm, 21)
GEN_VAFORM_PAIRED(vmaddfp, vnmsubfp, 23)

GEN_VXFORM_NOA(vclzb, 1, 28)
GEN_VXFORM_NOA(vclzh, 1, 29)
GEN_VXFORM_TRANS(vclzw, 1, 30)
GEN_VXFORM_TRANS(vclzd, 1, 31)
GEN_VXFORM_NOA_2(vnegw, 1, 24, 6)
GEN_VXFORM_NOA_2(vnegd, 1, 24, 7)
GEN_VXFORM_NOA_2(vextsb2w, 1, 24, 16)
GEN_VXFORM_NOA_2(vextsh2w, 1, 24, 17)
GEN_VXFORM_NOA_2(vextsb2d, 1, 24, 24)
GEN_VXFORM_NOA_2(vextsh2d, 1, 24, 25)
GEN_VXFORM_NOA_2(vextsw2d, 1, 24, 26)

static void gen_vextsd2q(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 tmp;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, tmp, rB(ctx->opcode), false);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, false);
    tcg_gen_sari_i64(tcg_ctx, tmp, tmp, 63);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, true);

    tcg_temp_free_i64(tcg_ctx, tmp);
}

GEN_VXFORM_NOA_2(vctzb, 1, 24, 28)
GEN_VXFORM_NOA_2(vctzh, 1, 24, 29)
GEN_VXFORM_NOA_2(vctzw, 1, 24, 30)
GEN_VXFORM_NOA_2(vctzd, 1, 24, 31)
GEN_VXFORM_NOA_3(vclzlsbb, 1, 24, 0)
GEN_VXFORM_NOA_3(vctzlsbb, 1, 24, 1)
GEN_VXFORM_NOA(vpopcntb, 1, 28)
GEN_VXFORM_NOA(vpopcnth, 1, 29)
GEN_VXFORM_NOA(vpopcntw, 1, 30)
GEN_VXFORM_NOA(vpopcntd, 1, 31)
GEN_VXFORM_DUAL(vclzb, PPC_NONE, PPC2_ALTIVEC_207, \
                vpopcntb, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vclzh, PPC_NONE, PPC2_ALTIVEC_207, \
                vpopcnth, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vclzw, PPC_NONE, PPC2_ALTIVEC_207, \
                vpopcntw, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vclzd, PPC_NONE, PPC2_ALTIVEC_207, \
                vpopcntd, PPC_NONE, PPC2_ALTIVEC_207)

#if defined(TARGET_PPC64)
static void gen_vcfuged(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    static const GVecGen3 g = {
        .fni8 = gen_helper_CFUGED,
        .vece = MO_64,
    };

    if (!Rc(ctx->opcode)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tcg_gen_gvec_3(tcg_ctx, avr_full_offset(rD(ctx->opcode)),
                   avr_full_offset(rA(ctx->opcode)),
                   avr_full_offset(rB(ctx->opcode)), 16, 16, &g);
}

static void gen_vcntzdm(DisasContext *ctx, bool trail)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    static const GVecGen3i g = {
        .fni8 = gen_cntzdm_i64,
        .vece = MO_64,
    };

    if (Rc(ctx->opcode)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tcg_gen_gvec_3i(tcg_ctx, avr_full_offset(rD(ctx->opcode)),
                    avr_full_offset(rA(ctx->opcode)),
                    avr_full_offset(rB(ctx->opcode)), 16, 16, trail, &g);
}

static void gen_vclzdm(DisasContext *ctx)
{
    gen_vcntzdm(ctx, false);
}

static void gen_vctzdm(DisasContext *ctx)
{
    gen_vcntzdm(ctx, true);
}

static void gen_vpdepd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    static const GVecGen3 g = {
        .fni8 = gen_helper_PDEPD,
        .vece = MO_64,
    };

    if (!Rc(ctx->opcode)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tcg_gen_gvec_3(tcg_ctx, avr_full_offset(rD(ctx->opcode)),
                   avr_full_offset(rA(ctx->opcode)),
                   avr_full_offset(rB(ctx->opcode)), 16, 16, &g);
}

static void gen_vpextd(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    static const GVecGen3 g = {
        .fni8 = gen_helper_PEXTD,
        .vece = MO_64,
    };

    if (!Rc(ctx->opcode)) {
        gen_invalid(ctx);
        return;
    }
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tcg_gen_gvec_3(tcg_ctx, avr_full_offset(rD(ctx->opcode)),
                   avr_full_offset(rA(ctx->opcode)),
                   avr_full_offset(rB(ctx->opcode)), 16, 16, &g);
}
#endif

static void gen_vexpandm(DisasContext *ctx, unsigned vece)
{
    const uint64_t elem_width = 8 << vece;
    const uint64_t elem_count_half = 8 >> vece;
    const uint64_t mask = dup_const(vece, 1ull << (elem_width - 1));
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 lo;
    TCGv_i64 hi;
    TCGv_i64 t0;
    TCGv_i64 t1;
    uint64_t c;
    uint64_t i;
    uint64_t j;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    hi = tcg_temp_new_i64(tcg_ctx);
    lo = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, lo, rB(ctx->opcode), false);
    get_avr64(tcg_ctx, hi, rB(ctx->opcode), true);

    tcg_gen_andi_i64(tcg_ctx, lo, lo, mask);
    tcg_gen_andi_i64(tcg_ctx, hi, hi, mask);

    for (i = elem_count_half / 2, j = 32; i > 0; i >>= 1, j >>= 1) {
        tcg_gen_shli_i64(tcg_ctx, t0, hi, j - i);
        tcg_gen_shli_i64(tcg_ctx, t1, lo, j - i);
        tcg_gen_or_i64(tcg_ctx, hi, hi, t0);
        tcg_gen_or_i64(tcg_ctx, lo, lo, t1);
    }

    tcg_gen_shri_i64(tcg_ctx, hi, hi, 64 - elem_count_half);
    tcg_gen_extract2_i64(tcg_ctx, lo, lo, hi, 64 - elem_count_half);
    tcg_gen_extract_i64(tcg_ctx, hi, lo, elem_count_half, elem_count_half);
    tcg_gen_extract_i64(tcg_ctx, lo, lo, 0, elem_count_half);

    for (i = elem_count_half / 2, j = 32; i > 0; i >>= 1, j >>= 1) {
        tcg_gen_shli_i64(tcg_ctx, t0, hi, j - i);
        tcg_gen_shli_i64(tcg_ctx, t1, lo, j - i);
        tcg_gen_or_i64(tcg_ctx, hi, hi, t0);
        tcg_gen_or_i64(tcg_ctx, lo, lo, t1);
    }

    c = dup_const(vece, 1);
    tcg_gen_andi_i64(tcg_ctx, hi, hi, c);
    tcg_gen_andi_i64(tcg_ctx, lo, lo, c);

    c = MAKE_64BIT_MASK(0, elem_width);
    tcg_gen_muli_i64(tcg_ctx, hi, hi, c);
    tcg_gen_muli_i64(tcg_ctx, lo, lo, c);

    set_avr64(tcg_ctx, rD(ctx->opcode), lo, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), hi, true);

    tcg_temp_free_i64(tcg_ctx, hi);
    tcg_temp_free_i64(tcg_ctx, lo);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

static void gen_vexpandqm(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 tmp;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, tmp, rB(ctx->opcode), true);
    tcg_gen_sari_i64(tcg_ctx, tmp, tmp, 63);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, true);

    tcg_temp_free_i64(tcg_ctx, tmp);
}

static void gen_vextractm(DisasContext *ctx, unsigned vece)
{
    const uint64_t elem_width = 8 << vece;
    const uint64_t elem_count_half = 8 >> vece;
    const uint64_t mask = dup_const(vece, 1ull << (elem_width - 1));
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 lo;
    TCGv_i64 hi;
    TCGv_i64 t0;
    TCGv_i64 t1;
    uint64_t i;
    uint64_t j;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    hi = tcg_temp_new_i64(tcg_ctx);
    lo = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, lo, rB(ctx->opcode), false);
    get_avr64(tcg_ctx, hi, rB(ctx->opcode), true);

    tcg_gen_andi_i64(tcg_ctx, lo, lo, mask);
    tcg_gen_andi_i64(tcg_ctx, hi, hi, mask);

    for (i = elem_count_half / 2, j = 32; i > 0; i >>= 1, j >>= 1) {
        tcg_gen_shli_i64(tcg_ctx, t0, hi, j - i);
        tcg_gen_shli_i64(tcg_ctx, t1, lo, j - i);
        tcg_gen_or_i64(tcg_ctx, hi, hi, t0);
        tcg_gen_or_i64(tcg_ctx, lo, lo, t1);
    }

    tcg_gen_shri_i64(tcg_ctx, hi, hi, 64 - elem_count_half);
    tcg_gen_extract2_i64(tcg_ctx, lo, lo, hi, 64 - elem_count_half);
    tcg_gen_trunc_i64_tl(tcg_ctx, cpu_gpr[rD(ctx->opcode)], lo);

    tcg_temp_free_i64(tcg_ctx, hi);
    tcg_temp_free_i64(tcg_ctx, lo);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

static void gen_vextractqm(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 tmp;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);

    get_avr64(tcg_ctx, tmp, rB(ctx->opcode), true);
    tcg_gen_shri_i64(tcg_ctx, tmp, tmp, 63);
    tcg_gen_trunc_i64_tl(tcg_ctx, cpu_gpr[rD(ctx->opcode)], tmp);

    tcg_temp_free_i64(tcg_ctx, tmp);
}

static void gen_mtvsrm(DisasContext *ctx, unsigned vece)
{
    const uint64_t elem_width = 8 << vece;
    const uint64_t elem_count_half = 8 >> vece;
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 hi;
    TCGv_i64 lo;
    TCGv_i64 t0;
    TCGv_i64 t1;
    uint64_t c;
    int i;
    int j;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    hi = tcg_temp_new_i64(tcg_ctx);
    lo = tcg_temp_new_i64(tcg_ctx);
    t0 = tcg_temp_new_i64(tcg_ctx);
    t1 = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_extu_tl_i64(tcg_ctx, t0, cpu_gpr[rB(ctx->opcode)]);
    tcg_gen_extract_i64(tcg_ctx, hi, t0, elem_count_half, elem_count_half);
    tcg_gen_extract_i64(tcg_ctx, lo, t0, 0, elem_count_half);

    for (i = elem_count_half / 2, j = 32; i > 0; i >>= 1, j >>= 1) {
        tcg_gen_shli_i64(tcg_ctx, t0, hi, j - i);
        tcg_gen_shli_i64(tcg_ctx, t1, lo, j - i);
        tcg_gen_or_i64(tcg_ctx, hi, hi, t0);
        tcg_gen_or_i64(tcg_ctx, lo, lo, t1);
    }

    c = dup_const(vece, 1);
    tcg_gen_andi_i64(tcg_ctx, hi, hi, c);
    tcg_gen_andi_i64(tcg_ctx, lo, lo, c);

    c = MAKE_64BIT_MASK(0, elem_width);
    tcg_gen_muli_i64(tcg_ctx, hi, hi, c);
    tcg_gen_muli_i64(tcg_ctx, lo, lo, c);

    set_avr64(tcg_ctx, rD(ctx->opcode), lo, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), hi, true);

    tcg_temp_free_i64(tcg_ctx, hi);
    tcg_temp_free_i64(tcg_ctx, lo);
    tcg_temp_free_i64(tcg_ctx, t0);
    tcg_temp_free_i64(tcg_ctx, t1);
}

static void gen_mtvsrqm(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 tmp;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    tmp = tcg_temp_new_i64(tcg_ctx);

    tcg_gen_ext_tl_i64(tcg_ctx, tmp, cpu_gpr[rB(ctx->opcode)]);
    tcg_gen_sextract_i64(tcg_ctx, tmp, tmp, 0, 1);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, false);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, true);

    tcg_temp_free_i64(tcg_ctx, tmp);
}

static void gen_mtvsrbmi(DisasContext *ctx)
{
    const uint64_t mask = dup_const(MO_8, 1);
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 tmp;
    uint16_t b = DX(ctx->opcode);
    uint64_t hi;
    uint64_t lo;
    int i;
    int j;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    hi = extract16(b, 8, 8);
    lo = extract16(b, 0, 8);

    for (i = 4, j = 32; i > 0; i >>= 1, j >>= 1) {
        hi |= hi << (j - i);
        lo |= lo << (j - i);
    }

    hi = (hi & mask) * 0xff;
    lo = (lo & mask) * 0xff;

    tmp = tcg_const_i64(tcg_ctx, lo);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, false);
    tcg_temp_free_i64(tcg_ctx, tmp);

    tmp = tcg_const_i64(tcg_ctx, hi);
    set_avr64(tcg_ctx, rD(ctx->opcode), tmp, true);
    tcg_temp_free_i64(tcg_ctx, tmp);
}

static void gen_vcntmb(DisasContext *ctx, unsigned vece, bool match)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_i64 rt;
    TCGv_i64 vrb;
    TCGv_i64 mask;
    int i;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }

    rt = tcg_const_i64(tcg_ctx, 0);
    vrb = tcg_temp_new_i64(tcg_ctx);
    mask = tcg_const_i64(tcg_ctx, dup_const(vece, 1ull << ((8 << vece) - 1)));

    for (i = 0; i < 2; i++) {
        get_avr64(tcg_ctx, vrb, rB(ctx->opcode), i);
        if (match) {
            tcg_gen_and_i64(tcg_ctx, vrb, mask, vrb);
        } else {
            tcg_gen_andc_i64(tcg_ctx, vrb, mask, vrb);
        }
        tcg_gen_ctpop_i64(tcg_ctx, vrb, vrb);
        tcg_gen_add_i64(tcg_ctx, rt, rt, vrb);
    }

    tcg_gen_shli_i64(tcg_ctx, rt, rt, TARGET_LONG_BITS - 8 + vece);
    tcg_gen_trunc_i64_tl(tcg_ctx, cpu_gpr[rD(ctx->opcode)], rt);

    tcg_temp_free_i64(tcg_ctx, vrb);
    tcg_temp_free_i64(tcg_ctx, rt);
    tcg_temp_free_i64(tcg_ctx, mask);
}

static void gen_vmask_isa310(DisasContext *ctx)
{
    switch (rA(ctx->opcode)) {
    case 0x00:
        return gen_vexpandm(ctx, MO_8);
    case 0x01:
        return gen_vexpandm(ctx, MO_16);
    case 0x02:
        return gen_vexpandm(ctx, MO_32);
    case 0x03:
        return gen_vexpandm(ctx, MO_64);
    case 0x04:
        return gen_vexpandqm(ctx);
    case 0x08:
        return gen_vextractm(ctx, MO_8);
    case 0x09:
        return gen_vextractm(ctx, MO_16);
    case 0x0a:
        return gen_vextractm(ctx, MO_32);
    case 0x0b:
        return gen_vextractm(ctx, MO_64);
    case 0x0c:
        return gen_vextractqm(ctx);
    case 0x10:
        return gen_mtvsrm(ctx, MO_8);
    case 0x11:
        return gen_mtvsrm(ctx, MO_16);
    case 0x12:
        return gen_mtvsrm(ctx, MO_32);
    case 0x13:
        return gen_mtvsrm(ctx, MO_64);
    case 0x14:
        return gen_mtvsrqm(ctx);
    case 0x18:
    case 0x19:
        return gen_vcntmb(ctx, MO_8, rA(ctx->opcode) & 1);
    case 0x1a:
    case 0x1b:
        return gen_vcntmb(ctx, MO_16, rA(ctx->opcode) & 1);
    case 0x1c:
    case 0x1d:
        return gen_vcntmb(ctx, MO_32, rA(ctx->opcode) & 1);
    case 0x1e:
    case 0x1f:
        return gen_vcntmb(ctx, MO_64, rA(ctx->opcode) & 1);
    default:
        gen_invalid(ctx);
        return;
    }
}

GEN_VXFORM(vbpermd, 6, 23);
GEN_VXFORM(vbpermq, 6, 21);
#if defined(TARGET_PPC64)
GEN_VXFORM_DUAL(vbpermd, PPC_NONE, PPC2_ISA300,
                vpdepd, PPC_NONE, PPC2_ISA310)
GEN_VXFORM_DUAL(vbpermq, PPC_NONE, PPC2_ALTIVEC_207,
                vcfuged, PPC_NONE, PPC2_ISA310)
#endif
GEN_VXFORM_TRANS(vgbbd, 6, 20);
GEN_VXFORM(vpmsumb, 4, 16)
GEN_VXFORM(vpmsumh, 4, 17)
GEN_VXFORM(vpmsumw, 4, 18)
GEN_VXFORM(vpmsumd, 4, 19)

#define GEN_BCD(op)                                 \
static void gen_##op(DisasContext *ctx)             \
{                                                   \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;         \
    TCGv_ptr ra, rb, rd;                            \
    TCGv_i32 ps;                                    \
                                                    \
    if (unlikely(!ctx->altivec_enabled)) {          \
        gen_exception(ctx, POWERPC_EXCP_VPU);       \
        return;                                     \
    }                                               \
                                                    \
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));     \
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));     \
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));     \
                                                    \
    ps = tcg_const_i32(tcg_ctx, (ctx->opcode & 0x200) != 0); \
                                                    \
    gen_helper_##op(tcg_ctx, cpu_crf[6], rd, ra, rb, ps);    \
                                                    \
    tcg_temp_free_ptr(tcg_ctx, ra);                 \
    tcg_temp_free_ptr(tcg_ctx, rb);                 \
    tcg_temp_free_ptr(tcg_ctx, rd);                 \
    tcg_temp_free_i32(tcg_ctx, ps);                 \
}

#define GEN_BCD2(op)                                \
static void gen_##op(DisasContext *ctx)             \
{                                                   \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;         \
    TCGv_ptr rd, rb;                                \
    TCGv_i32 ps;                                    \
                                                    \
    if (unlikely(!ctx->altivec_enabled)) {          \
        gen_exception(ctx, POWERPC_EXCP_VPU);       \
        return;                                     \
    }                                               \
                                                    \
    rb = gen_avr_ptr(tcg_ctx, rB(ctx->opcode));     \
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));     \
                                                    \
    ps = tcg_const_i32(tcg_ctx, (ctx->opcode & 0x200) != 0); \
                                                    \
    gen_helper_##op(tcg_ctx, cpu_crf[6], rd, rb, ps);        \
                                                    \
    tcg_temp_free_ptr(tcg_ctx, rb);                 \
    tcg_temp_free_ptr(tcg_ctx, rd);                 \
    tcg_temp_free_i32(tcg_ctx, ps);                 \
}

GEN_BCD(bcdadd)
GEN_BCD(bcdsub)
GEN_BCD2(bcdcfn)
GEN_BCD2(bcdctn)
GEN_BCD2(bcdcfz)
GEN_BCD2(bcdctz)
GEN_BCD2(bcdcfsq)
GEN_BCD2(bcdctsq)
GEN_BCD2(bcdsetsgn)
GEN_BCD(bcdcpsgn);
GEN_BCD(bcds);
GEN_BCD(bcdus);
GEN_BCD(bcdsr);
GEN_BCD(bcdtrunc);
GEN_BCD(bcdutrunc);

static void gen_xpnd04_1(DisasContext *ctx)
{
    switch (opc4(ctx->opcode)) {
    case 0:
        gen_bcdctsq(ctx);
        break;
    case 2:
        gen_bcdcfsq(ctx);
        break;
    case 4:
        gen_bcdctz(ctx);
        break;
    case 5:
        gen_bcdctn(ctx);
        break;
    case 6:
        gen_bcdcfz(ctx);
        break;
    case 7:
        gen_bcdcfn(ctx);
        break;
    case 31:
        gen_bcdsetsgn(ctx);
        break;
    default:
        gen_invalid(ctx);
        break;
    }
}

static void gen_xpnd04_2(DisasContext *ctx)
{
    switch (opc4(ctx->opcode)) {
    case 0:
        gen_bcdctsq(ctx);
        break;
    case 2:
        gen_bcdcfsq(ctx);
        break;
    case 4:
        gen_bcdctz(ctx);
        break;
    case 6:
        gen_bcdcfz(ctx);
        break;
    case 7:
        gen_bcdcfn(ctx);
        break;
    case 31:
        gen_bcdsetsgn(ctx);
        break;
    default:
        gen_invalid(ctx);
        break;
    }
}


GEN_VXFORM_DUAL(vsubcuw, PPC_ALTIVEC, PPC_NONE, \
                xpnd04_1, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_DUAL(vsubsws, PPC_ALTIVEC, PPC_NONE, \
                xpnd04_2, PPC_NONE, PPC2_ISA300)

GEN_VXFORM_DUAL(vsububm, PPC_ALTIVEC, PPC_NONE, \
                bcdadd, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vsububs, PPC_ALTIVEC, PPC_NONE, \
                bcdadd, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vsubuhm, PPC_ALTIVEC, PPC_NONE, \
                bcdsub, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vsubuhs, PPC_ALTIVEC, PPC_NONE, \
                bcdsub, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vaddshs, PPC_ALTIVEC, PPC_NONE, \
                bcdcpsgn, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_DUAL(vsubudm, PPC2_ALTIVEC_207, PPC_NONE, \
                bcds, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_DUAL(vsubuwm, PPC_ALTIVEC, PPC_NONE, \
                bcdus, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_DUAL(vsubsbs, PPC_ALTIVEC, PPC_NONE, \
                bcdtrunc, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_DUAL(vsubuqm, PPC2_ALTIVEC_207, PPC_NONE, \
                bcdtrunc, PPC_NONE, PPC2_ISA300)
GEN_VXFORM_DUAL(vsubcuq, PPC2_ALTIVEC_207, PPC_NONE, \
                bcdutrunc, PPC_NONE, PPC2_ISA300)


static void gen_vsbox(DisasContext *ctx)
{
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;
    TCGv_ptr ra, rd;
    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return;
    }
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));
    gen_helper_vsbox(tcg_ctx, rd, ra);
    tcg_temp_free_ptr(tcg_ctx, ra);
    tcg_temp_free_ptr(tcg_ctx, rd);
}

GEN_VXFORM(vcipher, 4, 20)
GEN_VXFORM(vcipherlast, 4, 20)
GEN_VXFORM(vncipher, 4, 21)
GEN_VXFORM(vncipherlast, 4, 21)

GEN_VXFORM_DUAL(vcipher, PPC_NONE, PPC2_ALTIVEC_207,
                vcipherlast, PPC_NONE, PPC2_ALTIVEC_207)
GEN_VXFORM_DUAL(vncipher, PPC_NONE, PPC2_ALTIVEC_207,
                vncipherlast, PPC_NONE, PPC2_ALTIVEC_207)

#define VSHASIGMA(op)                         \
static void gen_##op(DisasContext *ctx)       \
{                                             \
    TCGContext *tcg_ctx = ctx->uc->tcg_ctx;   \
    TCGv_ptr ra, rd;                          \
    TCGv_i32 st_six;                          \
    if (unlikely(!ctx->altivec_enabled)) {    \
        gen_exception(ctx, POWERPC_EXCP_VPU); \
        return;                               \
    }                                         \
    ra = gen_avr_ptr(tcg_ctx, rA(ctx->opcode));        \
    rd = gen_avr_ptr(tcg_ctx, rD(ctx->opcode));        \
    st_six = tcg_const_i32(tcg_ctx, rB(ctx->opcode));  \
    gen_helper_##op(tcg_ctx, rd, ra, st_six);          \
    tcg_temp_free_ptr(tcg_ctx, ra);           \
    tcg_temp_free_ptr(tcg_ctx, rd);           \
    tcg_temp_free_i32(tcg_ctx, st_six);       \
}

VSHASIGMA(vshasigmaw)
VSHASIGMA(vshasigmad)

GEN_VXFORM3(vpermxor, 22, 0xFF)
GEN_VXFORM_DUAL(vsldoi, PPC_ALTIVEC, PPC_NONE,
                vpermxor, PPC_NONE, PPC2_ALTIVEC_207)

#undef GEN_VR_LDX
#undef GEN_VR_STX
#undef GEN_VR_LVE
#undef GEN_VR_STVE

#undef GEN_VX_LOGICAL
#undef GEN_VX_LOGICAL_207
#undef GEN_VXFORM
#undef GEN_VXFORM_207
#undef GEN_VXFORM_DUAL
#undef GEN_VXRFORM_DUAL
#undef GEN_VXRFORM1
#undef GEN_VXRFORM
#undef GEN_VXFORM_DUPI
#undef GEN_VXFORM_NOA
#undef GEN_VXFORM_UIMM
#undef GEN_VAFORM_PAIRED

#undef GEN_BCD2
