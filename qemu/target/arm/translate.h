#ifndef TARGET_ARM_TRANSLATE_H
#define TARGET_ARM_TRANSLATE_H

#include "exec/translator.h"
#include "internals.h"

struct uc_struct;

/* internal defines */
typedef struct DisasContext {
    DisasContextBase base;
    const ARMISARegisters *isar;

    /* The address of the current instruction being translated. */
    target_ulong pc_curr;
    target_ulong page_start;
    uint32_t insn;
    /* Nonzero if this instruction has been conditionally skipped.  */
    int condjmp;
    /* The label that will be jumped to when the instruction is skipped.  */
    TCGLabel *condlabel;
    /* Thumb-2 conditional execution bits.  */
    int condexec_mask;
    int condexec_cond;
    int thumb;
    int sctlr_b;
    MemOp be_data;
    int user;
    ARMMMUIdx mmu_idx; /* MMU index to use for normal loads/stores */
    uint8_t tbii;      /* TBI1|TBI0 for insns */
    uint8_t tbid;      /* TBI1|TBI0 for data */
    bool ns;        /* Use non-secure CPREG bank on access */
    int fp_excp_el; /* FP exception EL or 0 if enabled */
    int sve_excp_el; /* SVE exception EL or 0 if enabled */
    int sve_len;     /* SVE vector length in bytes */
    /* Flag indicating that exceptions from secure mode are routed to EL3. */
    bool secure_routed_to_el3;
    bool vfp_enabled; /* FP enabled via FPSCR.EN */
    int vec_len;
    int vec_stride;
    bool v7m_handler_mode;
    bool v8m_secure; /* true if v8M and we're in Secure mode */
    bool v8m_stackcheck; /* true if we need to perform v8M stack limit checks */
    bool v8m_fpccr_s_wrong; /* true if v8M FPCCR.S != v8m_secure */
    bool v7m_new_fp_ctxt_needed; /* ASPEN set but no active FP context */
    bool v7m_lspact; /* FPCCR.LSPACT set */
    /* Immediate value in AArch32 SVC insn; must be set if is_jmp == DISAS_SWI
     * so that top level loop can generate correct syndrome information.
     */
    uint32_t svc_imm;
    int aarch64;
    int current_el;
    /* Debug target exception level for single-step exceptions */
    int debug_target_el;
    GHashTable *cp_regs;
    uint64_t features; /* CPU features bits */
    /* Because unallocated encodings generate different exception syndrome
     * information from traps due to FP being disabled, we can't do a single
     * "is fp access disabled" check at a high level in the decode tree.
     * To help in catching bugs where the access check was forgotten in some
     * code path, we set this flag when the access check is done, and assert
     * that it is set at the point where we actually touch the FP regs.
     */
    bool fp_access_checked;
    /* ARMv8 single-step state (this is distinct from the QEMU gdbstub
     * single-step support).
     */
    bool ss_active;
    bool pstate_ss;
    /* True if the insn just emitted was a load-exclusive instruction
     * (necessary for syndrome information for single step exceptions),
     * ie A64 LDX*, LDAX*, A32/T32 LDREX*, LDAEX*.
     */
    bool is_ldex;
    /* True if AccType_UNPRIV should be used for LDTR et al */
    bool unpriv;
    /* True if v8.3-PAuth is active.  */
    bool pauth_active;
    /* True with v8.5-BTI and SCTLR_ELx.BT* set.  */
    bool bt;
    /* True if any CP15 access is trapped by HSTR_EL2 */
    bool hstr_active;
    /*
     * >= 0, a copy of PSTATE.BTYPE, which will be 0 without v8.5-BTI.
     *  < 0, set by the current instruction.
     */
    int8_t btype;
    /* True if this page is guarded.  */
    bool guarded_page;
    /* Bottom two bits of XScale c15_cpar coprocessor access control reg */
    int c15_cpar;
    /* TCG op of the current insn_start.  */
    TCGOp *insn_start;
#define TMP_A64_MAX 16
    int tmp_a64_count;
    TCGv_i64 tmp_a64[TMP_A64_MAX];

    // Unicorn
    struct uc_struct *uc;
} DisasContext;

typedef struct DisasCompare {
    TCGCond cond;
    TCGv_i32 value;
    bool value_global;
} DisasCompare;

static inline int arm_dc_feature(DisasContext *dc, int feature)
{
    return (dc->features & (1ULL << feature)) != 0;
}

static inline int get_mem_index(DisasContext *s)
{
    return arm_to_core_mmu_idx(s->mmu_idx);
}

/* Function used to determine the target exception EL when otherwise not known
 * or default.
 */
static inline int default_exception_el(DisasContext *s)
{
    /* If we are coming from secure EL0 in a system with a 32-bit EL3, then
     * there is no secure EL1, so we route exceptions to EL3.  Otherwise,
     * exceptions can only be routed to ELs above 1, so we target the higher of
     * 1 or the current EL.
     */
    return (s->mmu_idx == ARMMMUIdx_SE10_0 && s->secure_routed_to_el3)
            ? 3 : MAX(1, s->current_el);
}

static inline void disas_set_insn_syndrome(DisasContext *s, uint32_t syn)
{
    /* We don't need to save all of the syndrome so we mask and shift
     * out unneeded bits to help the sleb128 encoder do a better job.
     */
    syn &= ARM_INSN_START_WORD2_MASK;
    syn >>= ARM_INSN_START_WORD2_SHIFT;

    /* We check and clear insn_start_idx to catch multiple updates.  */
    assert(s->insn_start != NULL);
    tcg_set_insn_start_param(s->insn_start, 2, syn);
    s->insn_start = NULL;
}

/* is_jmp field values */
#define DISAS_JUMP      DISAS_TARGET_0 /* only pc was modified dynamically */
#define DISAS_UPDATE    DISAS_TARGET_1 /* cpu state was modified dynamically */
/* These instructions trap after executing, so the A32/T32 decoder must
 * defer them until after the conditional execution state has been updated.
 * WFI also needs special handling when single-stepping.
 */
#define DISAS_WFI       DISAS_TARGET_2
#define DISAS_SWI       DISAS_TARGET_3
/* WFE */
#define DISAS_WFE       DISAS_TARGET_4
#define DISAS_HVC       DISAS_TARGET_5
#define DISAS_SMC       DISAS_TARGET_6
#define DISAS_YIELD     DISAS_TARGET_7
/* M profile branch which might be an exception return (and so needs
 * custom end-of-TB code)
 */
#define DISAS_BX_EXCRET DISAS_TARGET_8
/* For instructions which want an immediate exit to the main loop,
 * as opposed to attempting to use lookup_and_goto_ptr. Unlike
 * DISAS_UPDATE this doesn't write the PC on exiting the translation
 * loop so you need to ensure something (gen_a64_set_pc_im or runtime
 * helper) has done so before we reach return from cpu_tb_exec.
 */
#define DISAS_EXIT      DISAS_TARGET_9

#ifdef TARGET_AARCH64
void a64_translate_init(struct uc_struct *uc);
void gen_a64_set_pc_im(TCGContext *tcg_ctx, uint64_t val);
extern const TranslatorOps aarch64_translator_ops;
#else
static inline void a64_translate_init(struct uc_struct *uc)
{
}

static inline void gen_a64_set_pc_im(uint64_t val)
{
}
#endif

void arm_test_cc(TCGContext *tcg_ctx, DisasCompare *cmp, int cc);
void arm_free_cc(TCGContext *tcg_ctx, DisasCompare *cmp);
void arm_jump_cc(TCGContext *tcg_ctx, DisasCompare *cmp, TCGLabel *label);
void arm_gen_test_cc(TCGContext *tcg_ctx, int cc, TCGLabel *label);

/* Return state of Alternate Half-precision flag, caller frees result */
static inline TCGv_i32 get_ahp_flag(TCGContext *tcg_ctx)
{
    TCGv_i32 ret = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_ld_i32(tcg_ctx, ret, tcg_ctx->cpu_env,
                   offsetof(CPUARMState, vfp.xregs[ARM_VFP_FPSCR]));
    tcg_gen_extract_i32(tcg_ctx, ret, ret, 26, 1);

    return ret;
}

/* Set bits within PSTATE.  */
static inline void set_pstate_bits(TCGContext *tcg_ctx, uint32_t bits)
{
    TCGv_i32 p = tcg_temp_new_i32(tcg_ctx);

    tcg_debug_assert(!(bits & CACHED_PSTATE_BITS));

    tcg_gen_ld_i32(tcg_ctx, p, tcg_ctx->cpu_env, offsetof(CPUARMState, pstate));
    tcg_gen_ori_i32(tcg_ctx, p, p, bits);
    tcg_gen_st_i32(tcg_ctx, p, tcg_ctx->cpu_env, offsetof(CPUARMState, pstate));
    tcg_temp_free_i32(tcg_ctx, p);
}

/* Clear bits within PSTATE.  */
static inline void clear_pstate_bits(TCGContext *tcg_ctx, uint32_t bits)
{
    TCGv_i32 p = tcg_temp_new_i32(tcg_ctx);

    tcg_debug_assert(!(bits & CACHED_PSTATE_BITS));

    tcg_gen_ld_i32(tcg_ctx, p, tcg_ctx->cpu_env, offsetof(CPUARMState, pstate));
    tcg_gen_andi_i32(tcg_ctx, p, p, ~bits);
    tcg_gen_st_i32(tcg_ctx, p, tcg_ctx->cpu_env, offsetof(CPUARMState, pstate));
    tcg_temp_free_i32(tcg_ctx, p);
}

/* If the singlestep state is Active-not-pending, advance to Active-pending. */
static inline void gen_ss_advance(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    if (s->ss_active) {
        s->pstate_ss = 0;
        clear_pstate_bits(tcg_ctx, PSTATE_SS);
    }
}

static inline void gen_exception(TCGContext *tcg_ctx, int excp, uint32_t syndrome,
                                 uint32_t target_el)
{
    TCGv_i32 tcg_excp = tcg_const_i32(tcg_ctx, excp);
    TCGv_i32 tcg_syn = tcg_const_i32(tcg_ctx, syndrome);
    TCGv_i32 tcg_el = tcg_const_i32(tcg_ctx, target_el);

    gen_helper_exception_with_syndrome(tcg_ctx, tcg_ctx->cpu_env, tcg_excp,
                                       tcg_syn, tcg_el);

    tcg_temp_free_i32(tcg_ctx, tcg_el);
    tcg_temp_free_i32(tcg_ctx, tcg_syn);
    tcg_temp_free_i32(tcg_ctx, tcg_excp);
}

/* Generate an architectural singlestep exception */
static inline void gen_swstep_exception(DisasContext *s, int isv, int ex)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    bool same_el = (s->debug_target_el == s->current_el);

    /*
     * If singlestep is targeting a lower EL than the current one,
     * then s->ss_active must be false and we can never get here.
     */
    assert(s->debug_target_el >= s->current_el);

    gen_exception(tcg_ctx, EXCP_UDEF, syn_swstep(same_el, isv, ex), s->debug_target_el);
}

/*
 * Given a VFP floating point constant encoded into an 8 bit immediate in an
 * instruction, expand it to the actual constant value of the specified
 * size, as per the VFPExpandImm() pseudocode in the Arm ARM.
 */
uint64_t vfp_expand_imm(int size, uint8_t imm8);

/* Vector operations shared between ARM and AArch64.  */
extern const GVecGen3 mla_op[4];
extern const GVecGen3 mls_op[4];
extern const GVecGen3 cmtst_op[4];
extern const GVecGen3 sshl_op[4];
extern const GVecGen3 ushl_op[4];
extern const GVecGen2i ssra_op[4];
extern const GVecGen2i usra_op[4];
extern const GVecGen2i sri_op[4];
extern const GVecGen2i sli_op[4];
extern const GVecGen4 uqadd_op[4];
extern const GVecGen4 sqadd_op[4];
extern const GVecGen4 uqsub_op[4];
extern const GVecGen4 sqsub_op[4];
void gen_cmtst_i64(TCGContext *, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b);
void gen_ushl_i32(TCGContext *, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b);
void gen_sshl_i32(TCGContext *, TCGv_i32 d, TCGv_i32 a, TCGv_i32 b);
void gen_ushl_i64(TCGContext *, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b);
void gen_sshl_i64(TCGContext *, TCGv_i64 d, TCGv_i64 a, TCGv_i64 b);

/*
 * Forward to the isar_feature_* tests given a DisasContext pointer.
 */
#define dc_isar_feature(name, ctx) isar_feature_##name(ctx->isar)

#endif /* TARGET_ARM_TRANSLATE_H */
