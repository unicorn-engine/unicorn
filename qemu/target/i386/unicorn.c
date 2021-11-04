/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "uc_priv.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include <unicorn/x86.h> /* needed for uc_x86_mmr */
#include "unicorn.h"

#define FPST(n) (env->fpregs[(env->fpstt + (n)) & 7].d)

#define X86_NON_CS_FLAGS (DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK)
static void load_seg_16_helper(CPUX86State *env, int seg, uint32_t selector)
{
    cpu_x86_load_seg_cache(env, seg, selector, (selector << 4), 0xffff,
                           X86_NON_CS_FLAGS);
}

void cpu_get_fp80(uint64_t *pmant, uint16_t *pexp, floatx80 f);
floatx80 cpu_set_fp80(uint64_t mant, uint16_t upper);

extern void helper_wrmsr(CPUX86State *env);
extern void helper_rdmsr(CPUX86State *env);

static void x86_set_pc(struct uc_struct *uc, uint64_t address)
{
    if (uc->mode == UC_MODE_16) {
        int16_t cs = (uint16_t)X86_CPU(uc->cpu)->env.segs[R_CS].selector;
        ((CPUX86State *)uc->cpu->env_ptr)->eip = address - cs * 16;
    } else
        ((CPUX86State *)uc->cpu->env_ptr)->eip = address;
}

static void x86_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    X86CPU *cpu = (X86CPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;
    X86CPUClass *xcc = X86_CPU_GET_CLASS(cpu);

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }

    free(xcc->model);
}

void x86_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    env->features[FEAT_1_EDX] = CPUID_CX8 | CPUID_CMOV | CPUID_SSE2 |
                                CPUID_FXSR | CPUID_SSE | CPUID_CLFLUSH;
    env->features[FEAT_1_ECX] = CPUID_EXT_SSSE3 | CPUID_EXT_SSE41 |
                                CPUID_EXT_SSE42 | CPUID_EXT_AES |
                                CPUID_EXT_CX16;
    env->features[FEAT_8000_0001_EDX] = CPUID_EXT2_3DNOW | CPUID_EXT2_RDTSCP;
    env->features[FEAT_8000_0001_ECX] = CPUID_EXT3_LAHF_LM | CPUID_EXT3_ABM |
                                        CPUID_EXT3_SKINIT | CPUID_EXT3_CR8LEG;
    env->features[FEAT_7_0_EBX] = CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_BMI2 |
                                  CPUID_7_0_EBX_ADX | CPUID_7_0_EBX_SMAP;

    memset(env->regs, 0, sizeof(env->regs));
    memset(env->segs, 0, sizeof(env->segs));
    memset(env->cr, 0, sizeof(env->cr));

    memset(&env->ldt, 0, sizeof(env->ldt));
    memset(&env->gdt, 0, sizeof(env->gdt));
    memset(&env->tr, 0, sizeof(env->tr));
    memset(&env->idt, 0, sizeof(env->idt));

    env->eip = 0;
    env->eflags = 0;
    env->cc_op = CC_OP_EFLAGS;

    env->fpstt = 0; /* top of stack index */
    env->fpus = 0;
    env->fpuc = 0;
    memset(env->fptags, 0, sizeof(env->fptags)); /* 0 = valid, 1 = empty */

    env->mxcsr = 0;
    memset(env->xmm_regs, 0, sizeof(env->xmm_regs));
    memset(&env->xmm_t0, 0, sizeof(env->xmm_t0));
    memset(&env->mmx_t0, 0, sizeof(env->mmx_t0));

    memset(env->ymmh_regs, 0, sizeof(env->ymmh_regs));

    memset(env->opmask_regs, 0, sizeof(env->opmask_regs));
    memset(env->zmmh_regs, 0, sizeof(env->zmmh_regs));

    /* sysenter registers */
    env->sysenter_cs = 0;
    env->sysenter_esp = 0;
    env->sysenter_eip = 0;
    env->efer = 0;
    env->star = 0;

    env->vm_hsave = 0;

    env->tsc = 0;
    env->tsc_adjust = 0;
    env->tsc_deadline = 0;

    env->mcg_status = 0;
    env->msr_ia32_misc_enable = 0;
    env->msr_ia32_feature_control = 0;

    env->msr_fixed_ctr_ctrl = 0;
    env->msr_global_ctrl = 0;
    env->msr_global_status = 0;
    env->msr_global_ovf_ctrl = 0;
    memset(env->msr_fixed_counters, 0, sizeof(env->msr_fixed_counters));
    memset(env->msr_gp_counters, 0, sizeof(env->msr_gp_counters));
    memset(env->msr_gp_evtsel, 0, sizeof(env->msr_gp_evtsel));

#ifdef TARGET_X86_64
    memset(env->hi16_zmm_regs, 0, sizeof(env->hi16_zmm_regs));
    env->lstar = 0;
    env->cstar = 0;
    env->fmask = 0;
    env->kernelgsbase = 0;
#endif

    // TODO: reset other registers in CPUX86State qemu/target-i386/cpu.h

    // properly initialize internal setup for each mode
    switch (uc->mode) {
    default:
        break;
    case UC_MODE_16:
        env->hflags = 0;
        env->cr[0] = 0;
        // undo the damage done by the memset of env->segs above
        // for R_CS, not quite the same as x86_cpu_reset
        cpu_x86_load_seg_cache(env, R_CS, 0, 0, 0xffff,
                               DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                                   DESC_R_MASK | DESC_A_MASK);
        // remainder yields same state as x86_cpu_reset
        load_seg_16_helper(env, R_DS, 0);
        load_seg_16_helper(env, R_ES, 0);
        load_seg_16_helper(env, R_SS, 0);
        load_seg_16_helper(env, R_FS, 0);
        load_seg_16_helper(env, R_GS, 0);

        break;
    case UC_MODE_32:
        env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_OSFXSR_MASK;
        cpu_x86_update_cr0(env, CR0_PE_MASK); // protected mode
        break;
    case UC_MODE_64:
        env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK |
                       HF_LMA_MASK | HF_OSFXSR_MASK;
        env->hflags &= ~(HF_ADDSEG_MASK);
        env->efer |= MSR_EFER_LMA | MSR_EFER_LME; // extended mode activated
        cpu_x86_update_cr0(env, CR0_PE_MASK);     // protected mode
        /* If we are operating in 64bit mode then add the Long Mode flag
         * to the CPUID feature flag
         */
        env->features[FEAT_8000_0001_EDX] |= CPUID_EXT2_LM;
        break;
    }
}

static int x86_msr_read(CPUX86State *env, uc_x86_msr *msr)
{
    uint64_t ecx = env->regs[R_ECX];
    uint64_t eax = env->regs[R_EAX];
    uint64_t edx = env->regs[R_EDX];

    env->regs[R_ECX] = msr->rid;
    helper_rdmsr(env);

    msr->value = ((uint32_t)env->regs[R_EAX]) |
                 ((uint64_t)((uint32_t)env->regs[R_EDX]) << 32);

    env->regs[R_EAX] = eax;
    env->regs[R_ECX] = ecx;
    env->regs[R_EDX] = edx;

    /* The implementation doesn't throw exception or return an error if there is
     * one, so we will return 0.  */
    return 0;
}

static int x86_msr_write(CPUX86State *env, uc_x86_msr *msr)
{
    uint64_t ecx = env->regs[R_ECX];
    uint64_t eax = env->regs[R_EAX];
    uint64_t edx = env->regs[R_EDX];

    env->regs[R_ECX] = msr->rid;
    env->regs[R_EAX] = (unsigned int)msr->value;
    env->regs[R_EDX] = (unsigned int)(msr->value >> 32);
    helper_wrmsr(env);

    env->regs[R_ECX] = ecx;
    env->regs[R_EAX] = eax;
    env->regs[R_EDX] = edx;

    /* The implementation doesn't throw exception or return an error if there is
     * one, so we will return 0.  */
    return 0;
}

static void reg_read(CPUX86State *env, unsigned int regid, void *value,
                     uc_mode mode)
{
    switch (regid) {
    default:
        break;
    case UC_X86_REG_FP0:
    case UC_X86_REG_FP1:
    case UC_X86_REG_FP2:
    case UC_X86_REG_FP3:
    case UC_X86_REG_FP4:
    case UC_X86_REG_FP5:
    case UC_X86_REG_FP6:
    case UC_X86_REG_FP7: {
        floatx80 reg = env->fpregs[regid - UC_X86_REG_FP0].d;
        cpu_get_fp80(value, (uint16_t *)((char *)value + sizeof(uint64_t)),
                     reg);
    }
        return;
    case UC_X86_REG_FPSW: {
        uint16_t fpus = env->fpus;
        fpus = fpus & ~0x3800;
        fpus |= (env->fpstt & 0x7) << 11;
        *(uint16_t *)value = fpus;
    }
        return;
    case UC_X86_REG_FPCW:
        *(uint16_t *)value = env->fpuc;
        return;
    case UC_X86_REG_FPTAG: {
#define EXPD(fp) (fp.l.upper & 0x7fff)
#define MANTD(fp) (fp.l.lower)
#define MAXEXPD 0x7fff
        int fptag, exp, i;
        uint64_t mant;
        CPU_LDoubleU tmp;
        fptag = 0;
        for (i = 7; i >= 0; i--) {
            fptag <<= 2;
            if (env->fptags[i]) {
                fptag |= 3;
            } else {
                tmp.d = env->fpregs[i].d;
                exp = EXPD(tmp);
                mant = MANTD(tmp);
                if (exp == 0 && mant == 0) {
                    /* zero */
                    fptag |= 1;
                } else if (exp == 0 || exp == MAXEXPD ||
                           (mant & (1LL << 63)) == 0) {
                    /* NaNs, infinity, denormal */
                    fptag |= 2;
                }
            }
        }
        *(uint16_t *)value = fptag;
    }
        return;
    case UC_X86_REG_XMM0:
    case UC_X86_REG_XMM1:
    case UC_X86_REG_XMM2:
    case UC_X86_REG_XMM3:
    case UC_X86_REG_XMM4:
    case UC_X86_REG_XMM5:
    case UC_X86_REG_XMM6:
    case UC_X86_REG_XMM7: {
        float64 *dst = (float64 *)value;
        XMMReg *reg = (XMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
        dst[0] = reg->_d[0];
        dst[1] = reg->_d[1];
        return;
    }
    case UC_X86_REG_ST0:
    case UC_X86_REG_ST1:
    case UC_X86_REG_ST2:
    case UC_X86_REG_ST3:
    case UC_X86_REG_ST4:
    case UC_X86_REG_ST5:
    case UC_X86_REG_ST6:
    case UC_X86_REG_ST7: {
        // value must be big enough to keep 80 bits (10 bytes)
        memcpy(value, &FPST(regid - UC_X86_REG_ST0), 10);
        return;
    }
    case UC_X86_REG_YMM0:
    case UC_X86_REG_YMM1:
    case UC_X86_REG_YMM2:
    case UC_X86_REG_YMM3:
    case UC_X86_REG_YMM4:
    case UC_X86_REG_YMM5:
    case UC_X86_REG_YMM6:
    case UC_X86_REG_YMM7:
    case UC_X86_REG_YMM8:
    case UC_X86_REG_YMM9:
    case UC_X86_REG_YMM10:
    case UC_X86_REG_YMM11:
    case UC_X86_REG_YMM12:
    case UC_X86_REG_YMM13:
    case UC_X86_REG_YMM14:
    case UC_X86_REG_YMM15: {
        float64 *dst = (float64 *)value;
        XMMReg *lo_reg = (XMMReg *)&env->xmm_regs[regid - UC_X86_REG_YMM0];
        XMMReg *hi_reg = &env->ymmh_regs[regid - UC_X86_REG_YMM0];
        dst[0] = lo_reg->_d[0];
        dst[1] = lo_reg->_d[1];
        dst[2] = hi_reg->_d[0];
        dst[3] = hi_reg->_d[1];
        return;
    }
    }

    switch (mode) {
    default:
        break;
    case UC_MODE_16:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_ES:
            *(int16_t *)value = env->segs[R_ES].selector;
            return;
        case UC_X86_REG_SS:
            *(int16_t *)value = env->segs[R_SS].selector;
            return;
        case UC_X86_REG_DS:
            *(int16_t *)value = env->segs[R_DS].selector;
            return;
        case UC_X86_REG_FS:
            *(int16_t *)value = env->segs[R_FS].selector;
            return;
        case UC_X86_REG_GS:
            *(int16_t *)value = env->segs[R_GS].selector;
            return;
        case UC_X86_REG_FS_BASE:
            *(uint32_t *)value = (uint32_t)env->segs[R_FS].base;
            return;
        }
        // fall-thru
    case UC_MODE_32:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            *(int32_t *)value = env->cr[regid - UC_X86_REG_CR0];
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            *(int32_t *)value = env->dr[regid - UC_X86_REG_DR0];
            break;
        case UC_X86_REG_FLAGS:
            *(int16_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_EFLAGS:
            *(int32_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_EAX:
            *(int32_t *)value = env->regs[R_EAX];
            break;
        case UC_X86_REG_AX:
            *(int16_t *)value = READ_WORD(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EAX]);
            break;
        case UC_X86_REG_EBX:
            *(int32_t *)value = env->regs[R_EBX];
            break;
        case UC_X86_REG_BX:
            *(int16_t *)value = READ_WORD(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EBX]);
            break;
        case UC_X86_REG_ECX:
            *(int32_t *)value = env->regs[R_ECX];
            break;
        case UC_X86_REG_CX:
            *(int16_t *)value = READ_WORD(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ECX]);
            break;
        case UC_X86_REG_EDX:
            *(int32_t *)value = env->regs[R_EDX];
            break;
        case UC_X86_REG_DX:
            *(int16_t *)value = READ_WORD(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EDX]);
            break;
        case UC_X86_REG_ESP:
            *(int32_t *)value = env->regs[R_ESP];
            break;
        case UC_X86_REG_SP:
            *(int16_t *)value = READ_WORD(env->regs[R_ESP]);
            break;
        case UC_X86_REG_EBP:
            *(int32_t *)value = env->regs[R_EBP];
            break;
        case UC_X86_REG_BP:
            *(int16_t *)value = READ_WORD(env->regs[R_EBP]);
            break;
        case UC_X86_REG_ESI:
            *(int32_t *)value = env->regs[R_ESI];
            break;
        case UC_X86_REG_SI:
            *(int16_t *)value = READ_WORD(env->regs[R_ESI]);
            break;
        case UC_X86_REG_EDI:
            *(int32_t *)value = env->regs[R_EDI];
            break;
        case UC_X86_REG_DI:
            *(int16_t *)value = READ_WORD(env->regs[R_EDI]);
            break;
        case UC_X86_REG_EIP:
            *(int32_t *)value = env->eip;
            break;
        case UC_X86_REG_IP:
            *(int16_t *)value = READ_WORD(env->eip);
            break;
        case UC_X86_REG_CS:
            *(int16_t *)value = (uint16_t)env->segs[R_CS].selector;
            break;
        case UC_X86_REG_DS:
            *(int16_t *)value = (uint16_t)env->segs[R_DS].selector;
            break;
        case UC_X86_REG_SS:
            *(int16_t *)value = (uint16_t)env->segs[R_SS].selector;
            break;
        case UC_X86_REG_ES:
            *(int16_t *)value = (uint16_t)env->segs[R_ES].selector;
            break;
        case UC_X86_REG_FS:
            *(int16_t *)value = (uint16_t)env->segs[R_FS].selector;
            break;
        case UC_X86_REG_GS:
            *(int16_t *)value = (uint16_t)env->segs[R_GS].selector;
            break;
        case UC_X86_REG_IDTR:
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->idt.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->idt.base;
            break;
        case UC_X86_REG_GDTR:
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->gdt.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->gdt.base;
            break;
        case UC_X86_REG_LDTR:
            ((uc_x86_mmr *)value)->limit = env->ldt.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->ldt.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->ldt.selector;
            ((uc_x86_mmr *)value)->flags = env->ldt.flags;
            break;
        case UC_X86_REG_TR:
            ((uc_x86_mmr *)value)->limit = env->tr.limit;
            ((uc_x86_mmr *)value)->base = (uint32_t)env->tr.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->tr.selector;
            ((uc_x86_mmr *)value)->flags = env->tr.flags;
            break;
        case UC_X86_REG_MSR:
            x86_msr_read(env, (uc_x86_msr *)value);
            break;
        case UC_X86_REG_MXCSR:
            *(uint32_t *)value = env->mxcsr;
            break;
        case UC_X86_REG_FS_BASE:
            *(uint32_t *)value = (uint32_t)env->segs[R_FS].base;
            break;
        }
        break;

#ifdef TARGET_X86_64
    case UC_MODE_64:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            *(int64_t *)value = env->cr[regid - UC_X86_REG_CR0];
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            *(int64_t *)value = env->dr[regid - UC_X86_REG_DR0];
            break;
        case UC_X86_REG_FLAGS:
            *(int16_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_EFLAGS:
            *(int32_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_RFLAGS:
            *(int64_t *)value = cpu_compute_eflags(env);
            break;
        case UC_X86_REG_RAX:
            *(uint64_t *)value = env->regs[R_EAX];
            break;
        case UC_X86_REG_EAX:
            *(int32_t *)value = READ_DWORD(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AX:
            *(int16_t *)value = READ_WORD(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EAX]);
            break;
        case UC_X86_REG_AL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EAX]);
            break;
        case UC_X86_REG_RBX:
            *(uint64_t *)value = env->regs[R_EBX];
            break;
        case UC_X86_REG_EBX:
            *(int32_t *)value = READ_DWORD(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BX:
            *(int16_t *)value = READ_WORD(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EBX]);
            break;
        case UC_X86_REG_BL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EBX]);
            break;
        case UC_X86_REG_RCX:
            *(uint64_t *)value = env->regs[R_ECX];
            break;
        case UC_X86_REG_ECX:
            *(int32_t *)value = READ_DWORD(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CX:
            *(int16_t *)value = READ_WORD(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_ECX]);
            break;
        case UC_X86_REG_CL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ECX]);
            break;
        case UC_X86_REG_RDX:
            *(uint64_t *)value = env->regs[R_EDX];
            break;
        case UC_X86_REG_EDX:
            *(int32_t *)value = READ_DWORD(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DX:
            *(int16_t *)value = READ_WORD(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DH:
            *(int8_t *)value = READ_BYTE_H(env->regs[R_EDX]);
            break;
        case UC_X86_REG_DL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EDX]);
            break;
        case UC_X86_REG_RSP:
            *(uint64_t *)value = env->regs[R_ESP];
            break;
        case UC_X86_REG_ESP:
            *(int32_t *)value = READ_DWORD(env->regs[R_ESP]);
            break;
        case UC_X86_REG_SP:
            *(int16_t *)value = READ_WORD(env->regs[R_ESP]);
            break;
        case UC_X86_REG_SPL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ESP]);
            break;
        case UC_X86_REG_RBP:
            *(uint64_t *)value = env->regs[R_EBP];
            break;
        case UC_X86_REG_EBP:
            *(int32_t *)value = READ_DWORD(env->regs[R_EBP]);
            break;
        case UC_X86_REG_BP:
            *(int16_t *)value = READ_WORD(env->regs[R_EBP]);
            break;
        case UC_X86_REG_BPL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EBP]);
            break;
        case UC_X86_REG_RSI:
            *(uint64_t *)value = env->regs[R_ESI];
            break;
        case UC_X86_REG_ESI:
            *(int32_t *)value = READ_DWORD(env->regs[R_ESI]);
            break;
        case UC_X86_REG_SI:
            *(int16_t *)value = READ_WORD(env->regs[R_ESI]);
            break;
        case UC_X86_REG_SIL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_ESI]);
            break;
        case UC_X86_REG_RDI:
            *(uint64_t *)value = env->regs[R_EDI];
            break;
        case UC_X86_REG_EDI:
            *(int32_t *)value = READ_DWORD(env->regs[R_EDI]);
            break;
        case UC_X86_REG_DI:
            *(int16_t *)value = READ_WORD(env->regs[R_EDI]);
            break;
        case UC_X86_REG_DIL:
            *(int8_t *)value = READ_BYTE_L(env->regs[R_EDI]);
            break;
        case UC_X86_REG_RIP:
            *(uint64_t *)value = env->eip;
            break;
        case UC_X86_REG_EIP:
            *(int32_t *)value = READ_DWORD(env->eip);
            break;
        case UC_X86_REG_IP:
            *(int16_t *)value = READ_WORD(env->eip);
            break;
        case UC_X86_REG_CS:
            *(int16_t *)value = (uint16_t)env->segs[R_CS].selector;
            break;
        case UC_X86_REG_DS:
            *(int16_t *)value = (uint16_t)env->segs[R_DS].selector;
            break;
        case UC_X86_REG_SS:
            *(int16_t *)value = (uint16_t)env->segs[R_SS].selector;
            break;
        case UC_X86_REG_ES:
            *(int16_t *)value = (uint16_t)env->segs[R_ES].selector;
            break;
        case UC_X86_REG_FS:
            *(int16_t *)value = (uint16_t)env->segs[R_FS].selector;
            break;
        case UC_X86_REG_GS:
            *(int16_t *)value = (uint16_t)env->segs[R_GS].selector;
            break;
        case UC_X86_REG_R8:
            *(int64_t *)value = READ_QWORD(env->regs[8]);
            break;
        case UC_X86_REG_R8D:
            *(int32_t *)value = READ_DWORD(env->regs[8]);
            break;
        case UC_X86_REG_R8W:
            *(int16_t *)value = READ_WORD(env->regs[8]);
            break;
        case UC_X86_REG_R8B:
            *(int8_t *)value = READ_BYTE_L(env->regs[8]);
            break;
        case UC_X86_REG_R9:
            *(int64_t *)value = READ_QWORD(env->regs[9]);
            break;
        case UC_X86_REG_R9D:
            *(int32_t *)value = READ_DWORD(env->regs[9]);
            break;
        case UC_X86_REG_R9W:
            *(int16_t *)value = READ_WORD(env->regs[9]);
            break;
        case UC_X86_REG_R9B:
            *(int8_t *)value = READ_BYTE_L(env->regs[9]);
            break;
        case UC_X86_REG_R10:
            *(int64_t *)value = READ_QWORD(env->regs[10]);
            break;
        case UC_X86_REG_R10D:
            *(int32_t *)value = READ_DWORD(env->regs[10]);
            break;
        case UC_X86_REG_R10W:
            *(int16_t *)value = READ_WORD(env->regs[10]);
            break;
        case UC_X86_REG_R10B:
            *(int8_t *)value = READ_BYTE_L(env->regs[10]);
            break;
        case UC_X86_REG_R11:
            *(int64_t *)value = READ_QWORD(env->regs[11]);
            break;
        case UC_X86_REG_R11D:
            *(int32_t *)value = READ_DWORD(env->regs[11]);
            break;
        case UC_X86_REG_R11W:
            *(int16_t *)value = READ_WORD(env->regs[11]);
            break;
        case UC_X86_REG_R11B:
            *(int8_t *)value = READ_BYTE_L(env->regs[11]);
            break;
        case UC_X86_REG_R12:
            *(int64_t *)value = READ_QWORD(env->regs[12]);
            break;
        case UC_X86_REG_R12D:
            *(int32_t *)value = READ_DWORD(env->regs[12]);
            break;
        case UC_X86_REG_R12W:
            *(int16_t *)value = READ_WORD(env->regs[12]);
            break;
        case UC_X86_REG_R12B:
            *(int8_t *)value = READ_BYTE_L(env->regs[12]);
            break;
        case UC_X86_REG_R13:
            *(int64_t *)value = READ_QWORD(env->regs[13]);
            break;
        case UC_X86_REG_R13D:
            *(int32_t *)value = READ_DWORD(env->regs[13]);
            break;
        case UC_X86_REG_R13W:
            *(int16_t *)value = READ_WORD(env->regs[13]);
            break;
        case UC_X86_REG_R13B:
            *(int8_t *)value = READ_BYTE_L(env->regs[13]);
            break;
        case UC_X86_REG_R14:
            *(int64_t *)value = READ_QWORD(env->regs[14]);
            break;
        case UC_X86_REG_R14D:
            *(int32_t *)value = READ_DWORD(env->regs[14]);
            break;
        case UC_X86_REG_R14W:
            *(int16_t *)value = READ_WORD(env->regs[14]);
            break;
        case UC_X86_REG_R14B:
            *(int8_t *)value = READ_BYTE_L(env->regs[14]);
            break;
        case UC_X86_REG_R15:
            *(int64_t *)value = READ_QWORD(env->regs[15]);
            break;
        case UC_X86_REG_R15D:
            *(int32_t *)value = READ_DWORD(env->regs[15]);
            break;
        case UC_X86_REG_R15W:
            *(int16_t *)value = READ_WORD(env->regs[15]);
            break;
        case UC_X86_REG_R15B:
            *(int8_t *)value = READ_BYTE_L(env->regs[15]);
            break;
        case UC_X86_REG_IDTR:
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->idt.limit;
            ((uc_x86_mmr *)value)->base = env->idt.base;
            break;
        case UC_X86_REG_GDTR:
            ((uc_x86_mmr *)value)->limit = (uint16_t)env->gdt.limit;
            ((uc_x86_mmr *)value)->base = env->gdt.base;
            break;
        case UC_X86_REG_LDTR:
            ((uc_x86_mmr *)value)->limit = env->ldt.limit;
            ((uc_x86_mmr *)value)->base = env->ldt.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->ldt.selector;
            ((uc_x86_mmr *)value)->flags = env->ldt.flags;
            break;
        case UC_X86_REG_TR:
            ((uc_x86_mmr *)value)->limit = env->tr.limit;
            ((uc_x86_mmr *)value)->base = env->tr.base;
            ((uc_x86_mmr *)value)->selector = (uint16_t)env->tr.selector;
            ((uc_x86_mmr *)value)->flags = env->tr.flags;
            break;
        case UC_X86_REG_MSR:
            x86_msr_read(env, (uc_x86_msr *)value);
            break;
        case UC_X86_REG_MXCSR:
            *(uint32_t *)value = env->mxcsr;
            break;
        case UC_X86_REG_XMM8:
        case UC_X86_REG_XMM9:
        case UC_X86_REG_XMM10:
        case UC_X86_REG_XMM11:
        case UC_X86_REG_XMM12:
        case UC_X86_REG_XMM13:
        case UC_X86_REG_XMM14:
        case UC_X86_REG_XMM15: {
            float64 *dst = (float64 *)value;
            XMMReg *reg = (XMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
            dst[0] = reg->_d[0];
            dst[1] = reg->_d[1];
            break;
        }
        case UC_X86_REG_FS_BASE:
            *(uint64_t *)value = (uint64_t)env->segs[R_FS].base;
            break;
        case UC_X86_REG_GS_BASE:
            *(uint64_t *)value = (uint64_t)env->segs[R_GS].base;
            break;
        }
        break;
#endif
    }

    return;
}

static int reg_write(CPUX86State *env, unsigned int regid, const void *value,
                     uc_mode mode)
{
    int ret;

    switch (regid) {
    default:
        break;
    case UC_X86_REG_FP0:
    case UC_X86_REG_FP1:
    case UC_X86_REG_FP2:
    case UC_X86_REG_FP3:
    case UC_X86_REG_FP4:
    case UC_X86_REG_FP5:
    case UC_X86_REG_FP6:
    case UC_X86_REG_FP7: {
        uint64_t mant = *(uint64_t *)value;
        uint16_t upper = *(uint16_t *)((char *)value + sizeof(uint64_t));
        env->fpregs[regid - UC_X86_REG_FP0].d = cpu_set_fp80(mant, upper);
    }
        return 0;
    case UC_X86_REG_FPSW: {
        uint16_t fpus = *(uint16_t *)value;
        env->fpus = fpus & ~0x3800;
        env->fpstt = (fpus >> 11) & 0x7;
    }
        return 0;
    case UC_X86_REG_FPCW:
        cpu_set_fpuc(env, *(uint16_t *)value);
        return 0;
    case UC_X86_REG_FPTAG: {
        int i;
        uint16_t fptag = *(uint16_t *)value;
        for (i = 0; i < 8; i++) {
            env->fptags[i] = ((fptag & 3) == 3);
            fptag >>= 2;
        }

        return 0;
    } break;
    case UC_X86_REG_XMM0:
    case UC_X86_REG_XMM1:
    case UC_X86_REG_XMM2:
    case UC_X86_REG_XMM3:
    case UC_X86_REG_XMM4:
    case UC_X86_REG_XMM5:
    case UC_X86_REG_XMM6:
    case UC_X86_REG_XMM7: {
        float64 *src = (float64 *)value;
        XMMReg *reg = (XMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
        reg->_d[0] = src[0];
        reg->_d[1] = src[1];
        return 0;
    }
    case UC_X86_REG_ST0:
    case UC_X86_REG_ST1:
    case UC_X86_REG_ST2:
    case UC_X86_REG_ST3:
    case UC_X86_REG_ST4:
    case UC_X86_REG_ST5:
    case UC_X86_REG_ST6:
    case UC_X86_REG_ST7: {
        // value must be big enough to keep 80 bits (10 bytes)
        memcpy(&FPST(regid - UC_X86_REG_ST0), value, 10);
        return 0;
    }
    case UC_X86_REG_YMM0:
    case UC_X86_REG_YMM1:
    case UC_X86_REG_YMM2:
    case UC_X86_REG_YMM3:
    case UC_X86_REG_YMM4:
    case UC_X86_REG_YMM5:
    case UC_X86_REG_YMM6:
    case UC_X86_REG_YMM7:
    case UC_X86_REG_YMM8:
    case UC_X86_REG_YMM9:
    case UC_X86_REG_YMM10:
    case UC_X86_REG_YMM11:
    case UC_X86_REG_YMM12:
    case UC_X86_REG_YMM13:
    case UC_X86_REG_YMM14:
    case UC_X86_REG_YMM15: {
        float64 *src = (float64 *)value;
        XMMReg *lo_reg = (XMMReg *)&env->xmm_regs[regid - UC_X86_REG_YMM0];
        XMMReg *hi_reg = &env->ymmh_regs[regid - UC_X86_REG_YMM0];
        lo_reg->_d[0] = src[0];
        lo_reg->_d[1] = src[1];
        hi_reg->_d[0] = src[2];
        hi_reg->_d[1] = src[3];
        return 0;
    }
    }

    switch (mode) {
    default:
        break;

    case UC_MODE_16:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_ES:
            load_seg_16_helper(env, R_ES, *(uint16_t *)value);
            return 0;
        case UC_X86_REG_SS:
            load_seg_16_helper(env, R_SS, *(uint16_t *)value);
            return 0;
        case UC_X86_REG_DS:
            load_seg_16_helper(env, R_DS, *(uint16_t *)value);
            return 0;
        case UC_X86_REG_FS:
            load_seg_16_helper(env, R_FS, *(uint16_t *)value);
            return 0;
        case UC_X86_REG_GS:
            load_seg_16_helper(env, R_GS, *(uint16_t *)value);
            return 0;
        }
        // fall-thru
    case UC_MODE_32:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            env->cr[regid - UC_X86_REG_CR0] = *(uint32_t *)value;
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            env->dr[regid - UC_X86_REG_DR0] = *(uint32_t *)value;
            break;
        case UC_X86_REG_FLAGS:
            cpu_load_eflags(env, *(uint16_t *)value, -1);
            break;
        case UC_X86_REG_EFLAGS:
            cpu_load_eflags(env, *(uint32_t *)value, -1);
            break;
        case UC_X86_REG_EAX:
            env->regs[R_EAX] = *(uint32_t *)value;
            break;
        case UC_X86_REG_AX:
            WRITE_WORD(env->regs[R_EAX], *(uint16_t *)value);
            break;
        case UC_X86_REG_AH:
            WRITE_BYTE_H(env->regs[R_EAX], *(uint8_t *)value);
            break;
        case UC_X86_REG_AL:
            WRITE_BYTE_L(env->regs[R_EAX], *(uint8_t *)value);
            break;
        case UC_X86_REG_EBX:
            env->regs[R_EBX] = *(uint32_t *)value;
            break;
        case UC_X86_REG_BX:
            WRITE_WORD(env->regs[R_EBX], *(uint16_t *)value);
            break;
        case UC_X86_REG_BH:
            WRITE_BYTE_H(env->regs[R_EBX], *(uint8_t *)value);
            break;
        case UC_X86_REG_BL:
            WRITE_BYTE_L(env->regs[R_EBX], *(uint8_t *)value);
            break;
        case UC_X86_REG_ECX:
            env->regs[R_ECX] = *(uint32_t *)value;
            break;
        case UC_X86_REG_CX:
            WRITE_WORD(env->regs[R_ECX], *(uint16_t *)value);
            break;
        case UC_X86_REG_CH:
            WRITE_BYTE_H(env->regs[R_ECX], *(uint8_t *)value);
            break;
        case UC_X86_REG_CL:
            WRITE_BYTE_L(env->regs[R_ECX], *(uint8_t *)value);
            break;
        case UC_X86_REG_EDX:
            env->regs[R_EDX] = *(uint32_t *)value;
            break;
        case UC_X86_REG_DX:
            WRITE_WORD(env->regs[R_EDX], *(uint16_t *)value);
            break;
        case UC_X86_REG_DH:
            WRITE_BYTE_H(env->regs[R_EDX], *(uint8_t *)value);
            break;
        case UC_X86_REG_DL:
            WRITE_BYTE_L(env->regs[R_EDX], *(uint8_t *)value);
            break;
        case UC_X86_REG_ESP:
            env->regs[R_ESP] = *(uint32_t *)value;
            break;
        case UC_X86_REG_SP:
            WRITE_WORD(env->regs[R_ESP], *(uint16_t *)value);
            break;
        case UC_X86_REG_EBP:
            env->regs[R_EBP] = *(uint32_t *)value;
            break;
        case UC_X86_REG_BP:
            WRITE_WORD(env->regs[R_EBP], *(uint16_t *)value);
            break;
        case UC_X86_REG_ESI:
            env->regs[R_ESI] = *(uint32_t *)value;
            break;
        case UC_X86_REG_SI:
            WRITE_WORD(env->regs[R_ESI], *(uint16_t *)value);
            break;
        case UC_X86_REG_EDI:
            env->regs[R_EDI] = *(uint32_t *)value;
            break;
        case UC_X86_REG_DI:
            WRITE_WORD(env->regs[R_EDI], *(uint16_t *)value);
            break;
        case UC_X86_REG_EIP:
            env->eip = *(uint32_t *)value;
            break;
        case UC_X86_REG_IP:
            env->eip = *(uint16_t *)value;
            break;
        case UC_X86_REG_CS:
            ret = uc_check_cpu_x86_load_seg(env, R_CS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_CS, *(uint16_t *)value);
            break;
        case UC_X86_REG_DS:
            ret = uc_check_cpu_x86_load_seg(env, R_DS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_DS, *(uint16_t *)value);
            break;
        case UC_X86_REG_SS:
            ret = uc_check_cpu_x86_load_seg(env, R_SS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_SS, *(uint16_t *)value);
            break;
        case UC_X86_REG_ES:
            ret = uc_check_cpu_x86_load_seg(env, R_ES, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_ES, *(uint16_t *)value);
            break;
        case UC_X86_REG_FS:
            ret = uc_check_cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            break;
        case UC_X86_REG_GS:
            ret = uc_check_cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            break;
        case UC_X86_REG_IDTR:
            env->idt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->idt.base = (uint32_t)((uc_x86_mmr *)value)->base;
            break;
        case UC_X86_REG_GDTR:
            env->gdt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->gdt.base = (uint32_t)((uc_x86_mmr *)value)->base;
            break;
        case UC_X86_REG_LDTR:
            env->ldt.limit = ((uc_x86_mmr *)value)->limit;
            env->ldt.base = (uint32_t)((uc_x86_mmr *)value)->base;
            env->ldt.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->ldt.flags = ((uc_x86_mmr *)value)->flags;
            break;
        case UC_X86_REG_TR:
            env->tr.limit = ((uc_x86_mmr *)value)->limit;
            env->tr.base = (uint32_t)((uc_x86_mmr *)value)->base;
            env->tr.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->tr.flags = ((uc_x86_mmr *)value)->flags;
            break;
        case UC_X86_REG_MSR:
            x86_msr_write(env, (uc_x86_msr *)value);
            break;
        case UC_X86_REG_MXCSR:
            cpu_set_mxcsr(env, *(uint32_t *)value);
            break;
            /*
        // Don't think base registers are a "thing" on x86
        case UC_X86_REG_FS_BASE:
            env->segs[R_FS].base = *(uint32_t *)value;
            continue;
        case UC_X86_REG_GS_BASE:
            env->segs[R_GS].base = *(uint32_t *)value;
            continue;
            */
        }
        break;

#ifdef TARGET_X86_64
    case UC_MODE_64:
        switch (regid) {
        default:
            break;
        case UC_X86_REG_CR0:
        case UC_X86_REG_CR1:
        case UC_X86_REG_CR2:
        case UC_X86_REG_CR3:
        case UC_X86_REG_CR4:
            env->cr[regid - UC_X86_REG_CR0] = *(uint64_t *)value;
            break;
        case UC_X86_REG_DR0:
        case UC_X86_REG_DR1:
        case UC_X86_REG_DR2:
        case UC_X86_REG_DR3:
        case UC_X86_REG_DR4:
        case UC_X86_REG_DR5:
        case UC_X86_REG_DR6:
        case UC_X86_REG_DR7:
            env->dr[regid - UC_X86_REG_DR0] = *(uint64_t *)value;
            break;
        case UC_X86_REG_FLAGS:
            cpu_load_eflags(env, *(uint16_t *)value, -1);
            break;
        case UC_X86_REG_EFLAGS:
            cpu_load_eflags(env, *(uint32_t *)value, -1);
            break;
        case UC_X86_REG_RFLAGS:
            cpu_load_eflags(env, *(uint64_t *)value, -1);
            break;
        case UC_X86_REG_RAX:
            env->regs[R_EAX] = *(uint64_t *)value;
            break;
        case UC_X86_REG_EAX:
            WRITE_DWORD(env->regs[R_EAX], *(uint32_t *)value);
            break;
        case UC_X86_REG_AX:
            WRITE_WORD(env->regs[R_EAX], *(uint16_t *)value);
            break;
        case UC_X86_REG_AH:
            WRITE_BYTE_H(env->regs[R_EAX], *(uint8_t *)value);
            break;
        case UC_X86_REG_AL:
            WRITE_BYTE_L(env->regs[R_EAX], *(uint8_t *)value);
            break;
        case UC_X86_REG_RBX:
            env->regs[R_EBX] = *(uint64_t *)value;
            break;
        case UC_X86_REG_EBX:
            WRITE_DWORD(env->regs[R_EBX], *(uint32_t *)value);
            break;
        case UC_X86_REG_BX:
            WRITE_WORD(env->regs[R_EBX], *(uint16_t *)value);
            break;
        case UC_X86_REG_BH:
            WRITE_BYTE_H(env->regs[R_EBX], *(uint8_t *)value);
            break;
        case UC_X86_REG_BL:
            WRITE_BYTE_L(env->regs[R_EBX], *(uint8_t *)value);
            break;
        case UC_X86_REG_RCX:
            env->regs[R_ECX] = *(uint64_t *)value;
            break;
        case UC_X86_REG_ECX:
            WRITE_DWORD(env->regs[R_ECX], *(uint32_t *)value);
            break;
        case UC_X86_REG_CX:
            WRITE_WORD(env->regs[R_ECX], *(uint16_t *)value);
            break;
        case UC_X86_REG_CH:
            WRITE_BYTE_H(env->regs[R_ECX], *(uint8_t *)value);
            break;
        case UC_X86_REG_CL:
            WRITE_BYTE_L(env->regs[R_ECX], *(uint8_t *)value);
            break;
        case UC_X86_REG_RDX:
            env->regs[R_EDX] = *(uint64_t *)value;
            break;
        case UC_X86_REG_EDX:
            WRITE_DWORD(env->regs[R_EDX], *(uint32_t *)value);
            break;
        case UC_X86_REG_DX:
            WRITE_WORD(env->regs[R_EDX], *(uint16_t *)value);
            break;
        case UC_X86_REG_DH:
            WRITE_BYTE_H(env->regs[R_EDX], *(uint8_t *)value);
            break;
        case UC_X86_REG_DL:
            WRITE_BYTE_L(env->regs[R_EDX], *(uint8_t *)value);
            break;
        case UC_X86_REG_RSP:
            env->regs[R_ESP] = *(uint64_t *)value;
            break;
        case UC_X86_REG_ESP:
            WRITE_DWORD(env->regs[R_ESP], *(uint32_t *)value);
            break;
        case UC_X86_REG_SP:
            WRITE_WORD(env->regs[R_ESP], *(uint16_t *)value);
            break;
        case UC_X86_REG_SPL:
            WRITE_BYTE_L(env->regs[R_ESP], *(uint8_t *)value);
            break;
        case UC_X86_REG_RBP:
            env->regs[R_EBP] = *(uint64_t *)value;
            break;
        case UC_X86_REG_EBP:
            WRITE_DWORD(env->regs[R_EBP], *(uint32_t *)value);
            break;
        case UC_X86_REG_BP:
            WRITE_WORD(env->regs[R_EBP], *(uint16_t *)value);
            break;
        case UC_X86_REG_BPL:
            WRITE_BYTE_L(env->regs[R_EBP], *(uint8_t *)value);
            break;
        case UC_X86_REG_RSI:
            env->regs[R_ESI] = *(uint64_t *)value;
            break;
        case UC_X86_REG_ESI:
            WRITE_DWORD(env->regs[R_ESI], *(uint32_t *)value);
            break;
        case UC_X86_REG_SI:
            WRITE_WORD(env->regs[R_ESI], *(uint16_t *)value);
            break;
        case UC_X86_REG_SIL:
            WRITE_BYTE_L(env->regs[R_ESI], *(uint8_t *)value);
            break;
        case UC_X86_REG_RDI:
            env->regs[R_EDI] = *(uint64_t *)value;
            break;
        case UC_X86_REG_EDI:
            WRITE_DWORD(env->regs[R_EDI], *(uint32_t *)value);
            break;
        case UC_X86_REG_DI:
            WRITE_WORD(env->regs[R_EDI], *(uint16_t *)value);
            break;
        case UC_X86_REG_DIL:
            WRITE_BYTE_L(env->regs[R_EDI], *(uint8_t *)value);
            break;
        case UC_X86_REG_RIP:
            env->eip = *(uint64_t *)value;
            break;
        case UC_X86_REG_EIP:
            env->eip = *(uint32_t *)value;
            break;
        case UC_X86_REG_IP:
            WRITE_WORD(env->eip, *(uint16_t *)value);
            break;
        case UC_X86_REG_CS:
            env->segs[R_CS].selector = *(uint16_t *)value;
            break;
        case UC_X86_REG_DS:
            env->segs[R_DS].selector = *(uint16_t *)value;
            break;
        case UC_X86_REG_SS:
            env->segs[R_SS].selector = *(uint16_t *)value;
            break;
        case UC_X86_REG_ES:
            env->segs[R_ES].selector = *(uint16_t *)value;
            break;
        case UC_X86_REG_FS:
            ret = uc_check_cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_FS, *(uint16_t *)value);
            break;
        case UC_X86_REG_GS:
            ret = uc_check_cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            if (ret) {
                return ret;
            }
            cpu_x86_load_seg(env, R_GS, *(uint16_t *)value);
            break;
        case UC_X86_REG_R8:
            env->regs[8] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R8D:
            WRITE_DWORD(env->regs[8], *(uint32_t *)value);
            break;
        case UC_X86_REG_R8W:
            WRITE_WORD(env->regs[8], *(uint16_t *)value);
            break;
        case UC_X86_REG_R8B:
            WRITE_BYTE_L(env->regs[8], *(uint8_t *)value);
            break;
        case UC_X86_REG_R9:
            env->regs[9] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R9D:
            WRITE_DWORD(env->regs[9], *(uint32_t *)value);
            break;
        case UC_X86_REG_R9W:
            WRITE_WORD(env->regs[9], *(uint16_t *)value);
            break;
        case UC_X86_REG_R9B:
            WRITE_BYTE_L(env->regs[9], *(uint8_t *)value);
            break;
        case UC_X86_REG_R10:
            env->regs[10] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R10D:
            WRITE_DWORD(env->regs[10], *(uint32_t *)value);
            break;
        case UC_X86_REG_R10W:
            WRITE_WORD(env->regs[10], *(uint16_t *)value);
            break;
        case UC_X86_REG_R10B:
            WRITE_BYTE_L(env->regs[10], *(uint8_t *)value);
            break;
        case UC_X86_REG_R11:
            env->regs[11] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R11D:
            WRITE_DWORD(env->regs[11], *(uint32_t *)value);
            break;
        case UC_X86_REG_R11W:
            WRITE_WORD(env->regs[11], *(uint16_t *)value);
            break;
        case UC_X86_REG_R11B:
            WRITE_BYTE_L(env->regs[11], *(uint8_t *)value);
            break;
        case UC_X86_REG_R12:
            env->regs[12] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R12D:
            WRITE_DWORD(env->regs[12], *(uint32_t *)value);
            break;
        case UC_X86_REG_R12W:
            WRITE_WORD(env->regs[12], *(uint16_t *)value);
            break;
        case UC_X86_REG_R12B:
            WRITE_BYTE_L(env->regs[12], *(uint8_t *)value);
            break;
        case UC_X86_REG_R13:
            env->regs[13] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R13D:
            WRITE_DWORD(env->regs[13], *(uint32_t *)value);
            break;
        case UC_X86_REG_R13W:
            WRITE_WORD(env->regs[13], *(uint16_t *)value);
            break;
        case UC_X86_REG_R13B:
            WRITE_BYTE_L(env->regs[13], *(uint8_t *)value);
            break;
        case UC_X86_REG_R14:
            env->regs[14] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R14D:
            WRITE_DWORD(env->regs[14], *(uint32_t *)value);
            break;
        case UC_X86_REG_R14W:
            WRITE_WORD(env->regs[14], *(uint16_t *)value);
            break;
        case UC_X86_REG_R14B:
            WRITE_BYTE_L(env->regs[14], *(uint8_t *)value);
            break;
        case UC_X86_REG_R15:
            env->regs[15] = *(uint64_t *)value;
            break;
        case UC_X86_REG_R15D:
            WRITE_DWORD(env->regs[15], *(uint32_t *)value);
            break;
        case UC_X86_REG_R15W:
            WRITE_WORD(env->regs[15], *(uint16_t *)value);
            break;
        case UC_X86_REG_R15B:
            WRITE_BYTE_L(env->regs[15], *(uint8_t *)value);
            break;
        case UC_X86_REG_IDTR:
            env->idt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->idt.base = ((uc_x86_mmr *)value)->base;
            break;
        case UC_X86_REG_GDTR:
            env->gdt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
            env->gdt.base = ((uc_x86_mmr *)value)->base;
            break;
        case UC_X86_REG_LDTR:
            env->ldt.limit = ((uc_x86_mmr *)value)->limit;
            env->ldt.base = ((uc_x86_mmr *)value)->base;
            env->ldt.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->ldt.flags = ((uc_x86_mmr *)value)->flags;
            break;
        case UC_X86_REG_TR:
            env->tr.limit = ((uc_x86_mmr *)value)->limit;
            env->tr.base = ((uc_x86_mmr *)value)->base;
            env->tr.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
            env->tr.flags = ((uc_x86_mmr *)value)->flags;
            break;
        case UC_X86_REG_MSR:
            x86_msr_write(env, (uc_x86_msr *)value);
            break;
        case UC_X86_REG_MXCSR:
            cpu_set_mxcsr(env, *(uint32_t *)value);
            break;
        case UC_X86_REG_XMM8:
        case UC_X86_REG_XMM9:
        case UC_X86_REG_XMM10:
        case UC_X86_REG_XMM11:
        case UC_X86_REG_XMM12:
        case UC_X86_REG_XMM13:
        case UC_X86_REG_XMM14:
        case UC_X86_REG_XMM15: {
            float64 *src = (float64 *)value;
            XMMReg *reg = (XMMReg *)&env->xmm_regs[regid - UC_X86_REG_XMM0];
            reg->_d[0] = src[0];
            reg->_d[1] = src[1];
            break;
        }
        case UC_X86_REG_FS_BASE:
            env->segs[R_FS].base = *(uint64_t *)value;
            return 0;
        case UC_X86_REG_GS_BASE:
            env->segs[R_GS].base = *(uint64_t *)value;
            return 0;
        }
        break;
#endif
    }

    return 0;
}

int x86_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                 int count)
{
    CPUX86State *env = &(X86_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value, uc->mode);
    }

    return 0;
}

int x86_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                  int count)
{
    CPUX86State *env = &(X86_CPU(uc->cpu)->env);
    int i;
    int ret;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        ret = reg_write(env, regid, value, uc->mode);
        if (ret) {
            return ret;
        }
        switch (uc->mode) {
        default:
            break;
        case UC_MODE_32:
            switch (regid) {
            default:
                break;
            case UC_X86_REG_EIP:
            case UC_X86_REG_IP:
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);
                break;
            }

#ifdef TARGET_X86_64
        case UC_MODE_64:
            switch (regid) {
            default:
                break;
            case UC_X86_REG_RIP:
            case UC_X86_REG_EIP:
            case UC_X86_REG_IP:
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);
                break;
            }
#endif
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
int x86_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                         void **vals, int count)
{
    CPUX86State *env = (CPUX86State *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value, ctx->mode);
    }

    return 0;
}

DEFAULT_VISIBILITY
int x86_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                          void *const *vals, int count)
{
    CPUX86State *env = (CPUX86State *)ctx->data;
    int i;
    int ret;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        ret = reg_write(env, regid, value, ctx->mode);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static bool x86_stop_interrupt(struct uc_struct *uc, int intno)
{
    switch (intno) {
    default:
        return false;
    case EXCP06_ILLOP:
        return true;
    }
}

static bool x86_insn_hook_validate(uint32_t insn_enum)
{
    // for x86 we can only hook IN, OUT, and SYSCALL
    if (insn_enum != UC_X86_INS_IN && insn_enum != UC_X86_INS_OUT &&
        insn_enum != UC_X86_INS_SYSCALL && insn_enum != UC_X86_INS_SYSENTER &&
        insn_enum != UC_X86_INS_CPUID) {
        return false;
    }
    return true;
}

static bool x86_opcode_hook_invalidate(uint32_t op, uint32_t flags)
{
    if (op != UC_TCG_OP_SUB) {
        return false;
    }

    switch (op) {
    case UC_TCG_OP_SUB:

        if ((flags & UC_TCG_OP_FLAG_CMP) && (flags & UC_TCG_OP_FLAG_DIRECT)) {
            return false;
        }

        break;

    default:
        return false;
    }

    return true;
}

static int x86_cpus_init(struct uc_struct *uc, const char *cpu_model)
{

    X86CPU *cpu;

    cpu = cpu_x86_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
void x86_uc_init(struct uc_struct *uc)
{
    uc->reg_read = x86_reg_read;
    uc->reg_write = x86_reg_write;
    uc->reg_reset = x86_reg_reset;
    uc->release = x86_release;
    uc->set_pc = x86_set_pc;
    uc->stop_interrupt = x86_stop_interrupt;
    uc->insn_hook_validate = x86_insn_hook_validate;
    uc->opcode_hook_invalidate = x86_opcode_hook_invalidate;
    uc->cpus_init = x86_cpus_init;
    uc->cpu_context_size = offsetof(CPUX86State, retaddr);
    uc_common_init(uc);
}

/* vim: set ts=4 sts=4 sw=4 et:  */
