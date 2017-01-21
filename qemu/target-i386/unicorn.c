/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/i386/pc.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "tcg.h"
#include "unicorn_common.h"
#include <unicorn/x86.h>  /* needed for uc_x86_mmr */
#include "uc_priv.h"


const int X86_REGS_STORAGE_SIZE = offsetof(CPUX86State, tlb_table);

static void x86_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUX86State *)uc->current_cpu->env_ptr)->eip = address;
}

void x86_release(void *ctx);

void x86_release(void *ctx)
{
    int i;
    TCGContext *s = (TCGContext *) ctx;

    release_common(ctx);

    // arch specific
    g_free(s->cpu_A0);
    g_free(s->cpu_T[0]);
    g_free(s->cpu_T[1]);
    g_free(s->cpu_tmp0);
    g_free(s->cpu_tmp4);
    g_free(s->cpu_cc_srcT);
    g_free(s->cpu_cc_dst);
    g_free(s->cpu_cc_src);
    g_free(s->cpu_cc_src2);

    for (i = 0; i < CPU_NB_REGS; ++i) {
        g_free(s->cpu_regs[i]);
    }

    g_free(s->tb_ctx.tbs);
}

void x86_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    env->features[FEAT_1_EDX] = CPUID_CX8 | CPUID_CMOV | CPUID_SSE2 | CPUID_FXSR | CPUID_SSE | CPUID_CLFLUSH;
    env->features[FEAT_1_ECX] = CPUID_EXT_SSSE3 | CPUID_EXT_SSE41 | CPUID_EXT_SSE42 | CPUID_EXT_AES;
    env->features[FEAT_8000_0001_EDX] = CPUID_EXT2_3DNOW | CPUID_EXT2_RDTSCP;
    env->features[FEAT_8000_0001_ECX] = CPUID_EXT3_LAHF_LM | CPUID_EXT3_ABM | CPUID_EXT3_SKINIT | CPUID_EXT3_CR8LEG;
    env->features[FEAT_7_0_EBX] = CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ADX | CPUID_7_0_EBX_SMAP;

    memset(env->regs, 0, sizeof(env->regs));
    memset(env->segs, 0, sizeof(env->segs));
    memset(env->cr, 0, sizeof(env->cr));

    memset(&env->ldt, 0, sizeof(env->ldt));
    memset(&env->gdt, 0, sizeof(env->gdt));
    memset(&env->tr, 0, sizeof(env->tr));
    memset(&env->idt, 0, sizeof(env->idt));

    env->eip = 0;
    env->eflags = 0;
    env->eflags0 = 0;

    env->fpstt = 0; /* top of stack index */
    env->fpus = 0;
    env->fpuc = 0;
    memset(env->fptags, 0, sizeof(env->fptags));   /* 0 = valid, 1 = empty */

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
    switch(uc->mode) {
        default:
            break;
        case UC_MODE_16:
            env->hflags = 0;
            env->cr[0] = 0;
            break;
        case UC_MODE_32:
            env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_OSFXSR_MASK;
            cpu_x86_update_cr0(env, CR0_PE_MASK); // protected mode
            break;
        case UC_MODE_64:
            env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK | HF_LMA_MASK | HF_OSFXSR_MASK;
            env->hflags &= ~(HF_ADDSEG_MASK);
            cpu_x86_update_cr0(env, CR0_PE_MASK); // protected mode
            break;
    }
}

int x86_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        switch(regid) {
            default:
                break;
            case UC_X86_REG_FP0:
            case UC_X86_REG_FP1:
            case UC_X86_REG_FP2:
            case UC_X86_REG_FP3:
            case UC_X86_REG_FP4:
            case UC_X86_REG_FP5:
            case UC_X86_REG_FP6:
            case UC_X86_REG_FP7:
                {
                    floatx80 reg = X86_CPU(uc, mycpu)->env.fpregs[regid - UC_X86_REG_FP0].d;
                    cpu_get_fp80(value, (uint16_t*)((char*)value+sizeof(uint64_t)), reg);
                }
                continue;
            case UC_X86_REG_FPSW:
                {
                    uint16_t fpus = X86_CPU(uc, mycpu)->env.fpus;
                    fpus  = fpus & ~0x3800;
                    fpus |= ( X86_CPU(uc, mycpu)->env.fpstt & 0x7 ) << 11;
                    *(uint16_t*) value = fpus;
                }
                continue;
            case UC_X86_REG_FPCW:
                *(uint16_t*) value = X86_CPU(uc, mycpu)->env.fpuc;
                continue;
            case UC_X86_REG_FPTAG:
                {
                    #define EXPD(fp)        (fp.l.upper & 0x7fff)
                    #define MANTD(fp)       (fp.l.lower)
                    #define MAXEXPD 0x7fff
                    int fptag, exp, i;
                    uint64_t mant;
                    CPU_LDoubleU tmp;
                    fptag = 0;
                    for (i = 7; i >= 0; i--) {
                        fptag <<= 2;
                        if (X86_CPU(uc, mycpu)->env.fptags[i]) {
                            fptag |= 3;
                        } else {
                            tmp.d = X86_CPU(uc, mycpu)->env.fpregs[i].d;
                            exp = EXPD(tmp);
                            mant = MANTD(tmp);
                            if (exp == 0 && mant == 0) {
                                /* zero */
                                fptag |= 1;
                            } else if (exp == 0 || exp == MAXEXPD
                                       || (mant & (1LL << 63)) == 0) {
                                /* NaNs, infinity, denormal */
                                fptag |= 2;
                            }
                        }
                    }
                    *(uint16_t*) value = fptag; 
                }
                continue;
            case UC_X86_REG_XMM0:
            case UC_X86_REG_XMM1:
            case UC_X86_REG_XMM2:
            case UC_X86_REG_XMM3:
            case UC_X86_REG_XMM4:
            case UC_X86_REG_XMM5:
            case UC_X86_REG_XMM6:
            case UC_X86_REG_XMM7:
                {
                    float64 *dst = (float64*)value;
                    XMMReg *reg = &X86_CPU(uc, mycpu)->env.xmm_regs[regid - UC_X86_REG_XMM0];
                    dst[0] = reg->_d[0];
                    dst[1] = reg->_d[1];
                    continue;
                }
        }

        switch(uc->mode) {
            default:
                break;
            case UC_MODE_16:
                switch(regid) {
                    default: break;
                    case UC_X86_REG_ES:
                        *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_ES].selector;
                        continue;
                    case UC_X86_REG_SS:
                        *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_SS].selector;
                        continue;
                    case UC_X86_REG_DS:
                        *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_DS].selector;
                        continue;
                    case UC_X86_REG_FS:
                        *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_FS].selector;
                        continue;
                    case UC_X86_REG_GS:
                        *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_GS].selector;
                        continue;
                }
                // fall-thru
            case UC_MODE_32:
                switch(regid) {
                    default:
                        break;
                    case UC_X86_REG_CR0:
                    case UC_X86_REG_CR1:
                    case UC_X86_REG_CR2:
                    case UC_X86_REG_CR3:
                    case UC_X86_REG_CR4:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0];
                        break;
                    case UC_X86_REG_DR0:
                    case UC_X86_REG_DR1:
                    case UC_X86_REG_DR2:
                    case UC_X86_REG_DR3:
                    case UC_X86_REG_DR4:
                    case UC_X86_REG_DR5:
                    case UC_X86_REG_DR6:
                    case UC_X86_REG_DR7:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.dr[regid - UC_X86_REG_DR0];
                        break;
                    case UC_X86_REG_EFLAGS:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.eflags;
                        break;
                    case UC_X86_REG_EAX:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EAX];
                        break;
                    case UC_X86_REG_AX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_AH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_AL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_EBX:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EBX];
                        break;
                    case UC_X86_REG_BX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_BH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_BL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_ECX:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_ECX];
                        break;
                    case UC_X86_REG_CX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_CH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_CL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_EDX:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EDX];
                        break;
                    case UC_X86_REG_DX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_DH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_DL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_ESP:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_ESP];
                        break;
                    case UC_X86_REG_SP:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESP]);
                        break;
                    case UC_X86_REG_EBP:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EBP];
                        break;
                    case UC_X86_REG_BP:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBP]);
                        break;
                    case UC_X86_REG_ESI:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_ESI];
                        break;
                    case UC_X86_REG_SI:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESI]);
                        break;
                    case UC_X86_REG_EDI:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EDI];
                        break;
                    case UC_X86_REG_DI:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDI]);
                        break;
                    case UC_X86_REG_EIP:
                        *(int32_t *)value = X86_CPU(uc, mycpu)->env.eip;
                        break;
                    case UC_X86_REG_IP:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.eip);
                        break;
                    case UC_X86_REG_CS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_CS].selector;
                        break;
                    case UC_X86_REG_DS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_DS].selector;
                        break;
                    case UC_X86_REG_SS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_SS].selector;
                        break;
                    case UC_X86_REG_ES:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_ES].selector;
                        break;
                    case UC_X86_REG_FS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_FS].selector;
                        break;
                    case UC_X86_REG_GS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_GS].selector;
                        break;
                    case UC_X86_REG_IDTR:
                        ((uc_x86_mmr *)value)->limit = (uint16_t)X86_CPU(uc, mycpu)->env.idt.limit;
                        ((uc_x86_mmr *)value)->base = (uint32_t)X86_CPU(uc, mycpu)->env.idt.base;
                        break;
                    case UC_X86_REG_GDTR:
                        ((uc_x86_mmr *)value)->limit = (uint16_t)X86_CPU(uc, mycpu)->env.gdt.limit;
                        ((uc_x86_mmr *)value)->base = (uint32_t)X86_CPU(uc, mycpu)->env.gdt.base;
                        break;
                    case UC_X86_REG_LDTR:
                        ((uc_x86_mmr *)value)->limit = X86_CPU(uc, mycpu)->env.ldt.limit;
                        ((uc_x86_mmr *)value)->base = (uint32_t)X86_CPU(uc, mycpu)->env.ldt.base;
                        ((uc_x86_mmr *)value)->selector = (uint16_t)X86_CPU(uc, mycpu)->env.ldt.selector;
                        ((uc_x86_mmr *)value)->flags = X86_CPU(uc, mycpu)->env.ldt.flags;
                        break;
                    case UC_X86_REG_TR:
                        ((uc_x86_mmr *)value)->limit = X86_CPU(uc, mycpu)->env.tr.limit;
                        ((uc_x86_mmr *)value)->base = (uint32_t)X86_CPU(uc, mycpu)->env.tr.base;
                        ((uc_x86_mmr *)value)->selector = (uint16_t)X86_CPU(uc, mycpu)->env.tr.selector;
                        ((uc_x86_mmr *)value)->flags = X86_CPU(uc, mycpu)->env.tr.flags;
                        break;
                }
                break;

#ifdef TARGET_X86_64
            case UC_MODE_64:
                switch(regid) {
                    default:
                        break;
                    case UC_X86_REG_CR0:
                    case UC_X86_REG_CR1:
                    case UC_X86_REG_CR2:
                    case UC_X86_REG_CR3:
                    case UC_X86_REG_CR4:
                        *(int64_t *)value = X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0];
                        break;
                    case UC_X86_REG_DR0:
                    case UC_X86_REG_DR1:
                    case UC_X86_REG_DR2:
                    case UC_X86_REG_DR3:
                    case UC_X86_REG_DR4:
                    case UC_X86_REG_DR5:
                    case UC_X86_REG_DR6:
                    case UC_X86_REG_DR7:
                        *(int64_t *)value = X86_CPU(uc, mycpu)->env.dr[regid - UC_X86_REG_DR0];
                        break;
                    case UC_X86_REG_EFLAGS:
                        *(int64_t *)value = X86_CPU(uc, mycpu)->env.eflags;
                        break;
                    case UC_X86_REG_RAX:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EAX];
                        break;
                    case UC_X86_REG_EAX:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_AX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_AH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_AL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EAX]);
                        break;
                    case UC_X86_REG_RBX:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EBX];
                        break;
                    case UC_X86_REG_EBX:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_BX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_BH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_BL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EBX]);
                        break;
                    case UC_X86_REG_RCX:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_ECX];
                        break;
                    case UC_X86_REG_ECX:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_CX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_CH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_CL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ECX]);
                        break;
                    case UC_X86_REG_RDX:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EDX];
                        break;
                    case UC_X86_REG_EDX:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_DX:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_DH:
                        *(int8_t *)value = READ_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_DL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EDX]);
                        break;
                    case UC_X86_REG_RSP:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_ESP];
                        break;
                    case UC_X86_REG_ESP:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_ESP]);
                        break;
                    case UC_X86_REG_SP:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESP]);
                        break;
                    case UC_X86_REG_SPL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ESP]);
                        break;
                    case UC_X86_REG_RBP:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EBP];
                        break;
                    case UC_X86_REG_EBP:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EBP]);
                        break;
                    case UC_X86_REG_BP:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBP]);
                        break;
                    case UC_X86_REG_BPL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EBP]);
                        break;
                    case UC_X86_REG_RSI:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_ESI];
                        break;
                    case UC_X86_REG_ESI:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_ESI]);
                        break;
                    case UC_X86_REG_SI:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESI]);
                        break;
                    case UC_X86_REG_SIL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ESI]);
                        break;
                    case UC_X86_REG_RDI:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.regs[R_EDI];
                        break;
                    case UC_X86_REG_EDI:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EDI]);
                        break;
                    case UC_X86_REG_DI:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDI]);
                        break;
                    case UC_X86_REG_DIL:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EDI]);
                        break;
                    case UC_X86_REG_RIP:
                        *(uint64_t *)value = X86_CPU(uc, mycpu)->env.eip;
                        break;
                    case UC_X86_REG_EIP:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.eip);
                        break;
                    case UC_X86_REG_IP:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.eip);
                        break;
                    case UC_X86_REG_CS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_CS].selector;
                        break;
                    case UC_X86_REG_DS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_DS].selector;
                        break;
                    case UC_X86_REG_SS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_SS].selector;
                        break;
                    case UC_X86_REG_ES:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_ES].selector;
                        break;
                    case UC_X86_REG_FS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_FS].selector;
                        break;
                    case UC_X86_REG_GS:
                        *(int16_t *)value = (uint16_t)X86_CPU(uc, mycpu)->env.segs[R_GS].selector;
                        break;
                    case UC_X86_REG_R8:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[8]);
                        break;
                    case UC_X86_REG_R8D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[8]);
                        break;
                    case UC_X86_REG_R8W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[8]);
                        break;
                    case UC_X86_REG_R8B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[8]);
                        break;
                    case UC_X86_REG_R9:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[9]);
                        break;
                    case UC_X86_REG_R9D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[9]);
                        break;
                    case UC_X86_REG_R9W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[9]);
                        break;
                    case UC_X86_REG_R9B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[9]);
                        break;
                    case UC_X86_REG_R10:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[10]);
                        break;
                    case UC_X86_REG_R10D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[10]);
                        break;
                    case UC_X86_REG_R10W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[10]);
                        break;
                    case UC_X86_REG_R10B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[10]);
                        break;
                    case UC_X86_REG_R11:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[11]);
                        break;
                    case UC_X86_REG_R11D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[11]);
                        break;
                    case UC_X86_REG_R11W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[11]);
                        break;
                    case UC_X86_REG_R11B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[11]);
                        break;
                    case UC_X86_REG_R12:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[12]);
                        break;
                    case UC_X86_REG_R12D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[12]);
                        break;
                    case UC_X86_REG_R12W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[12]);
                        break;
                    case UC_X86_REG_R12B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[12]);
                        break;
                    case UC_X86_REG_R13:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[13]);
                        break;
                    case UC_X86_REG_R13D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[13]);
                        break;
                    case UC_X86_REG_R13W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[13]);
                        break;
                    case UC_X86_REG_R13B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[13]);
                        break;
                    case UC_X86_REG_R14:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[14]);
                        break;
                    case UC_X86_REG_R14D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[14]);
                        break;
                    case UC_X86_REG_R14W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[14]);
                        break;
                    case UC_X86_REG_R14B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[14]);
                        break;
                    case UC_X86_REG_R15:
                        *(int64_t *)value = READ_QWORD(X86_CPU(uc, mycpu)->env.regs[15]);
                        break;
                    case UC_X86_REG_R15D:
                        *(int32_t *)value = READ_DWORD(X86_CPU(uc, mycpu)->env.regs[15]);
                        break;
                    case UC_X86_REG_R15W:
                        *(int16_t *)value = READ_WORD(X86_CPU(uc, mycpu)->env.regs[15]);
                        break;
                    case UC_X86_REG_R15B:
                        *(int8_t *)value = READ_BYTE_L(X86_CPU(uc, mycpu)->env.regs[15]);
                        break;
                    case UC_X86_REG_IDTR:
                        ((uc_x86_mmr *)value)->limit = (uint16_t)X86_CPU(uc, mycpu)->env.idt.limit;
                        ((uc_x86_mmr *)value)->base = X86_CPU(uc, mycpu)->env.idt.base;
                        break;
                    case UC_X86_REG_GDTR:
                        ((uc_x86_mmr *)value)->limit = (uint16_t)X86_CPU(uc, mycpu)->env.gdt.limit;
                        ((uc_x86_mmr *)value)->base = X86_CPU(uc, mycpu)->env.gdt.base;
                        break;
                    case UC_X86_REG_LDTR:
                        ((uc_x86_mmr *)value)->limit = X86_CPU(uc, mycpu)->env.ldt.limit;
                        ((uc_x86_mmr *)value)->base = X86_CPU(uc, mycpu)->env.ldt.base;
                        ((uc_x86_mmr *)value)->selector = (uint16_t)X86_CPU(uc, mycpu)->env.ldt.selector;
                        ((uc_x86_mmr *)value)->flags = X86_CPU(uc, mycpu)->env.ldt.flags;
                        break;
                    case UC_X86_REG_TR:
                        ((uc_x86_mmr *)value)->limit = X86_CPU(uc, mycpu)->env.tr.limit;
                        ((uc_x86_mmr *)value)->base = X86_CPU(uc, mycpu)->env.tr.base;
                        ((uc_x86_mmr *)value)->selector = (uint16_t)X86_CPU(uc, mycpu)->env.tr.selector;
                        ((uc_x86_mmr *)value)->flags = X86_CPU(uc, mycpu)->env.tr.flags;
                        break;
                }
                break;
#endif
        }
    }

    return 0;
}

int x86_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        switch(regid) {
            default:
                break;
            case UC_X86_REG_FP0:
            case UC_X86_REG_FP1:
            case UC_X86_REG_FP2:
            case UC_X86_REG_FP3:
            case UC_X86_REG_FP4:
            case UC_X86_REG_FP5:
            case UC_X86_REG_FP6:
            case UC_X86_REG_FP7:
                {
                    uint64_t mant = *(uint64_t*) value;
                    uint16_t upper = *(uint16_t*) ((char*)value + sizeof(uint64_t));
                    X86_CPU(uc, mycpu)->env.fpregs[regid - UC_X86_REG_FP0].d = cpu_set_fp80(mant, upper);
                }
                continue;
            case UC_X86_REG_FPSW:
                {
                    uint16_t fpus = *(uint16_t*) value;
                    X86_CPU(uc, mycpu)->env.fpus = fpus & ~0x3800;
                    X86_CPU(uc, mycpu)->env.fpstt = (fpus >> 11) & 0x7;
                }
                continue;
            case UC_X86_REG_FPCW:
                X86_CPU(uc, mycpu)->env.fpuc = *(uint16_t *)value;
                continue;
            case UC_X86_REG_FPTAG:
                {
                    int i;
                    uint16_t fptag = *(uint16_t*) value;
                    for (i = 0; i < 8; i++) {
                        X86_CPU(uc, mycpu)->env.fptags[i] = ((fptag & 3) == 3);
                        fptag >>= 2;
                    }

                    continue;
                }
                break;
            case UC_X86_REG_XMM0:
            case UC_X86_REG_XMM1:
            case UC_X86_REG_XMM2:
            case UC_X86_REG_XMM3:
            case UC_X86_REG_XMM4:
            case UC_X86_REG_XMM5:
            case UC_X86_REG_XMM6:
            case UC_X86_REG_XMM7:
                {
                    float64 *src = (float64*)value;
                    XMMReg *reg = &X86_CPU(uc, mycpu)->env.xmm_regs[regid - UC_X86_REG_XMM0];
                    reg->_d[0] = src[0];
                    reg->_d[1] = src[1];
                    continue;
                }
        }

        switch(uc->mode) {
            default:
                break;

            case UC_MODE_16:
                switch(regid) {
                    default: break;
                    case UC_X86_REG_ES:
                        X86_CPU(uc, mycpu)->env.segs[R_ES].selector = *(uint16_t *)value;
                        continue;
                    case UC_X86_REG_SS:
                        X86_CPU(uc, mycpu)->env.segs[R_SS].selector = *(uint16_t *)value;
                        continue;
                    case UC_X86_REG_DS:
                        X86_CPU(uc, mycpu)->env.segs[R_DS].selector = *(uint16_t *)value;
                        continue;
                    case UC_X86_REG_FS:
                        X86_CPU(uc, mycpu)->env.segs[R_FS].selector = *(uint16_t *)value;
                        continue;
                    case UC_X86_REG_GS:
                        X86_CPU(uc, mycpu)->env.segs[R_GS].selector = *(uint16_t *)value;
                        continue;
                }
                // fall-thru
            case UC_MODE_32:
                switch(regid) {
                    default:
                        break;
                    case UC_X86_REG_CR0:
                    case UC_X86_REG_CR1:
                    case UC_X86_REG_CR2:
                    case UC_X86_REG_CR3:
                    case UC_X86_REG_CR4:
                        X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_DR0:
                    case UC_X86_REG_DR1:
                    case UC_X86_REG_DR2:
                    case UC_X86_REG_DR3:
                    case UC_X86_REG_DR4:
                    case UC_X86_REG_DR5:
                    case UC_X86_REG_DR6:
                    case UC_X86_REG_DR7:
                        X86_CPU(uc, mycpu)->env.dr[regid - UC_X86_REG_DR0] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_EFLAGS:
                        X86_CPU(uc, mycpu)->env.eflags = *(uint32_t *)value;
                        X86_CPU(uc, mycpu)->env.eflags0 = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_EAX:
                        X86_CPU(uc, mycpu)->env.regs[R_EAX] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_AX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_AH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_AL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_EBX:
                        X86_CPU(uc, mycpu)->env.regs[R_EBX] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_BX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_BH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_BL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_ECX:
                        X86_CPU(uc, mycpu)->env.regs[R_ECX] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_CX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_CH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_CL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_EDX:
                        X86_CPU(uc, mycpu)->env.regs[R_EDX] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_DX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_DH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_DL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_ESP:
                        X86_CPU(uc, mycpu)->env.regs[R_ESP] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_SP:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESP], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_EBP:
                        X86_CPU(uc, mycpu)->env.regs[R_EBP] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_BP:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBP], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_ESI:
                        X86_CPU(uc, mycpu)->env.regs[R_ESI] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_SI:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESI], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_EDI:
                        X86_CPU(uc, mycpu)->env.regs[R_EDI] = *(uint32_t *)value;
                        break;
                    case UC_X86_REG_DI:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDI], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_EIP:
                        X86_CPU(uc, mycpu)->env.eip = *(uint32_t *)value;
                        // force to quit execution and flush TB
                        uc->quit_request = true;
                        uc_emu_stop(uc);
                        break;
                    case UC_X86_REG_IP:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.eip, *(uint16_t *)value);
                        // force to quit execution and flush TB
                        uc->quit_request = true;
                        uc_emu_stop(uc);
                        break;
                    case UC_X86_REG_CS:
                        cpu_x86_load_seg(&X86_CPU(uc, mycpu)->env, R_CS, *(uint16_t *)value);
                        break;
                    case UC_X86_REG_DS:
                        cpu_x86_load_seg(&X86_CPU(uc, mycpu)->env, R_DS, *(uint16_t *)value);
                        break;
                    case UC_X86_REG_SS:
                        cpu_x86_load_seg(&X86_CPU(uc, mycpu)->env, R_SS, *(uint16_t *)value);
                        break;
                    case UC_X86_REG_ES:
                        cpu_x86_load_seg(&X86_CPU(uc, mycpu)->env, R_ES, *(uint16_t *)value);
                        break;
                    case UC_X86_REG_FS:
                        cpu_x86_load_seg(&X86_CPU(uc, mycpu)->env, R_FS, *(uint16_t *)value);
                        break;
                    case UC_X86_REG_GS:
                        cpu_x86_load_seg(&X86_CPU(uc, mycpu)->env, R_GS, *(uint16_t *)value);
                        break;
                    case UC_X86_REG_IDTR:
                        X86_CPU(uc, mycpu)->env.idt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.idt.base = (uint32_t)((uc_x86_mmr *)value)->base;
                        break;
                    case UC_X86_REG_GDTR:
                        X86_CPU(uc, mycpu)->env.gdt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.gdt.base = (uint32_t)((uc_x86_mmr *)value)->base;
                        break;
                    case UC_X86_REG_LDTR:
                        X86_CPU(uc, mycpu)->env.ldt.limit = ((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.ldt.base = (uint32_t)((uc_x86_mmr *)value)->base;
                        X86_CPU(uc, mycpu)->env.ldt.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
                        X86_CPU(uc, mycpu)->env.ldt.flags = ((uc_x86_mmr *)value)->flags;
                        break;
                    case UC_X86_REG_TR:
                        X86_CPU(uc, mycpu)->env.tr.limit = ((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.tr.base = (uint32_t)((uc_x86_mmr *)value)->base;
                        X86_CPU(uc, mycpu)->env.tr.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
                        X86_CPU(uc, mycpu)->env.tr.flags = ((uc_x86_mmr *)value)->flags;
                        break;
                }
                break;

#ifdef TARGET_X86_64
            case UC_MODE_64:
                switch(regid) {
                    default:
                        break;
                    case UC_X86_REG_CR0:
                    case UC_X86_REG_CR1:
                    case UC_X86_REG_CR2:
                    case UC_X86_REG_CR3:
                    case UC_X86_REG_CR4:
                        X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_DR0:
                    case UC_X86_REG_DR1:
                    case UC_X86_REG_DR2:
                    case UC_X86_REG_DR3:
                    case UC_X86_REG_DR4:
                    case UC_X86_REG_DR5:
                    case UC_X86_REG_DR6:
                    case UC_X86_REG_DR7:
                        X86_CPU(uc, mycpu)->env.dr[regid - UC_X86_REG_DR0] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_EFLAGS:
                        X86_CPU(uc, mycpu)->env.eflags = *(uint64_t *)value;
                        X86_CPU(uc, mycpu)->env.eflags0 = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_RAX:
                        X86_CPU(uc, mycpu)->env.regs[R_EAX] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_EAX:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_AX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_AH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_AL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EAX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RBX:
                        X86_CPU(uc, mycpu)->env.regs[R_EBX] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_EBX:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_BX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_BH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_BL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EBX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RCX:
                        X86_CPU(uc, mycpu)->env.regs[R_ECX] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_ECX:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_CX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_CH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_CL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ECX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RDX:
                        X86_CPU(uc, mycpu)->env.regs[R_EDX] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_EDX:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_DX:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_DH:
                        WRITE_BYTE_H(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_DL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EDX], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RSP:
                        X86_CPU(uc, mycpu)->env.regs[R_ESP] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_ESP:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_ESP], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_SP:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESP], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_SPL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ESP], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RBP:
                        X86_CPU(uc, mycpu)->env.regs[R_EBP] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_EBP:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EBP], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_BP:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EBP], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_BPL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EBP], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RSI:
                        X86_CPU(uc, mycpu)->env.regs[R_ESI] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_ESI:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_ESI], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_SI:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_ESI], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_SIL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_ESI], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RDI:
                        X86_CPU(uc, mycpu)->env.regs[R_EDI] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_EDI:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[R_EDI], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_DI:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[R_EDI], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_DIL:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[R_EDI], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_RIP:
                        X86_CPU(uc, mycpu)->env.eip = *(uint64_t *)value;
                        // force to quit execution and flush TB
                        uc->quit_request = true;
                        uc_emu_stop(uc);
                        break;
                    case UC_X86_REG_EIP:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.eip, *(uint32_t *)value);
                        // force to quit execution and flush TB
                        uc->quit_request = true;
                        uc_emu_stop(uc);
                        break;
                    case UC_X86_REG_IP:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.eip, *(uint16_t *)value);
                        // force to quit execution and flush TB
                        uc->quit_request = true;
                        uc_emu_stop(uc);
                        break;
                    case UC_X86_REG_CS:
                        X86_CPU(uc, mycpu)->env.segs[R_CS].selector = *(uint16_t *)value;
                        break;
                    case UC_X86_REG_DS:
                        X86_CPU(uc, mycpu)->env.segs[R_DS].selector = *(uint16_t *)value;
                        break;
                    case UC_X86_REG_SS:
                        X86_CPU(uc, mycpu)->env.segs[R_SS].selector = *(uint16_t *)value;
                        break;
                    case UC_X86_REG_ES:
                        X86_CPU(uc, mycpu)->env.segs[R_ES].selector = *(uint16_t *)value;
                        break;
                    case UC_X86_REG_FS:
                        X86_CPU(uc, mycpu)->env.segs[R_FS].selector = *(uint16_t *)value;
                        break;
                    case UC_X86_REG_GS:
                        X86_CPU(uc, mycpu)->env.segs[R_GS].selector = *(uint16_t *)value;
                        break;
                    case UC_X86_REG_R8:
                        X86_CPU(uc, mycpu)->env.regs[8] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R8D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[8], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R8W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[8], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R8B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[8], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R9:
                        X86_CPU(uc, mycpu)->env.regs[9] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R9D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[9], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R9W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[9], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R9B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[9], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R10:
                        X86_CPU(uc, mycpu)->env.regs[10] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R10D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[10], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R10W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[10], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R10B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[10], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R11:
                        X86_CPU(uc, mycpu)->env.regs[11] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R11D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[11], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R11W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[11], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R11B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[11], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R12:
                        X86_CPU(uc, mycpu)->env.regs[12] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R12D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[12], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R12W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[12], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R12B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[12], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R13:
                        X86_CPU(uc, mycpu)->env.regs[13] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R13D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[13], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R13W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[13], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R13B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[13], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R14:
                        X86_CPU(uc, mycpu)->env.regs[14] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R14D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[14], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R14W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[14], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R14B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[14], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_R15:
                        X86_CPU(uc, mycpu)->env.regs[15] = *(uint64_t *)value;
                        break;
                    case UC_X86_REG_R15D:
                        WRITE_DWORD(X86_CPU(uc, mycpu)->env.regs[15], *(uint32_t *)value);
                        break;
                    case UC_X86_REG_R15W:
                        WRITE_WORD(X86_CPU(uc, mycpu)->env.regs[15], *(uint16_t *)value);
                        break;
                    case UC_X86_REG_R15B:
                        WRITE_BYTE_L(X86_CPU(uc, mycpu)->env.regs[15], *(uint8_t *)value);
                        break;
                    case UC_X86_REG_IDTR:
                        X86_CPU(uc, mycpu)->env.idt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.idt.base = ((uc_x86_mmr *)value)->base;
                        break;
                    case UC_X86_REG_GDTR:
                        X86_CPU(uc, mycpu)->env.gdt.limit = (uint16_t)((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.gdt.base = ((uc_x86_mmr *)value)->base;
                        break;
                    case UC_X86_REG_LDTR:
                        X86_CPU(uc, mycpu)->env.ldt.limit = ((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.ldt.base = ((uc_x86_mmr *)value)->base;
                        X86_CPU(uc, mycpu)->env.ldt.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
                        X86_CPU(uc, mycpu)->env.ldt.flags = ((uc_x86_mmr *)value)->flags;
                        break;
                    case UC_X86_REG_TR:
                        X86_CPU(uc, mycpu)->env.tr.limit = ((uc_x86_mmr *)value)->limit;
                        X86_CPU(uc, mycpu)->env.tr.base = ((uc_x86_mmr *)value)->base;
                        X86_CPU(uc, mycpu)->env.tr.selector = (uint16_t)((uc_x86_mmr *)value)->selector;
                        X86_CPU(uc, mycpu)->env.tr.flags = ((uc_x86_mmr *)value)->flags;
                        break;
                }
                break;
#endif
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
int x86_uc_machine_init(struct uc_struct *uc)
{
    return machine_initialize(uc);
}

static bool x86_stop_interrupt(int intno)
{
    switch(intno) {
        default:
            return false;
        case EXCP06_ILLOP:
            return true;
    }
}

void pc_machine_init(struct uc_struct *uc);

DEFAULT_VISIBILITY
void x86_uc_init(struct uc_struct* uc)
{
    apic_register_types(uc);
    apic_common_register_types(uc);
    register_accel_types(uc);
    pc_machine_register_types(uc);
    x86_cpu_register_types(uc);
    pc_machine_init(uc); // pc_piix
    uc->reg_read = x86_reg_read;
    uc->reg_write = x86_reg_write;
    uc->reg_reset = x86_reg_reset;
    uc->release = x86_release;
    uc->set_pc = x86_set_pc;
    uc->stop_interrupt = x86_stop_interrupt;
    uc_common_init(uc);
}
