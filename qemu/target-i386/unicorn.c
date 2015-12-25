/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "sysemu/cpus.h"
#include "hw/i386/pc.h"
#include "unicorn.h"
#include "cpu.h"
#include "tcg.h"

#include "unicorn_common.h"

#define READ_QWORD(x) ((uint64)x)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_WORD(x) (x & 0xffff)
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)


static void x86_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUX86State *)uc->current_cpu->env_ptr)->eip = address;
}

void x86_release(void *ctx);

void x86_release(void *ctx)
{
    release_common(ctx);
    TCGContext *s = (TCGContext *) ctx;

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

    int i;
    for (i = 0; i < CPU_NB_REGS; ++i) {
        g_free(s->cpu_regs[i]);
    }

    g_free(s->tb_ctx.tbs);
}

void x86_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = first_cpu->env_ptr;

    env->features[FEAT_1_EDX] = CPUID_CX8 | CPUID_CMOV | CPUID_SSE2 | CPUID_FXSR | CPUID_SSE | CPUID_CLFLUSH;
    env->features[FEAT_1_ECX] = CPUID_EXT_SSSE3 | CPUID_EXT_SSE41 | CPUID_EXT_SSE42 | CPUID_EXT_AES;
    env->features[FEAT_8000_0001_EDX] = CPUID_EXT2_3DNOW | CPUID_EXT2_RDTSCP;
    env->features[FEAT_8000_0001_ECX] = CPUID_EXT3_LAHF_LM | CPUID_EXT3_ABM | CPUID_EXT3_SKINIT | CPUID_EXT3_CR8LEG;
    env->features[FEAT_7_0_EBX] = CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ADX | CPUID_7_0_EBX_SMAP;

    env->invalid_error = UC_ERR_OK; // no error
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

int x86_reg_read(struct uc_struct *uc, unsigned int regid, void *value)
{
    CPUState *mycpu = first_cpu;

    switch(uc->mode) {
        default:
            break;
        case UC_MODE_16:
            switch(regid) {
                default: break;
                case UC_X86_REG_ES:
                    *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_ES].selector;
                    return 0;
                case UC_X86_REG_SS:
                    *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_SS].selector;
                    return 0;
                case UC_X86_REG_DS:
                    *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_DS].selector;
                    return 0;
                case UC_X86_REG_FS:
                    *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_FS].selector;
                    return 0;
                case UC_X86_REG_GS:
                    *(int16_t *)value = X86_CPU(uc, mycpu)->env.segs[R_GS].selector;
                    return 0;
            }
            // fall-thru
        case UC_MODE_32:
            switch(regid) {
                default:
                    break;
                case UC_X86_REG_CR0 ... UC_X86_REG_CR4:
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0];
                    break;
                case UC_X86_REG_DR0 ... UC_X86_REG_DR7:
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
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.segs[R_CS].base;
                    break;
                case UC_X86_REG_DS:
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.segs[R_DS].base;
                    break;
                case UC_X86_REG_SS:
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.segs[R_SS].base;
                    break;
                case UC_X86_REG_ES:
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.segs[R_ES].base;
                    break;
                case UC_X86_REG_FS:
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.segs[R_FS].base;
                    break;
                case UC_X86_REG_GS:
                    *(int32_t *)value = X86_CPU(uc, mycpu)->env.segs[R_GS].base;
                    break;
            }
            break;

#ifdef TARGET_X86_64
        case UC_MODE_64:
            switch(regid) {
                default:
                    break;
                case UC_X86_REG_CR0 ... UC_X86_REG_CR4:
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0];
                    break;
                case UC_X86_REG_DR0 ... UC_X86_REG_DR7:
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
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.segs[R_CS].base;
                    break;
                case UC_X86_REG_DS:
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.segs[R_DS].base;
                    break;
                case UC_X86_REG_SS:
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.segs[R_SS].base;
                    break;
                case UC_X86_REG_ES:
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.segs[R_ES].base;
                    break;
                case UC_X86_REG_FS:
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.segs[R_FS].base;
                    break;
                case UC_X86_REG_GS:
                    *(int64_t *)value = X86_CPU(uc, mycpu)->env.segs[R_GS].base;
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
            }
            break;
#endif
    }


    return 0;
}


#define WRITE_DWORD(x, w) (x = (x & ~0xffffffff) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | (b & 0xff))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))

int x86_reg_write(struct uc_struct *uc, unsigned int regid, const void *value)
{
    CPUState *mycpu = first_cpu;

    switch(uc->mode) {
        default:
            break;

        case UC_MODE_16:
            switch(regid) {
                default: break;
                case UC_X86_REG_ES:
                    X86_CPU(uc, mycpu)->env.segs[R_ES].selector = *(uint16_t *)value;
                    return 0;
                case UC_X86_REG_SS:
                    X86_CPU(uc, mycpu)->env.segs[R_SS].selector = *(uint16_t *)value;
                    return 0;
                case UC_X86_REG_DS:
                    X86_CPU(uc, mycpu)->env.segs[R_DS].selector = *(uint16_t *)value;
                    return 0;
                case UC_X86_REG_FS:
                    X86_CPU(uc, mycpu)->env.segs[R_FS].selector = *(uint16_t *)value;
                    return 0;
                case UC_X86_REG_GS:
                    X86_CPU(uc, mycpu)->env.segs[R_GS].selector = *(uint16_t *)value;
                    return 0;
            }
            // fall-thru
        case UC_MODE_32:
            switch(regid) {
                default:
                    break;
                case UC_X86_REG_CR0 ... UC_X86_REG_CR4:
                    X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0] = *(uint32_t *)value;
                    break;
                case UC_X86_REG_DR0 ... UC_X86_REG_DR7:
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
                    break;
                case UC_X86_REG_IP:
                    WRITE_WORD(X86_CPU(uc, mycpu)->env.eip, *(uint16_t *)value);
                    break;
                case UC_X86_REG_CS:
                    X86_CPU(uc, mycpu)->env.segs[R_CS].base = *(uint32_t *)value;
                    break;
                case UC_X86_REG_DS:
                    X86_CPU(uc, mycpu)->env.segs[R_DS].base = *(uint32_t *)value;
                    break;
                case UC_X86_REG_SS:
                    X86_CPU(uc, mycpu)->env.segs[R_SS].base = *(uint32_t *)value;
                    break;
                case UC_X86_REG_ES:
                    X86_CPU(uc, mycpu)->env.segs[R_ES].base = *(uint32_t *)value;
                    break;
                case UC_X86_REG_FS:
                    X86_CPU(uc, mycpu)->env.segs[R_FS].base = *(uint32_t *)value;
                    break;
                case UC_X86_REG_GS:
                    X86_CPU(uc, mycpu)->env.segs[R_GS].base = *(uint32_t *)value;
                    break;
            }
            break;

#ifdef TARGET_X86_64
        case UC_MODE_64:
            switch(regid) {
                default:
                    break;
                case UC_X86_REG_CR0 ... UC_X86_REG_CR4:
                    X86_CPU(uc, mycpu)->env.cr[regid - UC_X86_REG_CR0] = *(uint64_t *)value;
                    break;
                case UC_X86_REG_DR0 ... UC_X86_REG_DR7:
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
                    break;
                case UC_X86_REG_EIP:
                    WRITE_DWORD(X86_CPU(uc, mycpu)->env.eip, *(uint32_t *)value);
                    break;
                case UC_X86_REG_IP:
                    WRITE_WORD(X86_CPU(uc, mycpu)->env.eip, *(uint16_t *)value);
                    break;
                case UC_X86_REG_CS:
                    X86_CPU(uc, mycpu)->env.segs[R_CS].base = *(uint64_t *)value;
                    break;
                case UC_X86_REG_DS:
                    X86_CPU(uc, mycpu)->env.segs[R_DS].base = *(uint64_t *)value;
                    break;
                case UC_X86_REG_SS:
                    X86_CPU(uc, mycpu)->env.segs[R_SS].base = *(uint64_t *)value;
                    break;
                case UC_X86_REG_ES:
                    X86_CPU(uc, mycpu)->env.segs[R_ES].base = *(uint64_t *)value;
                    break;
                case UC_X86_REG_FS:
                    X86_CPU(uc, mycpu)->env.segs[R_FS].base = *(uint64_t *)value;
                    break;
                case UC_X86_REG_GS:
                    X86_CPU(uc, mycpu)->env.segs[R_GS].base = *(uint64_t *)value;
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
            }
            break;
#endif
    }

    return 0;
}

__attribute__ ((visibility ("default")))
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

__attribute__ ((visibility ("default")))
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
