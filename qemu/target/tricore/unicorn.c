/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

/*
   Created for Unicorn Engine by Eric Poole <eric.poole@aptiv.com>, 2022
   Copyright 2022 Aptiv
*/

#include "qemu/typedefs.h"
#include "unicorn/unicorn.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "cpu.h"
#include "uc_priv.h"
#include "unicorn_common.h"
#include "unicorn.h"

TriCoreCPU *cpu_tricore_init(struct uc_struct *uc);

static void tricore_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUTriCoreState *)uc->cpu->env_ptr)->PC = address;
}

static uint64_t tricore_get_pc(struct uc_struct *uc)
{
    return ((CPUTriCoreState *)uc->cpu->env_ptr)->PC;
}

static void reg_reset(struct uc_struct *uc)
{
    CPUTriCoreState *env;
    (void)uc;

    env = uc->cpu->env_ptr;
    memset(env->gpr_a, 0, sizeof(env->gpr_a));
    memset(env->gpr_d, 0, sizeof(env->gpr_d));

    env->PC = 0;
}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUTriCoreState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_TRICORE_REG_A0 && regid <= UC_TRICORE_REG_A9) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->gpr_a[regid - UC_TRICORE_REG_A0];
    } else if (regid >= UC_TRICORE_REG_A12 && regid <= UC_TRICORE_REG_A15) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->gpr_a[regid - UC_TRICORE_REG_A0];
    } else if (regid >= UC_TRICORE_REG_D0 && regid <= UC_TRICORE_REG_D15) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->gpr_d[regid - UC_TRICORE_REG_D0];
    } else {
        switch (regid) {
        // case UC_TRICORE_REG_SP:
        case UC_TRICORE_REG_A10:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->gpr_a[10];
            break;
        // case UC_TRICORE_REG_LR:
        case UC_TRICORE_REG_A11:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->gpr_a[11];
            break;
        case UC_TRICORE_REG_PC:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PC;
            break;
        case UC_TRICORE_REG_PCXI:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PCXI;
            break;
        case UC_TRICORE_REG_PSW:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PSW;
            break;
        case UC_TRICORE_REG_PSW_USB_C:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PSW_USB_C;
            break;
        case UC_TRICORE_REG_PSW_USB_V:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PSW_USB_V;
            break;
        case UC_TRICORE_REG_PSW_USB_SV:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PSW_USB_SV;
            break;
        case UC_TRICORE_REG_PSW_USB_AV:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PSW_USB_AV;
            break;
        case UC_TRICORE_REG_PSW_USB_SAV:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->PSW_USB_SAV;
            break;
        case UC_TRICORE_REG_SYSCON:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->SYSCON;
            break;
        case UC_TRICORE_REG_CPU_ID:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->CPU_ID;
            break;
        case UC_TRICORE_REG_BIV:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->BIV;
            break;
        case UC_TRICORE_REG_BTV:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->BTV;
            break;
        case UC_TRICORE_REG_ISP:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->ISP;
            break;
        case UC_TRICORE_REG_ICR:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->ICR;
            break;
        case UC_TRICORE_REG_FCX:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->FCX;
            break;
        case UC_TRICORE_REG_LCX:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->LCX;
            break;
        case UC_TRICORE_REG_COMPAT:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->COMPAT;
            break;
        }
    }

    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUTriCoreState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_TRICORE_REG_A0 && regid <= UC_TRICORE_REG_A9) {
        CHECK_REG_TYPE(uint32_t);
        env->gpr_a[regid - UC_TRICORE_REG_A0] = *(uint32_t *)value;
    } else if (regid >= UC_TRICORE_REG_A12 && regid <= UC_TRICORE_REG_A15) {
        CHECK_REG_TYPE(uint32_t);
        env->gpr_a[regid - UC_TRICORE_REG_A0] = *(uint32_t *)value;
    } else if (regid >= UC_TRICORE_REG_D0 && regid <= UC_TRICORE_REG_D15) {
        CHECK_REG_TYPE(uint32_t);
        env->gpr_d[regid - UC_TRICORE_REG_D0] = *(uint32_t *)value;
    } else {
        switch (regid) {
        // case UC_TRICORE_REG_SP:
        case UC_TRICORE_REG_A10:
            CHECK_REG_TYPE(uint32_t);
            env->gpr_a[10] = *(uint32_t *)value;
            break;
        // case UC_TRICORE_REG_LR:
        case UC_TRICORE_REG_A11:
            CHECK_REG_TYPE(uint32_t);
            env->gpr_a[11] = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PC:
            CHECK_REG_TYPE(uint32_t);
            env->PC = *(uint32_t *)value;
            *setpc = 1;
            break;
        case UC_TRICORE_REG_PCXI:
            CHECK_REG_TYPE(uint32_t);
            env->PCXI = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PSW:
            CHECK_REG_TYPE(uint32_t);
            env->PSW = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_C:
            CHECK_REG_TYPE(uint32_t);
            env->PSW_USB_C = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_V:
            CHECK_REG_TYPE(uint32_t);
            env->PSW_USB_V = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_SV:
            CHECK_REG_TYPE(uint32_t);
            env->PSW_USB_SV = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_AV:
            CHECK_REG_TYPE(uint32_t);
            env->PSW_USB_AV = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_SAV:
            CHECK_REG_TYPE(uint32_t);
            env->PSW_USB_SAV = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_SYSCON:
            CHECK_REG_TYPE(uint32_t);
            env->SYSCON = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_CPU_ID:
            CHECK_REG_TYPE(uint32_t);
            env->CPU_ID = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_BIV:
            CHECK_REG_TYPE(uint32_t);
            env->BIV = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_BTV:
            CHECK_REG_TYPE(uint32_t);
            env->BTV = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_ISP:
            CHECK_REG_TYPE(uint32_t);
            env->ISP = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_ICR:
            CHECK_REG_TYPE(uint32_t);
            env->ICR = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_FCX:
            CHECK_REG_TYPE(uint32_t);
            env->FCX = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_LCX:
            CHECK_REG_TYPE(uint32_t);
            env->LCX = *(uint32_t *)value;
            break;
        case UC_TRICORE_REG_COMPAT:
            CHECK_REG_TYPE(uint32_t);
            env->COMPAT = *(uint32_t *)value;
            break;
        }
    }

    return ret;
}

static int tricore_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    TriCoreCPU *cpu;

    cpu = cpu_tricore_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

static void tricore_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    TriCoreCPU *cpu = (TriCoreCPU *)tcg_ctx->uc->cpu;
    CPUTLBDesc *d = cpu->neg.tlb.d;
    CPUTLBDescFast *f = cpu->neg.tlb.f;
    CPUTLBDesc *desc;
    CPUTLBDescFast *fast;

    release_common(ctx);
    for (i = 0; i < NB_MMU_MODES; i++) {
        desc = &(d[i]);
        fast = &(f[i]);
        g_free(desc->iotlb);
        g_free(fast->table);
    }
}

DEFAULT_VISIBILITY
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->set_pc = tricore_set_pc;
    uc->get_pc = tricore_get_pc;
    uc->cpus_init = tricore_cpus_init;
    uc->release = tricore_release;
    uc->cpu_context_size = offsetof(CPUTriCoreState, end_reset_fields);
    uc_common_init(uc);
}
