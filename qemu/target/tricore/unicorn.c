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

#define TRICORE_READ_REG_FIELD(reg, field)                                    \
    case reg:                                                                 \
        CHECK_REG_TYPE(uint32_t);                                             \
        *(uint32_t *)value = env->field;                                      \
        break

#define TRICORE_WRITE_REG_FIELD(reg, field)                                   \
    case reg:                                                                 \
        CHECK_REG_TYPE(uint32_t);                                             \
        env->field = *(uint32_t *)value;                                      \
        break

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
            *(uint32_t *)value = psw_read(env);
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
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR0_U, DPR0_0U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR1_U, DPR0_1U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR2_U, DPR0_2U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR3_U, DPR0_3U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR0_L, DPR0_0L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR1_L, DPR0_1L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR2_L, DPR0_2L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPR3_L, DPR0_3L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR0_U, CPR0_0U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR1_U, CPR0_1U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR2_U, CPR0_2U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR3_U, CPR0_3U);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR0_L, CPR0_0L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR1_L, CPR0_1L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR2_L, CPR0_2L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPR3_L, CPR0_3L);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPM0, DPM0);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPM1, DPM1);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPM2, DPM2);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DPM3, DPM3);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPM0, CPM0);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPM1, CPM1);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPM2, CPM2);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CPM3, CPM3);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MMU_CON, MMU_CON);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MMU_ASI, MMU_ASI);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MMU_TVA, MMU_TVA);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MMU_TPA, MMU_TPA);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MMU_TPX, MMU_TPX);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MMU_TFA, MMU_TFA);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_BMACON, BMACON);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_SMACON, SMACON);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DIEAR, DIEAR);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DIETR, DIETR);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CCDIER, CCDIER);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_MIECON, MIECON);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_PIEAR, PIEAR);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_PIETR, PIETR);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CCPIER, CCPIER);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DBGSR, DBGSR);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_EXEVT, EXEVT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CREVT, CREVT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_SWEVT, SWEVT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_TR0EVT, TR0EVT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_TR1EVT, TR1EVT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DMS, DMS);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DCX, DCX);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_DBGTCR, DBGTCR);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CCTRL, CCTRL);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_CCNT, CCNT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_ICNT, ICNT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_M1CNT, M1CNT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_M2CNT, M2CNT);
        TRICORE_READ_REG_FIELD(UC_TRICORE_REG_M3CNT, M3CNT);
        }
    }

    CHECK_RET_DEPRECATE(ret, regid);
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
            psw_write(env, *(uint32_t *)value);
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
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR0_U, DPR0_0U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR1_U, DPR0_1U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR2_U, DPR0_2U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR3_U, DPR0_3U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR0_L, DPR0_0L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR1_L, DPR0_1L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR2_L, DPR0_2L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPR3_L, DPR0_3L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR0_U, CPR0_0U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR1_U, CPR0_1U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR2_U, CPR0_2U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR3_U, CPR0_3U);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR0_L, CPR0_0L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR1_L, CPR0_1L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR2_L, CPR0_2L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPR3_L, CPR0_3L);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPM0, DPM0);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPM1, DPM1);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPM2, DPM2);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DPM3, DPM3);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPM0, CPM0);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPM1, CPM1);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPM2, CPM2);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CPM3, CPM3);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MMU_CON, MMU_CON);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MMU_ASI, MMU_ASI);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MMU_TVA, MMU_TVA);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MMU_TPA, MMU_TPA);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MMU_TPX, MMU_TPX);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MMU_TFA, MMU_TFA);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_BMACON, BMACON);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_SMACON, SMACON);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DIEAR, DIEAR);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DIETR, DIETR);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CCDIER, CCDIER);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_MIECON, MIECON);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_PIEAR, PIEAR);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_PIETR, PIETR);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CCPIER, CCPIER);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DBGSR, DBGSR);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_EXEVT, EXEVT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CREVT, CREVT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_SWEVT, SWEVT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_TR0EVT, TR0EVT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_TR1EVT, TR1EVT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DMS, DMS);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DCX, DCX);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_DBGTCR, DBGTCR);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CCTRL, CCTRL);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_CCNT, CCNT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_ICNT, ICNT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_M1CNT, M1CNT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_M2CNT, M2CNT);
        TRICORE_WRITE_REG_FIELD(UC_TRICORE_REG_M3CNT, M3CNT);
        }
    }

    CHECK_RET_DEPRECATE(ret, regid);
    return ret;
}

#undef TRICORE_READ_REG_FIELD
#undef TRICORE_WRITE_REG_FIELD

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
