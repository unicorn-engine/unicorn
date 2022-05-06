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

void tricore_reg_reset(struct uc_struct *uc)
{
    CPUTriCoreState *env;
    (void)uc;

    env = uc->cpu->env_ptr;
    memset(env->gpr_a, 0, sizeof(env->gpr_a));
    memset(env->gpr_d, 0, sizeof(env->gpr_d));

    env->PC = 0;
}

static void reg_read(CPUTriCoreState *env, unsigned int regid, void *value)
{
    if (regid >= UC_TRICORE_REG_A0 && regid <= UC_TRICORE_REG_A9)
        *(int32_t *)value = env->gpr_a[regid - UC_TRICORE_REG_A0];
    if (regid >= UC_TRICORE_REG_A12 && regid <= UC_TRICORE_REG_A15)
        *(int32_t *)value = env->gpr_a[regid - UC_TRICORE_REG_A0];
    else if (regid >= UC_TRICORE_REG_D0 && regid <= UC_TRICORE_REG_D15)
        *(int32_t *)value = env->gpr_d[regid - UC_TRICORE_REG_D0];
    else {
        switch (regid) {
        // case UC_TRICORE_REG_SP:
        case UC_TRICORE_REG_A10:
            *(int32_t *)value = env->gpr_a[10];
            break;
        // case UC_TRICORE_REG_LR:
        case UC_TRICORE_REG_A11:
            *(int32_t *)value = env->gpr_a[11];
            break;
        case UC_TRICORE_REG_PC:
            *(int32_t *)value = env->PC;
            break;
        case UC_TRICORE_REG_PCXI:
            *(int32_t *)value = env->PCXI;
            break;
        case UC_TRICORE_REG_PSW:
            *(int32_t *)value = env->PSW;
            break;
        case UC_TRICORE_REG_PSW_USB_C:
            *(int32_t *)value = env->PSW_USB_C;
            break;
        case UC_TRICORE_REG_PSW_USB_V:
            *(int32_t *)value = env->PSW_USB_V;
            break;
        case UC_TRICORE_REG_PSW_USB_SV:
            *(int32_t *)value = env->PSW_USB_SV;
            break;
        case UC_TRICORE_REG_PSW_USB_AV:
            *(int32_t *)value = env->PSW_USB_AV;
            break;
        case UC_TRICORE_REG_PSW_USB_SAV:
            *(int32_t *)value = env->PSW_USB_SAV;
            break;
        case UC_TRICORE_REG_SYSCON:
            *(int32_t *)value = env->SYSCON;
            break;
        case UC_TRICORE_REG_CPU_ID:
            *(int32_t *)value = env->CPU_ID;
            break;
        case UC_TRICORE_REG_BIV:
            *(int32_t *)value = env->BIV;
            break;
        case UC_TRICORE_REG_BTV:
            *(int32_t *)value = env->BTV;
            break;
        case UC_TRICORE_REG_ISP:
            *(int32_t *)value = env->ISP;
            break;
        case UC_TRICORE_REG_ICR:
            *(int32_t *)value = env->ICR;
            break;
        case UC_TRICORE_REG_FCX:
            *(int32_t *)value = env->FCX;
            break;
        case UC_TRICORE_REG_LCX:
            *(int32_t *)value = env->LCX;
            break;
        case UC_TRICORE_REG_COMPAT:
            *(int32_t *)value = env->COMPAT;
            break;
        }
    }
}

int tricore_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                     int count)
{
    CPUTriCoreState *env = &(TRICORE_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int tricore_context_reg_read(struct uc_context *uc, unsigned int *regs,
                             void **vals, int count)
{
    CPUTriCoreState *env = (CPUTriCoreState *)uc->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

static void reg_write(CPUTriCoreState *env, unsigned int regid,
                      const void *value)
{
    if (regid >= UC_TRICORE_REG_A0 && regid <= UC_TRICORE_REG_A9)
        env->gpr_a[regid - UC_TRICORE_REG_A0] = *(int32_t *)value;
    if (regid >= UC_TRICORE_REG_A12 && regid <= UC_TRICORE_REG_A15)
        env->gpr_a[regid - UC_TRICORE_REG_A0] = *(int32_t *)value;
    else if (regid >= UC_TRICORE_REG_D0 && regid <= UC_TRICORE_REG_D15)
        env->gpr_d[regid - UC_TRICORE_REG_D0] = *(int32_t *)value;
    else {
        switch (regid) {
        // case UC_TRICORE_REG_SP:
        case UC_TRICORE_REG_A10:
            env->gpr_a[10] = *(int32_t *)value;
            break;
        // case UC_TRICORE_REG_LR:
        case UC_TRICORE_REG_A11:
            env->gpr_a[11] = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PC:
            env->PC = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PCXI:
            env->PCXI = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PSW:
            env->PSW = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_C:
            env->PSW_USB_C = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_V:
            env->PSW_USB_V = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_SV:
            env->PSW_USB_SV = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_AV:
            env->PSW_USB_AV = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_PSW_USB_SAV:
            env->PSW_USB_SAV = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_SYSCON:
            env->SYSCON = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_CPU_ID:
            env->CPU_ID = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_BIV:
            env->BIV = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_BTV:
            env->BTV = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_ISP:
            env->ISP = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_ICR:
            env->ICR = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_FCX:
            env->FCX = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_LCX:
            env->LCX = *(int32_t *)value;
            break;
        case UC_TRICORE_REG_COMPAT:
            env->COMPAT = *(int32_t *)value;
            break;
        }
    }
}

int tricore_reg_write(struct uc_struct *uc, unsigned int *regs,
                      void *const *vals, int count)
{
    CPUTriCoreState *env = &(TRICORE_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_TRICORE_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

int tricore_context_reg_write(struct uc_context *uc, unsigned int *regs,
                              void *const *vals, int count)
{
    CPUTriCoreState *env = (CPUTriCoreState *)uc->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
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

void tricore_uc_init(struct uc_struct *uc)
{
    uc->reg_read = tricore_reg_read;
    uc->reg_write = tricore_reg_write;
    uc->reg_reset = tricore_reg_reset;
    uc->set_pc = tricore_set_pc;
    uc->get_pc = tricore_get_pc;
    uc->cpus_init = tricore_cpus_init;
    uc->cpu_context_size = offsetof(CPUTriCoreState, end_reset_fields);
    uc_common_init(uc);
}