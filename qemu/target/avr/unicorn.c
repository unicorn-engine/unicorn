/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

/*
   Created for Unicorn Engine by Glenn Baker <glenn.baker@gmx.com>, 2024
*/

#include "qemu/typedefs.h"
#include "unicorn/unicorn.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"
#include "cpu.h"
#include "uc_priv.h"
#include "unicorn_common.h"
#include "unicorn.h"

AVRCPU *cpu_avr_init(struct uc_struct *uc);

static inline uint32_t get_pc(CPUAVRState *env)
{
    return env->pc_w*2;
}

static uint64_t avr_get_pc(struct uc_struct *uc)
{
    return get_pc((CPUAVRState *)uc->cpu->env_ptr);
}

static inline void set_pc(CPUAVRState *env, uint32_t value)
{
    env->pc_w = value/2;
}

static void avr_set_pc(struct uc_struct *uc, uint64_t address)
{
    set_pc((CPUAVRState *)uc->cpu->env_ptr, address);
}

void avr_reg_reset(struct uc_struct *uc)
{
}

#define GET_BYTE(x, n)          (((x) >> (n)*8) & 0xff)
#define SET_BYTE(x, n, b)       (x = ((x) & ~(0xff << ((n)*8))) | ((b) << ((n)*8)))
#define GET_RAMP(reg)           GET_BYTE(env->glue(ramp,reg), 2)
#define SET_RAMP(reg, val)      SET_BYTE(env->glue(ramp,reg), 2, val)

static void reg_read(CPUAVRState *env, unsigned int regid, void *value)
{
    switch (regid) {
    case UC_AVR_REG_PC:
        *(uint32_t *)value = get_pc(env);
        break;
    case UC_AVR_REG_SP:
        *(uint32_t *)value = env->sp;
        break;

    case UC_AVR_REG_RAMPD:
        *(uint8_t *)value = GET_RAMP(D);
        break;
    case UC_AVR_REG_RAMPX:
        *(uint8_t *)value = GET_RAMP(X);
        break;
    case UC_AVR_REG_RAMPY:
        *(uint8_t *)value = GET_RAMP(Y);
        break;
    case UC_AVR_REG_RAMPZ:
        *(uint8_t *)value = GET_RAMP(Z);
        break;
    case UC_AVR_REG_EIND:
        *(uint8_t *)value = GET_BYTE(env->eind, 2);
        break;
    case UC_AVR_REG_SPL:
        *(uint8_t *)value = GET_BYTE(env->sp, 0);
        break;
    case UC_AVR_REG_SPH:
        *(uint8_t *)value = GET_BYTE(env->sp, 1);
        break;
    case UC_AVR_REG_SREG:
        *(uint8_t *)value = cpu_get_sreg(env);
        break;

    default:
        if (regid >= UC_AVR_REG_R0 && regid <= UC_AVR_REG_R31) {
            *(int8_t *)value = (int8_t)env->r[regid - UC_AVR_REG_R0];
        }
        break;
    }
}

int avr_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                     int count)
{
    CPUAVRState *env = &(AVR_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int avr_context_reg_read(struct uc_context *uc, unsigned int *regs,
                             void **vals, int count)
{
    CPUAVRState *env = (CPUAVRState *)uc->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

static void reg_write(CPUAVRState *env, unsigned int regid,
                      const void *value)
{
    switch (regid) {
    case UC_AVR_REG_PC:
        set_pc(env, *(uint32_t *)value);
        break;
    case UC_AVR_REG_SP:
        env->sp = *(uint32_t *)value;
        break;

    case UC_AVR_REG_RAMPD:
        SET_RAMP(D, *(uint8_t *)value);
        break;
    case UC_AVR_REG_RAMPX:
        SET_RAMP(X, *(uint8_t *)value);
        break;
    case UC_AVR_REG_RAMPY:
        SET_RAMP(Y, *(uint8_t *)value);
        break;
    case UC_AVR_REG_RAMPZ:
        SET_RAMP(Z, *(uint8_t *)value);
        break;
    case UC_AVR_REG_EIND:
        SET_BYTE(env->eind, 2, *(uint8_t *)value);
        break;
    case UC_AVR_REG_SPL:
        SET_BYTE(env->sp, 0, *(uint8_t *)value);
        break;
    case UC_AVR_REG_SPH:
        SET_BYTE(env->sp, 1, *(uint8_t *)value);
        break;
    case UC_AVR_REG_SREG:
        cpu_set_sreg(env, *(uint8_t *)value);
        break;

    default:
        if (regid >= UC_AVR_REG_R0 && regid <= UC_AVR_REG_R31) {
            env->r[regid - UC_AVR_REG_R0] = *(uint8_t *)value;
        }
    }
}

int avr_reg_write(struct uc_struct *uc, unsigned int *regs,
                      void *const *vals, int count)
{
    CPUAVRState *env = &(AVR_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_AVR_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

int avr_context_reg_write(struct uc_context *uc, unsigned int *regs,
                              void *const *vals, int count)
{
    CPUAVRState *env = (CPUAVRState *)uc->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
}

static int avr_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    AVRCPU *cpu;

    cpu = cpu_avr_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

static void avr_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    AVRCPU *cpu = (AVRCPU *)tcg_ctx->uc->cpu;
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

void avr_uc_init(struct uc_struct *uc)
{
    uc->reg_read = avr_reg_read;
    uc->reg_write = avr_reg_write;
    uc->reg_reset = avr_reg_reset;
    uc->set_pc = avr_set_pc;
    uc->get_pc = avr_get_pc;
    uc->cpus_init = avr_cpus_init;
    uc->release = avr_release;
    uc->cpu_context_size = offsetof(CPUAVRState, features);
    uc_common_init(uc);
}
