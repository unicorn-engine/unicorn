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

static void reg_reset(struct uc_struct *uc)
{
}

#define GET_BYTE(x, n)          (((x) >> (n)*8) & 0xff)
#define SET_BYTE(x, n, b)       (x = ((x) & ~(0xff << ((n)*8))) | ((b) << ((n)*8)))
#define GET_RAMP(reg)           GET_BYTE(env->glue(ramp,reg), 2)
#define SET_RAMP(reg, val)      SET_BYTE(env->glue(ramp,reg), 2, val)

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUAVRState *const env = _env;
    uc_err ret = UC_ERR_ARG;

    switch (regid) {
    case UC_AVR_REG_PC:
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = get_pc(env);
        break;
    case UC_AVR_REG_SP:
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->sp;
        break;

    case UC_AVR_REG_RAMPD:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_RAMP(D);
        break;
    case UC_AVR_REG_RAMPX:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_RAMP(X);
        break;
    case UC_AVR_REG_RAMPY:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_RAMP(Y);
        break;
    case UC_AVR_REG_RAMPZ:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_RAMP(Z);
        break;
    case UC_AVR_REG_EIND:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_BYTE(env->eind, 2);
        break;
    case UC_AVR_REG_SPL:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_BYTE(env->sp, 0);
        break;
    case UC_AVR_REG_SPH:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = GET_BYTE(env->sp, 1);
        break;
    case UC_AVR_REG_SREG:
        CHECK_REG_TYPE(uint8_t);
        *(uint8_t *)value = cpu_get_sreg(env);
        break;

    default: {
        uint64_t v = 0;
        if (regid >= UC_AVR_REG_R0 && regid <= UC_AVR_REG_R31) {
            CHECK_REG_TYPE(uint8_t);
            *(int8_t *)value = (int8_t)env->r[regid - UC_AVR_REG_R0];
        }
        else if (regid >= UC_AVR_REG_R0W && regid <= UC_AVR_REG_R30W) {
            const uint32_t *const r = &env->r[regid - UC_AVR_REG_R0W];
            for (int k = 0; k < 2; k++)
                SET_BYTE(v, k, (r[k] & 0xff));
            CHECK_REG_TYPE(uint16_t);
            *(int16_t *)value = (int16_t)v;
        }
        else if (regid >= UC_AVR_REG_R0D && regid <= UC_AVR_REG_R28D) {
            const uint32_t *const r = &env->r[regid - UC_AVR_REG_R0D];
            for (int k = 0; k < 4; k++)
                SET_BYTE(v, k, (r[k] & 0xff));
            CHECK_REG_TYPE(uint32_t);
            *(int32_t *)value = (int32_t)v;
        }
        break;
    }
    }
    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUAVRState *const env = _env;
    uc_err ret = UC_ERR_ARG;

    switch (regid) {
    case UC_AVR_REG_PC:
        CHECK_REG_TYPE(uint32_t);
        set_pc(env, *(uint32_t *)value);
        *setpc = 1;
        break;
    case UC_AVR_REG_SP:
        CHECK_REG_TYPE(uint32_t);
        env->sp = *(uint32_t *)value;
        break;

    case UC_AVR_REG_RAMPD:
        CHECK_REG_TYPE(uint8_t);
        SET_RAMP(D, *(uint8_t *)value);
        break;
    case UC_AVR_REG_RAMPX:
        CHECK_REG_TYPE(uint8_t);
        SET_RAMP(X, *(uint8_t *)value);
        break;
    case UC_AVR_REG_RAMPY:
        CHECK_REG_TYPE(uint8_t);
        SET_RAMP(Y, *(uint8_t *)value);
        break;
    case UC_AVR_REG_RAMPZ:
        CHECK_REG_TYPE(uint8_t);
        SET_RAMP(Z, *(uint8_t *)value);
        break;
    case UC_AVR_REG_EIND:
        CHECK_REG_TYPE(uint8_t);
        SET_BYTE(env->eind, 2, *(uint8_t *)value);
        break;
    case UC_AVR_REG_SPL:
        CHECK_REG_TYPE(uint8_t);
        SET_BYTE(env->sp, 0, *(uint8_t *)value);
        break;
    case UC_AVR_REG_SPH:
        CHECK_REG_TYPE(uint8_t);
        SET_BYTE(env->sp, 1, *(uint8_t *)value);
        break;
    case UC_AVR_REG_SREG:
        CHECK_REG_TYPE(uint8_t);
        cpu_set_sreg(env, *(uint8_t *)value);
        break;

    default: {
        uint64_t v;
        uint32_t *r = NULL;
        int rlen = 0;
        if (regid >= UC_AVR_REG_R0 && regid <= UC_AVR_REG_R31) {
            v = *(uint8_t *)value;
            r = &env->r[regid - UC_AVR_REG_R0];
            rlen = 1;
            CHECK_REG_TYPE(uint8_t);
        }
        else if (regid >= UC_AVR_REG_R0W && regid <= UC_AVR_REG_R30W) {
            v = *(uint16_t *)value;
            r = &env->r[regid - UC_AVR_REG_R0W];
            rlen = 2;
            CHECK_REG_TYPE(uint16_t);
        }
        else if (regid >= UC_AVR_REG_R0D && regid <= UC_AVR_REG_R28D) {
            v = *(uint32_t *)value;
            r = &env->r[regid - UC_AVR_REG_R0D];
            rlen = 4;
            CHECK_REG_TYPE(uint32_t);
        }
        if (r && rlen > 0) {
            for (int k = 0; k < rlen; k++)
                r[k] = GET_BYTE(v, k);
        }
    }
    }
    return ret;
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

static inline bool is_flash_memory(hwaddr addr, size_t size, uint32_t perms)
{
    if ((addr ^ UC_AVR_MEM_FLASH) >> 24)
        return false;
    if ((perms & UC_PROT_ALL) != (UC_PROT_READ|UC_PROT_EXEC))
        return false;
    return true;
}

static MemoryRegion *avr_memory_map(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms)
{
    MemoryRegion *const mr = memory_map(uc, begin, size, perms);
    if (mr && is_flash_memory(begin, size, perms))
        set_avr_feature(&AVR_CPU(uc->cpu)->env, AVR_FEATURE_FLASH);
    return mr;
}

static MemoryRegion *avr_memory_map_ptr(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms, void *ptr)
{
    MemoryRegion *const mr = memory_map_ptr(uc, begin, size, perms, ptr);
    if (mr && is_flash_memory(begin, size, perms))
        set_avr_feature(&AVR_CPU(uc->cpu)->env, AVR_FEATURE_FLASH);
    return mr;
}

DEFAULT_VISIBILITY
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->set_pc = avr_set_pc;
    uc->get_pc = avr_get_pc;
    uc->cpus_init = avr_cpus_init;
    uc->release = avr_release;
    uc->cpu_context_size = offsetof(CPUAVRState, features);
    uc_common_init(uc);
    uc->memory_map = avr_memory_map;
    uc->memory_map_ptr = avr_memory_map_ptr;
}
