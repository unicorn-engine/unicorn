/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

M68kCPU *cpu_m68k_init(struct uc_struct *uc);

static void m68k_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUM68KState *)uc->cpu->env_ptr)->pc = address;
}

static uint64_t m68k_get_pc(struct uc_struct *uc)
{
    return ((CPUM68KState *)uc->cpu->env_ptr)->pc;
}

static void m68k_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    M68kCPU *cpu = (M68kCPU *)tcg_ctx->uc->cpu;
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

static void reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->aregs, 0, sizeof(env->aregs));
    memset(env->dregs, 0, sizeof(env->dregs));

    env->pc = 0;
}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPUM68KState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->aregs[regid - UC_M68K_REG_A0];
    } else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->dregs[regid - UC_M68K_REG_D0];
    } else {
        switch (regid) {
        default:
            break;
        case UC_M68K_REG_PC:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->pc;
            break;
        case UC_M68K_REG_SR:
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->sr;
            break;
        }
    }

    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPUM68KState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_M68K_REG_A0 && regid <= UC_M68K_REG_A7) {
        CHECK_REG_TYPE(uint32_t);
        env->aregs[regid - UC_M68K_REG_A0] = *(uint32_t *)value;
    } else if (regid >= UC_M68K_REG_D0 && regid <= UC_M68K_REG_D7) {
        CHECK_REG_TYPE(uint32_t);
        env->dregs[regid - UC_M68K_REG_D0] = *(uint32_t *)value;
    } else {
        switch (regid) {
        default:
            break;
        case UC_M68K_REG_PC:
            CHECK_REG_TYPE(uint32_t);
            env->pc = *(uint32_t *)value;
            *setpc = 1;
            break;
        case UC_M68K_REG_SR:
            CHECK_REG_TYPE(uint32_t);
            cpu_m68k_set_sr(env, *(uint32_t *)value);
            break;
        }
    }

    return ret;
}

static int m68k_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    M68kCPU *cpu;

    cpu = cpu_m68k_init(uc);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void uc_init(struct uc_struct *uc)
{
    uc->release = m68k_release;
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->set_pc = m68k_set_pc;
    uc->get_pc = m68k_get_pc;
    uc->cpus_init = m68k_cpus_init;
    uc->cpu_context_size = offsetof(CPUM68KState, end_reset_fields);
    uc_common_init(uc);
}
