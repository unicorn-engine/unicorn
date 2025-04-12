/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2021 */
/* Modified for Unicorn Engine by Damien Cauquil<dcauquil@quarkslab.com>, 2020
 */

#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "unicorn.h"

RH850CPU *cpu_rh850_init(struct uc_struct *uc);

static void rh850_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPURH850State *)uc->cpu->env_ptr)->pc = address;
}

static uint64_t rh850_get_pc(struct uc_struct *uc)
{
    return ((CPURH850State *)uc->cpu->env_ptr)->pc;
}

static void rh850_release(void *ctx)
{

    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    RH850CPU *cpu = (RH850CPU *)tcg_ctx->uc->cpu;
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

    memset(env->gpRegs, 0, sizeof(env->gpRegs));
    env->pc = 0;
}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    int sel_id;
    CPURH850State *env = _env;
    uc_err ret = UC_ERR_ARG;

    /* PC */
    if (regid == UC_RH850_REG_PC) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->pc;
    }

    /* General purpose register. */
    if ((regid >= UC_RH850_REG_R0) && (regid <= UC_RH850_REG_R31)) {
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->gpRegs[regid];
    }

    /* System registers. */
    if ((regid >= UC_RH850_REG_EIPC) &&
        (regid < (UC_RH850_REG_PC))) {
        CHECK_REG_TYPE(uint32_t);
        sel_id = (regid - 32) / 32;
        *(uint32_t *)value = env->sys_reg[sel_id][regid % 32];
    }

    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    int sel_id;
    CPURH850State *env = _env;
    uc_err ret = UC_ERR_ARG;

    /* PC */
    if (regid == UC_RH850_REG_PC) {
        CHECK_REG_TYPE(uint32_t);
        env->pc = *(uint32_t *)value;
        *setpc = 1;
    }

    /* General purpose register. */
    if ((regid >= UC_RH850_REG_R0) && (regid <= UC_RH850_REG_R31)) {
        CHECK_REG_TYPE(uint32_t);
        env->gpRegs[regid] = *(uint32_t *)value;
    }

    /* System registers. */
    if ((regid >= UC_RH850_REG_EIPC) &&
        (regid <= (UC_RH850_REG_PC))) {
        CHECK_REG_TYPE(uint32_t);
        sel_id = (regid - 32) / 32;
        env->sys_reg[sel_id][regid % 32] = *(uint32_t *)value;
    }

    return ret;
}

static int rh850_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    RH850CPU *cpu;

    cpu = cpu_rh850_init(uc);
    if (cpu == NULL) {
        return -1;
    }
    return 0;
}

DEFAULT_VISIBILITY
void uc_init_rh850(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->release = rh850_release;
    uc->set_pc = rh850_set_pc;
    uc->get_pc = rh850_get_pc;
    uc->cpus_init = rh850_cpus_init;
    uc->cpu_context_size = offsetof(CPURH850State, uc);
    uc_common_init(uc);
}
