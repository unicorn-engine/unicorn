/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "unicorn_common.h"
#include "uc_priv.h"

const int ARM64_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    CPUArchState *state = uc->cpu->env_ptr;

    state->pc = address;
}

void arm64_release(void* ctx);

void arm64_release(void* ctx)
{
    TCGContext *s = (TCGContext *) ctx;
    struct uc_struct* uc = s->uc;
    ARMCPU* cpu = ARM_CPU(uc, uc->cpu);

    g_free(s->tb_ctx.tbs);
    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);

    release_common(ctx);
}

void arm64_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;
    memset(env->xregs, 0, sizeof(env->xregs));

    env->pc = 0;
}

int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    CPUARMState *state = &ARM_CPU(uc, mycpu)->env;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        // V & Q registers are the same
        if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            *(int64_t *)value = state->xregs[regid - UC_ARM64_REG_X0];
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            *(int32_t *)value = READ_DWORD(state->xregs[regid - UC_ARM64_REG_W0]);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *dst = (float64*) value;
            uint32_t reg_index = 2*(regid - UC_ARM64_REG_Q0);
            dst[0] = state->vfp.regs[reg_index];
            dst[1] = state->vfp.regs[reg_index+1];
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            *(float64*)value = state->vfp.regs[2*(regid - UC_ARM64_REG_D0)];
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            *(int32_t*)value = READ_DWORD(state->vfp.regs[2*(regid - UC_ARM64_REG_S0)]);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            *(int16_t*)value = READ_WORD(state->vfp.regs[2*(regid - UC_ARM64_REG_H0)]);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            *(int8_t*)value = READ_BYTE_L(state->vfp.regs[2*(regid - UC_ARM64_REG_B0)]);
        } else {
            switch(regid) {
                default: break;
                case UC_ARM64_REG_CPACR_EL1:
                    *(uint32_t *)value = state->cp15.cpacr_el1;
                    break;
                case UC_ARM64_REG_ESR:
                    *(uint32_t *)value = state->exception.syndrome;
                    break;
                case UC_ARM64_REG_TPIDR_EL0:
                    *(int64_t *)value = state->cp15.tpidr_el[0];
                    break;
                case UC_ARM64_REG_TPIDRRO_EL0:
                    *(int64_t *)value = state->cp15.tpidrro_el[0];
                    break;
                case UC_ARM64_REG_TPIDR_EL1:
                    *(int64_t *)value = state->cp15.tpidr_el[1];
                    break;
                case UC_ARM64_REG_X29:
                    *(int64_t *)value = state->xregs[29];
                    break;
                case UC_ARM64_REG_X30:
                    *(int64_t *)value = state->xregs[30];
                    break;
                case UC_ARM64_REG_PC:
                    *(uint64_t *)value = state->pc;
                    break;
                case UC_ARM64_REG_SP:
                    *(int64_t *)value = state->xregs[31];
                    break;
                case UC_ARM64_REG_NZCV:
                    *(int32_t *)value = cpsr_read(state) & CPSR_NZCV;
                    break;
                case UC_ARM64_REG_PSTATE:
                    *(uint32_t *)value = pstate_read(state);
                    break;
                case UC_ARM64_REG_FPCR:
                    *(uint32_t *)value = vfp_get_fpcr(state);
                    break;
                case UC_ARM64_REG_FPSR:
                    *(uint32_t *)value = vfp_get_fpsr(state);
                    break;
            }
        }
    }

    return 0;
}

int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    CPUARMState *state = &ARM_CPU(uc, mycpu)->env;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            state->xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            WRITE_DWORD(state->xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *src = (float64*) value;
            uint32_t reg_index = 2*(regid - UC_ARM64_REG_Q0);
            state->vfp.regs[reg_index] = src[0];
            state->vfp.regs[reg_index+1] = src[1];
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            state->vfp.regs[2*(regid - UC_ARM64_REG_D0)] = * (float64*) value;
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            WRITE_DWORD(state->vfp.regs[2*(regid - UC_ARM64_REG_S0)], *(int32_t*) value);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            WRITE_WORD(state->vfp.regs[2*(regid - UC_ARM64_REG_H0)], *(int16_t*) value);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            WRITE_BYTE_L(state->vfp.regs[2*(regid - UC_ARM64_REG_B0)], *(int8_t*) value);
        } else {
            switch(regid) {
                default: break;
                case UC_ARM64_REG_CPACR_EL1:
                    state->cp15.cpacr_el1 = *(uint32_t *)value;
                    break;
                case UC_ARM64_REG_TPIDR_EL0:
                    state->cp15.tpidr_el[0] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TPIDRRO_EL0:
                    state->cp15.tpidrro_el[0] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TPIDR_EL1:
                    state->cp15.tpidr_el[1] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_X29:
                    state->xregs[29] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_X30:
                    state->xregs[30] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_PC:
                    state->pc = *(uint64_t *)value;
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);
                    break;
                case UC_ARM64_REG_SP:
                    state->xregs[31] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_NZCV:
                    cpsr_write(state, *(uint32_t *) value, CPSR_NZCV, CPSRWriteRaw);
                    break;
                case UC_ARM64_REG_PSTATE:
                    pstate_write(state, *(uint32_t *)value);
                    break;
                case UC_ARM64_REG_FPCR:
                    vfp_set_fpcr(state, *(uint32_t *)value);
                    break;
                case UC_ARM64_REG_FPSR:
                    vfp_set_fpsr(state, *(uint32_t *)value);
                    break;
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
void arm64eb_uc_init(struct uc_struct* uc)
#else
void arm64_uc_init(struct uc_struct* uc)
#endif
{
    register_accel_types(uc);
    arm_cpu_register_types(uc);
    aarch64_cpu_register_types(uc);
    machvirt_machine_init(uc);
    uc->reg_read = arm64_reg_read;
    uc->reg_write = arm64_reg_write;
    uc->reg_reset = arm64_reg_reset;
    uc->set_pc = arm64_set_pc;
    uc->release = arm64_release;
    uc_common_init(uc);
}
