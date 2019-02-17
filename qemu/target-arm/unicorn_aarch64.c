/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "arm64_cpreg_info.h"

const int ARM64_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

const uc_arm_cp_reg ARM64_CP_REGS_INFO[] =  {
    //{ UC_ARM64_REG_XXXXX,           cp, crn,crm,opc0,opc1,opc2 }

    // Manual entries

    // Automatical generated entries
    UC_ARM64_CPREG_INFO_LIST       // C macro, see arm_cpgreg_info.h
};

static uint64_t raw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (cpreg_field_is_64bit(ri)) {
        return CPREG_FIELD64(env, ri);
    } else {
        return CPREG_FIELD32(env, ri);
    }
}

static void raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                      uint64_t value)
{
    if (cpreg_field_is_64bit(ri)) {
        CPREG_FIELD64(env, ri) = value;
    } else {
        CPREG_FIELD32(env, ri) = value;
    }
}

static int arm64_uc_to_qemu_cp_regs(unsigned int regid)
{
    int i;
    const uc_arm_cp_reg * tmp = NULL;
    for(i=0; i < sizeof(ARM64_CP_REGS_INFO); i++){
        tmp = &ARM64_CP_REGS_INFO[i];
        if (regid==tmp->uc_reg_id){   
            return ENCODE_AA64_CP_REG(tmp->cp, tmp->crn, tmp->crm, tmp->opc0, tmp->opc1, tmp->opc2);
        }
    }

    return -1;
}

static uint64_t read_raw_cp_reg(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Raw read of a coprocessor register (as needed for migration, etc). */
    if (ri->type & ARM_CP_CONST) {
        return ri->resetvalue;
    } else if (ri->raw_readfn) {
        return ri->raw_readfn(env, ri);
    } else if (ri->readfn) {
        return ri->readfn(env, ri);
    } else {
        return raw_read(env, ri);
    }
}

static void write_raw_cp_reg(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t v)
{
    /* Raw write of a coprocessor register (as needed for migration, etc).
     * Note that constant registers are treated as write-ignored; the
     * caller should check for success by whether a readback gives the
     * value written.
     */
    if (ri->type & ARM_CP_CONST) {
        return;
    } else if (ri->raw_writefn) {
        ri->raw_writefn(env, ri, v);
    } else if (ri->writefn) {
        ri->writefn(env, ri, v);
    } else {
        raw_write(env, ri, v);
    }
}

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
}

void arm64_release(void* ctx);

void arm64_release(void* ctx)
{
    struct uc_struct* uc;
    ARMCPU* cpu;
    TCGContext *s = (TCGContext *) ctx;

    g_free(s->tb_ctx.tbs);
    uc = s->uc;
    cpu = (ARMCPU*) uc->cpu;
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
    const ARMCPRegInfo *ri = NULL;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        // V & Q registers are the same
        if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0];
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            *(int32_t *)value = READ_DWORD(ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_W0]);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *dst = (float64*) value;
            uint32_t reg_index = 2*(regid - UC_ARM64_REG_Q0);
            dst[0] = ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index];
            dst[1] = ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index+1];
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            *(float64*)value = ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_D0)];
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            *(int32_t*)value = READ_DWORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_S0)]);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            *(int16_t*)value = READ_WORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_H0)]);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            *(int8_t*)value = READ_BYTE_L(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_B0)]);
        } else {
            switch(regid) {
                default: break;
                case UC_ARM64_REG_X29:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[29];
                    break;
                case UC_ARM64_REG_X30:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[30];
                    break;
                case UC_ARM64_REG_PC:
                    *(uint64_t *)value = ARM_CPU(uc, mycpu)->env.pc;
                    break;
                case UC_ARM64_REG_SP:
                    *(int64_t *)value = ARM_CPU(uc, mycpu)->env.xregs[31];
                    break;
                case UC_ARM64_REG_NZCV:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env) & CPSR_NZCV;
                    break;
            }
        }

        regid = arm64_uc_to_qemu_cp_regs(regid);
        ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
        if (ri){

            if (cpreg_field_is_64bit(ri)) {
               *(int64_t *)value = read_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri);
            } else {
                *(int32_t *)value = read_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri);
            }
        }
    }

    return 0;
}

int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    const ARMCPRegInfo *ri = NULL;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            regid += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            WRITE_DWORD(ARM_CPU(uc, mycpu)->env.xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *src = (float64*) value;
            uint32_t reg_index = 2*(regid - UC_ARM64_REG_Q0);
            ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index] = src[0];
            ARM_CPU(uc, mycpu)->env.vfp.regs[reg_index+1] = src[1];
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_D0)] = * (float64*) value;
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            WRITE_DWORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_S0)], *(int32_t*) value);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            WRITE_WORD(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_H0)], *(int16_t*) value);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            WRITE_BYTE_L(ARM_CPU(uc, mycpu)->env.vfp.regs[2*(regid - UC_ARM64_REG_B0)], *(int8_t*) value);
        } else {
            switch(regid) {
                default: break;
                case UC_ARM64_REG_CPACR_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.c1_coproc = *(uint32_t *)value;
                    break;
                case UC_ARM64_REG_TPIDR_EL0:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidr_el0 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TPIDRRO_EL0:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidrro_el0 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_TPIDR_EL1:
                    ARM_CPU(uc, mycpu)->env.cp15.tpidr_el1 = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_X29:
                    ARM_CPU(uc, mycpu)->env.xregs[29] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_X30:
                    ARM_CPU(uc, mycpu)->env.xregs[30] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_PC:
                    ARM_CPU(uc, mycpu)->env.pc = *(uint64_t *)value;
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);
                    break;
                case UC_ARM64_REG_SP:
                    ARM_CPU(uc, mycpu)->env.xregs[31] = *(uint64_t *)value;
                    break;
                case UC_ARM64_REG_NZCV:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *) value, CPSR_NZCV);
                    break;
            }

            regid = arm64_uc_to_qemu_cp_regs(regid);
            ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
            if (ri){
                if (cpreg_field_is_64bit(ri)) {
                    write_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri, *(uint64_t *)value);
                } else {
                    write_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri, *(uint32_t *)value);
                }
            }
        }
    }

    return 0;
}

int arm64_cpreg_read( struct uc_struct *uc,
                    uint8_t cp,
                    uint8_t crn,
                    uint8_t crm,
                    uint8_t opc0,
                    uint8_t opc1,
                    uint8_t opc2,
                    void *value)
{
    CPUState *mycpu = uc->cpu;
    const ARMCPRegInfo *ri = NULL;

    unsigned int regid = ENCODE_AA64_CP_REG(cp, crn, crm, opc0, opc1, opc2);

    ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
    if (ri){

        if (cpreg_field_is_64bit(ri)) {
           *(int64_t *)value = CPREG_FIELD64(&ARM_CPU(uc, mycpu)->env, ri);
        } else {
            *(int32_t *)value = CPREG_FIELD32(&ARM_CPU(uc, mycpu)->env, ri);
        }
    return 0;
    }
    return 1;
}

int arm64_cpreg_write( struct uc_struct *uc,
                    uint8_t cp,
                    uint8_t crn,
                    uint8_t crm,
                    uint8_t opc0,
                    uint8_t opc1,
                    uint8_t opc2,
                    const void *value)
{
    CPUState *mycpu = uc->cpu;
    const ARMCPRegInfo *ri = NULL;

    unsigned int regid = ENCODE_AA64_CP_REG(cp, crn, crm, opc0, opc1, opc2);

    ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
    if (ri){
        if (cpreg_field_is_64bit(ri)) {
            write_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri, *(uint64_t *)value);
        } else {
            write_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri, *(uint32_t *)value);
        }
        return 0;
    }
    return 1;
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
