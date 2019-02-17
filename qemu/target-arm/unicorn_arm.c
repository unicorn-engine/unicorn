/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"
#include "arm_cpreg_info.h"
const int ARM_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

const uc_arm_cp_reg ARM_CP_REGS_INFO[] =  {
    // { UC_ARM_REG_XXXXX,           cp, crn,crm,opc0,opc1,opc2 }

    // Manual entries

    // Automatical generated entries
    UC_ARM_CPREG_INFO_LIST       // C macro, see arm_cpgreg_info.h
};


static int arm_uc_to_qemu_cp_regs(unsigned int regid)
{
    int i;
    const uc_arm_cp_reg * tmp = NULL;
    for(i=0; i < sizeof(ARM_CP_REGS_INFO); i++){
        tmp = &ARM_CP_REGS_INFO[i];
        if (regid==tmp->uc_reg_id){   
            return ENCODE_CP_REG(tmp->cp,tmp->crn, tmp->crm, tmp->opc0, tmp->opc1, tmp->opc2);
        }
    }

    return -1;
}

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

static void arm_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUARMState *)uc->current_cpu->env_ptr)->pc = address;
    ((CPUARMState *)uc->current_cpu->env_ptr)->regs[15] = address;
}

void arm_release(void* ctx);

void arm_release(void* ctx)
{
    ARMCPU* cpu;
    struct uc_struct* uc;
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

void arm_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;
    (void)uc;

    env = uc->cpu->env_ptr;
    memset(env->regs, 0, sizeof(env->regs));

    env->pc = 0;
}

int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu;
    const ARMCPRegInfo *ri = NULL;
    int i;

    mycpu = uc->cpu;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
            *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0];
        else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31)
            *(float64 *)value = ARM_CPU(uc, mycpu)->env.vfp.regs[regid - UC_ARM_REG_D0];
        else {
            switch(regid) {
                case UC_ARM_REG_APSR:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env) & CPSR_NZCV;
                    break;
                case UC_ARM_REG_CPSR:
                    *(int32_t *)value = cpsr_read(&ARM_CPU(uc, mycpu)->env);
                    break;
                //case UC_ARM_REG_SP:
                case UC_ARM_REG_R13:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[13];
                    break;
                //case UC_ARM_REG_LR:
                case UC_ARM_REG_R14:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[14];
                    break;
                //case UC_ARM_REG_PC:
                case UC_ARM_REG_R15:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.regs[15];
                    break;
                case UC_ARM_REG_FPEXC:
                    *(int32_t *)value = ARM_CPU(uc, mycpu)->env.vfp.xregs[ARM_VFP_FPEXC];
                    break;
            }

            regid = arm_uc_to_qemu_cp_regs(regid);
            ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
            if (ri){
                   *(int32_t *)value = read_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri);
            }
        }
    }
    return 0;
}

int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    const ARMCPRegInfo *ri = NULL;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12)
            ARM_CPU(uc, mycpu)->env.regs[regid - UC_ARM_REG_R0] = *(uint32_t *)value;
        else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31)
            ARM_CPU(uc, mycpu)->env.vfp.regs[regid - UC_ARM_REG_D0] = *(float64 *)value;
        else {
            switch(regid) {
                case UC_ARM_REG_APSR:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, CPSR_NZCV);
                    break;
                case UC_ARM_REG_CPSR:
                    cpsr_write(&ARM_CPU(uc, mycpu)->env, *(uint32_t *)value, ~0);
                    break;
                //case UC_ARM_REG_SP:
                case UC_ARM_REG_R13:
                    ARM_CPU(uc, mycpu)->env.regs[13] = *(uint32_t *)value;
                    break;
                //case UC_ARM_REG_LR:
                case UC_ARM_REG_R14:
                    ARM_CPU(uc, mycpu)->env.regs[14] = *(uint32_t *)value;
                    break;
                //case UC_ARM_REG_PC:
                case UC_ARM_REG_R15:
                    ARM_CPU(uc, mycpu)->env.pc = (*(uint32_t *)value & ~1);
                    ARM_CPU(uc, mycpu)->env.thumb = (*(uint32_t *)value & 1);
                    ARM_CPU(uc, mycpu)->env.uc->thumb = (*(uint32_t *)value & 1);
                    ARM_CPU(uc, mycpu)->env.regs[15] = (*(uint32_t *)value & ~1);
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);

                    break;
                case UC_ARM_REG_FPEXC:
                    ARM_CPU(uc, mycpu)->env.vfp.xregs[ARM_VFP_FPEXC] = *(int32_t *)value;
                    break;
            }

            regid = arm_uc_to_qemu_cp_regs(regid);
            ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
            if (ri){
                write_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri, *(uint32_t *)value);
            }
        }
    }

    return 0;
}

int arm_cpreg_read( struct uc_struct *uc,
                    uint8_t cp,
                    uint8_t crn,
                    uint8_t crm,
                    uint8_t opc0,
                    uint8_t opc1,
                    uint8_t opc2,
                    void * value)
{
    CPUState *mycpu = uc->cpu;
    const ARMCPRegInfo *ri = NULL;

    unsigned int regid = ENCODE_CP_REG(cp, crn, crm, opc0, opc1, opc2);

    ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
    if (ri){
           *(int32_t *)value = read_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri);
        return 0;
    }
    return 1;
}

int arm_cpreg_write( struct uc_struct *uc,
                    uint8_t cp,
                    uint8_t crn,
                    uint8_t crm,
                    uint8_t opc0,
                    uint8_t opc1,
                    uint8_t opc2,
                    const void * value)
{
    CPUState *mycpu = uc->cpu;
    const ARMCPRegInfo *ri = NULL;

    unsigned int regid = ENCODE_CP_REG(cp, crn, crm, opc0, opc1, opc2);

    ri = get_arm_cp_reginfo(ARM_CPU(uc, mycpu)->cp_regs, regid);
    if (ri){
        write_raw_cp_reg(&ARM_CPU(uc, mycpu)->env, ri, *(uint32_t *)value);
        return 0;
    }
    return 1;
}

static bool arm_stop_interrupt(int intno)
{
    switch(intno) {
        default:
            return false;
        case EXCP_UDEF:
        case EXCP_YIELD:
            return true;
    }
}

static uc_err arm_query(struct uc_struct *uc, uc_query_type type, size_t *result)
{
    CPUState *mycpu = uc->cpu;
    uint32_t mode;

    switch(type) {
        case UC_QUERY_MODE:
            // zero out ARM/THUMB mode
            mode = uc->mode & ~(UC_MODE_ARM | UC_MODE_THUMB);
            // THUMB mode or ARM MOde
            mode += ((ARM_CPU(uc, mycpu)->env.thumb != 0)? UC_MODE_THUMB : UC_MODE_ARM);
            *result = mode;
            return UC_ERR_OK;
        default:
            return UC_ERR_ARG;
    }
}

#ifdef TARGET_WORDS_BIGENDIAN
void armeb_uc_init(struct uc_struct* uc)
#else
void arm_uc_init(struct uc_struct* uc)
#endif
{
    register_accel_types(uc);
    arm_cpu_register_types(uc);
    tosa_machine_init(uc);
    uc->reg_read = arm_reg_read;
    uc->reg_write = arm_reg_write;
    uc->reg_reset = arm_reg_reset;
    uc->set_pc = arm_set_pc;
    uc->stop_interrupt = arm_stop_interrupt;
    uc->release = arm_release;
    uc->query = arm_query;
    uc_common_init(uc);
}
