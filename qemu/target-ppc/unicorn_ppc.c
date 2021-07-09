/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/ppc/ppc.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


/*** HELPER PROTOTYPES ***/
static target_ulong __read_xer(CPUPPCState* env);
static void __write_xer(CPUPPCState *env, target_ulong xer);



#ifdef TARGET_WORDS_BIGENDIAN
#ifdef TARGET_PPC64
const int PPC64_REGS_STORAGE_SIZE = offsetof(CPUPPCState, tlb_table);
#else 
const int PPC_REGS_STORAGE_SIZE = offsetof(CPUPPCState, tlb_table);
#endif
#endif

static void ppc_set_nip(struct uc_struct *uc, uint64_t address)
{
    ppc_cpu_set_pc(uc->current_cpu, address);
}


void ppc_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env;

    env = uc->cpu->env_ptr;
    memset(env->gpr, 0, sizeof(env->gpr));
    memset(env->fpr, 0, sizeof(env->fpr));
    memset(env->crf, 0, sizeof(env->crf));
    // memset(env->spr, 0, sizeof(env->spr));
    memset(env->avr, 0, sizeof(env->avr));
    env->nip = 0;
}

int ppc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    int i;
    PowerPCCPU* ppc_cpu = POWERPC_CPU(uc, uc->cpu);
 
    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_PPC_REG_GPR_0 && regid <= UC_PPC_REG_GPR_31)
            *(target_ulong *)value = ppc_cpu->env.gpr[regid - UC_PPC_REG_GPR_0];
        else if (regid >= UC_PPC_REG_GPRH_0 && regid <= UC_PPC_REG_GPRH_31)
            *(target_ulong *)value = ppc_cpu->env.gprh[regid - UC_PPC_REG_GPRH_0];
        else if (regid >= UC_PPC_REG_FPR_0 && regid <= UC_PPC_REG_FPR_31)
            *(float64 *)value = ppc_cpu->env.fpr[regid - UC_PPC_REG_FPR_0];
        else if (regid >= UC_PPC_REG_CR_0 && regid <= UC_PPC_REG_CR_7)
            *(int32_t *)value = ppc_cpu->env.crf[regid - UC_PPC_REG_CR_0];
#ifdef CONFIG_INT128
        else if (regid >= UC_PPC_REG_VR_0 && regid <= UC_PPC_REG_VR_31)
            *(__uint128_t *)value = ppc_cpu->env.avr[regid - UC_PPC_REG_VR_0].u128;
#endif
        else {
            switch(regid) {
                case UC_PPC_REG_FPSCR:
                    *(int32_t *)value = ppc_cpu->env.fpscr;
                    break;
                case UC_PPC_REG_MSR:
                    *(target_ulong *)value = ppc_cpu->env.msr;
                    break;
                case UC_PPC_REG_XER:
                    *(target_ulong *)value = __read_xer(&ppc_cpu->env);
                    break;
                case UC_PPC_REG_SO:
                    *(int32_t *)value = ppc_cpu->env.so;
                    break;
                case UC_PPC_REG_OV:
                    *(int32_t *)value = ppc_cpu->env.ov;
                    break;
                case UC_PPC_REG_CA:
                    *(int32_t *)value = ppc_cpu->env.ca;
                    break;
                case UC_PPC_REG_CTR:
                    *(target_ulong *)value = ppc_cpu->env.ctr;
                    break;
                case UC_PPC_REG_LR:
                    *(target_ulong *)value = ppc_cpu->env.lr;
                    break;
                case UC_PPC_REG_NIP:
                    *(target_ulong *)value = ppc_cpu->env.nip;
                    break;
            }
        }
    }
    return 0;
}

int ppc_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    
    PowerPCCPU* ppc_cpu = POWERPC_CPU(uc, uc->cpu);

    int i;
    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_PPC_REG_GPR_0 && regid <= UC_PPC_REG_GPR_31)
            ppc_cpu->env.gpr[regid - UC_PPC_REG_GPR_0] = *(target_ulong *)value;
        else if (regid >= UC_PPC_REG_GPRH_0 && regid <= UC_PPC_REG_GPRH_31)
            ppc_cpu->env.gprh[regid - UC_PPC_REG_GPRH_0] = *(target_ulong *)value;
        else if (regid >= UC_PPC_REG_FPR_0 && regid <= UC_PPC_REG_FPR_31)
            ppc_cpu->env.fpr[regid - UC_PPC_REG_FPR_0] = *(float64 *)value;
        else if (regid >= UC_PPC_REG_CR_0 && regid <= UC_PPC_REG_CR_7)
            ppc_cpu->env.crf[regid - UC_PPC_REG_CR_0] = *(uint32_t *)value;
#ifdef CONFIG_INT128
        else if (regid >= UC_PPC_REG_VR_0 && regid <= UC_PPC_REG_VR_31)
            ppc_cpu->env.avr[regid - UC_PPC_REG_VR_0].u128 = *(__uint128_t *)value;
#endif
        else {
            switch(regid) {
                case UC_PPC_REG_FPSCR:
                    ppc_cpu->env.fpscr = *(uint32_t *)value;
                    break;
                case UC_PPC_REG_MSR:
                    ppc_cpu->env.msr = *(target_ulong *)value;
                    break;
                case UC_PPC_REG_XER:
                    __write_xer(&ppc_cpu->env, *(target_ulong *)value);
                    break;
                 case UC_PPC_REG_SO:
                    ppc_cpu->env.so = *(uint32_t *)value;
                    break;
                case UC_PPC_REG_OV:
                    ppc_cpu->env.ov = *(uint32_t *)value;
                    break;
                case UC_PPC_REG_CA:
                    ppc_cpu->env.ca = *(uint32_t *)value;
                    break;
                case UC_PPC_REG_CTR:
                    ppc_cpu->env.ctr = *(target_ulong *)value;
                    break;
                case UC_PPC_REG_LR:
                    ppc_cpu->env.lr = *(target_ulong *)value;
                    break;
                case UC_PPC_REG_NIP:
                    ppc_cpu->env.nip = *(target_ulong *)value;
                    // force to quit execution and flush TB
                    uc->quit_request = true;
                    uc_emu_stop(uc);
                    break;
            }
        }
    }
    return 0;
}

static bool ppc_stop_interrupt(int intno)
{
    return false;
}

static void ppc_release(void* ctx)
{

    TCGContext *s = (TCGContext *) ctx;

    struct uc_struct* uc = s->uc;
    PowerPCCPU* cpu = POWERPC_CPU(uc, uc->cpu);
    
    // free tlb6 (tlb is a union no need to free tlbe,tlbm)
    g_free(cpu->env.tlb.tlb6);

    //g_free(cpu->env.tlb.tlbe);
    //g_free(cpu->env.tlb.tlbm);
    
    g_free(s->tb_ctx.tbs);

    //release opcodes
    object_property_set_bool(uc, OBJECT(cpu), false, "realized", NULL);

    release_common(ctx);
}

__attribute__ ((visibility ("default")))
#ifdef TARGET_PPC64
#ifdef TARGET_WORDS_BIGENDIAN
void ppc64_uc_init(struct uc_struct* uc)
#else 
void ppc64le_uc_init(struct uc_struct* uc)
#endif
#else
#ifdef TARGET_WORDS_BIGENDIAN
void ppc_uc_init(struct uc_struct* uc)
#else
void ppcle_uc_init(struct uc_struct* uc)
#endif
#endif
{
    register_accel_types(uc);
    ppc_cpu_register_types(uc);
    generic_ppc_machine_init(uc);
    uc->reg_read = ppc_reg_read;
    uc->reg_write = ppc_reg_write;
    uc->reg_reset = ppc_reg_reset;
    uc->set_pc = ppc_set_nip;
    uc->stop_interrupt = ppc_stop_interrupt;
    uc->release = ppc_release;
    //uc->query = arm_query;
    uc_common_init(uc);
}


/**************************************************************************/
/***************************** HELPERS ************************************/
/**************************************************************************/

static target_ulong __read_xer(CPUPPCState* env){
    return env->xer | (env->so << XER_SO) | (env->ov << XER_OV) |
        (env->ca << XER_CA);
}

static void __write_xer(CPUPPCState *env, target_ulong xer)
{
    env->so = (xer >> XER_SO) & 1;
    env->ov = (xer >> XER_OV) & 1;
    env->ca = (xer >> XER_CA) & 1;
    env->xer = xer & ~(1 << XER_SO | 1 << XER_OV | 1 << XER_CA);
}
