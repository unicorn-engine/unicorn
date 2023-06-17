/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "uc_priv.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "cpu_bits.h"
#include <unicorn/riscv.h>
#include "unicorn.h"

static int csrno_map[] = {
    CSR_USTATUS,       CSR_UIE,           CSR_UTVEC,         CSR_USCRATCH,
    CSR_UEPC,          CSR_UCAUSE,        CSR_UTVAL,         CSR_UIP,
    CSR_FFLAGS,        CSR_FRM,           CSR_FCSR,          CSR_CYCLE,
    CSR_TIME,          CSR_INSTRET,       CSR_HPMCOUNTER3,   CSR_HPMCOUNTER4,
    CSR_HPMCOUNTER5,   CSR_HPMCOUNTER6,   CSR_HPMCOUNTER7,   CSR_HPMCOUNTER8,
    CSR_HPMCOUNTER9,   CSR_HPMCOUNTER10,  CSR_HPMCOUNTER11,  CSR_HPMCOUNTER12,
    CSR_HPMCOUNTER13,  CSR_HPMCOUNTER14,  CSR_HPMCOUNTER15,  CSR_HPMCOUNTER16,
    CSR_HPMCOUNTER17,  CSR_HPMCOUNTER18,  CSR_HPMCOUNTER19,  CSR_HPMCOUNTER20,
    CSR_HPMCOUNTER21,  CSR_HPMCOUNTER22,  CSR_HPMCOUNTER23,  CSR_HPMCOUNTER24,
    CSR_HPMCOUNTER25,  CSR_HPMCOUNTER26,  CSR_HPMCOUNTER27,  CSR_HPMCOUNTER28,
    CSR_HPMCOUNTER29,  CSR_HPMCOUNTER30,  CSR_HPMCOUNTER31,  CSR_CYCLEH,
    CSR_TIMEH,         CSR_INSTRETH,      CSR_HPMCOUNTER3H,  CSR_HPMCOUNTER4H,
    CSR_HPMCOUNTER5H,  CSR_HPMCOUNTER6H,  CSR_HPMCOUNTER7H,  CSR_HPMCOUNTER8H,
    CSR_HPMCOUNTER9H,  CSR_HPMCOUNTER10H, CSR_HPMCOUNTER11H, CSR_HPMCOUNTER12H,
    CSR_HPMCOUNTER13H, CSR_HPMCOUNTER14H, CSR_HPMCOUNTER15H, CSR_HPMCOUNTER16H,
    CSR_HPMCOUNTER17H, CSR_HPMCOUNTER18H, CSR_HPMCOUNTER19H, CSR_HPMCOUNTER20H,
    CSR_HPMCOUNTER21H, CSR_HPMCOUNTER22H, CSR_HPMCOUNTER23H, CSR_HPMCOUNTER24H,
    CSR_HPMCOUNTER25H, CSR_HPMCOUNTER26H, CSR_HPMCOUNTER27H, CSR_HPMCOUNTER28H,
    CSR_HPMCOUNTER29H, CSR_HPMCOUNTER30H, CSR_HPMCOUNTER31H, CSR_MCYCLE,
    CSR_MINSTRET,      CSR_MCYCLEH,       CSR_MINSTRETH,     CSR_MVENDORID,
    CSR_MARCHID,       CSR_MIMPID,        CSR_MHARTID,       CSR_MSTATUS,
    CSR_MISA,          CSR_MEDELEG,       CSR_MIDELEG,       CSR_MIE,
    CSR_MTVEC,         CSR_MCOUNTEREN,    CSR_MSTATUSH,      CSR_MUCOUNTEREN,
    CSR_MSCOUNTEREN,   CSR_MHCOUNTEREN,   CSR_MSCRATCH,      CSR_MEPC,
    CSR_MCAUSE,        CSR_MTVAL,         CSR_MIP,           CSR_MBADADDR,
    CSR_SSTATUS,       CSR_SEDELEG,       CSR_SIDELEG,       CSR_SIE,
    CSR_STVEC,         CSR_SCOUNTEREN,    CSR_SSCRATCH,      CSR_SEPC,
    CSR_SCAUSE,        CSR_STVAL,         CSR_SIP,           CSR_SBADADDR,
    CSR_SPTBR,         CSR_SATP,          CSR_HSTATUS,       CSR_HEDELEG,
    CSR_HIDELEG,       CSR_HIE,           CSR_HCOUNTEREN,    CSR_HTVAL,
    CSR_HIP,           CSR_HTINST,        CSR_HGATP,         CSR_HTIMEDELTA,
    CSR_HTIMEDELTAH,
};
#define csrno_count (sizeof(csrno_map) / sizeof(int))

RISCVCPU *cpu_riscv_init(struct uc_struct *uc);

static void riscv_set_pc(struct uc_struct *uc, uint64_t address)
{
    RISCV_CPU(uc->cpu)->env.pc = address;
}

static uint64_t riscv_get_pc(struct uc_struct *uc)
{
    return RISCV_CPU(uc->cpu)->env.pc;
}

static void riscv_release(void *ctx)
{
    int i;
    TCGContext *tcg_ctx = (TCGContext *)ctx;
    RISCVCPU *cpu = (RISCVCPU *)tcg_ctx->uc->cpu;
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

static void reg_reset(struct uc_struct *uc) {}

DEFAULT_VISIBILITY
uc_err reg_read(void *_env, int mode, unsigned int regid, void *value,
                size_t *size)
{
    CPURISCVState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_RISCV_REG_X0 && regid <= UC_RISCV_REG_X31) {
#ifdef TARGET_RISCV64
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->gpr[regid - UC_RISCV_REG_X0];
#else
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = env->gpr[regid - UC_RISCV_REG_X0];
#endif
    } else if (regid >= UC_RISCV_REG_F0 &&
               regid <= UC_RISCV_REG_F31) { // "ft0".."ft31"
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = env->fpr[regid - UC_RISCV_REG_F0];
    } else if (regid >= UC_RISCV_REG_USTATUS &&
               regid < UC_RISCV_REG_USTATUS + csrno_count) {
        target_ulong val;
        int csrno = csrno_map[regid - UC_RISCV_REG_USTATUS];
        riscv_csrrw(env, csrno, &val, -1, 0);
#ifdef TARGET_RISCV64
        CHECK_REG_TYPE(uint64_t);
        *(uint64_t *)value = (uint64_t)val;
#else
        CHECK_REG_TYPE(uint32_t);
        *(uint32_t *)value = (uint32_t)val;
#endif
    } else {
        switch (regid) {
        default:
            break;
        case UC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
            CHECK_REG_TYPE(uint64_t);
            *(uint64_t *)value = env->pc;
#else
            CHECK_REG_TYPE(uint32_t);
            *(uint32_t *)value = env->pc;
#endif
            break;
        }
    }

    return ret;
}

DEFAULT_VISIBILITY
uc_err reg_write(void *_env, int mode, unsigned int regid, const void *value,
                 size_t *size, int *setpc)
{
    CPURISCVState *env = _env;
    uc_err ret = UC_ERR_ARG;

    if (regid >= UC_RISCV_REG_X0 && regid <= UC_RISCV_REG_X31) {
#ifdef TARGET_RISCV64
        CHECK_REG_TYPE(uint64_t);
        env->gpr[regid - UC_RISCV_REG_X0] = *(uint64_t *)value;
#else
        CHECK_REG_TYPE(uint32_t);
        env->gpr[regid - UC_RISCV_REG_X0] = *(uint32_t *)value;
#endif
    } else if (regid >= UC_RISCV_REG_F0 &&
               regid <= UC_RISCV_REG_F31) { // "ft0".."ft31"
        CHECK_REG_TYPE(uint64_t);
        env->fpr[regid - UC_RISCV_REG_F0] = *(uint64_t *)value;
    } else if (regid >= UC_RISCV_REG_USTATUS &&
               regid < UC_RISCV_REG_USTATUS + csrno_count) {
        target_ulong val;
        int csrno = csrno_map[regid - UC_RISCV_REG_USTATUS];
#ifdef TARGET_RISCV64
        CHECK_REG_TYPE(uint64_t);
        riscv_csrrw(env, csrno, &val, *(uint64_t *)value, -1);
#else
        CHECK_REG_TYPE(uint32_t);
        riscv_csrrw(env, csrno, &val, *(uint32_t *)value, -1);
#endif
    } else {
        switch (regid) {
        default:
            break;
        case UC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
            CHECK_REG_TYPE(uint64_t);
            env->pc = *(uint64_t *)value;
#else
            CHECK_REG_TYPE(uint32_t);
            env->pc = *(uint32_t *)value;
#endif
            *setpc = 1;
            break;
        }
    }

    return ret;
}

static bool riscv_stop_interrupt(struct uc_struct *uc, int intno)
{
    // detect stop exception
    switch (intno) {
    default:
        return false;
    case RISCV_EXCP_UNICORN_END:
        return true;
    case RISCV_EXCP_BREAKPOINT:
        uc->invalid_error = UC_ERR_EXCEPTION;
        return true;
    }
}

static bool riscv_insn_hook_validate(uint32_t insn_enum)
{
    return false;
}

static int riscv_cpus_init(struct uc_struct *uc, const char *cpu_model)
{

    RISCVCPU *cpu;

    cpu = cpu_riscv_init(uc);
    if (cpu == NULL) {
        return -1;
    }

    return 0;
}

DEFAULT_VISIBILITY
void uc_init(struct uc_struct *uc)
{
    uc->reg_read = reg_read;
    uc->reg_write = reg_write;
    uc->reg_reset = reg_reset;
    uc->release = riscv_release;
    uc->set_pc = riscv_set_pc;
    uc->get_pc = riscv_get_pc;
    uc->stop_interrupt = riscv_stop_interrupt;
    uc->insn_hook_validate = riscv_insn_hook_validate;
    uc->cpus_init = riscv_cpus_init;
    uc->cpu_context_size = offsetof(CPURISCVState, rdtime_fn);
    uc_common_init(uc);
}
