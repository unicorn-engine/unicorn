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

RISCVCPU *cpu_riscv_init(struct uc_struct *uc);

static void riscv_set_pc(struct uc_struct *uc, uint64_t address)
{
    RISCV_CPU(uc->cpu)->env.pc = address;
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

void riscv_reg_reset(struct uc_struct *uc) {}

static void reg_read(CPURISCVState *env, unsigned int regid, void *value)
{
    switch (regid) {
    case UC_RISCV_REG_X0:
    case UC_RISCV_REG_X1:
    case UC_RISCV_REG_X2:
    case UC_RISCV_REG_X3:
    case UC_RISCV_REG_X4:
    case UC_RISCV_REG_X5:
    case UC_RISCV_REG_X6:
    case UC_RISCV_REG_X7:
    case UC_RISCV_REG_X8:
    case UC_RISCV_REG_X9:
    case UC_RISCV_REG_X10:
    case UC_RISCV_REG_X11:
    case UC_RISCV_REG_X12:
    case UC_RISCV_REG_X13:
    case UC_RISCV_REG_X14:
    case UC_RISCV_REG_X15:
    case UC_RISCV_REG_X16:
    case UC_RISCV_REG_X17:
    case UC_RISCV_REG_X18:
    case UC_RISCV_REG_X19:
    case UC_RISCV_REG_X20:
    case UC_RISCV_REG_X21:
    case UC_RISCV_REG_X22:
    case UC_RISCV_REG_X23:
    case UC_RISCV_REG_X24:
    case UC_RISCV_REG_X25:
    case UC_RISCV_REG_X26:
    case UC_RISCV_REG_X27:
    case UC_RISCV_REG_X28:
    case UC_RISCV_REG_X29:
    case UC_RISCV_REG_X30:
    case UC_RISCV_REG_X31:
#ifdef TARGET_RISCV64
        *(int64_t *)value = env->gpr[regid - UC_RISCV_REG_X0];
#else
        *(int32_t *)value = env->gpr[regid - UC_RISCV_REG_X0];
#endif
        break;
    case UC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
        *(int64_t *)value = env->pc;
#else
        *(int32_t *)value = env->pc;
#endif
        break;

    case UC_RISCV_REG_F0:  // "ft0"
    case UC_RISCV_REG_F1:  // "ft1"
    case UC_RISCV_REG_F2:  // "ft2"
    case UC_RISCV_REG_F3:  // "ft3"
    case UC_RISCV_REG_F4:  // "ft4"
    case UC_RISCV_REG_F5:  // "ft5"
    case UC_RISCV_REG_F6:  // "ft6"
    case UC_RISCV_REG_F7:  // "ft7"
    case UC_RISCV_REG_F8:  // "fs0"
    case UC_RISCV_REG_F9:  // "fs1"
    case UC_RISCV_REG_F10: // "fa0"
    case UC_RISCV_REG_F11: // "fa1"
    case UC_RISCV_REG_F12: // "fa2"
    case UC_RISCV_REG_F13: // "fa3"
    case UC_RISCV_REG_F14: // "fa4"
    case UC_RISCV_REG_F15: // "fa5"
    case UC_RISCV_REG_F16: // "fa6"
    case UC_RISCV_REG_F17: // "fa7"
    case UC_RISCV_REG_F18: // "fs2"
    case UC_RISCV_REG_F19: // "fs3"
    case UC_RISCV_REG_F20: // "fs4"
    case UC_RISCV_REG_F21: // "fs5"
    case UC_RISCV_REG_F22: // "fs6"
    case UC_RISCV_REG_F23: // "fs7"
    case UC_RISCV_REG_F24: // "fs8"
    case UC_RISCV_REG_F25: // "fs9"
    case UC_RISCV_REG_F26: // "fs10"
    case UC_RISCV_REG_F27: // "fs11"
    case UC_RISCV_REG_F28: // "ft8"
    case UC_RISCV_REG_F29: // "ft9"
    case UC_RISCV_REG_F30: // "ft10"
    case UC_RISCV_REG_F31: // "ft11"
#ifdef TARGET_RISCV64
        *(int64_t *)value = env->fpr[regid - UC_RISCV_REG_F0];
#else
        *(int32_t *)value = env->fpr[regid - UC_RISCV_REG_F0];
#endif
        break;
    case UC_RISCV_REG_USTATUS:
    case UC_RISCV_REG_UIE:
    case UC_RISCV_REG_UTVEC:
    case UC_RISCV_REG_USCRATCH:
    case UC_RISCV_REG_UEPC:
    case UC_RISCV_REG_UCAUSE:
    case UC_RISCV_REG_UTVAL:
    case UC_RISCV_REG_UIP:
    case UC_RISCV_REG_FFLAGS:
    case UC_RISCV_REG_FRM:
    case UC_RISCV_REG_FCSR:
    case UC_RISCV_REG_CYCLE:
    case UC_RISCV_REG_TIME:
    case UC_RISCV_REG_INSTRET:
    case UC_RISCV_REG_HPMCOUNTER3:
    case UC_RISCV_REG_HPMCOUNTER4:
    case UC_RISCV_REG_HPMCOUNTER5:
    case UC_RISCV_REG_HPMCOUNTER6:
    case UC_RISCV_REG_HPMCOUNTER7:
    case UC_RISCV_REG_HPMCOUNTER8:
    case UC_RISCV_REG_HPMCOUNTER9:
    case UC_RISCV_REG_HPMCOUNTER10:
    case UC_RISCV_REG_HPMCOUNTER11:
    case UC_RISCV_REG_HPMCOUNTER12:
    case UC_RISCV_REG_HPMCOUNTER13:
    case UC_RISCV_REG_HPMCOUNTER14:
    case UC_RISCV_REG_HPMCOUNTER15:
    case UC_RISCV_REG_HPMCOUNTER16:
    case UC_RISCV_REG_HPMCOUNTER17:
    case UC_RISCV_REG_HPMCOUNTER18:
    case UC_RISCV_REG_HPMCOUNTER19:
    case UC_RISCV_REG_HPMCOUNTER20:
    case UC_RISCV_REG_HPMCOUNTER21:
    case UC_RISCV_REG_HPMCOUNTER22:
    case UC_RISCV_REG_HPMCOUNTER23:
    case UC_RISCV_REG_HPMCOUNTER24:
    case UC_RISCV_REG_HPMCOUNTER25:
    case UC_RISCV_REG_HPMCOUNTER26:
    case UC_RISCV_REG_HPMCOUNTER27:
    case UC_RISCV_REG_HPMCOUNTER28:
    case UC_RISCV_REG_HPMCOUNTER29:
    case UC_RISCV_REG_HPMCOUNTER30:
    case UC_RISCV_REG_HPMCOUNTER31:
    case UC_RISCV_REG_CYCLEH:
    case UC_RISCV_REG_TIMEH:
    case UC_RISCV_REG_INSTRETH:
    case UC_RISCV_REG_HPMCOUNTER3H:
    case UC_RISCV_REG_HPMCOUNTER4H:
    case UC_RISCV_REG_HPMCOUNTER5H:
    case UC_RISCV_REG_HPMCOUNTER6H:
    case UC_RISCV_REG_HPMCOUNTER7H:
    case UC_RISCV_REG_HPMCOUNTER8H:
    case UC_RISCV_REG_HPMCOUNTER9H:
    case UC_RISCV_REG_HPMCOUNTER10H:
    case UC_RISCV_REG_HPMCOUNTER11H:
    case UC_RISCV_REG_HPMCOUNTER12H:
    case UC_RISCV_REG_HPMCOUNTER13H:
    case UC_RISCV_REG_HPMCOUNTER14H:
    case UC_RISCV_REG_HPMCOUNTER15H:
    case UC_RISCV_REG_HPMCOUNTER16H:
    case UC_RISCV_REG_HPMCOUNTER17H:
    case UC_RISCV_REG_HPMCOUNTER18H:
    case UC_RISCV_REG_HPMCOUNTER19H:
    case UC_RISCV_REG_HPMCOUNTER20H:
    case UC_RISCV_REG_HPMCOUNTER21H:
    case UC_RISCV_REG_HPMCOUNTER22H:
    case UC_RISCV_REG_HPMCOUNTER23H:
    case UC_RISCV_REG_HPMCOUNTER24H:
    case UC_RISCV_REG_HPMCOUNTER25H:
    case UC_RISCV_REG_HPMCOUNTER26H:
    case UC_RISCV_REG_HPMCOUNTER27H:
    case UC_RISCV_REG_HPMCOUNTER28H:
    case UC_RISCV_REG_HPMCOUNTER29H:
    case UC_RISCV_REG_HPMCOUNTER30H:
    case UC_RISCV_REG_HPMCOUNTER31H:
    case UC_RISCV_REG_MCYCLE:
    case UC_RISCV_REG_MINSTRET:
    case UC_RISCV_REG_MCYCLEH:
    case UC_RISCV_REG_MINSTRETH:
    case UC_RISCV_REG_MVENDORID:
    case UC_RISCV_REG_MARCHID:
    case UC_RISCV_REG_MIMPID:
    case UC_RISCV_REG_MHARTID:
    case UC_RISCV_REG_MSTATUS:
    case UC_RISCV_REG_MISA:
    case UC_RISCV_REG_MEDELEG:
    case UC_RISCV_REG_MIDELEG:
    case UC_RISCV_REG_MIE:
    case UC_RISCV_REG_MTVEC:
    case UC_RISCV_REG_MCOUNTEREN:
    case UC_RISCV_REG_MSTATUSH:
    case UC_RISCV_REG_MUCOUNTEREN:
    case UC_RISCV_REG_MSCOUNTEREN:
    case UC_RISCV_REG_MHCOUNTEREN:
    case UC_RISCV_REG_MSCRATCH:
    case UC_RISCV_REG_MEPC:
    case UC_RISCV_REG_MCAUSE:
    case UC_RISCV_REG_MTVAL:
    case UC_RISCV_REG_MIP:
    case UC_RISCV_REG_MBADADDR:
    case UC_RISCV_REG_SSTATUS:
    case UC_RISCV_REG_SEDELEG:
    case UC_RISCV_REG_SIDELEG:
    case UC_RISCV_REG_SIE:
    case UC_RISCV_REG_STVEC:
    case UC_RISCV_REG_SCOUNTEREN:
    case UC_RISCV_REG_SSCRATCH:
    case UC_RISCV_REG_SEPC:
    case UC_RISCV_REG_SCAUSE:
    case UC_RISCV_REG_STVAL:
    case UC_RISCV_REG_SIP:
    case UC_RISCV_REG_SBADADDR:
    case UC_RISCV_REG_SPTBR:
    case UC_RISCV_REG_SATP:
    case UC_RISCV_REG_HSTATUS:
    case UC_RISCV_REG_HEDELEG:
    case UC_RISCV_REG_HIDELEG:
    case UC_RISCV_REG_HIE:
    case UC_RISCV_REG_HCOUNTEREN:
    case UC_RISCV_REG_HTVAL:
    case UC_RISCV_REG_HIP:
    case UC_RISCV_REG_HTINST:
    case UC_RISCV_REG_HGATP:
    case UC_RISCV_REG_HTIMEDELTA:
    case UC_RISCV_REG_HTIMEDELTAH: {
        target_ulong val;
        int csrno = csrno_map[regid - UC_RISCV_REG_USTATUS];
        riscv_csrrw(env, csrno, &val, -1, 0);
#ifdef TARGET_RISCV64
        *(uint64_t *)value = (uint64_t)val;
#else
        *(uint32_t *)value = (uint32_t)val;
#endif
        break;
    }
    default:
        break;
    }

    return;
}

static void reg_write(CPURISCVState *env, unsigned int regid, const void *value)
{
    switch (regid) {
    case UC_RISCV_REG_X0:
    case UC_RISCV_REG_X1:
    case UC_RISCV_REG_X2:
    case UC_RISCV_REG_X3:
    case UC_RISCV_REG_X4:
    case UC_RISCV_REG_X5:
    case UC_RISCV_REG_X6:
    case UC_RISCV_REG_X7:
    case UC_RISCV_REG_X8:
    case UC_RISCV_REG_X9:
    case UC_RISCV_REG_X10:
    case UC_RISCV_REG_X11:
    case UC_RISCV_REG_X12:
    case UC_RISCV_REG_X13:
    case UC_RISCV_REG_X14:
    case UC_RISCV_REG_X15:
    case UC_RISCV_REG_X16:
    case UC_RISCV_REG_X17:
    case UC_RISCV_REG_X18:
    case UC_RISCV_REG_X19:
    case UC_RISCV_REG_X20:
    case UC_RISCV_REG_X21:
    case UC_RISCV_REG_X22:
    case UC_RISCV_REG_X23:
    case UC_RISCV_REG_X24:
    case UC_RISCV_REG_X25:
    case UC_RISCV_REG_X26:
    case UC_RISCV_REG_X27:
    case UC_RISCV_REG_X28:
    case UC_RISCV_REG_X29:
    case UC_RISCV_REG_X30:
    case UC_RISCV_REG_X31:
#ifdef TARGET_RISCV64
        env->gpr[regid - UC_RISCV_REG_X0] = *(uint64_t *)value;
#else
        env->gpr[regid - UC_RISCV_REG_X0] = *(uint32_t *)value;
#endif
        break;
    case UC_RISCV_REG_PC:
#ifdef TARGET_RISCV64
        env->pc = *(uint64_t *)value;
#else
        env->pc = *(uint32_t *)value;
#endif
        break;
    case UC_RISCV_REG_F0:  // "ft0"
    case UC_RISCV_REG_F1:  // "ft1"
    case UC_RISCV_REG_F2:  // "ft2"
    case UC_RISCV_REG_F3:  // "ft3"
    case UC_RISCV_REG_F4:  // "ft4"
    case UC_RISCV_REG_F5:  // "ft5"
    case UC_RISCV_REG_F6:  // "ft6"
    case UC_RISCV_REG_F7:  // "ft7"
    case UC_RISCV_REG_F8:  // "fs0"
    case UC_RISCV_REG_F9:  // "fs1"
    case UC_RISCV_REG_F10: // "fa0"
    case UC_RISCV_REG_F11: // "fa1"
    case UC_RISCV_REG_F12: // "fa2"
    case UC_RISCV_REG_F13: // "fa3"
    case UC_RISCV_REG_F14: // "fa4"
    case UC_RISCV_REG_F15: // "fa5"
    case UC_RISCV_REG_F16: // "fa6"
    case UC_RISCV_REG_F17: // "fa7"
    case UC_RISCV_REG_F18: // "fs2"
    case UC_RISCV_REG_F19: // "fs3"
    case UC_RISCV_REG_F20: // "fs4"
    case UC_RISCV_REG_F21: // "fs5"
    case UC_RISCV_REG_F22: // "fs6"
    case UC_RISCV_REG_F23: // "fs7"
    case UC_RISCV_REG_F24: // "fs8"
    case UC_RISCV_REG_F25: // "fs9"
    case UC_RISCV_REG_F26: // "fs10"
    case UC_RISCV_REG_F27: // "fs11"
    case UC_RISCV_REG_F28: // "ft8"
    case UC_RISCV_REG_F29: // "ft9"
    case UC_RISCV_REG_F30: // "ft10"
    case UC_RISCV_REG_F31: // "ft11"
#ifdef TARGET_RISCV64
        env->fpr[regid - UC_RISCV_REG_F0] = *(uint64_t *)value;
#else
        env->fpr[regid - UC_RISCV_REG_F0] = *(uint32_t *)value;
#endif
        break;
    case UC_RISCV_REG_USTATUS:
    case UC_RISCV_REG_UIE:
    case UC_RISCV_REG_UTVEC:
    case UC_RISCV_REG_USCRATCH:
    case UC_RISCV_REG_UEPC:
    case UC_RISCV_REG_UCAUSE:
    case UC_RISCV_REG_UTVAL:
    case UC_RISCV_REG_UIP:
    case UC_RISCV_REG_FFLAGS:
    case UC_RISCV_REG_FRM:
    case UC_RISCV_REG_FCSR:
    case UC_RISCV_REG_CYCLE:
    case UC_RISCV_REG_TIME:
    case UC_RISCV_REG_INSTRET:
    case UC_RISCV_REG_HPMCOUNTER3:
    case UC_RISCV_REG_HPMCOUNTER4:
    case UC_RISCV_REG_HPMCOUNTER5:
    case UC_RISCV_REG_HPMCOUNTER6:
    case UC_RISCV_REG_HPMCOUNTER7:
    case UC_RISCV_REG_HPMCOUNTER8:
    case UC_RISCV_REG_HPMCOUNTER9:
    case UC_RISCV_REG_HPMCOUNTER10:
    case UC_RISCV_REG_HPMCOUNTER11:
    case UC_RISCV_REG_HPMCOUNTER12:
    case UC_RISCV_REG_HPMCOUNTER13:
    case UC_RISCV_REG_HPMCOUNTER14:
    case UC_RISCV_REG_HPMCOUNTER15:
    case UC_RISCV_REG_HPMCOUNTER16:
    case UC_RISCV_REG_HPMCOUNTER17:
    case UC_RISCV_REG_HPMCOUNTER18:
    case UC_RISCV_REG_HPMCOUNTER19:
    case UC_RISCV_REG_HPMCOUNTER20:
    case UC_RISCV_REG_HPMCOUNTER21:
    case UC_RISCV_REG_HPMCOUNTER22:
    case UC_RISCV_REG_HPMCOUNTER23:
    case UC_RISCV_REG_HPMCOUNTER24:
    case UC_RISCV_REG_HPMCOUNTER25:
    case UC_RISCV_REG_HPMCOUNTER26:
    case UC_RISCV_REG_HPMCOUNTER27:
    case UC_RISCV_REG_HPMCOUNTER28:
    case UC_RISCV_REG_HPMCOUNTER29:
    case UC_RISCV_REG_HPMCOUNTER30:
    case UC_RISCV_REG_HPMCOUNTER31:
    case UC_RISCV_REG_CYCLEH:
    case UC_RISCV_REG_TIMEH:
    case UC_RISCV_REG_INSTRETH:
    case UC_RISCV_REG_HPMCOUNTER3H:
    case UC_RISCV_REG_HPMCOUNTER4H:
    case UC_RISCV_REG_HPMCOUNTER5H:
    case UC_RISCV_REG_HPMCOUNTER6H:
    case UC_RISCV_REG_HPMCOUNTER7H:
    case UC_RISCV_REG_HPMCOUNTER8H:
    case UC_RISCV_REG_HPMCOUNTER9H:
    case UC_RISCV_REG_HPMCOUNTER10H:
    case UC_RISCV_REG_HPMCOUNTER11H:
    case UC_RISCV_REG_HPMCOUNTER12H:
    case UC_RISCV_REG_HPMCOUNTER13H:
    case UC_RISCV_REG_HPMCOUNTER14H:
    case UC_RISCV_REG_HPMCOUNTER15H:
    case UC_RISCV_REG_HPMCOUNTER16H:
    case UC_RISCV_REG_HPMCOUNTER17H:
    case UC_RISCV_REG_HPMCOUNTER18H:
    case UC_RISCV_REG_HPMCOUNTER19H:
    case UC_RISCV_REG_HPMCOUNTER20H:
    case UC_RISCV_REG_HPMCOUNTER21H:
    case UC_RISCV_REG_HPMCOUNTER22H:
    case UC_RISCV_REG_HPMCOUNTER23H:
    case UC_RISCV_REG_HPMCOUNTER24H:
    case UC_RISCV_REG_HPMCOUNTER25H:
    case UC_RISCV_REG_HPMCOUNTER26H:
    case UC_RISCV_REG_HPMCOUNTER27H:
    case UC_RISCV_REG_HPMCOUNTER28H:
    case UC_RISCV_REG_HPMCOUNTER29H:
    case UC_RISCV_REG_HPMCOUNTER30H:
    case UC_RISCV_REG_HPMCOUNTER31H:
    case UC_RISCV_REG_MCYCLE:
    case UC_RISCV_REG_MINSTRET:
    case UC_RISCV_REG_MCYCLEH:
    case UC_RISCV_REG_MINSTRETH:
    case UC_RISCV_REG_MVENDORID:
    case UC_RISCV_REG_MARCHID:
    case UC_RISCV_REG_MIMPID:
    case UC_RISCV_REG_MHARTID:
    case UC_RISCV_REG_MSTATUS:
    case UC_RISCV_REG_MISA:
    case UC_RISCV_REG_MEDELEG:
    case UC_RISCV_REG_MIDELEG:
    case UC_RISCV_REG_MIE:
    case UC_RISCV_REG_MTVEC:
    case UC_RISCV_REG_MCOUNTEREN:
    case UC_RISCV_REG_MSTATUSH:
    case UC_RISCV_REG_MUCOUNTEREN:
    case UC_RISCV_REG_MSCOUNTEREN:
    case UC_RISCV_REG_MHCOUNTEREN:
    case UC_RISCV_REG_MSCRATCH:
    case UC_RISCV_REG_MEPC:
    case UC_RISCV_REG_MCAUSE:
    case UC_RISCV_REG_MTVAL:
    case UC_RISCV_REG_MIP:
    case UC_RISCV_REG_MBADADDR:
    case UC_RISCV_REG_SSTATUS:
    case UC_RISCV_REG_SEDELEG:
    case UC_RISCV_REG_SIDELEG:
    case UC_RISCV_REG_SIE:
    case UC_RISCV_REG_STVEC:
    case UC_RISCV_REG_SCOUNTEREN:
    case UC_RISCV_REG_SSCRATCH:
    case UC_RISCV_REG_SEPC:
    case UC_RISCV_REG_SCAUSE:
    case UC_RISCV_REG_STVAL:
    case UC_RISCV_REG_SIP:
    case UC_RISCV_REG_SBADADDR:
    case UC_RISCV_REG_SPTBR:
    case UC_RISCV_REG_SATP:
    case UC_RISCV_REG_HSTATUS:
    case UC_RISCV_REG_HEDELEG:
    case UC_RISCV_REG_HIDELEG:
    case UC_RISCV_REG_HIE:
    case UC_RISCV_REG_HCOUNTEREN:
    case UC_RISCV_REG_HTVAL:
    case UC_RISCV_REG_HIP:
    case UC_RISCV_REG_HTINST:
    case UC_RISCV_REG_HGATP:
    case UC_RISCV_REG_HTIMEDELTA:
    case UC_RISCV_REG_HTIMEDELTAH: {
        target_ulong val;
        int csrno = csrno_map[regid - UC_RISCV_REG_USTATUS];
#ifdef TARGET_RISCV64
        riscv_csrrw(env, csrno, &val, *(uint64_t *)value, -1);
#else
        riscv_csrrw(env, csrno, &val, *(uint32_t *)value, -1);
#endif
        break;
    }
    default:
        break;
    }
}

int riscv_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count)
{
    CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

int riscv_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count)
{
    CPURISCVState *env = &(RISCV_CPU(uc->cpu)->env);
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
        if (regid == UC_RISCV_REG_PC) {
            // force to quit execution and flush TB
            uc->quit_request = true;
            uc_emu_stop(uc);
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
int riscv32_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count)
#else
/* TARGET_RISCV64 */
int riscv64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count)
#endif
{
    CPURISCVState *env = (CPURISCVState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        reg_read(env, regid, value);
    }

    return 0;
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
int riscv32_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count)
#else
/* TARGET_RISCV64 */
int riscv64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count)
#endif
{
    CPURISCVState *env = (CPURISCVState *)ctx->data;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        reg_write(env, regid, value);
    }

    return 0;
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
#ifdef TARGET_RISCV32
void riscv32_uc_init(struct uc_struct *uc)
#else
/* TARGET_RISCV64 */
void riscv64_uc_init(struct uc_struct *uc)
#endif
{
    uc->reg_read = riscv_reg_read;
    uc->reg_write = riscv_reg_write;
    uc->reg_reset = riscv_reg_reset;
    uc->release = riscv_release;
    uc->set_pc = riscv_set_pc;
    uc->stop_interrupt = riscv_stop_interrupt;
    uc->insn_hook_validate = riscv_insn_hook_validate;
    uc->cpus_init = riscv_cpus_init;
    uc->cpu_context_size = offsetof(CPURISCVState, rdtime_fn);
    uc_common_init(uc);
}
