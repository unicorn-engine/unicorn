/*
 * QEMU RH850 CPU
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 * Copyright (c) 2023 Quarkslab
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RH850_CPU_H
#define RH850_CPU_H

#define TCG_GUEST_DEFAULT_MO 0

#define ELF_MACHINE EM_RH850
#define CPUArchState struct CPURH850State

#include "qemu-common.h"
#include "hw/core/cpu.h"
#include "exec/cpu-defs.h"
#include "fpu/softfloat.h"

#define TYPE_RH850_CPU "rh850-cpu"

#define RH850_CPU_TYPE_SUFFIX "-" TYPE_RH850_CPU
#define RH850_CPU_TYPE_NAME(name) (name RH850_CPU_TYPE_SUFFIX)
#define CPU_RESOLVING_TYPE TYPE_RH850_CPU
#define TYPE_RH850_CPU_ANY              RH850_CPU_TYPE_NAME("any")

#define RV32 ((target_ulong)1 << (TARGET_LONG_BITS - 2))
#define RV64 ((target_ulong)2 << (TARGET_LONG_BITS - 2))

#if defined(TARGET_RH850)
#define RVXLEN RV32
#elif defined(TARGET_RH85064)
#define RVXLEN RV64
#endif

#define RV(x) ((target_ulong)1 << (x - 'A'))

#define RVI RV('I')
#define RVM RV('M')
#define RVA RV('A')
#define RVF RV('F')
#define RVD RV('D')
#define RVC RV('C')
#define RVS RV('S')
#define RVU RV('U')

/* S extension denotes that Supervisor mode exists, however it is possible
   to have a core that support S mode but does not have an MMU and there
   is currently no bit in misa to indicate whether an MMU exists or not
   so a cpu features bitfield is required */
enum {
    RH850_FEATURE_MMU
};

#define USER_VERSION_2_02_0 0x00020200
#define PRIV_VERSION_1_09_1 0x00010901
#define PRIV_VERSION_1_10_0 0x00011000

#define TRANSLATE_FAIL 1
#define TRANSLATE_SUCCESS 0
#define MMU_USER_IDX 3

#define MAX_RH850_PMPS (16)

typedef struct CPURH850State CPURH850State;

#include "pmp.h"

#include "register_indices.h"

#define NUM_GP_REGS 32
#define NUM_SYS_REG_BANKS 7
#define MAX_SYS_REGS_IN_BANK 32
#define BANK_ID_BASIC_0 0
#define BANK_ID_BASIC_1 1
#define BANK_ID_BASIC_2 2

struct CPURH850State {


    target_ulong gpRegs[NUM_GP_REGS];
    target_ulong pc;
    target_ulong sysDatabuffRegs[1];
    target_ulong systemRegs[NUM_SYS_REG_BANKS][MAX_SYS_REGS_IN_BANK];
    //target_ulong sysBasicRegs[31];
    //target_ulong sysInterruptRegs[5];
    //uint64_t sysFpuRegs[6];  //using rh850 basic system registers(sr6-sr11), 32-bit or 64-bit precision
    //target_ulong sysMpuRegs[56];
    //target_ulong sysCacheRegs[7];

    // flags contained in PSW register
    uint32_t Z_flag;
    uint32_t S_flag;
    uint32_t OV_flag;
    uint32_t CY_flag;
    uint32_t SAT_flag;
    uint32_t ID_flag;
    uint32_t EP_flag;
    uint32_t NP_flag;
    uint32_t EBV_flag;
    uint32_t CU0_flag;
    uint32_t CU1_flag;
    uint32_t CU2_flag;
    uint32_t UM_flag;

       uint32_t features;
    uint32_t badaddr;

    target_ulong cpu_LLbit;     // register for mutual exclusion (LDL.W, STC.W)
    target_ulong cpu_LLAddress;     // register for mutual exclusion (LDL.W, STC.W)

    target_ulong load_res;      // inst addr for TCG
    target_ulong load_val;      // inst val for TCG

    float_status fp_status;     // not used yet in rh850, left for floating-point support.

    target_ulong fpsr;      /* floating-point configuration/status register. */

    uint32_t exception_cause;
    int exception_priority;
    bool exception_dv;  

    // Unicorn engine
    struct uc_struct *uc;
};

#define RH850_CPU(obj) ((RH850CPU *)obj)
#define RH850_CPU_CLASS(klass) ((RH850CPUClass *)klass)
#define RH850_CPU_GET_CLASS(obj) (&((RH850CPU *)obj)->cc)


/**
 * RH850CPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * A RH850 CPU model.
 */
typedef struct RH850CPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/
    void (*parent_reset)(CPUState *cpu);
} RH850CPUClass;

/**
 * RH850CPU:
 * @env: #CPURH850State
 *
 * A RH850 CPU.
 */
typedef struct RH850CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/
    CPUNegativeOffsetState neg;
    CPURH850State env;

    RH850CPUClass cc;
} RH850CPU;

typedef RH850CPU ArchCPU;

static inline RH850CPU *rh850_env_get_cpu(CPURH850State *env)
{
    return container_of(env, RH850CPU, env);
}

static inline int rh850_has_ext(CPURH850State *env, target_ulong ext)
{		// TODO: what does value 'ext' represent??
    //return (env->misa & ext) != 0;
	return true;
}

static inline bool rh850_feature(CPURH850State *env, int feature)
{
    return env->features & (1ULL << feature);
}

#include "cpu_user.h"
#include "cpu_bits.h"

extern const char * const rh850_gp_regnames[];
extern const char * const rh850_sys_regnames[][MAX_SYS_REGS_IN_BANK];
extern const char * const rh850_sys_databuff_regnames[];

extern const char * const rh850_excp_names[];
extern const char * const rh850_intr_names[];
extern const uint32_t rh850_sys_reg_read_only_values[][MAX_SYS_REGS_IN_BANK];
extern const uint32_t rh850_sys_reg_read_only_masks[][MAX_SYS_REGS_IN_BANK];

#define ENV_GET_CPU(e) CPU(rh850_env_get_cpu(e))
#define ENV_OFFSET offsetof(RH850CPU, env)

void rh850_cpu_do_interrupt(CPUState *cpu);
int rh850_cpu_gdb_read_register(CPUState *cpu, uint8_t *buf, int reg);
int rh850_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);
bool rh850_cpu_exec_interrupt(CPUState *cs, int interrupt_request);
int rh850_cpu_mmu_index(CPURH850State *env, bool ifetch);
hwaddr rh850_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
void  rh850_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                    MMUAccessType access_type, int mmu_idx,
                                    uintptr_t retaddr);
int rh850_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int size,
                              int rw, int mmu_idx);

char *rh850_isa_string(RH850CPU *cpu);
void rh850_cpu_list(void);

#define cpu_init(cpu_model) cpu_generic_init(TYPE_RH850_CPU, cpu_model)
#define cpu_signal_handler cpu_rh850_signal_handler
#define cpu_list rh850_cpu_list
#define cpu_mmu_index rh850_cpu_mmu_index

void rh850_set_mode(CPURH850State *env, target_ulong newpriv);

void rh850_translate_init(struct uc_struct *uc);
RH850CPU *cpu_rh850_init(struct uc_struct *uc, const char *cpu_model);
int cpu_rh850_signal_handler(int host_signum, void *pinfo, void *puc);
void QEMU_NORETURN do_raise_exception_err(CPURH850State *env,
                                          uint32_t exception, uintptr_t pc);

target_ulong cpu_rh850_get_fflags(CPURH850State *env);
void cpu_rh850_set_fflags(CPURH850State *env, target_ulong);
void rh850_cpu_set_pc(CPUState *cs, vaddr value);
vaddr rh850_cpu_get_pc(CPUState *cs);
AddressSpace *cpu_addressspace(CPUState *cs, MemTxAttrs attrs);

#define TB_FLAGS_MMU_MASK  3
#define TB_FLAGS_FP_ENABLE MSTATUS_FS

/*
 * This f. is called from  tcg_gen_lookup_and_goto_ptr() to obtain PC
 * which is then used for TB lookup.
 */
static inline void cpu_get_tb_cpu_state(CPURH850State *env, target_ulong *pc,
                                        target_ulong *cs_base, uint32_t *flags)
{
    *pc = env->pc;
    *cs_base = 0;
#ifdef CONFIG_USER_ONLY
    *flags = TB_FLAGS_FP_ENABLE;
#else
    *flags = cpu_mmu_index(env, 0);
#endif
}

void csr_write_helper(CPURH850State *env, target_ulong val_to_write,
        target_ulong csrno);
target_ulong csr_read_helper(CPURH850State *env, target_ulong csrno);

#ifndef CONFIG_USER_ONLY
void rh850_set_local_interrupt(RH850CPU *cpu, target_ulong mask, int value);
#endif

extern const int NUM_GDB_REGS;

#include "exec/cpu-all.h"

#endif /* RH850_CPU_H */
