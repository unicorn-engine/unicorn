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

// #define TARGET_INSN_START_EXTRA_WORDS 2

#define ELF_MACHINE EM_RH850
#define CPUArchState struct CPURH850State

#include "cpu-qom.h"
#include "exec/cpu-defs.h"
#include "fpu/softfloat.h"

#define RH850_CPU_TYPE_SUFFIX "-" TYPE_RH850_CPU
#define RH850_CPU_TYPE_NAME(name) (name RH850_CPU_TYPE_SUFFIX)
#define CPU_RESOLVING_TYPE TYPE_RH850_CPU
#define TYPE_RH850_CPU_ANY RH850_CPU_TYPE_NAME("any")

#define TRANSLATE_FAIL 1
#define TRANSLATE_SUCCESS 0

#define MAX_RH850_PMPS (16)

typedef struct CPURH850State CPURH850State;

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
    target_ulong cpu_sys_databuf_reg;
    target_ulong sys_reg[NUM_SYS_REG_BANKS][MAX_SYS_REGS_IN_BANK];
    // target_ulong sysBasicRegs[31];
    // target_ulong sysInterruptRegs[5];
    // uint64_t sysFpuRegs[6];  //using rh850 basic system registers(sr6-sr11),
    // 32-bit or 64-bit precision target_ulong sysMpuRegs[56]; target_ulong
    // sysCacheRegs[7];

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
    target_ulong cpu_LLAddress; // register for mutual exclusion (LDL.W, STC.W)

    target_ulong load_res; // inst addr for TCG
    target_ulong load_val; // inst val for TCG

    float_status
        fp_status; // not used yet in rh850, left for floating-point support.

    target_ulong fpsr; /* floating-point configuration/status register. */

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

static inline bool rh850_feature(CPURH850State *env, int feature)
{
    return env->features & (1ULL << feature);
}

#include "cpu_user.h"
#include "cpu_bits.h"

#define ENV_GET_CPU(e) CPU(rh850_env_get_cpu(e))
#define ENV_OFFSET offsetof(RH850CPU, env)

void rh850_cpu_do_interrupt(CPUState *cpu);
bool rh850_cpu_exec_interrupt(CPUState *cs, int interrupt_request);
int rh850_cpu_mmu_index(CPURH850State *env, bool ifetch);
hwaddr rh850_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
void rh850_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                   MMUAccessType access_type, int mmu_idx,
                                   uintptr_t retaddr);
int rh850_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int size, int rw,
                               int mmu_idx);

#define cpu_init(cpu_model) cpu_generic_init(TYPE_RH850_CPU, cpu_model)
#define cpu_list rh850_cpu_list
#define cpu_mmu_index rh850_cpu_mmu_index

void rh850_translate_init(struct uc_struct *uc);
void QEMU_NORETURN do_raise_exception_err(CPURH850State *env,
                                          uint32_t exception, uintptr_t pc);

target_ulong cpu_rh850_get_fflags(CPURH850State *env);
void rh850_cpu_set_pc(CPUState *cs, vaddr value);
vaddr rh850_cpu_get_pc(CPUState *cs);

#define TB_FLAGS_MMU_MASK 3
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
    *flags = 0;
}

#include "exec/cpu-all.h"

#endif /* RH850_CPU_H */
