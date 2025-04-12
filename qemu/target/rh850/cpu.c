/*
 * QEMU RH850 CPU
 *
 * Copyright (c) 2018-2019 iSYSTEM Labs d.o.o.
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

#include "exec/exec-all.h"

/* RH850 CPU definitions */

/* Program registers:
 * r0 - zero
 * r1 - assembler reserved register
 * r2 - real-time OS register / address and data variable register
 * r3 - stack pointer
 * r4 - global pointer
 * r5 - text pointer
 * r6-r29 - address and data variable registers
 * r30 - element pointer
 * r31 - link pointer
 */

void rh850_cpu_set_pc(CPUState *cs, vaddr value)
{
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;
    env->pc = value;
}

vaddr rh850_cpu_get_pc(CPUState *cs)
{
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;
    return env->pc;
}

/* called by qemu's softmmu to fill the qemu tlb */
static bool rh850_tlb_fill(CPUState *cs, vaddr addr, int size,
                           MMUAccessType access_type, int mmu_idx,
                           bool probe, uintptr_t retaddr)
{
    int ret;
    ret = rh850_cpu_handle_mmu_fault(cs, addr, size, access_type, mmu_idx);
    if (ret == TRANSLATE_FAIL) {
        RH850CPU *cpu = RH850_CPU(cs);
        CPURH850State *env = &cpu->env;
        do_raise_exception_err(env, cs->exception_index, retaddr);
    }
    return true;
}


static void rh850_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;
    env->pc = tb->pc;
}

static bool rh850_cpu_has_work(CPUState *cs)
{
    return true;
}

void restore_state_to_opc(CPURH850State *env, TranslationBlock *tb,
                          target_ulong *data)
{
    env->pc = data[0];
}


static void rh850_raise_exception(CPURH850State *env, uint32_t excp,
                           uint32_t syndrome, uint32_t target_el)
{
    CPUState *cs = CPU(rh850_env_get_cpu(env));

    cs->exception_index = excp;
    cpu_loop_exit(cs);
}


static void rh850_debug_excp_handler(CPUState *cs)
{
    /* Called by core code when a watchpoint or breakpoint fires;
     * need to check which one and raise the appropriate exception.
     */
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;
    CPUWatchpoint *wp_hit = cs->watchpoint_hit;

    if (wp_hit) {
        if (wp_hit->flags & BP_CPU) {
            cs->watchpoint_hit = NULL;
            rh850_raise_exception(env, 0, 0, 0);
        }
    } else {
        uint64_t pc = env->pc;

        /* (1) GDB breakpoints should be handled first.
         * (2) Do not raise a CPU exception if no CPU breakpoint has fired,
         * since singlestep is also done by generating a debug internal
         * exception.
         */
        if (!cpu_breakpoint_test(cs, pc, BP_GDB)  &&
             cpu_breakpoint_test(cs, pc, BP_CPU)) {

            rh850_raise_exception(env, 0, 0, 0);
        }
    }
}

static void rh850_cpu_reset(CPUState *cs)
{
	RH850CPU *cpu = RH850_CPU(cs);
    RH850CPUClass *mcc = RH850_CPU_GET_CLASS(cpu);
    CPURH850State *env = &cpu->env;

    mcc->parent_reset(cs);
    cs->exception_index = EXCP_NONE;
    set_default_nan_mode(1, &env->fp_status);
    env->pc = 0; // move to direct vector ? (always 0?)
    env->ID_flag = 1;   // interrupts are disable on reset
    env->sys_reg[BANK_ID_BASIC_0][EIPSW_IDX] = 0x20;
    env->sys_reg[BANK_ID_BASIC_0][FEPSW_IDX] = 0x20;
    env->sys_reg[BANK_ID_BASIC_0][EIIC_IDX] = 0x0;
    env->sys_reg[BANK_ID_BASIC_0][FEIC_IDX] = 0x0;
    env->sys_reg[BANK_ID_BASIC_0][PSW_IDX] = 0x20; // reset value of PSW
    env->sys_reg[BANK_ID_BASIC_0][CTPSW_IDX] = 0;
    env->sys_reg[BANK_ID_BASIC_0][CTBP_IDX] = 0;   // only bit 0 must be set to 0
    env->sys_reg[BANK_ID_BASIC_2][ASID_IDX2] = 0;   // only bits 31-10 must be set to 0
    env->sys_reg[BANK_ID_BASIC_2][HTCFG0_IDX2] = 0x00018000;   // const value
    env->sys_reg[BANK_ID_BASIC_2][MEI_IDX2] = 0;    // only some bits must be 0
    env->sys_reg[BANK_ID_BASIC_1][RBASE_IDX1] = 0;
    env->sys_reg[BANK_ID_BASIC_1][EBASE_IDX1] = 0;  // only bits 8-1 must be 0
    env->sys_reg[BANK_ID_BASIC_1][INTBP_IDX1] = 0;  // only bits 8-0 must be 0
    env->sys_reg[BANK_ID_BASIC_1][PID_IDX1] = 0x05000120;  // const
    env->sys_reg[BANK_ID_BASIC_1][SCCFG_IDX1] = 0;  // bits 31-8 must be 0
    env->sys_reg[BANK_ID_BASIC_1][SCBP_IDX1] = 0;  // bits 1-0 must be 0
    env->sys_reg[BANK_ID_BASIC_1][MCFG0_IDX1] = 0x4;  // bits 31-8 must be 0
    env->sys_reg[BANK_ID_BASIC_1][MCTL_IDX1] = 0x80000000;  // bits 31-8 must be 0

    env->sys_reg[BANK_ID_BASIC_2][FPIPR_IDX1] = 0;
    env->sys_reg[BANK_ID_BASIC_2][ISPR_IDX2] = 0;
    env->sys_reg[BANK_ID_BASIC_2][PMR_IDX2] = 0;
    env->sys_reg[BANK_ID_BASIC_2][ICSR_IDX2] = 0;
    env->sys_reg[BANK_ID_BASIC_2][INTCFG_IDX2] = 0;
}

static void rh850_cpu_realize(CPUState *cs)
{
    cpu_exec_realizefn(cs);
    qemu_init_vcpu(cs);
    cpu_reset(cs);
}

static void rh850_cpu_initfn(struct uc_struct *uc, CPUState *cs)
{
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);
}

static void rh850_cpu_class_init(CPUClass *c)
{
    RH850CPUClass *mcc = RH850_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    /* parent class is CPUClass, parent_reset() is cpu_common_reset(). */
    mcc->parent_reset = cc->reset;
    /* overwrite the CPUClass->reset to arch reset: avr_cpu_reset(). */
    cc->reset = rh850_cpu_reset;

    cc->has_work = rh850_cpu_has_work;
    cc->do_interrupt = rh850_cpu_do_interrupt;
    cc->cpu_exec_interrupt = rh850_cpu_exec_interrupt;
    cc->set_pc = rh850_cpu_set_pc;
    cc->tlb_fill = rh850_tlb_fill;
    cc->synchronize_from_tb = rh850_cpu_synchronize_from_tb;
    cc->debug_excp_handler = rh850_debug_excp_handler;

    cc->do_unaligned_access = rh850_cpu_do_unaligned_access;
    cc->get_phys_page_debug = rh850_cpu_get_phys_page_debug;
    cc->tcg_initialize = rh850_translate_init;
}

RH850CPU *cpu_rh850_init(struct uc_struct *uc)
{
    RH850CPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = qemu_memalign(8, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }
    memset((void *)cpu, 0, sizeof(*cpu));

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init RH850CPUClass */
    rh850_cpu_class_init(cc);

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init RH850CPU */
    rh850_cpu_initfn(uc, cs);

    /* realize RH850CPU */
    rh850_cpu_realize(cs);

    // init addresss space
    cpu_address_space_init(cs, 0, cs->memory);

    return cpu;
}
