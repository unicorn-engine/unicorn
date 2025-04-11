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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/ctype.h"
#include "cpu.h"
#include "exec/exec-all.h"

/* RH850 CPU definitions */

/* Program registers (rh850_prog_regnames):
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

const char * const rh850_gp_regnames[] = {
  "r0-zero", "r1", "r2", "r3-sp", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10 ", "r11", "r12", "r13", "r14", "r15",
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r2 ",
  "r24", "r25", "r26", "r27", "r28", "r29", "r30-ep", "r31-lp"
};

// Basic system registers
const char * const rh850_sys_regnames[][MAX_SYS_REGS_IN_BANK] = {

{ // SELECTION ID 0                           [5] used to be psw, but now it is stored in flags only
  "eipc",  "eipsw", "fepc",   "fepsw", NULL,  NULL,    "fpsr",   "fpepc", "fpst",  "fpcc",
  "fpcfg", "fpec",  NULL,     "eiic",  "feic", NULL,    "ctpc",   "ctpsw", NULL,    NULL,
  "ctbp",  NULL,    NULL,     NULL,    NULL,   NULL,    NULL,     NULL,    "eiwr",  "fewr",
  NULL,    "bsel"},
{ // SELECTION ID 1
  "mcfg0", NULL,    "rbase",  "ebase", "intbp", "mctl", "pid",    "fpipr", NULL,    NULL,
  NULL,    "sccfg", "scbp",
},
{ // SELECTION ID 2
  "htcfg0",NULL,    NULL,     NULL,    NULL,    NULL,   "mea",    "asid",  "mei",   NULL,
  "ispr",  "pmr",   "icsr",   "intcfg"
},
{ // SELECTION ID 3
    NULL,  NULL,    NULL,     NULL,    NULL,    NULL,   NULL,     NULL,    NULL,    NULL
},
{ // SELECTION ID 4
  NULL,    NULL,    NULL,     NULL,    NULL,    NULL,    NULL,     NULL,    NULL,    NULL,
  NULL,    NULL,    NULL,     NULL,    NULL,    NULL,    "ictagl", "ictagh","icdatl","icdath",
  NULL,    NULL,    NULL,     NULL,    "icctrl",NULL,    "iccfg",  NULL,    "icerr", NULL
},
{ // SELECTION ID 5
  "mpm",   "mprc",  NULL,     NULL,    "mpbrgn","mptrgn",NULL,     NULL,    "mca",   "mcs"
  "mcc",   "mcr"
},
{ // SELECTION ID 6
  "mpla0", "mpua0", "mpat0",  NULL,    "mpla1", "mpua1", "mpat1",  NULL,    "mpla2", "mpua2",
  "mpat2", NULL,    "mpla3",  "mpua3", "mpat3", NULL,    "mpla4",  "mpua4", "mpat4", NULL,
  "mpla5", "mpua5", "mpat5",  NULL,    "mpla6",  "mpua6", "mpat6", NULL,    "mpla7", "mpua7",
  "mpat7", NULL
},
{ // SELECTION ID 7
    /* MPU function system registers */
  "mpla8", "mpua8", "mpat8",  NULL,    "mpla9",  "mpua9", "mpat9", NULL,    "mpla10","mpua10",
  "mpat10",NULL,    "mpla11", "mpua11", "mpat11",NULL,    "mpla12","mpua12","mpat12",NULL,
  "mpla13","mpua13","mpat13", NULL,     "mpla14","mpua14","mpat14",NULL,    "mpla15","mpua15",
  "mpat15",NULL
}
};

// Where bits are read only, mask is set to 0
const uint32_t rh850_sys_reg_read_only_masks[][MAX_SYS_REGS_IN_BANK] = {

{	//SELECTION ID 0                                            PSW - implemented as registers for each used bit, see cpu_ZF, ...
	0xFFFFFFFF, 0x40078EFF, 0xFFFFFFFF, 0x40078EFF, 0x0, /*0x40018EFF*/  0, 0xFFEEFFFF, 0xFFFFFFFE, 0x00003F3F, 0x000000FF,
	0x0000031F, 0x00000001, 0x0,		0xFFFFFFFF, 0xFFFFFFFF, 0x0,		0xFFFFFFFF, 0x0000001F, 0x0,		0x0,
	0xFFFFFFFE, 0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0xFFFFFFFF, 0xFFFFFFFF,
	0x0, 		0x0
},
{	//SELECTION ID 1
    // for MCFG (idx = 0), byte 3 seems to not be writable, at least on devicee used for testing
	0x00000000, 0x0, 		0x00000000, 0xFFFFFE01, 0xFFFFFE00, 0x00000003, 0x00000000, 0x0000001F, 0x0, 		0x0,
	0x0, 		0x000000FF, 0xFFFFFFFC
},
{	//SELECTION ID 2
	0x00000000, 0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0xFFFFFFFF, 0x000003FF, 0x001F073F, 0x0,
	0x00000000, 0x0000FFFF, 0x00000000, 0x00000001
},
{	//SELECTION ID 3
	0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0
},
{	//SELECTION ID 4
	0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0,
	0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0xFFFFFA35, 0xF0FFFF00, 0xFFFFFFFF, 0xFFFFFFFF,
	0x0, 		0x0, 		0x0, 		0x0, 		0x00020107, 0x0, 		0x00000000, 0x0, 		0xBF3F7FFD, 0x0
},
{	//SELECTION ID 5
	0x00000003, 0x0000FFFF, 0x0, 		0x0, 		0x00000000, 0x00000000, 0x0, 		0x0, 		0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0x0000013F
},
{	//SELECTION ID 6
	0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFF,
	0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0,
	0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC,
	0x03FF00FF, 0x0
},
{	//SELECTION ID 7
	0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFF,
	0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0,
	0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC, 0x03FF00FF, 0x0, 		0xFFFFFFFC, 0xFFFFFFFC,
	0x03FF00FF, 0x0
}
};


const uint32_t rh850_sys_reg_read_only_values[][MAX_SYS_REGS_IN_BANK] = {
{	//SELECTION ID 0
	0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0,
	0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0,
	0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0, 		0x0,
	0x0,		0x0
},
{	//SELECTION ID 1
	0x4,		0x0,		0x0,		0x0,		0x0,		0x80000000, 0x12345678, 0x0,		0x0,		0x0,
	0x0,		0x0,		0x0
},
{	//SELECTION ID 2
	0x00008000, 0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0
},
{	//SELECTION ID 3
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0
},
{	//SELECTION ID 4
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0,		0x00010000, 0x0,		0x00010000,	0x0,		0x0,		0x0
},
{	//SELECTION ID 5
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0
},
{	//SELECTION ID 6
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0
},
{	//SELECTION ID 7
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,		0x0,
	0x0,		0x0
}
};



/*Data Buffer Operation Registers (rh850_sys_databuff_regnames):
 * sr24, 13 - cbdcr */
const char * const rh850_sys_databuff_regnames[] = { /* Data buffer operation registers */
  "cbdcr"
};

const char * const rh850_excp_names[] = {
    "misaligned_fetch",
    "fault_fetch",
    "illegal_instruction",
    "breakpoint",
    "misaligned_load",
    "fault_load",
    "misaligned_store",
    "fault_store",
    "user_ecall",
    "supervisor_ecall",
    "hypervisor_ecall",
    "machine_ecall",
    "exec_page_fault",
    "load_page_fault",
    "reserved",
    "store_page_fault"
};

const char * const rh850_intr_names[] = {
    "u_software",
    "s_software",
    "h_software",
    "m_software",
    "u_timer",
    "s_timer",
    "h_timer",
    "m_timer",
    "u_external",
    "s_external",
    "h_external",
    "m_external",
    "coprocessor",
    "host"
};


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

AddressSpace *cpu_addressspace(CPUState *cs, MemTxAttrs attrs)
{
    return cpu_get_address_space(cs, cpu_asidx_from_attrs(cs, attrs));
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
#ifndef CONFIG_USER_ONLY
    return true;
#else
    return true;
#endif
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
            // bool wnr = (wp_hit->flags & BP_WATCHPOINT_HIT_WRITE) != 0;
            // bool same_el = true;

            cs->watchpoint_hit = NULL;

            // env->exception.fsr = arm_debug_exception_fsr(env);
            // env->exception.vaddress = wp_hit->hitaddr;
            rh850_raise_exception(env, 0, 0, 0);
        }
    } else {
        uint64_t pc = env->pc;
        // bool same_el = true;

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

static bool check_watchpoints(RH850CPU *cpu)
{
    return true;
}


static bool rh850_debug_check_watchpoint(CPUState *cs, CPUWatchpoint *wp)
{
    /* Called by core code when a CPU watchpoint fires; need to check if this
     * is also an architectural watchpoint match.
     */
    RH850CPU *cpu = RH850_CPU(cs);

    return check_watchpoints(cpu);
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
    env->systemRegs[BANK_ID_BASIC_0][EIPSW_IDX] = 0x20;
    env->systemRegs[BANK_ID_BASIC_0][FEPSW_IDX] = 0x20;
    env->systemRegs[BANK_ID_BASIC_0][EIIC_IDX] = 0x0;
    env->systemRegs[BANK_ID_BASIC_0][FEIC_IDX] = 0x0;
    env->systemRegs[BANK_ID_BASIC_0][PSW_IDX] = 0x20; // reset value of PSW
    env->systemRegs[BANK_ID_BASIC_0][CTPSW_IDX] = 0;
    env->systemRegs[BANK_ID_BASIC_0][CTBP_IDX] = 0;   // only bit 0 must be set to 0
    env->systemRegs[BANK_ID_BASIC_2][ASID_IDX2] = 0;   // only bits 31-10 must be set to 0
    env->systemRegs[BANK_ID_BASIC_2][HTCFG0_IDX2] = 0x00018000;   // const value
    env->systemRegs[BANK_ID_BASIC_2][MEI_IDX2] = 0;    // only some bits must be 0
    env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1] = 0;
    env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1] = 0;  // only bits 8-1 must be 0
    env->systemRegs[BANK_ID_BASIC_1][INTBP_IDX1] = 0;  // only bits 8-0 must be 0
    env->systemRegs[BANK_ID_BASIC_1][PID_IDX1] = 0x05000120;  // const
    env->systemRegs[BANK_ID_BASIC_1][SCCFG_IDX1] = 0;  // bits 31-8 must be 0
    env->systemRegs[BANK_ID_BASIC_1][SCBP_IDX1] = 0;  // bits 1-0 must be 0
    env->systemRegs[BANK_ID_BASIC_1][MCFG0_IDX1] = 0x4;  // bits 31-8 must be 0
    env->systemRegs[BANK_ID_BASIC_1][MCTL_IDX1] = 0x80000000;  // bits 31-8 must be 0

    env->systemRegs[BANK_ID_BASIC_2][FPIPR_IDX1] = 0;
    env->systemRegs[BANK_ID_BASIC_2][ISPR_IDX2] = 0;
    env->systemRegs[BANK_ID_BASIC_2][PMR_IDX2] = 0;
    env->systemRegs[BANK_ID_BASIC_2][ICSR_IDX2] = 0;
    env->systemRegs[BANK_ID_BASIC_2][INTCFG_IDX2] = 0;
}

static void rh850_cpu_realize(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);

    cpu_exec_realizefn(cs);
    
    qemu_init_vcpu(cs);
    
    cpu_reset(cs);
}

static void rh850_cpu_init(struct uc_struct *uc, CPUState *obj)
{
    CPUState *cs = CPU(obj);
    RH850CPU *cpu = RH850_CPU(obj);

    /* Set CPU pointers. */
    cpu_set_cpustate_pointers(cpu);

    cs->env_ptr = &cpu->env;
    cpu->env.uc = uc;
}

static void rh850_cpu_class_init(struct uc_struct *uc, CPUClass *c)
{
    RH850CPUClass *mcc = RH850_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    mcc->parent_reset = cc->reset;
    cc->reset = rh850_cpu_reset;

    cc->has_work = rh850_cpu_has_work;
    cc->do_interrupt = rh850_cpu_do_interrupt;
    cc->cpu_exec_interrupt = rh850_cpu_exec_interrupt;
    cc->set_pc = rh850_cpu_set_pc;
    cc->tlb_fill = rh850_tlb_fill;
    cc->synchronize_from_tb = rh850_cpu_synchronize_from_tb;
    cc->debug_excp_handler = rh850_debug_excp_handler;
    cc->debug_check_watchpoint = rh850_debug_check_watchpoint;

#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = rh850_cpu_handle_mmu_fault;
#else
    cc->do_unaligned_access = rh850_cpu_do_unaligned_access;
    cc->get_phys_page_debug = rh850_cpu_get_phys_page_debug;
#endif
#ifdef CONFIG_TCG
    cc->tcg_initialize = rh850_translate_init;
#endif
}

RH850CPU *cpu_rh850_init(struct uc_struct *uc, const char *cpu_model)
{
    RH850CPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init CPUClass */
    rh850_cpu_class_init(uc, cc);

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init CPU */
    rh850_cpu_init(uc, cs);

    /* realize CPU */
    rh850_cpu_realize(uc, cs);

    // init addresss space
    cpu_address_space_init(cs, 0, cs->memory);

    return cpu;
}




