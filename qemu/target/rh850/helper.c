/*
 * RH850 emulation helpers for qemu.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 * Copyright (c) 2018-2019 iSYSTEM Labs d.o.o.
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
#include "cpu.h"
#include "exec/exec-all.h"

#define RH850_DEBUG_INTERRUPT 0

int rh850_cpu_mmu_index(CPURH850State *env, bool ifetch)
{
  return 0;
}

#ifndef CONFIG_USER_ONLY
/*
 * Return RH850 IRQ number if an interrupt should be taken, else -1.
 * Used in cpu-exec.c
 *
 * Adapted from Spike's processor_t::take_interrupt()
 */

#if 0 /* Not used */
static int rh850_cpu_hw_interrupts_pending(CPURH850State *env)
{

    return EXCP_NONE;
}
#endif
#endif

uint32_t psw2int(CPURH850State * env);
uint32_t mem_deref_4(CPUState * cs, uint32_t addr);


uint32_t psw2int(CPURH850State * env)
{
  uint32_t ret = 0; 
  ret |= env->UM_flag<<30;
  ret |= env->CU0_flag<<16;
  ret |= env->CU1_flag<<17;
  ret |= env->CU2_flag<<18;
  ret |= env->EBV_flag<<15;
  ret |= env->NP_flag<<7;
  ret |= env->EP_flag<<6;
  ret |= env->ID_flag<<5; 
  ret |= env->SAT_flag<<4;
  ret |= env->CY_flag<<3;
  ret |= env->OV_flag<<2;
  ret |= env->S_flag<<1;
  ret |= env->Z_flag; 

  return ret;
}

/*
 * RH850 interrupt handler.
 **/

bool rh850_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
#if !defined(CONFIG_USER_ONLY)
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;

    //qemu_log("[cpu] exec_interrupt: got interrupt_req=%08x\n", interrupt_request);

    /* Handle FENMI interrupt. */
    if (interrupt_request == RH850_INT_FENMI)
    {
        /* Set exception info. */
        cs->exception_index = RH850_EXCP_FENMI;
        env->exception_cause = 0xE0;
        env->exception_priority = 1;

        /* Acknowledge interrupt. */
        rh850_cpu_do_interrupt(cs);
    }
    else if (interrupt_request == RH850_INT_FEINT)
    {
        if (!(env->systemRegs[BANK_ID_BASIC_2][PMR_IDX2] & (1<<env->exception_priority)))
        {
            /* Set exception info. */
            cs->exception_index = RH850_EXCP_FEINT;
            env->exception_cause = 0xF0;
            env->exception_priority = 3;

            /* Acknowledge interrupt. */
            rh850_cpu_do_interrupt(cs);
        }
    }
    else if (interrupt_request == RH850_EXCP_EIINT)
    {
        //qemu_log("exec_interrupt got RH850_EXCP_EIINT\n");

        /* Get interrupt request number. */
        //int intn = env->exception_cause & 0xfff;
        int priority = 4;

        //qemu_log("[cpu] exec_interrupt: got interrupt_req=%08x\n", interrupt_request);

        /* Check if interrupt priority is not masked (through PMR). */
        if (!(env->systemRegs[BANK_ID_BASIC_2][PMR_IDX2] & (1<<priority)))
        {
            /**
             * Interrupt is not masked, process it.
             * We set the exception index to RH850_EXCP_EIINT to notify an EIINT interrupt,
             * and we set the exception cause to indicate the channel.
             **/

            /* Set exception info. */
            cs->exception_index = RH850_EXCP_EIINT;
            //env->exception_cause = 0x1000 | (intn);
            //env->exception_dv = !(interrupt_request & RH850_INT_TAB_REF);
            env->exception_priority = priority;

            /* Acknowledge interrupt. */
            rh850_cpu_do_interrupt(cs);
        }
        else
        {
            //qemu_log("[cpu] interrupt priority is masked\n");
        }
    }
#endif

    /* Interrupt request has been processed. */
    cs->interrupt_request = 0;
    return false;
}

#if !defined(CONFIG_USER_ONLY)


static int get_physical_address(CPURH850State *env, hwaddr *physical,
                                int *prot, target_ulong addr,
                                int access_type, int mmu_idx)
{
    
        /*
         * There is no memory virtualization in RH850 (at least for the targeted SoC)
         * Address resolution is straightforward 
         */
        *physical = addr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;

}

static void raise_mmu_exception(CPURH850State *env, target_ulong address,
                                MMUAccessType access_type)
{
    CPUState *cs = CPU(rh850_env_get_cpu(env));
    int page_fault_exceptions = RH850_EXCP_INST_PAGE_FAULT; 
    switch (access_type) {
    case MMU_INST_FETCH:
        cs->exception_index = page_fault_exceptions ?
            RH850_EXCP_INST_PAGE_FAULT : RH850_EXCP_INST_ACCESS_FAULT;
        break;
    case MMU_DATA_LOAD:
        cs->exception_index = page_fault_exceptions ?
            RH850_EXCP_LOAD_PAGE_FAULT : RH850_EXCP_LOAD_ACCESS_FAULT;
        break;
    case MMU_DATA_STORE:
        cs->exception_index = page_fault_exceptions ?
            RH850_EXCP_STORE_PAGE_FAULT : RH850_EXCP_STORE_AMO_ACCESS_FAULT;
        break;
    default:
        g_assert_not_reached();
    }
    env->badaddr = address;
}

hwaddr rh850_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    RH850CPU *cpu = RH850_CPU(cs);
    hwaddr phys_addr;
    int prot;
    int mmu_idx = cpu_mmu_index(&cpu->env, false);

    if (get_physical_address(&cpu->env, &phys_addr, &prot, addr, 0, mmu_idx)) {
        return -1;
    }
    return phys_addr;
}

void rh850_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                   MMUAccessType access_type, int mmu_idx,
                                   uintptr_t retaddr)
{
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;
    switch (access_type) {
    case MMU_INST_FETCH:
        cs->exception_index = RH850_EXCP_INST_ADDR_MIS;
        break;
    case MMU_DATA_LOAD:
        cs->exception_index = RH850_EXCP_LOAD_ADDR_MIS;
        break;
    case MMU_DATA_STORE:
        cs->exception_index = RH850_EXCP_STORE_AMO_ADDR_MIS;
        break;
    default:
        g_assert_not_reached();
    }
    env->badaddr = addr;
    //qemu_log_mask(CPU_LOG_INT, "%s\n", __func__);
    do_raise_exception_err(env, cs->exception_index, retaddr);
}

#endif

int rh850_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int size,
        int rw, int mmu_idx)
{


    /*
     * TODO: Add check to system register concerning MPU configuratuon MPLA, MPUA
     *
     */
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;
#if !defined(CONFIG_USER_ONLY)
    hwaddr pa = 0;
    int prot;
#endif
    int ret = TRANSLATE_FAIL;
    qemu_log_mask(CPU_LOG_MMU,
            "%s pc " TARGET_FMT_lx " ad %" VADDR_PRIx " rw %d mmu_idx \
             %d\n", __func__, env->pc, address, rw, mmu_idx);

#if !defined(CONFIG_USER_ONLY)

    ret = get_physical_address(env, &pa, &prot, address, rw, mmu_idx);
    qemu_log_mask(CPU_LOG_MMU,
            "%s address=%" VADDR_PRIx " ret %d physical " TARGET_FMT_plx
             " prot %d\n", __func__, address, ret, pa, prot);
    if (ret == TRANSLATE_SUCCESS) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK, pa & TARGET_PAGE_MASK,
                     prot, mmu_idx, TARGET_PAGE_SIZE);
    } else if (ret == TRANSLATE_FAIL) {
        raise_mmu_exception(env, address, rw);
    }
#else
    switch (rw) {
    case MMU_INST_FETCH:
        cs->exception_index = RH850_EXCP_INST_PAGE_FAULT;
        break;
    case MMU_DATA_LOAD:
        cs->exception_index = RH850_EXCP_LOAD_PAGE_FAULT;
        break;
    case MMU_DATA_STORE:
        cs->exception_index = RH850_EXCP_STORE_PAGE_FAULT;
        break;
    }
#endif
    return ret;
}


uint32_t mem_deref_4(CPUState * cs, uint32_t addr){
          uint8_t * buf = g_malloc(4); 
          uint32_t ret_dword = 0;
          cpu_memory_rw_debug(cs, addr,  buf, 4, false); 
          
          ret_dword |= buf[3] << 24;
          ret_dword |= buf[2] << 16;
          ret_dword |= buf[1] << 8; 
          ret_dword |= buf[0]; 
          g_free(buf); 
          return ret_dword; 
}


void rh850_cpu_do_interrupt(CPUState *cs)
{

    //qemu_log("[cpu] rh850_cpu_do_interrupt()\n");
    //qemu_log_mask(CPU_LOG_INT, "%s\n", __func__);
#if !defined(CONFIG_USER_ONLY)
    uint32_t intbp;
    RH850CPU *cpu = RH850_CPU(cs);
    CPURH850State *env = &cpu->env;

    uint32_t direct_vector_ba; 
    qemu_log_mask(CPU_LOG_INT, "%s: entering switch\n", __func__);
    switch (cs->exception_index) {
        case RH850_EXCP_FETRAP: 

            qemu_log_mask(CPU_LOG_INT, "%s: entering FETRAP handler\n", __func__);
            // store PSW to FEPSW (and update env->EBV_flag)
            env->systemRegs[BANK_ID_BASIC_0][FEPSW_IDX] = psw2int(env);
            // store PC to FEPC
            env->systemRegs[BANK_ID_BASIC_0][FEPC_IDX] = env->pc+2;
            // Set Exception Cause
		    env->systemRegs[BANK_ID_BASIC_0][FEIC_IDX] = env->exception_cause;

            qemu_log_mask(CPU_LOG_INT, "%s, saved pc : %x\n", __func__,env->pc);

            // update PSW
            env->UM_flag = 0;
            env->NP_flag = 1;
            env->EP_flag = 1;
            env->ID_flag = 1;

            // modify PC, keep RBASE or EBASE bits 9 to 31 (discard bits 0 to 8)
            if (env->EBV_flag) 
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1] & 0xFFFFFE00;
            else
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1] & 0xFFFFFE00; 
    
            qemu_log_mask(CPU_LOG_INT, "%s: direct vector addr : %x \n", __func__,direct_vector_ba);
            env->pc = direct_vector_ba + 0x30; 
            break; 
        
        case RH850_EXCP_TRAP:
            qemu_log_mask(CPU_LOG_INT, "%s: entering TRAP handler\n", __func__);
            // store PSW to EIPSW
            env->systemRegs[BANK_ID_BASIC_0][EIPSW_IDX] = psw2int(env);
            // store PC to EIPC
            env->systemRegs[BANK_ID_BASIC_0][EIPC_IDX] = env->pc+4;
            // Set Exception Cause
            env->systemRegs[BANK_ID_BASIC_0][EIIC_IDX] = env->exception_cause;

            env->UM_flag = 0;
            env->EP_flag = 1;
            env->ID_flag = 1;

            // modify PC, keep RBASE or EBASE bits 9 to 31 (discard bits 0 to 8)
            if (env->EBV_flag)
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1] & 0xFFFFFE00;
            else
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1] & 0xFFFFFE00; 

            if (env->exception_cause < 0x50) {
            env->pc = direct_vector_ba + 0x40; 
            } else {
            env->pc = direct_vector_ba + 0x50; 
            }
            break; 

        case RH850_EXCP_RIE:
            //qemu_log("%s: entering RIE handler\n", __func__);
            // store PSW to FEPSW
            env->systemRegs[BANK_ID_BASIC_0][FEPSW_IDX] = psw2int(env);
            // store PC to FEPC
            env->systemRegs[BANK_ID_BASIC_0][FEPC_IDX] = env->pc;
            // Set Exception Cause
                env->systemRegs[BANK_ID_BASIC_0][FEIC_IDX] = env->exception_cause;
            //qemu_log("%s, saved pc : %x\n", __func__,env->pc);
            // update PSW

            env->UM_flag = 0;
            env->NP_flag = 1;
            env->EP_flag = 1;
            env->ID_flag = 1;

            // modify PC, keep RBASE or EBASE bits 9 to 31 (discard bits 0 to 8)
            if (env->EBV_flag) 
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1] & 0xFFFFFE00;
            else
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1] & 0xFFFFFE00; 

            //qemu_log("%s: direct vector addr : %x \n", __func__,direct_vector_ba);
            env->pc = direct_vector_ba + 0x60;
            //qemu_log("%s: pc : 0x%08x \n", __func__, direct_vector_ba+0x60); 
            break;

        case RH850_EXCP_SYSCALL:
          qemu_log_mask(CPU_LOG_INT, "%s: entering SYSCALL handler\n", __func__);
          uint32_t syscall_cfg = env->systemRegs[BANK_ID_BASIC_1][SCCFG_IDX1] & 0xff;
          uint32_t syscall_number = env->exception_cause - 0x8000; 
          uint32_t syscall_bp = env->systemRegs[BANK_ID_BASIC_1][SCBP_IDX1]; 
          uint32_t handler_offset=0, deref_addr=0;
          
          if (syscall_number <= syscall_cfg) {
            deref_addr = syscall_bp + (syscall_number<<2); 
          } else {

            deref_addr = syscall_bp; 
          }

          qemu_log_mask(CPU_LOG_INT, "%s syscall_cfg_size = %d\n", __func__,syscall_cfg);
          qemu_log_mask(CPU_LOG_INT, "%s syscall_bp = %d\n", __func__,syscall_bp);
          qemu_log_mask(CPU_LOG_INT, "%s syscall_num = %d\n", __func__,syscall_number);
          qemu_log_mask(CPU_LOG_INT, "%s deref_addr = 0x%x\n", __func__,deref_addr);
          handler_offset = mem_deref_4(cs,deref_addr); 
          qemu_log_mask(CPU_LOG_INT, "%s handler offset = %x\n", __func__,handler_offset);

          // store PSW to EIPSW
          env->systemRegs[BANK_ID_BASIC_0][EIPSW_IDX] = psw2int(env);
          // store PC to EIPC
          env->systemRegs[BANK_ID_BASIC_0][EIPC_IDX] = env->pc+4;
          // Set Exception Cause
		  env->systemRegs[BANK_ID_BASIC_0][EIIC_IDX] = env->exception_cause;

          env->UM_flag = 0;
          env->EP_flag = 1;
          env->ID_flag = 1;

          // modify PC 
          env->pc = syscall_bp + handler_offset; 
          qemu_log_mask(CPU_LOG_INT, "%s: moving pc to = 0x%x\n", __func__,env->pc);
          
          break; 

        case RH850_EXCP_FEINT:
            //qemu_log("[cpu] entering FEINT handler\n");
            // store PSW to FEPSW
            env->systemRegs[BANK_ID_BASIC_0][FEPSW_IDX] = psw2int(env);
            // store PC to FEPC
            env->systemRegs[BANK_ID_BASIC_0][FEPC_IDX] = env->pc;
            // Set Exception Cause
            env->systemRegs[BANK_ID_BASIC_0][FEIC_IDX] = env->exception_cause;

            /* Update PSW. */
            env->UM_flag = 0;
            env->ID_flag = 1;
            env->NP_flag = 1;
            env->EP_flag = 0;

            /* Direct vector. */
            if (env->EBV_flag) 
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1];
            else
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1]; 
           
            /* Redirect to FEINT exception handler. */
            env->pc = (direct_vector_ba & 0xFFFFFF00) + 0xF0;  
            //qemu_log("%s: moving pc to = 0x%x\n", __func__,env->pc);
            break;

        case RH850_EXCP_FENMI:
            //qemu_log("[cpu] entering FENMI handler\n");
            // store PSW to FEPSW
            env->systemRegs[BANK_ID_BASIC_0][FEPSW_IDX] = psw2int(env);
            // store PC to FEPC
            env->systemRegs[BANK_ID_BASIC_0][FEPC_IDX] = env->pc;
            // Set Exception Cause
            env->systemRegs[BANK_ID_BASIC_0][FEIC_IDX] = env->exception_cause;

            /* Update PSW. */
            env->UM_flag = 0;
            env->ID_flag = 1;
            env->NP_flag = 1;
            env->EP_flag = 0;

            /* Direct vector. */
            if (env->EBV_flag) 
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1];
            else
                direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1]; 
           
            /* Redirect to FENMI exception handler. */
            env->pc = (direct_vector_ba & 0xFFFFFF00) + 0xE0;  
            break;

        case RH850_EXCP_EIINT:
            //qemu_log("[cpu] entering EIINT handler\n");
            //qemu_log_mask(CPU_LOG_INT, "%s: entering EIINT handler\n", __func__);

            // store PSW to EIPSW
            env->systemRegs[BANK_ID_BASIC_0][EIPSW_IDX] = psw2int(env);
            // store PC to EIPC
            env->systemRegs[BANK_ID_BASIC_0][EIPC_IDX] = env->pc;
            // Set Exception Cause
            env->systemRegs[BANK_ID_BASIC_0][EIIC_IDX] = env->exception_cause;
            // Set priority to ISPR
            env->systemRegs[BANK_ID_BASIC_2][ISPR_IDX2] |= (1 << env->exception_priority);

            /* Set PSW.ID (disable further EI exceptions). */
            env->ID_flag = 1;

            /* Clear PSW.EP (we are processing an interrupt). */
            env->EP_flag = 0;

            /* Modify PC based on dispatch method (direct vector or table reference). */
            if (!env->exception_dv)
            {
                //qemu_log("[cpu] dispatch EIINT (table reference) for IRQ %d\n", env->exception_cause&0x1ff);
                /* Table reference, first read INTBP value. */
                intbp = env->systemRegs[BANK_ID_BASIC_1][INTBP_IDX1];
                //qemu_log("[cpu] INTBP=0x%08x\n", intbp);

                /* Compute address of interrupt handler (based on channel). */
                env->pc = mem_deref_4(cs, intbp + 4*(env->exception_cause & 0x1ff));
                //qemu_log("[cpu] PC=0x%08x\n", env->pc);
            }
            else
            {
                //qemu_log("[cpu] dispatch EIINT (direct vector) for IRQ %d\n", env->exception_cause&0x1ff);
                //qemu_log("[cpu] exception priority=%d\n", env->exception_priority);
                /* Direct vector. */
                if (env->EBV_flag) 
                    direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][EBASE_IDX1];
                else
                    direct_vector_ba = env->systemRegs[BANK_ID_BASIC_1][RBASE_IDX1]; 
                //qemu_log("[cpu] Direct vector Base Address = 0x%08x\n", direct_vector_ba);
               
                /* Is RINT bit set ? */
                if (direct_vector_ba & 1)
                {
                    //qemu_log("[cpu] RINT bit set\n");
                    /* Reduced vector (one handler for any priority). */
                    env->pc = (direct_vector_ba & 0xFFFFFF00) + 0x100; 
                }
                else
                {
                    //qemu_log("[cpu] RINT bit NOT set\n");
                    /* One handler per priority level. */
                    env->pc = (direct_vector_ba & 0xFFFFFF00) + 0x100 + (env->exception_priority<<4); 
                }
                //qemu_log("[cpu] PC=0x%08x\n", env->pc);
            }
            break;
      }
      
#endif
    cs->exception_index = EXCP_NONE; /* mark handled to qemu */
}
