/*
 * register_indices.h
 *
 *  Created on: Jun 18, 2018
 *
 */

#ifndef TARGET_RH850_REGISTER_INDICES_H_
#define TARGET_RH850_REGISTER_INDICES_H_


// BANK ID 0, sys basic regs
#define EIPC_IDX     0
#define EIPSW_IDX    1
#define FEPC_IDX     2
#define FEPSW_IDX    3
#define PSW_IDX	 	 5	//program status word
// sysFpuRegs indices
#define FPSR_IDX     6   //floating-point configuration/status   <---write the bit defines
#define FPEPC_IDX    7   //floating point exception PC
#define FPST_IDX     8
#define FPCC_IDX     9
#define FPCFG_IDX   10
#define FPEC_IDX    11

#define EIIC_IDX	13	//EI level exception cause
#define FEIC_IDX	14	//FI level exception cause
#define CTPC_IDX    16
#define CTPSW_IDX   17
#define CTBP_IDX    20
#define EIWR_IDX    28
#define FEWR_IDX    29
#define BSEL_IDX    31

// BANK ID 1, sys basic regs
#define MCFG0_IDX1	0	//machine configuration
#define RBASE_IDX1	2	//reset vector base address (if psw.ebv==0, this is also exception vector)
#define EBASE_IDX1	3	//exception handler vector address
#define INTBP_IDX1  4
#define MCTL_IDX1   5	//CPU control
#define PID_IDX1    6   //processor ID
#define SCCFG_IDX1  11  // SYSCALL config
#define SCBP_IDX1   12  // SYSCALL base pointer

// BANK ID 2, sys basic regs
#define HTCFG0_IDX2	0	//thread configuration
#define MEA_IDX2	6	//memory error address (when misaligned or MPU)
#define ASID_IDX2	7	//memory error address (when misaligned or MPU)
#define MEI_IDX2	8	//memory error info (info about instruction that caused exception)

// BANK ID 1, 2 sysInterruptRegs indices
#define FPIPR_IDX1  7
#define ISPR_IDX2   10
#define PMR_IDX2    11
#define ICSR_IDX2	12	//interrupt control status register
#define INTCFG_IDX2	13	//interrupt function setting


// BANK ID 5, 6, 7 system MPU regs indices
#define MPM_IDX5	0	//memory protection operation mode


#endif /* TARGET_RH850_REGISTER_INDICES_H_ */
