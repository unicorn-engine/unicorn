/*
 * i386 virtual CPU header
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef CPU_I386_H
#define CPU_I386_H

#include "config.h"
#include "qemu-common.h"

#ifdef TARGET_X86_64
#define TARGET_LONG_BITS 64
#else
#define TARGET_LONG_BITS 32
#endif

/* target supports implicit self modifying code */
#define TARGET_HAS_SMC
/* support for self modifying code even if the modified instruction is
   close to the modifying instruction */
#define TARGET_HAS_PRECISE_SMC

#define TARGET_HAS_ICE 1

#ifdef TARGET_X86_64
#define ELF_MACHINE     EM_X86_64
#define ELF_MACHINE_UNAME "x86_64"
#else
#define ELF_MACHINE     EM_386
#define ELF_MACHINE_UNAME "i686"
#endif

#define CPUArchState struct CPUX86State

#include "exec/cpu-defs.h"

#include "fpu/softfloat.h"

#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7

#define R_AL 0
#define R_CL 1
#define R_DL 2
#define R_BL 3
#define R_AH 4
#define R_CH 5
#define R_DH 6
#define R_BH 7

#define R_ES 0
#define R_CS 1
#define R_SS 2
#define R_DS 3
#define R_FS 4
#define R_GS 5

/* segment descriptor fields */
#define DESC_G_MASK     (1 << 23)
#define DESC_B_SHIFT    22
#define DESC_B_MASK     (1 << DESC_B_SHIFT)
#define DESC_L_SHIFT    21 /* x86_64 only : 64 bit code segment */
#define DESC_L_MASK     (1 << DESC_L_SHIFT)
#define DESC_AVL_MASK   (1 << 20)
#define DESC_P_MASK     (1 << 15)
#define DESC_DPL_SHIFT  13
#define DESC_DPL_MASK   (3 << DESC_DPL_SHIFT)
#define DESC_S_MASK     (1 << 12)
#define DESC_TYPE_SHIFT 8
#define DESC_TYPE_MASK  (15 << DESC_TYPE_SHIFT)
#define DESC_A_MASK     (1 << 8)

#define DESC_CS_MASK    (1 << 11) /* 1=code segment 0=data segment */
#define DESC_C_MASK     (1 << 10) /* code: conforming */
#define DESC_R_MASK     (1 << 9)  /* code: readable */

#define DESC_E_MASK     (1 << 10) /* data: expansion direction */
#define DESC_W_MASK     (1 << 9)  /* data: writable */

#define DESC_TSS_BUSY_MASK (1 << 9)

/* eflags masks */
#define CC_C    0x0001
#define CC_P    0x0004
#define CC_A    0x0010
#define CC_Z    0x0040
#define CC_S    0x0080
#define CC_O    0x0800

#define TF_SHIFT   8
#define IOPL_SHIFT 12
#define VM_SHIFT   17

#define TF_MASK                 0x00000100
#define IF_MASK                 0x00000200
#define DF_MASK                 0x00000400
#define IOPL_MASK               0x00003000
#define NT_MASK                 0x00004000
#define RF_MASK                 0x00010000
#define VM_MASK                 0x00020000
#define AC_MASK                 0x00040000
#define VIF_MASK                0x00080000
#define VIP_MASK                0x00100000
#define ID_MASK                 0x00200000

/* hidden flags - used internally by qemu to represent additional cpu
   states. Only the INHIBIT_IRQ, SMM and SVMI are not redundant. We
   avoid using the IOPL_MASK, TF_MASK, VM_MASK and AC_MASK bit
   positions to ease oring with eflags. */
/* current cpl */
#define HF_CPL_SHIFT         0
/* true if soft mmu is being used */
#define HF_SOFTMMU_SHIFT     2
/* true if hardware interrupts must be disabled for next instruction */
#define HF_INHIBIT_IRQ_SHIFT 3
/* 16 or 32 segments */
#define HF_CS32_SHIFT        4
#define HF_SS32_SHIFT        5
/* zero base for DS, ES and SS : can be '0' only in 32 bit CS segment */
#define HF_ADDSEG_SHIFT      6
/* copy of CR0.PE (protected mode) */
#define HF_PE_SHIFT          7
#define HF_TF_SHIFT          8 /* must be same as eflags */
#define HF_MP_SHIFT          9 /* the order must be MP, EM, TS */
#define HF_EM_SHIFT         10
#define HF_TS_SHIFT         11
#define HF_IOPL_SHIFT       12 /* must be same as eflags */
#define HF_LMA_SHIFT        14 /* only used on x86_64: long mode active */
#define HF_CS64_SHIFT       15 /* only used on x86_64: 64 bit code segment  */
#define HF_RF_SHIFT         16 /* must be same as eflags */
#define HF_VM_SHIFT         17 /* must be same as eflags */
#define HF_AC_SHIFT         18 /* must be same as eflags */
#define HF_SMM_SHIFT        19 /* CPU in SMM mode */
#define HF_SVME_SHIFT       20 /* SVME enabled (copy of EFER.SVME) */
#define HF_SVMI_SHIFT       21 /* SVM intercepts are active */
#define HF_OSFXSR_SHIFT     22 /* CR4.OSFXSR */
#define HF_SMAP_SHIFT       23 /* CR4.SMAP */

#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)
#define HF_SOFTMMU_MASK      (1 << HF_SOFTMMU_SHIFT)
#define HF_INHIBIT_IRQ_MASK  (1 << HF_INHIBIT_IRQ_SHIFT)
#define HF_CS32_MASK         (1 << HF_CS32_SHIFT)
#define HF_SS32_MASK         (1 << HF_SS32_SHIFT)
#define HF_ADDSEG_MASK       (1 << HF_ADDSEG_SHIFT)
#define HF_PE_MASK           (1 << HF_PE_SHIFT)
#define HF_TF_MASK           (1 << HF_TF_SHIFT)
#define HF_MP_MASK           (1 << HF_MP_SHIFT)
#define HF_EM_MASK           (1 << HF_EM_SHIFT)
#define HF_TS_MASK           (1 << HF_TS_SHIFT)
#define HF_IOPL_MASK         (3 << HF_IOPL_SHIFT)
#define HF_LMA_MASK          (1 << HF_LMA_SHIFT)
#define HF_CS64_MASK         (1 << HF_CS64_SHIFT)
#define HF_RF_MASK           (1 << HF_RF_SHIFT)
#define HF_VM_MASK           (1 << HF_VM_SHIFT)
#define HF_AC_MASK           (1 << HF_AC_SHIFT)
#define HF_SMM_MASK          (1 << HF_SMM_SHIFT)
#define HF_SVME_MASK         (1 << HF_SVME_SHIFT)
#define HF_SVMI_MASK         (1 << HF_SVMI_SHIFT)
#define HF_OSFXSR_MASK       (1 << HF_OSFXSR_SHIFT)
#define HF_SMAP_MASK         (1 << HF_SMAP_SHIFT)

/* hflags2 */

#define HF2_GIF_SHIFT        0 /* if set CPU takes interrupts */
#define HF2_HIF_SHIFT        1 /* value of IF_MASK when entering SVM */
#define HF2_NMI_SHIFT        2 /* CPU serving NMI */
#define HF2_VINTR_SHIFT      3 /* value of V_INTR_MASKING bit */

#define HF2_GIF_MASK          (1 << HF2_GIF_SHIFT)
#define HF2_HIF_MASK          (1 << HF2_HIF_SHIFT)
#define HF2_NMI_MASK          (1 << HF2_NMI_SHIFT)
#define HF2_VINTR_MASK        (1 << HF2_VINTR_SHIFT)

#define CR0_PE_SHIFT 0
#define CR0_MP_SHIFT 1

#define CR0_PE_MASK  (1U << 0)
#define CR0_MP_MASK  (1U << 1)
#define CR0_EM_MASK  (1U << 2)
#define CR0_TS_MASK  (1U << 3)
#define CR0_ET_MASK  (1U << 4)
#define CR0_NE_MASK  (1U << 5)
#define CR0_WP_MASK  (1U << 16)
#define CR0_AM_MASK  (1U << 18)
#define CR0_PG_MASK  (1U << 31)

#define CR4_VME_MASK  (1U << 0)
#define CR4_PVI_MASK  (1U << 1)
#define CR4_TSD_MASK  (1U << 2)
#define CR4_DE_MASK   (1U << 3)
#define CR4_PSE_MASK  (1U << 4)
#define CR4_PAE_MASK  (1U << 5)
#define CR4_MCE_MASK  (1U << 6)
#define CR4_PGE_MASK  (1U << 7)
#define CR4_PCE_MASK  (1U << 8)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1U << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK  (1U << 10)
#define CR4_VMXE_MASK   (1U << 13)
#define CR4_SMXE_MASK   (1U << 14)
#define CR4_FSGSBASE_MASK (1U << 16)
#define CR4_PCIDE_MASK  (1U << 17)
#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_SMEP_MASK   (1U << 20)
#define CR4_SMAP_MASK   (1U << 21)

#define DR6_BD          (1 << 13)
#define DR6_BS          (1 << 14)
#define DR6_BT          (1 << 15)
#define DR6_FIXED_1     0xffff0ff0

#define DR7_GD          (1 << 13)
#define DR7_TYPE_SHIFT  16
#define DR7_LEN_SHIFT   18
#define DR7_FIXED_1     0x00000400
#define DR7_LOCAL_BP_MASK    0x55
#define DR7_MAX_BP           4
#define DR7_TYPE_BP_INST     0x0
#define DR7_TYPE_DATA_WR     0x1
#define DR7_TYPE_IO_RW       0x2
#define DR7_TYPE_DATA_RW     0x3

#define PG_PRESENT_BIT  0
#define PG_RW_BIT       1
#define PG_USER_BIT     2
#define PG_PWT_BIT      3
#define PG_PCD_BIT      4
#define PG_ACCESSED_BIT 5
#define PG_DIRTY_BIT    6
#define PG_PSE_BIT      7
#define PG_GLOBAL_BIT   8
#define PG_PSE_PAT_BIT  12
#define PG_NX_BIT       63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK       (1 << PG_RW_BIT)
#define PG_USER_MASK     (1 << PG_USER_BIT)
#define PG_PWT_MASK      (1 << PG_PWT_BIT)
#define PG_PCD_MASK      (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK    (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK      (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK   (1 << PG_GLOBAL_BIT)
#define PG_PSE_PAT_MASK  (1 << PG_PSE_PAT_BIT)
#define PG_ADDRESS_MASK  0x000ffffffffff000LL
#define PG_HI_RSVD_MASK  (PG_ADDRESS_MASK & ~PHYS_ADDR_MASK)
#define PG_HI_USER_MASK  0x7ff0000000000000LL
#define PG_NX_MASK       (1ULL << PG_NX_BIT)

#define PG_ERROR_W_BIT     1

#define PG_ERROR_P_MASK    0x01
#define PG_ERROR_W_MASK    (1 << PG_ERROR_W_BIT)
#define PG_ERROR_U_MASK    0x04
#define PG_ERROR_RSVD_MASK 0x08
#define PG_ERROR_I_D_MASK  0x10

#define MCG_CTL_P       (1ULL<<8)   /* MCG_CAP register available */
#define MCG_SER_P       (1ULL<<24) /* MCA recovery/new status bits */

#define MCE_CAP_DEF     (MCG_CTL_P|MCG_SER_P)
#define MCE_BANKS_DEF   10

#define MCG_STATUS_RIPV (1ULL<<0)   /* restart ip valid */
#define MCG_STATUS_EIPV (1ULL<<1)   /* ip points to correct instruction */
#define MCG_STATUS_MCIP (1ULL<<2)   /* machine check in progress */

#define MCI_STATUS_VAL   (1ULL<<63)  /* valid error */
#define MCI_STATUS_OVER  (1ULL<<62)  /* previous errors lost */
#define MCI_STATUS_UC    (1ULL<<61)  /* uncorrected error */
#define MCI_STATUS_EN    (1ULL<<60)  /* error enabled */
#define MCI_STATUS_MISCV (1ULL<<59)  /* misc error reg. valid */
#define MCI_STATUS_ADDRV (1ULL<<58)  /* addr reg. valid */
#define MCI_STATUS_PCC   (1ULL<<57)  /* processor context corrupt */
#define MCI_STATUS_S     (1ULL<<56)  /* Signaled machine check */
#define MCI_STATUS_AR    (1ULL<<55)  /* Action required */

/* MISC register defines */
#define MCM_ADDR_SEGOFF  0      /* segment offset */
#define MCM_ADDR_LINEAR  1      /* linear address */
#define MCM_ADDR_PHYS    2      /* physical address */
#define MCM_ADDR_MEM     3      /* memory address */
#define MCM_ADDR_GENERIC 7      /* generic */

#define MSR_IA32_TSC                    0x10
#define MSR_IA32_APICBASE               0x1b
#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE        (1<<11)
#define MSR_IA32_APICBASE_BASE          (0xfffff<<12)
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_TSC_ADJUST                  0x0000003b
#define MSR_IA32_TSCDEADLINE            0x6e0

#define MSR_P6_PERFCTR0                 0xc1

#define MSR_MTRRcap                     0xfe
#define MSR_MTRRcap_VCNT                8
#define MSR_MTRRcap_FIXRANGE_SUPPORT    (1 << 8)
#define MSR_MTRRcap_WC_SUPPORTED        (1 << 10)

#define MSR_IA32_SYSENTER_CS            0x174
#define MSR_IA32_SYSENTER_ESP           0x175
#define MSR_IA32_SYSENTER_EIP           0x176

#define MSR_MCG_CAP                     0x179
#define MSR_MCG_STATUS                  0x17a
#define MSR_MCG_CTL                     0x17b

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MSR_IA32_MISC_ENABLE            0x1a0
/* Indicates good rep/movs microcode on some processors: */
#define MSR_IA32_MISC_ENABLE_DEFAULT    1

#define MSR_MTRRphysBase(reg)           (0x200 + 2 * (reg))
#define MSR_MTRRphysMask(reg)           (0x200 + 2 * (reg) + 1)

#define MSR_MTRRphysIndex(addr)         ((((addr) & ~1u) - 0x200) / 2)

#define MSR_MTRRfix64K_00000            0x250
#define MSR_MTRRfix16K_80000            0x258
#define MSR_MTRRfix16K_A0000            0x259
#define MSR_MTRRfix4K_C0000             0x268
#define MSR_MTRRfix4K_C8000             0x269
#define MSR_MTRRfix4K_D0000             0x26a
#define MSR_MTRRfix4K_D8000             0x26b
#define MSR_MTRRfix4K_E0000             0x26c
#define MSR_MTRRfix4K_E8000             0x26d
#define MSR_MTRRfix4K_F0000             0x26e
#define MSR_MTRRfix4K_F8000             0x26f

#define MSR_PAT                         0x277

#define MSR_MTRRdefType                 0x2ff

#define MSR_CORE_PERF_FIXED_CTR0        0x309
#define MSR_CORE_PERF_FIXED_CTR1        0x30a
#define MSR_CORE_PERF_FIXED_CTR2        0x30b
#define MSR_CORE_PERF_FIXED_CTR_CTRL    0x38d
#define MSR_CORE_PERF_GLOBAL_STATUS     0x38e
#define MSR_CORE_PERF_GLOBAL_CTRL       0x38f
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL   0x390

#define MSR_MC0_CTL                     0x400
#define MSR_MC0_STATUS                  0x401
#define MSR_MC0_ADDR                    0x402
#define MSR_MC0_MISC                    0x403

#define MSR_EFER                        0xc0000080

#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_SVME  (1 << 12)
#define MSR_EFER_FFXSR (1 << 14)

#define MSR_STAR                        0xc0000081
#define MSR_LSTAR                       0xc0000082
#define MSR_CSTAR                       0xc0000083
#define MSR_FMASK                       0xc0000084
#define MSR_FSBASE                      0xc0000100
#define MSR_GSBASE                      0xc0000101
#define MSR_KERNELGSBASE                0xc0000102
#define MSR_TSC_AUX                     0xc0000103

#define MSR_VM_HSAVE_PA                 0xc0010117

#define MSR_IA32_BNDCFGS                0x00000d90

#define XSTATE_FP                       (1ULL << 0)
#define XSTATE_SSE                      (1ULL << 1)
#define XSTATE_YMM                      (1ULL << 2)
#define XSTATE_BNDREGS                  (1ULL << 3)
#define XSTATE_BNDCSR                   (1ULL << 4)
#define XSTATE_OPMASK                   (1ULL << 5)
#define XSTATE_ZMM_Hi256                (1ULL << 6)
#define XSTATE_Hi16_ZMM                 (1ULL << 7)


/* CPUID feature words */
typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEATURE_WORDS,
} FeatureWord;

typedef uint32_t FeatureWordArray[FEATURE_WORDS];

/* cpuid_features bits */
#define CPUID_FP87 (1U << 0)
#define CPUID_VME  (1U << 1)
#define CPUID_DE   (1U << 2)
#define CPUID_PSE  (1U << 3)
#define CPUID_TSC  (1U << 4)
#define CPUID_MSR  (1U << 5)
#define CPUID_PAE  (1U << 6)
#define CPUID_MCE  (1U << 7)
#define CPUID_CX8  (1U << 8)
#define CPUID_APIC (1U << 9)
#define CPUID_SEP  (1U << 11) /* sysenter/sysexit */
#define CPUID_MTRR (1U << 12)
#define CPUID_PGE  (1U << 13)
#define CPUID_MCA  (1U << 14)
#define CPUID_CMOV (1U << 15)
#define CPUID_PAT  (1U << 16)
#define CPUID_PSE36   (1U << 17)
#define CPUID_PN   (1U << 18)
#define CPUID_CLFLUSH (1U << 19)
#define CPUID_DTS (1U << 21)
#define CPUID_ACPI (1U << 22)
#define CPUID_MMX  (1U << 23)
#define CPUID_FXSR (1U << 24)
#define CPUID_SSE  (1U << 25)
#define CPUID_SSE2 (1U << 26)
#define CPUID_SS (1U << 27)
#define CPUID_HT (1U << 28)
#define CPUID_TM (1U << 29)
#define CPUID_IA64 (1U << 30)
#define CPUID_PBE (1U << 31)

#define CPUID_EXT_SSE3     (1U << 0)
#define CPUID_EXT_PCLMULQDQ (1U << 1)
#define CPUID_EXT_DTES64   (1U << 2)
#define CPUID_EXT_MONITOR  (1U << 3)
#define CPUID_EXT_DSCPL    (1U << 4)
#define CPUID_EXT_VMX      (1U << 5)
#define CPUID_EXT_SMX      (1U << 6)
#define CPUID_EXT_EST      (1U << 7)
#define CPUID_EXT_TM2      (1U << 8)
#define CPUID_EXT_SSSE3    (1U << 9)
#define CPUID_EXT_CID      (1U << 10)
#define CPUID_EXT_FMA      (1U << 12)
#define CPUID_EXT_CX16     (1U << 13)
#define CPUID_EXT_XTPR     (1U << 14)
#define CPUID_EXT_PDCM     (1U << 15)
#define CPUID_EXT_PCID     (1U << 17)
#define CPUID_EXT_DCA      (1U << 18)
#define CPUID_EXT_SSE41    (1U << 19)
#define CPUID_EXT_SSE42    (1U << 20)
#define CPUID_EXT_X2APIC   (1U << 21)
#define CPUID_EXT_MOVBE    (1U << 22)
#define CPUID_EXT_POPCNT   (1U << 23)
#define CPUID_EXT_TSC_DEADLINE_TIMER (1U << 24)
#define CPUID_EXT_AES      (1U << 25)
#define CPUID_EXT_XSAVE    (1U << 26)
#define CPUID_EXT_OSXSAVE  (1U << 27)
#define CPUID_EXT_AVX      (1U << 28)
#define CPUID_EXT_F16C     (1U << 29)
#define CPUID_EXT_RDRAND   (1U << 30)
#define CPUID_EXT_HYPERVISOR  (1U << 31)

#define CPUID_EXT2_FPU     (1U << 0)
#define CPUID_EXT2_VME     (1U << 1)
#define CPUID_EXT2_DE      (1U << 2)
#define CPUID_EXT2_PSE     (1U << 3)
#define CPUID_EXT2_TSC     (1U << 4)
#define CPUID_EXT2_MSR     (1U << 5)
#define CPUID_EXT2_PAE     (1U << 6)
#define CPUID_EXT2_MCE     (1U << 7)
#define CPUID_EXT2_CX8     (1U << 8)
#define CPUID_EXT2_APIC    (1U << 9)
#define CPUID_EXT2_SYSCALL (1U << 11)
#define CPUID_EXT2_MTRR    (1U << 12)
#define CPUID_EXT2_PGE     (1U << 13)
#define CPUID_EXT2_MCA     (1U << 14)
#define CPUID_EXT2_CMOV    (1U << 15)
#define CPUID_EXT2_PAT     (1U << 16)
#define CPUID_EXT2_PSE36   (1U << 17)
#define CPUID_EXT2_MP      (1U << 19)
#define CPUID_EXT2_NX      (1U << 20)
#define CPUID_EXT2_MMXEXT  (1U << 22)
#define CPUID_EXT2_MMX     (1U << 23)
#define CPUID_EXT2_FXSR    (1U << 24)
#define CPUID_EXT2_FFXSR   (1U << 25)
#define CPUID_EXT2_PDPE1GB (1U << 26)
#define CPUID_EXT2_RDTSCP  (1U << 27)
#define CPUID_EXT2_LM      (1U << 29)
#define CPUID_EXT2_3DNOWEXT (1U << 30)
#define CPUID_EXT2_3DNOW   (1U << 31)

/* CPUID[8000_0001].EDX bits that are aliase of CPUID[1].EDX bits on AMD CPUs */
#define CPUID_EXT2_AMD_ALIASES (CPUID_EXT2_FPU | CPUID_EXT2_VME | \
                                CPUID_EXT2_DE | CPUID_EXT2_PSE | \
                                CPUID_EXT2_TSC | CPUID_EXT2_MSR | \
                                CPUID_EXT2_PAE | CPUID_EXT2_MCE | \
                                CPUID_EXT2_CX8 | CPUID_EXT2_APIC | \
                                CPUID_EXT2_MTRR | CPUID_EXT2_PGE | \
                                CPUID_EXT2_MCA | CPUID_EXT2_CMOV | \
                                CPUID_EXT2_PAT | CPUID_EXT2_PSE36 | \
                                CPUID_EXT2_MMX | CPUID_EXT2_FXSR)

#define CPUID_EXT3_LAHF_LM (1U << 0)
#define CPUID_EXT3_CMP_LEG (1U << 1)
#define CPUID_EXT3_SVM     (1U << 2)
#define CPUID_EXT3_EXTAPIC (1U << 3)
#define CPUID_EXT3_CR8LEG  (1U << 4)
#define CPUID_EXT3_ABM     (1U << 5)
#define CPUID_EXT3_SSE4A   (1U << 6)
#define CPUID_EXT3_MISALIGNSSE (1U << 7)
#define CPUID_EXT3_3DNOWPREFETCH (1U << 8)
#define CPUID_EXT3_OSVW    (1U << 9)
#define CPUID_EXT3_IBS     (1U << 10)
#define CPUID_EXT3_XOP     (1U << 11)
#define CPUID_EXT3_SKINIT  (1U << 12)
#define CPUID_EXT3_WDT     (1U << 13)
#define CPUID_EXT3_LWP     (1U << 15)
#define CPUID_EXT3_FMA4    (1U << 16)
#define CPUID_EXT3_TCE     (1U << 17)
#define CPUID_EXT3_NODEID  (1U << 19)
#define CPUID_EXT3_TBM     (1U << 21)
#define CPUID_EXT3_TOPOEXT (1U << 22)
#define CPUID_EXT3_PERFCORE (1U << 23)
#define CPUID_EXT3_PERFNB  (1U << 24)

#define CPUID_SVM_NPT          (1U << 0)
#define CPUID_SVM_LBRV         (1U << 1)
#define CPUID_SVM_SVMLOCK      (1U << 2)
#define CPUID_SVM_NRIPSAVE     (1U << 3)
#define CPUID_SVM_TSCSCALE     (1U << 4)
#define CPUID_SVM_VMCBCLEAN    (1U << 5)
#define CPUID_SVM_FLUSHASID    (1U << 6)
#define CPUID_SVM_DECODEASSIST (1U << 7)
#define CPUID_SVM_PAUSEFILTER  (1U << 10)
#define CPUID_SVM_PFTHRESHOLD  (1U << 12)

#define CPUID_7_0_EBX_FSGSBASE (1U << 0)
#define CPUID_7_0_EBX_BMI1     (1U << 3)
#define CPUID_7_0_EBX_HLE      (1U << 4)
#define CPUID_7_0_EBX_AVX2     (1U << 5)
#define CPUID_7_0_EBX_SMEP     (1U << 7)
#define CPUID_7_0_EBX_BMI2     (1U << 8)
#define CPUID_7_0_EBX_ERMS     (1U << 9)
#define CPUID_7_0_EBX_INVPCID  (1U << 10)
#define CPUID_7_0_EBX_RTM      (1U << 11)
#define CPUID_7_0_EBX_MPX      (1U << 14)
#define CPUID_7_0_EBX_AVX512F  (1U << 16) /* AVX-512 Foundation */
#define CPUID_7_0_EBX_RDSEED   (1U << 18)
#define CPUID_7_0_EBX_ADX      (1U << 19)
#define CPUID_7_0_EBX_SMAP     (1U << 20)
#define CPUID_7_0_EBX_AVX512PF (1U << 26) /* AVX-512 Prefetch */
#define CPUID_7_0_EBX_AVX512ER (1U << 27) /* AVX-512 Exponential and Reciprocal */
#define CPUID_7_0_EBX_AVX512CD (1U << 28) /* AVX-512 Conflict Detection */

/* CPUID[0x80000007].EDX flags: */
#define CPUID_APM_INVTSC       (1U << 8)

#define CPUID_VENDOR_SZ      12

#define CPUID_VENDOR_INTEL_1 0x756e6547 /* "Genu" */
#define CPUID_VENDOR_INTEL_2 0x49656e69 /* "ineI" */
#define CPUID_VENDOR_INTEL_3 0x6c65746e /* "ntel" */
#define CPUID_VENDOR_INTEL "GenuineIntel"

#define CPUID_VENDOR_AMD_1   0x68747541 /* "Auth" */
#define CPUID_VENDOR_AMD_2   0x69746e65 /* "enti" */
#define CPUID_VENDOR_AMD_3   0x444d4163 /* "cAMD" */
#define CPUID_VENDOR_AMD   "AuthenticAMD"

#define CPUID_VENDOR_VIA   "CentaurHauls"

#define CPUID_MWAIT_IBE     (1U << 1) /* Interrupts can exit capability */
#define CPUID_MWAIT_EMX     (1U << 0) /* enumeration supported */

#ifndef HYPERV_SPINLOCK_NEVER_RETRY
#define HYPERV_SPINLOCK_NEVER_RETRY             0xFFFFFFFF
#endif

#define EXCP00_DIVZ	0
#define EXCP01_DB	1
#define EXCP02_NMI	2
#define EXCP03_INT3	3
#define EXCP04_INTO	4
#define EXCP05_BOUND	5
#define EXCP06_ILLOP	6
#define EXCP07_PREX	7
#define EXCP08_DBLE	8
#define EXCP09_XERR	9
#define EXCP0A_TSS	10
#define EXCP0B_NOSEG	11
#define EXCP0C_STACK	12
#define EXCP0D_GPF	13
#define EXCP0E_PAGE	14
#define EXCP10_COPR	16
#define EXCP11_ALGN	17
#define EXCP12_MCHK	18

#define EXCP_SYSCALL    0x100 /* only happens in user only emulation
                                 for syscall instruction */

/* i386-specific interrupt pending bits.  */
#define CPU_INTERRUPT_POLL      CPU_INTERRUPT_TGT_EXT_1
#define CPU_INTERRUPT_SMI       CPU_INTERRUPT_TGT_EXT_2
#define CPU_INTERRUPT_NMI       CPU_INTERRUPT_TGT_EXT_3
#define CPU_INTERRUPT_MCE       CPU_INTERRUPT_TGT_EXT_4
#define CPU_INTERRUPT_VIRQ      CPU_INTERRUPT_TGT_INT_0
#define CPU_INTERRUPT_SIPI      CPU_INTERRUPT_TGT_INT_1
#define CPU_INTERRUPT_TPR       CPU_INTERRUPT_TGT_INT_2

/* Use a clearer name for this.  */
#define CPU_INTERRUPT_INIT      CPU_INTERRUPT_RESET

typedef enum {
    CC_OP_DYNAMIC, /* must use dynamic code to get cc_op */
    CC_OP_EFLAGS,  /* all cc are explicitly computed, CC_SRC = flags */

    CC_OP_MULB, /* modify all flags, C, O = (CC_SRC != 0) */
    CC_OP_MULW,
    CC_OP_MULL,
    CC_OP_MULQ,

    CC_OP_ADDB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_ADDW,
    CC_OP_ADDL,
    CC_OP_ADDQ,

    CC_OP_ADCB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_ADCW,
    CC_OP_ADCL,
    CC_OP_ADCQ,

    CC_OP_SUBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_SUBW,
    CC_OP_SUBL,
    CC_OP_SUBQ,

    CC_OP_SBBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
    CC_OP_SBBW,
    CC_OP_SBBL,
    CC_OP_SBBQ,

    CC_OP_LOGICB, /* modify all flags, CC_DST = res */
    CC_OP_LOGICW,
    CC_OP_LOGICL,
    CC_OP_LOGICQ,

    CC_OP_INCB, /* modify all flags except, CC_DST = res, CC_SRC = C */
    CC_OP_INCW,
    CC_OP_INCL,
    CC_OP_INCQ,

    CC_OP_DECB, /* modify all flags except, CC_DST = res, CC_SRC = C  */
    CC_OP_DECW,
    CC_OP_DECL,
    CC_OP_DECQ,

    CC_OP_SHLB, /* modify all flags, CC_DST = res, CC_SRC.msb = C */
    CC_OP_SHLW,
    CC_OP_SHLL,
    CC_OP_SHLQ,

    CC_OP_SARB, /* modify all flags, CC_DST = res, CC_SRC.lsb = C */
    CC_OP_SARW,
    CC_OP_SARL,
    CC_OP_SARQ,

    CC_OP_BMILGB, /* Z,S via CC_DST, C = SRC==0; O=0; P,A undefined */
    CC_OP_BMILGW,
    CC_OP_BMILGL,
    CC_OP_BMILGQ,

    CC_OP_ADCX, /* CC_DST = C, CC_SRC = rest.  */
    CC_OP_ADOX, /* CC_DST = O, CC_SRC = rest.  */
    CC_OP_ADCOX, /* CC_DST = C, CC_SRC2 = O, CC_SRC = rest.  */

    CC_OP_CLR, /* Z set, all other flags clear.  */

    CC_OP_NB,
} CCOp;

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
    float32 _s[4];
    float64 _d[2];
} XMMReg;

typedef union {
    uint8_t _b[32];
    uint16_t _w[16];
    uint32_t _l[8];
    uint64_t _q[4];
    float32 _s[8];
    float64 _d[4];
} YMMReg;

typedef union {
    uint8_t _b[64];
    uint16_t _w[32];
    uint32_t _l[16];
    uint64_t _q[8];
    float32 _s[16];
    float64 _d[8];
} ZMMReg;

typedef union {
    uint8_t _b[8];
    uint16_t _w[4];
    uint32_t _l[2];
    float32 _s[2];
    uint64_t q;
} MMXReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

#ifdef HOST_WORDS_BIGENDIAN
#define ZMM_B(n) _b[63 - (n)]
#define ZMM_W(n) _w[31 - (n)]
#define ZMM_L(n) _l[15 - (n)]
#define ZMM_S(n) _s[15 - (n)]
#define ZMM_Q(n) _q[7 - (n)]
#define ZMM_D(n) _d[7 - (n)]

#define YMM_B(n) _b[31 - (n)]
#define YMM_W(n) _w[15 - (n)]
#define YMM_L(n) _l[7 - (n)]
#define YMM_S(n) _s[7 - (n)]
#define YMM_Q(n) _q[3 - (n)]
#define YMM_D(n) _d[3 - (n)]

#define XMM_B(n) _b[15 - (n)]
#define XMM_W(n) _w[7 - (n)]
#define XMM_L(n) _l[3 - (n)]
#define XMM_S(n) _s[3 - (n)]
#define XMM_Q(n) _q[1 - (n)]
#define XMM_D(n) _d[1 - (n)]

#define MMX_B(n) _b[7 - (n)]
#define MMX_W(n) _w[3 - (n)]
#define MMX_L(n) _l[1 - (n)]
#define MMX_S(n) _s[1 - (n)]
#else
#define ZMM_B(n) _b[n]
#define ZMM_W(n) _w[n]
#define ZMM_L(n) _l[n]
#define ZMM_S(n) _s[n]
#define ZMM_Q(n) _q[n]
#define ZMM_D(n) _d[n]

#define YMM_B(n) _b[n]
#define YMM_W(n) _w[n]
#define YMM_L(n) _l[n]
#define YMM_S(n) _s[n]
#define YMM_Q(n) _q[n]
#define YMM_D(n) _d[n]

#define XMM_B(n) _b[n]
#define XMM_W(n) _w[n]
#define XMM_L(n) _l[n]
#define XMM_S(n) _s[n]
#define XMM_Q(n) _q[n]
#define XMM_D(n) _d[n]

#define MMX_B(n) _b[n]
#define MMX_W(n) _w[n]
#define MMX_L(n) _l[n]
#define MMX_S(n) _s[n]
#endif
#define MMX_Q(n) q

typedef union {
    floatx80 QEMU_ALIGN(16, d);
    MMXReg mmx;
} FPReg;

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

#define CPU_NB_REGS64 16
#define CPU_NB_REGS32 8

#ifdef TARGET_X86_64
#define CPU_NB_REGS CPU_NB_REGS64
#else
#define CPU_NB_REGS CPU_NB_REGS32
#endif

#define MAX_FIXED_COUNTERS 3
#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define NB_MMU_MODES 3

#define NB_OPMASK_REGS 8

typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];
    target_ulong eip;
    target_ulong eflags0; // copy of eflags that does not change thru the BB
    target_ulong eflags; /* eflags register. During CPU emulation, CC
                        flags and DF are set to zero because they are
                        stored elsewhere */

    /* emulator internal eflags handling */
    target_ulong cc_dst;
    target_ulong cc_src;
    target_ulong cc_src2;
    uint32_t cc_op;
    int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
                        are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    /* segments */
    SegmentCache segs[6]; /* selector values */
    SegmentCache ldt;
    SegmentCache tr;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

    target_ulong cr[5]; /* NOTE: cr1 is unused */
    int32_t a20_mask;

    BNDReg bnd_regs[4];
    BNDCSReg bndcs_regs;
    uint64_t msr_bndcfgs;

    /* Beginning of state preserved by INIT (dummy marker).  */
    //struct {} start_init_save;
    int start_init_save;

    /* FPU state */
    unsigned int fpstt; /* top of stack index */
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8];   /* 0 = valid, 1 = empty */
    FPReg fpregs[8];
    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    XMMReg xmm_regs[CPU_NB_REGS];
    XMMReg xmm_t0;
    MMXReg mmx_t0;

    XMMReg ymmh_regs[CPU_NB_REGS];

    uint64_t opmask_regs[NB_OPMASK_REGS];
    YMMReg zmmh_regs[CPU_NB_REGS];
#ifdef TARGET_X86_64
    ZMMReg hi16_zmm_regs[CPU_NB_REGS];
#endif

    /* sysenter registers */
    uint32_t sysenter_cs;
    target_ulong sysenter_esp;
    target_ulong sysenter_eip;
    uint64_t efer;
    uint64_t star;

    uint64_t vm_hsave;

#ifdef TARGET_X86_64
    target_ulong lstar;
    target_ulong cstar;
    target_ulong fmask;
    target_ulong kernelgsbase;
#endif

    uint64_t tsc;
    uint64_t tsc_adjust;
    uint64_t tsc_deadline;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;
    uint64_t msr_ia32_feature_control;

    uint64_t msr_fixed_ctr_ctrl;
    uint64_t msr_global_ctrl;
    uint64_t msr_global_status;
    uint64_t msr_global_ovf_ctrl;
    uint64_t msr_fixed_counters[MAX_FIXED_COUNTERS];
    uint64_t msr_gp_counters[MAX_GP_COUNTERS];
    uint64_t msr_gp_evtsel[MAX_GP_COUNTERS];

    uint64_t pat;
    uint32_t smbase;

    /* End of state preserved by INIT (dummy marker).  */
    //struct {} end_init_save;
    int end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;

    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_tsc;

    /* exception/interrupt handling */
    int error_code;
    int exception_is_int;
    target_ulong exception_next_eip;
    target_ulong dr[8]; /* debug registers */
    union {
        struct CPUBreakpoint *cpu_breakpoint[4];
        struct CPUWatchpoint *cpu_watchpoint[4];
    }; /* break/watchpoints for dr[0..3] */
    int old_exception;  /* exception in flight */

    uint64_t vm_vmcb;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint8_t v_tpr;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    CPU_COMMON

    /* Fields from here on are preserved across CPU reset. */

    /* processor features (e.g. for CPUID insn) */
    uint32_t cpuid_level;
    uint32_t cpuid_xlevel;
    uint32_t cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    FeatureWordArray features;
    uint32_t cpuid_model[12];
    uint32_t cpuid_apic_id;

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];

    /* For KVM */
    uint32_t mp_state;
    int32_t exception_injected;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t has_error_code;
    uint32_t sipi_vector;
    bool tsc_valid;
    int tsc_khz;
    void *kvm_xsave_buf;

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mce_banks[MCE_BANKS_DEF*4];

    uint64_t tsc_aux;

    /* vmstate */
    uint16_t fpus_vmstate;
    uint16_t fptag_vmstate;
    uint16_t fpregs_format_vmstate;
    uint64_t xstate_bv;

    uint64_t xcr0;

    TPRAccess tpr_access_type;

    // Unicorn engine
    struct uc_struct *uc;
} CPUX86State;

#include "cpu-qom.h"

X86CPU *cpu_x86_init(struct uc_struct *uc, const char *cpu_model);
X86CPU *cpu_x86_create(struct uc_struct *uc, const char *cpu_model, Error **errp);
int cpu_x86_exec(struct uc_struct *uc, CPUX86State *s);
void x86_cpudef_setup(void);
int cpu_x86_support_mca_broadcast(CPUX86State *env);

int cpu_get_pic_interrupt(CPUX86State *s);
/* MSDOS compatibility mode FPU exception support */
void cpu_set_ferr(CPUX86State *s);

/* this function must always be used to load data in the segment
   cache: it synchronizes the hflags with the segment cache values */
static inline void cpu_x86_load_seg_cache(CPUX86State *env,
                                          int seg_reg, unsigned int selector,
                                          target_ulong base,
                                          unsigned int limit,
                                          unsigned int flags)
{
    SegmentCache *sc;
    unsigned int new_hflags;

    sc = &env->segs[seg_reg];
    sc->selector = selector;
    sc->base = base;
    sc->limit = limit;
    sc->flags = flags;

    /* update the hidden flags */
    {
        if (seg_reg == R_CS) {
#ifdef TARGET_X86_64
            if ((env->hflags & HF_LMA_MASK) && (flags & DESC_L_MASK)) {
                /* long mode */
                env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
                env->hflags &= ~(HF_ADDSEG_MASK);
            } else
#endif
            {
                /* legacy / compatibility case */
                new_hflags = (env->segs[R_CS].flags & DESC_B_MASK)
                    >> (DESC_B_SHIFT - HF_CS32_SHIFT);
                env->hflags = (env->hflags & ~(HF_CS32_MASK | HF_CS64_MASK)) |
                    new_hflags;
            }
        }
        if (seg_reg == R_SS) {
            int cpl = (flags >> DESC_DPL_SHIFT) & 3;
#if HF_CPL_MASK != 3
#error HF_CPL_MASK is hardcoded
#endif
            env->hflags = (env->hflags & ~HF_CPL_MASK) | cpl;
        }
        new_hflags = (env->segs[R_SS].flags & DESC_B_MASK)
            >> (DESC_B_SHIFT - HF_SS32_SHIFT);
        if (env->hflags & HF_CS64_MASK) {
            /* zero base assumed for DS, ES and SS in long mode */
        } else if (!(env->cr[0] & CR0_PE_MASK) ||
                   (env->eflags & VM_MASK) ||
                   !(env->hflags & HF_CS32_MASK)) {
            /* XXX: try to avoid this test. The problem comes from the
               fact that is real mode or vm86 mode we only modify the
               'base' and 'selector' fields of the segment cache to go
               faster. A solution may be to force addseg to one in
               translate-i386.c. */
            new_hflags |= HF_ADDSEG_MASK;
        } else {
            new_hflags |= ((env->segs[R_DS].base |
                            env->segs[R_ES].base |
                            env->segs[R_SS].base) != 0) <<
                HF_ADDSEG_SHIFT;
        }
        env->hflags = (env->hflags &
                       ~(HF_SS32_MASK | HF_ADDSEG_MASK)) | new_hflags;
    }
}

static inline void cpu_x86_load_seg_cache_sipi(X86CPU *cpu,
                                               uint8_t sipi_vector)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;

    env->eip = 0;
    cpu_x86_load_seg_cache(env, R_CS, sipi_vector << 8,
                           sipi_vector << 12,
                           env->segs[R_CS].limit,
                           env->segs[R_CS].flags);
    cs->halted = 0;
}

int cpu_x86_get_descr_debug(CPUX86State *env, unsigned int selector,
                            target_ulong *base, unsigned int *limit,
                            unsigned int *flags);

/* op_helper.c */
/* used for debug or cpu save/restore */
void cpu_get_fp80(uint64_t *pmant, uint16_t *pexp, floatx80 f);
floatx80 cpu_set_fp80(uint64_t mant, uint16_t upper);

/* cpu-exec.c */
/* the following helpers are only usable in user mode simulation as
   they can trigger unexpected exceptions */
void cpu_x86_load_seg(CPUX86State *s, int seg_reg, int selector);
void cpu_x86_fsave(CPUX86State *s, target_ulong ptr, int data32);
void cpu_x86_frstor(CPUX86State *s, target_ulong ptr, int data32);

/*  the binding language can not catch the exceptions.
    check the arguments, return error instead of raise exceptions. */
int uc_check_cpu_x86_load_seg(CPUX86State *env, int seg_reg, int sel);

/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_x86_signal_handler(int host_signum, void *pinfo,
                           void *puc);

/* cpuid.c */
void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx);
void cpu_clear_apic_feature(CPUX86State *env);
void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

/* helper.c */
int x86_cpu_handle_mmu_fault(CPUState *cpu, vaddr addr,
                             int is_write, int mmu_idx);
void x86_cpu_set_a20(X86CPU *cpu, int a20_state);

static inline bool hw_local_breakpoint_enabled(unsigned long dr7, int index)
{
    return (dr7 >> (index * 2)) & 1;
}

static inline bool hw_global_breakpoint_enabled(unsigned long dr7, int index)
{
    return (dr7 >> (index * 2)) & 2;

}
static inline bool hw_breakpoint_enabled(unsigned long dr7, int index)
{
    return hw_global_breakpoint_enabled(dr7, index) ||
           hw_local_breakpoint_enabled(dr7, index);
}

static inline int hw_breakpoint_type(unsigned long dr7, int index)
{
    return (dr7 >> (DR7_TYPE_SHIFT + (index * 4))) & 3;
}

static inline int hw_breakpoint_len(unsigned long dr7, int index)
{
    int len = ((dr7 >> (DR7_LEN_SHIFT + (index * 4))) & 3);
    return (len == 2) ? 8 : len + 1;
}

void hw_breakpoint_insert(CPUX86State *env, int index);
void hw_breakpoint_remove(CPUX86State *env, int index);
bool check_hw_breakpoints(CPUX86State *env, bool force_dr6_update);
void breakpoint_handler(CPUState *cs);

/* will be suppressed */
void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0);
void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3);
void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4);

/* hw/pc.c */
void cpu_smm_update(CPUX86State *env);
uint64_t cpu_get_tsc(CPUX86State *env);

#define TARGET_PAGE_BITS 12

#ifdef TARGET_X86_64
#define TARGET_PHYS_ADDR_SPACE_BITS 52
/* ??? This is really 48 bits, sign-extended, but the only thing
   accessible to userland with bit 48 set is the VSYSCALL, and that
   is handled via other mechanisms.  */
#define TARGET_VIRT_ADDR_SPACE_BITS 47
#else
#define TARGET_PHYS_ADDR_SPACE_BITS 36
#define TARGET_VIRT_ADDR_SPACE_BITS 32
#endif

/* XXX: This value should match the one returned by CPUID
 * and in exec.c */
# if defined(TARGET_X86_64)
# define PHYS_ADDR_MASK 0xffffffffffLL
# else
# define PHYS_ADDR_MASK 0xfffffffffLL
# endif

static inline CPUX86State *cpu_init(struct uc_struct *uc, const char *cpu_model)
{
    X86CPU *cpu = cpu_x86_init(uc, cpu_model);
    if (cpu == NULL) {
        return NULL;
    }
    return &cpu->env;
}

#ifdef TARGET_I386
#define cpu_exec cpu_x86_exec
#define cpu_gen_code cpu_x86_gen_code
#define cpu_signal_handler cpu_x86_signal_handler
#define cpudef_setup x86_cpudef_setup
#endif

/* MMU modes definitions */
#define MMU_MODE0_SUFFIX _ksmap
#define MMU_MODE1_SUFFIX _user
#define MMU_MODE2_SUFFIX _knosmap /* SMAP disabled or CPL<3 && AC=1 */
#define MMU_KSMAP_IDX   0
#define MMU_USER_IDX    1
#define MMU_KNOSMAP_IDX 2
static inline int cpu_mmu_index(CPUX86State *env)
{
    return (env->hflags & HF_CPL_MASK) == 3 ? MMU_USER_IDX :
        (!(env->hflags & HF_SMAP_MASK) || (env->eflags & AC_MASK))
        ? MMU_KNOSMAP_IDX : MMU_KSMAP_IDX;
}

static inline int cpu_mmu_index_kernel(CPUX86State *env)
{
    return !(env->hflags & HF_SMAP_MASK) ? MMU_KNOSMAP_IDX :
        ((env->hflags & HF_CPL_MASK) < 3 && (env->eflags & AC_MASK))
        ? MMU_KNOSMAP_IDX : MMU_KSMAP_IDX;
}

#define CC_DST  (env->cc_dst)
#define CC_SRC  (env->cc_src)
#define CC_SRC2 (env->cc_src2)
#define CC_OP   (env->cc_op)

/* n must be a constant to be efficient */
static inline target_long lshift(target_long x, int n)
{
    if (n >= 0) {
        return x << n;
    } else {
        return x >> (-n);
    }
}

/* float macros */
#define FT0    (env->ft0)
#define ST0    (env->fpregs[env->fpstt].d)
#define ST(n)  (env->fpregs[(env->fpstt + (n)) & 7].d)
#define ST1    ST(1)

/* translate.c */
void optimize_flags_init(struct uc_struct *);

#include "exec/cpu-all.h"
#include "svm.h"

#if !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif

#include "exec/exec-all.h"

static inline void cpu_get_tb_cpu_state(CPUX86State *env, target_ulong *pc,
                                        target_ulong *cs_base, int *flags)
{
    *cs_base = env->segs[R_CS].base;
    *pc = *cs_base + env->eip;
    *flags = env->hflags |
        (env->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK));
}

void do_cpu_init(X86CPU *cpu);
void do_cpu_sipi(X86CPU *cpu);

#define MCE_INJECT_BROADCAST    1
#define MCE_INJECT_UNCOND_AO    2

/* excp_helper.c */
void QEMU_NORETURN raise_exception(CPUX86State *env, int exception_index);
void QEMU_NORETURN raise_exception_err(CPUX86State *env, int exception_index,
                                       int error_code);
void QEMU_NORETURN raise_interrupt(CPUX86State *nenv, int intno, int is_int,
                                   int error_code, int next_eip_addend);

/* cc_helper.c */
extern const uint8_t parity_table[256];
uint32_t cpu_cc_compute_all(CPUX86State *env1, int op);
void update_fp_status(CPUX86State *env);

static inline uint32_t cpu_compute_eflags(CPUX86State *env)
{
    return (env->eflags & ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK)) | cpu_cc_compute_all(env, CC_OP) | (env->df & DF_MASK);
}

/* NOTE: the translator must set DisasContext.cc_op to CC_OP_EFLAGS
 * after generating a call to a helper that uses this.
 */
static inline void cpu_load_eflags(CPUX86State *env, int eflags,
                                   int update_mask)
{
    CC_SRC = eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    CC_OP = CC_OP_EFLAGS;
    env->df = 1 - (2 * ((eflags >> 10) & 1));
    env->eflags = (env->eflags & ~update_mask) |
        (eflags & update_mask) | 0x2;
}

/* load efer and update the corresponding hflags. XXX: do consistency
   checks with cpuid bits? */
static inline void cpu_load_efer(CPUX86State *env, uint64_t val)
{
    env->efer = val;
    env->hflags &= ~(HF_LMA_MASK | HF_SVME_MASK);
    if (env->efer & MSR_EFER_LMA) {
        env->hflags |= HF_LMA_MASK;
    }
    if (env->efer & MSR_EFER_SVME) {
        env->hflags |= HF_SVME_MASK;
    }
}

/* fpu_helper.c */
void cpu_set_mxcsr(CPUX86State *env, uint32_t val);
void cpu_set_fpuc(CPUX86State *env, uint16_t val);

/* svm_helper.c */
void cpu_svm_check_intercept_param(CPUX86State *env1, uint32_t type,
                                   uint64_t param);
void cpu_vmexit(CPUX86State *nenv, uint32_t exit_code, uint64_t exit_info_1);

/* seg_helper.c */
void do_interrupt_x86_hardirq(CPUX86State *env, int intno, int is_hw);

void do_smm_enter(X86CPU *cpu);

void cpu_report_tpr_access(CPUX86State *env, TPRAccess access);

void x86_cpu_compat_set_features(const char *cpu_model, FeatureWord w,
                                 uint32_t feat_add, uint32_t feat_remove);

void x86_cpu_compat_kvm_no_autoenable(FeatureWord w, uint32_t features);
void x86_cpu_compat_kvm_no_autodisable(FeatureWord w, uint32_t features);


/* Return name of 32-bit register, from a R_* constant */
const char *get_register_name_32(unsigned int reg);

uint32_t x86_cpu_apic_id_from_index(unsigned int cpu_index);
void enable_compat_apic_id_mode(void);

#define APIC_DEFAULT_ADDRESS 0xfee00000
#define APIC_SPACE_SIZE      0x100000

#endif /* CPU_I386_H */
