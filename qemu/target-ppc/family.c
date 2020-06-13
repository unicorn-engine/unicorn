#include "family.h"
#include "translate.h"
#include "mmu-hash32.h"

#if !defined(TARGET_PPC64)

/*************************************************************************************/

static int check_pow_nocheck(CPUPPCState *env)
{
    return 1;
}

/*************************************************************************************/

void ppc_e500v2_cpu_family_register_types(struct uc_struct* uc)
{
    const TypeInfo ppc_e500v2_cpu_family_type_info = {                      
        "e500v2-family-" TYPE_POWERPC_CPU,
        TYPE_POWERPC_CPU,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc_e500v2_cpu_family_class_init,
        NULL,
        NULL,
        true
    };

    type_register_static(uc,&ppc_e500v2_cpu_family_type_info);  
}

void ppc_e500v2_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(uc,oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc,oc);

    dc->desc = "e500v2 core";
    pcc->init_proc = init_proc_e500v2;
    pcc->check_pow = check_pow_nocheck; // check_pow_hid0;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_ISEL |
                       PPC_SPE | PPC_SPE_SINGLE | PPC_SPE_DOUBLE |
                       PPC_WRTEE | PPC_RFDI |
                       PPC_CACHE | PPC_CACHE_LOCK | PPC_CACHE_ICBI |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_TLBSYNC | PPC_TLBIVAX | PPC_MEM_SYNC;
    pcc->insns_flags2 = PPC2_BOOKE206;
    pcc->msr_mask = (1ull << MSR_UCLE) |
                    (1ull << MSR_SPE) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    pcc->mmu_model = POWERPC_MMU_BOOKE206;
    pcc->excp_model = POWERPC_EXCP_BOOKE;
    pcc->bus_model = PPC_FLAGS_INPUT_BookE;
    pcc->bfd_mach = 860; // bfd_mach_ppc_860;
    pcc->flags = POWERPC_FLAG_SPE | POWERPC_FLAG_CE |
                 POWERPC_FLAG_UBLE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}

void ppc_405_cpu_family_register_types(struct uc_struct* uc)
{
    const TypeInfo ppc_405_cpu_family_type_info = {                      
        "405-family-" TYPE_POWERPC_CPU,
        TYPE_POWERPC_CPU,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc_405_cpu_family_class_init,
        NULL,
        NULL,
        true
    };

    type_register_static(uc,&ppc_405_cpu_family_type_info);  
}

void ppc_405_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(uc,oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc,oc);

    dc->desc = "PowerPC 405";
    pcc->init_proc = init_proc_405;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_DCR | PPC_WRTEE |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ | PPC_CACHE_DCBA |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_40x_TLB | PPC_MEM_TLBIA | PPC_MEM_TLBSYNC |
                       PPC_4xx_COMMON | PPC_405_MAC | PPC_40x_EXCP;
    
    pcc->insns_flags |= PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_FRSQRTES |
                       PPC_FLOAT_STFIWX |
                       PPC_FLOAT_EXT ; // float support

    pcc->insns_flags |= PPC_ISEL; // ISEL support

    //pcc->insns_flags |= PPC_SPE | PPC_SPE_SINGLE;
     

    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_DWE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR);
    
    //ppc->msr_mask = (1ull << MSR_SPE);

    
    pcc->mmu_model = POWERPC_MMU_SOFT_4xx;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_405;
    pcc->bfd_mach = 403; //bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DWE |
                 POWERPC_FLAG_DE | POWERPC_FLAG_BUS_CLK;

    //pcc->flags|= POWERPC_FLAG_SPE;

}


void ppc_401_cpu_family_register_types(struct uc_struct* uc)
{
    const TypeInfo ppc_401_cpu_family_type_info = {                      
        "401-family-" TYPE_POWERPC_CPU,
        TYPE_POWERPC_CPU,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc_401_cpu_family_class_init,
        NULL,
        NULL,
        true
    };
    type_register_static(uc, &ppc_401_cpu_family_type_info);  
}

void ppc_401_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(uc,oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc,oc);

    dc->desc = "PowerPC 401";
    pcc->init_proc = init_proc_401;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING |
                       PPC_WRTEE | PPC_DCR |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_40x_ICBT |
                       PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_4xx_COMMON | PPC_40x_EXCP;
    pcc->msr_mask = (1ull << MSR_KEY) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_CE) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_REAL;
    pcc->excp_model = POWERPC_EXCP_40x;
    pcc->bus_model = PPC_FLAGS_INPUT_401;
    //pcc->bfd_mach = bfd_mach_ppc_403;
    pcc->flags = POWERPC_FLAG_CE | POWERPC_FLAG_DE |
                 POWERPC_FLAG_BUS_CLK;
}


void ppc_604_cpu_family_register_types(struct uc_struct* uc)
{
    const TypeInfo ppc_604_cpu_family_type_info = {                      
        "604-family-" TYPE_POWERPC_CPU,
        TYPE_POWERPC_CPU,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc_604_cpu_family_class_init,
        NULL,
        NULL,
        true
    };
    type_register_static(uc, &ppc_604_cpu_family_type_info);  
}

void ppc_604_cpu_family_class_init(struct uc_struct* uc,ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(uc,oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc,oc);

    dc->desc = "PowerPC 604";
    pcc->init_proc = init_proc_604;
    pcc->check_pow = check_pow_nocheck;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FRSQRTE | PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_SEGMENT | PPC_EXTERN;
    pcc->msr_mask = (1ull << MSR_POW) |
                    (1ull << MSR_ILE) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_EP) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI) |
                    (1ull << MSR_LE);
    pcc->mmu_model = POWERPC_MMU_32B;
#if defined(CONFIG_SOFTMMU)
    pcc->handle_mmu_fault = ppc_hash32_handle_mmu_fault;
#endif
    pcc->excp_model = POWERPC_EXCP_604;
    pcc->bus_model = PPC_FLAGS_INPUT_6xx;
    //pcc->bfd_mach = bfd_mach_ppc_604;
    pcc->flags = POWERPC_FLAG_SE | POWERPC_FLAG_BE |
                 POWERPC_FLAG_PMM | POWERPC_FLAG_BUS_CLK;
}

#else

#include "mmu-hash64.h"

/*************************************************************************************/

static int check_pow_970(CPUPPCState *env)
{
    if (env->spr[SPR_HID0] & (HID0_DEEPNAP | HID0_DOZE | HID0_NAP)) {
        return 1;
    }

    return 0;
}

/*************************************************************************************/

void ppc64_970_cpu_family_class_init(struct uc_struct* uc,ObjectClass* oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(uc,oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc,oc);

    dc->desc = "PowerPC 970";
    pcc->init_proc = init_proc_970;
    pcc->check_pow = check_pow_970;
    pcc->insns_flags = PPC_INSNS_BASE | PPC_STRING | PPC_MFTB |
                       PPC_FLOAT | PPC_FLOAT_FSEL | PPC_FLOAT_FRES |
                       PPC_FLOAT_FSQRT | PPC_FLOAT_FRSQRTE |
                       PPC_FLOAT_STFIWX |
                       PPC_CACHE | PPC_CACHE_ICBI | PPC_CACHE_DCBZ |
                       PPC_MEM_SYNC | PPC_MEM_EIEIO |
                       PPC_MEM_TLBIE | PPC_MEM_TLBSYNC |
                       PPC_64B | PPC_ALTIVEC |
                       PPC_SEGMENT_64B | PPC_SLBI;
    pcc->insns_flags2 = PPC2_FP_CVT_S64;
    pcc->msr_mask = (1ull << MSR_SF) |
                    (1ull << MSR_VR) |
                    (1ull << MSR_POW) |
                    (1ull << MSR_EE) |
                    (1ull << MSR_PR) |
                    (1ull << MSR_FP) |
                    (1ull << MSR_ME) |
                    (1ull << MSR_FE0) |
                    (1ull << MSR_SE) |
                    (1ull << MSR_DE) |
                    (1ull << MSR_FE1) |
                    (1ull << MSR_IR) |
                    (1ull << MSR_DR) |
                    (1ull << MSR_PMM) |
                    (1ull << MSR_RI);
    pcc->mmu_model = POWERPC_MMU_64B;
#if defined(CONFIG_SOFTMMU)
    pcc->handle_mmu_fault = ppc_hash64_handle_mmu_fault;
#endif
    pcc->excp_model = POWERPC_EXCP_970;
    pcc->bus_model = PPC_FLAGS_INPUT_970;
    //pcc->bfd_mach = bfd_mach_ppc64;
    pcc->flags = POWERPC_FLAG_VRE | POWERPC_FLAG_SE |
                 POWERPC_FLAG_BE | POWERPC_FLAG_PMM |
                 POWERPC_FLAG_BUS_CLK;
    pcc->l1_dcache_size = 0x8000;
    pcc->l1_icache_size = 0x10000;
}


void ppc64_970_cpu_family_register_types(struct uc_struct* uc)
{
    const TypeInfo ppc64_970_cpu_family_type_info = {                      
        "970-family-" TYPE_POWERPC_CPU,
        TYPE_POWERPC_CPU,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,                                
        NULL,
        ppc64_970_cpu_family_class_init,
        NULL,
        NULL,
        true
    };
    type_register_static(uc, &ppc64_970_cpu_family_type_info);  
}

#endif