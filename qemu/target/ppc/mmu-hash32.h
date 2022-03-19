#ifndef MMU_HASH32_H
#define MMU_HASH32_H

hwaddr get_pteg_offset32(PowerPCCPU *cpu, hwaddr hash);
hwaddr ppc_hash32_get_phys_page_debug(PowerPCCPU *cpu, target_ulong addr);
int ppc_hash32_handle_mmu_fault(PowerPCCPU *cpu, vaddr address, int rw,
                                int mmu_idx);

/*
 * Segment register definitions
 */

#define SR32_T                  0x80000000
#define SR32_KS                 0x40000000
#define SR32_KP                 0x20000000
#define SR32_NX                 0x10000000
#define SR32_VSID               0x00ffffff

/*
 * Block Address Translation (BAT) definitions
 */

#define BATU32_BEPI             0xfffe0000
#define BATU32_BL               0x00001ffc
#define BATU32_VS               0x00000002
#define BATU32_VP               0x00000001


#define BATL32_BRPN             0xfffe0000
#define BATL32_WIMG             0x00000078
#define BATL32_PP               0x00000003

/* PowerPC 601 has slightly different BAT registers */

#define BATU32_601_KS           0x00000008
#define BATU32_601_KP           0x00000004
#define BATU32_601_PP           0x00000003

#define BATL32_601_V            0x00000040
#define BATL32_601_BL           0x0000003f

/*
 * Hash page table definitions
 */
#define SDR_32_HTABORG         0xFFFF0000UL
#define SDR_32_HTABMASK        0x000001FFUL

#define HPTES_PER_GROUP         8
#define HASH_PTE_SIZE_32        8
#define HASH_PTEG_SIZE_32       (HASH_PTE_SIZE_32 * HPTES_PER_GROUP)

#define HPTE32_V_VALID          0x80000000
#define HPTE32_V_VSID           0x7fffff80
#define HPTE32_V_SECONDARY      0x00000040
#define HPTE32_V_API            0x0000003f
#define HPTE32_V_COMPARE(x, y)  (!(((x) ^ (y)) & 0x7fffffbf))

#define HPTE32_R_RPN            0xfffff000
#define HPTE32_R_R              0x00000100
#define HPTE32_R_C              0x00000080
#define HPTE32_R_W              0x00000040
#define HPTE32_R_I              0x00000020
#define HPTE32_R_M              0x00000010
#define HPTE32_R_G              0x00000008
#define HPTE32_R_WIMG           0x00000078
#define HPTE32_R_PP             0x00000003

static inline hwaddr ppc_hash32_hpt_base(PowerPCCPU *cpu)
{
    return cpu->env.spr[SPR_SDR1] & SDR_32_HTABORG;
}

static inline hwaddr ppc_hash32_hpt_mask(PowerPCCPU *cpu)
{
    return ((cpu->env.spr[SPR_SDR1] & SDR_32_HTABMASK) << 16) | 0xFFFF;
}

static inline target_ulong ppc_hash32_load_hpte0(PowerPCCPU *cpu,
                                                 hwaddr pte_offset)
{
    target_ulong base = ppc_hash32_hpt_base(cpu);

#ifdef UNICORN_ARCH_POSTFIX
    return glue(ldl_phys, UNICORN_ARCH_POSTFIX)(cpu->env.uc, CPU(cpu)->as, base + pte_offset);
#else
    return ldl_phys(cpu->env.uc, CPU(cpu)->as, base + pte_offset);
#endif
}

static inline target_ulong ppc_hash32_load_hpte1(PowerPCCPU *cpu,
                                                 hwaddr pte_offset)
{
    target_ulong base = ppc_hash32_hpt_base(cpu);

#ifdef UNICORN_ARCH_POSTFIX
    return glue(ldl_phys, UNICORN_ARCH_POSTFIX)(cpu->env.uc, CPU(cpu)->as, base + pte_offset + HASH_PTE_SIZE_32 / 2);
#else
    return ldl_phys(cpu->env.uc, CPU(cpu)->as, base + pte_offset + HASH_PTE_SIZE_32 / 2);
#endif
}

static inline void ppc_hash32_store_hpte0(PowerPCCPU *cpu,
                                          hwaddr pte_offset, target_ulong pte0)
{
    target_ulong base = ppc_hash32_hpt_base(cpu);

#ifdef UNICORN_ARCH_POSTFIX
    glue(stl_phys, UNICORN_ARCH_POSTFIX)(cpu->env.uc, CPU(cpu)->as, base + pte_offset, pte0);
#else
    stl_phys(cpu->env.uc, CPU(cpu)->as, base + pte_offset, pte0);
#endif
}

static inline void ppc_hash32_store_hpte1(PowerPCCPU *cpu,
                                          hwaddr pte_offset, target_ulong pte1)
{
    target_ulong base = ppc_hash32_hpt_base(cpu);

#ifdef UNICORN_ARCH_POSTFIX
    glue(stl_phys, UNICORN_ARCH_POSTFIX)(cpu->env.uc, CPU(cpu)->as, base + pte_offset + HASH_PTE_SIZE_32 / 2, pte1);
#else
    stl_phys(cpu->env.uc, CPU(cpu)->as, base + pte_offset + HASH_PTE_SIZE_32 / 2, pte1);
#endif
}

typedef struct {
    uint32_t pte0, pte1;
} ppc_hash_pte32_t;

#endif /* MMU_HASH32_H */
