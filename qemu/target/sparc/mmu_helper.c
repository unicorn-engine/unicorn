/*
 *  Sparc MMU helpers
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"

/* Sparc MMU emulation */

#ifndef TARGET_SPARC64
/*
 * Sparc V8 Reference MMU (SRMMU)
 */
static const int access_table[8][8] = {
    { 0, 0, 0, 0, 8, 0, 12, 12 },
    { 0, 0, 0, 0, 8, 0, 0, 0 },
    { 8, 8, 0, 0, 0, 8, 12, 12 },
    { 8, 8, 0, 0, 0, 8, 0, 0 },
    { 8, 0, 8, 0, 8, 8, 12, 12 },
    { 8, 0, 8, 0, 8, 0, 8, 0 },
    { 8, 8, 8, 0, 8, 8, 12, 12 },
    { 8, 8, 8, 0, 8, 8, 8, 0 }
};

static const int perm_table[2][8] = {
    {
        PAGE_READ,
        PAGE_READ | PAGE_WRITE,
        PAGE_READ | PAGE_EXEC,
        PAGE_READ | PAGE_WRITE | PAGE_EXEC,
        PAGE_EXEC,
        PAGE_READ | PAGE_WRITE,
        PAGE_READ | PAGE_EXEC,
        PAGE_READ | PAGE_WRITE | PAGE_EXEC
    },
    {
        PAGE_READ,
        PAGE_READ | PAGE_WRITE,
        PAGE_READ | PAGE_EXEC,
        PAGE_READ | PAGE_WRITE | PAGE_EXEC,
        PAGE_EXEC,
        PAGE_READ,
        0,
        0,
    }
};

static int get_physical_address(CPUSPARCState *env, hwaddr *physical,
                                int *prot, int *access_index, MemTxAttrs *attrs,
                                target_ulong address, int rw, int mmu_idx,
                                target_ulong *page_size)
{
    int access_perms = 0;
    hwaddr pde_ptr;
    uint32_t pde;
    int error_code = 0, is_dirty, is_user;
    unsigned long page_offset;
    CPUState *cs = env_cpu(env);
    MemTxResult result;

    is_user = mmu_idx == MMU_USER_IDX;

    if (mmu_idx == MMU_PHYS_IDX) {
        *page_size = TARGET_PAGE_SIZE;
        /* Boot mode: instruction fetches are taken from PROM */
        if (rw == 2 && (env->mmuregs[0] & env->def.mmu_bm)) {
            *physical = env->prom_addr | (address & 0x7ffffULL);
            *prot = PAGE_READ | PAGE_EXEC;
            return 0;
        }
        *physical = address;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return 0;
    }

    *access_index = ((rw & 1) << 2) | (rw & 2) | (is_user ? 0 : 1);
    *physical = 0xffffffffffff0000ULL;

    /* SPARC reference MMU table walk: Context table->L1->L2->PTE */
    /* Context base + context number */
    pde_ptr = (env->mmuregs[1] << 4) + (env->mmuregs[2] << 2);
    pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr, MEMTXATTRS_UNSPECIFIED, &result);
    if (result != MEMTX_OK) {
        return 4 << 2; /* Translation fault, L = 0 */
    }

    /* Ctx pde */
    switch (pde & PTE_ENTRYTYPE_MASK) {
    default:
    case 0: /* Invalid */
        return 1 << 2;
    case 2: /* L0 PTE, maybe should not happen? */
    case 3: /* Reserved */
        return 4 << 2;
    case 1: /* L0 PDE */
        pde_ptr = ((address >> 22) & ~3) + ((pde & ~3) << 4);
        pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr,
                                MEMTXATTRS_UNSPECIFIED, &result);
        if (result != MEMTX_OK) {
            return (1 << 8) | (4 << 2); /* Translation fault, L = 1 */
        }

        switch (pde & PTE_ENTRYTYPE_MASK) {
        default:
        case 0: /* Invalid */
            return (1 << 8) | (1 << 2);
        case 3: /* Reserved */
            return (1 << 8) | (4 << 2);
        case 1: /* L1 PDE */
            pde_ptr = ((address & 0xfc0000) >> 16) + ((pde & ~3) << 4);
            pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr,
                                    MEMTXATTRS_UNSPECIFIED, &result);
            if (result != MEMTX_OK) {
                return (2 << 8) | (4 << 2); /* Translation fault, L = 2 */
            }

            switch (pde & PTE_ENTRYTYPE_MASK) {
            default:
            case 0: /* Invalid */
                return (2 << 8) | (1 << 2);
            case 3: /* Reserved */
                return (2 << 8) | (4 << 2);
            case 1: /* L2 PDE */
                pde_ptr = ((address & 0x3f000) >> 10) + ((pde & ~3) << 4);
                pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr,
                                        MEMTXATTRS_UNSPECIFIED, &result);
                if (result != MEMTX_OK) {
                    return (3 << 8) | (4 << 2); /* Translation fault, L = 3 */
                }

                switch (pde & PTE_ENTRYTYPE_MASK) {
                default:
                case 0: /* Invalid */
                    return (3 << 8) | (1 << 2);
                case 1: /* PDE, should not happen */
                case 3: /* Reserved */
                    return (3 << 8) | (4 << 2);
                case 2: /* L3 PTE */
                    page_offset = 0;
                }
                *page_size = TARGET_PAGE_SIZE;
                break;
            case 2: /* L2 PTE */
                page_offset = address & 0x3f000;
                *page_size = 0x40000;
            }
            break;
        case 2: /* L1 PTE */
            page_offset = address & 0xfff000;
            *page_size = 0x1000000;
        }
    }

    /* check access */
    access_perms = (pde & PTE_ACCESS_MASK) >> PTE_ACCESS_SHIFT;
    error_code = access_table[*access_index][access_perms];
    if (error_code && !((env->mmuregs[0] & MMU_NF) && is_user)) {
        return error_code;
    }

    /* update page modified and dirty bits */
    is_dirty = (rw & 1) && !(pde & PG_MODIFIED_MASK);
    if (!(pde & PG_ACCESSED_MASK) || is_dirty) {
        pde |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pde |= PG_MODIFIED_MASK;
        }
        stl_phys_notdirty(cs->as, pde_ptr, pde);
    }

    /* the page can be put in the TLB */
    *prot = perm_table[is_user][access_perms];
    if (!(pde & PG_MODIFIED_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        *prot &= ~PAGE_WRITE;
    }

    /* Even if large ptes, we map only one 4KB page in the cache to
       avoid filling it too fast */
    *physical = ((hwaddr)(pde & PTE_ADDR_MASK) << 4) + page_offset;
    return error_code;
}

/* Perform address translation */
bool sparc_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;
    hwaddr paddr;
    target_ulong vaddr;
    target_ulong page_size;
    int error_code = 0, prot, access_index;
    MemTxAttrs attrs = { 0 };

    /*
     * TODO: If we ever need tlb_vaddr_to_host for this target,
     * then we must figure out how to manipulate FSR and FAR
     * when both MMU_NF and probe are set.  In the meantime,
     * do not support this use case.
     */
    assert(!probe);

    address &= TARGET_PAGE_MASK;
    error_code = get_physical_address(env, &paddr, &prot, &access_index, &attrs,
                                      address, access_type,
                                      mmu_idx, &page_size);
    vaddr = address;
    if (likely(error_code == 0)) {
        qemu_log_mask(CPU_LOG_MMU,
                      "Translate at %" VADDR_PRIx " -> "
                      TARGET_FMT_plx ", vaddr " TARGET_FMT_lx "\n",
                      address, paddr, vaddr);
        tlb_set_page(cs, vaddr, paddr, prot, mmu_idx, page_size);
        return true;
    }

    if (env->mmuregs[3]) { /* Fault status register */
        env->mmuregs[3] = 1; /* overflow (not read before another fault) */
    }
    env->mmuregs[3] |= (access_index << 5) | error_code | 2;
    env->mmuregs[4] = address; /* Fault address register */

    if ((env->mmuregs[0] & MMU_NF) || env->psret == 0)  {
        /* No fault mode: if a mapping is available, just override
           permissions. If no mapping is available, redirect accesses to
           neverland. Fake/overridden mappings will be flushed when
           switching to normal mode. */
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        tlb_set_page(cs, vaddr, paddr, prot, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    } else {
        if (access_type == MMU_INST_FETCH) {
            cs->exception_index = TT_TFAULT;
        } else {
            cs->exception_index = TT_DFAULT;
        }
        cpu_loop_exit_restore(cs, retaddr);
    }
}

target_ulong mmu_probe(CPUSPARCState *env, target_ulong address, int mmulev)
{
    CPUState *cs = env_cpu(env);
    hwaddr pde_ptr;
    uint32_t pde;
    MemTxResult result;

    /*
     * TODO: MMU probe operations are supposed to set the fault
     * status registers, but we don't do this.
     */

    /* Context base + context number */
    pde_ptr = (hwaddr)(env->mmuregs[1] << 4) +
        (env->mmuregs[2] << 2);
    pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr, MEMTXATTRS_UNSPECIFIED, &result);
    if (result != MEMTX_OK) {
        return 0;
    }

    switch (pde & PTE_ENTRYTYPE_MASK) {
    default:
    case 0: /* Invalid */
    case 2: /* PTE, maybe should not happen? */
    case 3: /* Reserved */
        return 0;
    case 1: /* L1 PDE */
        if (mmulev == 3) {
            return pde;
        }
        pde_ptr = ((address >> 22) & ~3) + ((pde & ~3) << 4);
        pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr,
                                MEMTXATTRS_UNSPECIFIED, &result);
        if (result != MEMTX_OK) {
            return 0;
        }

        switch (pde & PTE_ENTRYTYPE_MASK) {
        default:
        case 0: /* Invalid */
        case 3: /* Reserved */
            return 0;
        case 2: /* L1 PTE */
            return pde;
        case 1: /* L2 PDE */
            if (mmulev == 2) {
                return pde;
            }
            pde_ptr = ((address & 0xfc0000) >> 16) + ((pde & ~3) << 4);
            pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr,
                                    MEMTXATTRS_UNSPECIFIED, &result);
            if (result != MEMTX_OK) {
                return 0;
            }

            switch (pde & PTE_ENTRYTYPE_MASK) {
            default:
            case 0: /* Invalid */
            case 3: /* Reserved */
                return 0;
            case 2: /* L2 PTE */
                return pde;
            case 1: /* L3 PDE */
                if (mmulev == 1) {
                    return pde;
                }
                pde_ptr = ((address & 0x3f000) >> 10) + ((pde & ~3) << 4);
                pde = glue(address_space_ldl, UNICORN_ARCH_POSTFIX)(cs->as->uc, cs->as, pde_ptr,
                                        MEMTXATTRS_UNSPECIFIED, &result);
                if (result != MEMTX_OK) {
                    return 0;
                }

                switch (pde & PTE_ENTRYTYPE_MASK) {
                default:
                case 0: /* Invalid */
                case 1: /* PDE, should not happen */
                case 3: /* Reserved */
                    return 0;
                case 2: /* L3 PTE */
                    return pde;
                }
            }
        }
    }
    return 0;
}

/* Gdb expects all registers windows to be flushed in ram. This function handles
 * reads (and only reads) in stack frames as if windows were flushed. We assume
 * that the sparc ABI is followed.
 */
int sparc_cpu_memory_rw_debug(CPUState *cs, vaddr address,
                              uint8_t *buf, int len, bool is_write)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;
    target_ulong addr = address;
    int i;
    int len1;
    int cwp = env->cwp;

    if (!is_write) {
        for (i = 0; i < env->nwindows; i++) {
            int off;
            target_ulong fp = env->regbase[cwp * 16 + 22];

            /* Assume fp == 0 means end of frame.  */
            if (fp == 0) {
                break;
            }

            cwp = cpu_cwp_inc(env, cwp + 1);

            /* Invalid window ? */
            if (env->wim & (1 << cwp)) {
                break;
            }

            /* According to the ABI, the stack is growing downward.  */
            if (addr + len < fp) {
                break;
            }

            /* Not in this frame.  */
            if (addr > fp + 64) {
                continue;
            }

            /* Handle access before this window.  */
            if (addr < fp) {
                len1 = fp - addr;
                if (cpu_memory_rw_debug(cs, addr, buf, len1, is_write) != 0) {
                    return -1;
                }
                addr += len1;
                len -= len1;
                buf += len1;
            }

            /* Access byte per byte to registers. Not very efficient but speed
             * is not critical.
             */
            off = addr - fp;
            len1 = 64 - off;

            if (len1 > len) {
                len1 = len;
            }

            for (; len1; len1--) {
                int reg = cwp * 16 + 8 + (off >> 2);
                union {
                    uint32_t v;
                    uint8_t c[4];
                } u;
                u.v = cpu_to_be32(env->regbase[reg]);
                *buf++ = u.c[off & 3];
                addr++;
                len--;
                off++;
            }

            if (len == 0) {
                return 0;
            }
        }
    }
    return cpu_memory_rw_debug(cs, addr, buf, len, is_write);
}

#else /* !TARGET_SPARC64 */

/* 41 bit physical address space */
static inline hwaddr ultrasparc_truncate_physical(uint64_t x)
{
    return x & 0x1ffffffffffULL;
}

/*
 * UltraSparc IIi I/DMMUs
 */

/* Returns true if TTE tag is valid and matches virtual address value
   in context requires virtual address mask value calculated from TTE
   entry size */
static inline int ultrasparc_tag_match(SparcTLBEntry *tlb,
                                       uint64_t address, uint64_t context,
                                       hwaddr *physical)
{
#ifdef _MSC_VER
    uint64_t mask = 0 - (8192ULL << 3 * TTE_PGSIZE(tlb->tte));
#else
    uint64_t mask = -(8192ULL << 3 * TTE_PGSIZE(tlb->tte));
#endif

    /* valid, context match, virtual address match? */
    if (TTE_IS_VALID(tlb->tte) &&
        (TTE_IS_GLOBAL(tlb->tte) || tlb_compare_context(tlb, context))
        && compare_masked(address, tlb->tag, mask)) {
        /* decode physical address */
        *physical = ((tlb->tte & mask) | (address & ~mask)) & 0x1ffffffe000ULL;
        return 1;
    }

    return 0;
}

static int get_physical_address_data(CPUSPARCState *env, hwaddr *physical,
                                     int *prot, MemTxAttrs *attrs,
                                     target_ulong address, int rw, int mmu_idx)
{
    CPUState *cs = env_cpu(env);
    unsigned int i;
    uint64_t context;
    uint64_t sfsr = 0;
    bool is_user = false;

    switch (mmu_idx) {
    case MMU_PHYS_IDX:
        g_assert_not_reached();
    case MMU_USER_IDX:
        is_user = true;
        /* fallthru */
    case MMU_KERNEL_IDX:
        context = env->dmmu.mmu_primary_context & 0x1fff;
        sfsr |= SFSR_CT_PRIMARY;
        break;
    case MMU_USER_SECONDARY_IDX:
        is_user = true;
        /* fallthru */
    case MMU_KERNEL_SECONDARY_IDX:
        context = env->dmmu.mmu_secondary_context & 0x1fff;
        sfsr |= SFSR_CT_SECONDARY;
        break;
    case MMU_NUCLEUS_IDX:
        sfsr |= SFSR_CT_NUCLEUS;
        /* FALLTHRU */
    default:
        context = 0;
        break;
    }

    if (rw == 1) {
        sfsr |= SFSR_WRITE_BIT;
    } else if (rw == 4) {
        sfsr |= SFSR_NF_BIT;
    }

    for (i = 0; i < 64; i++) {
        /* ctx match, vaddr match, valid? */
        if (ultrasparc_tag_match(&env->dtlb[i], address, context, physical)) {
            int do_fault = 0;

            if (TTE_IS_IE(env->dtlb[i].tte)) {
                attrs->byte_swap = true;
            }

            /* access ok? */
            /* multiple bits in SFSR.FT may be set on TT_DFAULT */
            if (TTE_IS_PRIV(env->dtlb[i].tte) && is_user) {
                do_fault = 1;
                sfsr |= SFSR_FT_PRIV_BIT; /* privilege violation */
            }
            if (rw == 4) {
                if (TTE_IS_SIDEEFFECT(env->dtlb[i].tte)) {
                    do_fault = 1;
                    sfsr |= SFSR_FT_NF_E_BIT;
                }
            } else {
                if (TTE_IS_NFO(env->dtlb[i].tte)) {
                    do_fault = 1;
                    sfsr |= SFSR_FT_NFO_BIT;
                }
            }

            if (do_fault) {
                /* faults above are reported with TT_DFAULT. */
                cs->exception_index = TT_DFAULT;
            } else if (!TTE_IS_W_OK(env->dtlb[i].tte) && (rw == 1)) {
                do_fault = 1;
                cs->exception_index = TT_DPROT;
            }

            if (!do_fault) {
                *prot = PAGE_READ;
                if (TTE_IS_W_OK(env->dtlb[i].tte)) {
                    *prot |= PAGE_WRITE;
                }

                TTE_SET_USED(env->dtlb[i].tte);

                return 0;
            }

            if (env->dmmu.sfsr & SFSR_VALID_BIT) { /* Fault status register */
                sfsr |= SFSR_OW_BIT; /* overflow (not read before
                                        another fault) */
            }

            if (env->pstate & PS_PRIV) {
                sfsr |= SFSR_PR_BIT;
            }

            /* FIXME: ASI field in SFSR must be set */
            env->dmmu.sfsr = sfsr | SFSR_VALID_BIT;

            env->dmmu.sfar = address; /* Fault address register */

            env->dmmu.tag_access = (address & ~0x1fffULL) | context;

            return 1;
        }
    }

    /*
     * On MMU misses:
     * - UltraSPARC IIi: SFSR and SFAR unmodified
     * - JPS1: SFAR updated and some fields of SFSR updated
     */
    env->dmmu.tag_access = (address & ~0x1fffULL) | context;
    cs->exception_index = TT_DMISS;
    return 1;
}

static int get_physical_address_code(CPUSPARCState *env, hwaddr *physical,
                                     int *prot, MemTxAttrs *attrs,
                                     target_ulong address, int mmu_idx)
{
    CPUState *cs = env_cpu(env);
    unsigned int i;
    uint64_t context;
    bool is_user = false;

    switch (mmu_idx) {
    case MMU_PHYS_IDX:
    case MMU_USER_SECONDARY_IDX:
    case MMU_KERNEL_SECONDARY_IDX:
        g_assert_not_reached();
    case MMU_USER_IDX:
        is_user = true;
        /* fallthru */
    case MMU_KERNEL_IDX:
        context = env->dmmu.mmu_primary_context & 0x1fff;
        break;
    default:
        context = 0;
        break;
    }

    if (env->tl == 0) {
        /* PRIMARY context */
        context = env->dmmu.mmu_primary_context & 0x1fff;
    } else {
        /* NUCLEUS context */
        context = 0;
    }

    for (i = 0; i < 64; i++) {
        /* ctx match, vaddr match, valid? */
        if (ultrasparc_tag_match(&env->itlb[i],
                                 address, context, physical)) {
            /* access ok? */
            if (TTE_IS_PRIV(env->itlb[i].tte) && is_user) {
                /* Fault status register */
                if (env->immu.sfsr & SFSR_VALID_BIT) {
                    env->immu.sfsr = SFSR_OW_BIT; /* overflow (not read before
                                                     another fault) */
                } else {
                    env->immu.sfsr = 0;
                }
                if (env->pstate & PS_PRIV) {
                    env->immu.sfsr |= SFSR_PR_BIT;
                }
                if (env->tl > 0) {
                    env->immu.sfsr |= SFSR_CT_NUCLEUS;
                }

                /* FIXME: ASI field in SFSR must be set */
                env->immu.sfsr |= SFSR_FT_PRIV_BIT | SFSR_VALID_BIT;
                cs->exception_index = TT_TFAULT;

                env->immu.tag_access = (address & ~0x1fffULL) | context;

                return 1;
            }
            *prot = PAGE_EXEC;
            TTE_SET_USED(env->itlb[i].tte);
            return 0;
        }
    }

    /* Context is stored in DMMU (dmmuregs[1]) also for IMMU */
    env->immu.tag_access = (address & ~0x1fffULL) | context;
    cs->exception_index = TT_TMISS;
    return 1;
}

static int get_physical_address(CPUSPARCState *env, hwaddr *physical,
                                int *prot, int *access_index, MemTxAttrs *attrs,
                                target_ulong address, int rw, int mmu_idx,
                                target_ulong *page_size)
{
    /* ??? We treat everything as a small page, then explicitly flush
       everything when an entry is evicted.  */
    *page_size = TARGET_PAGE_SIZE;

#if 0
    /* safety net to catch wrong softmmu index use from dynamic code */
    if (env->tl > 0 && mmu_idx != MMU_NUCLEUS_IDX) {
        if (rw == 2) {
            trace_mmu_helper_get_phys_addr_code(env->tl, mmu_idx,
                                                env->dmmu.mmu_primary_context,
                                                env->dmmu.mmu_secondary_context,
                                                address);
        } else {
            trace_mmu_helper_get_phys_addr_data(env->tl, mmu_idx,
                                                env->dmmu.mmu_primary_context,
                                                env->dmmu.mmu_secondary_context,
                                                address);
        }
    }
#endif

    if (mmu_idx == MMU_PHYS_IDX) {
        *physical = ultrasparc_truncate_physical(address);
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return 0;
    }

    if (rw == 2) {
        return get_physical_address_code(env, physical, prot, attrs, address,
                                         mmu_idx);
    } else {
        return get_physical_address_data(env, physical, prot, attrs, address,
                                         rw, mmu_idx);
    }
}

/* Perform address translation */
bool sparc_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;
    target_ulong vaddr;
    hwaddr paddr;
    target_ulong page_size;
    MemTxAttrs attrs = { 0 };
    int error_code = 0, prot, access_index;

    address &= TARGET_PAGE_MASK;
    error_code = get_physical_address(env, &paddr, &prot, &access_index, &attrs,
                                      address, access_type,
                                      mmu_idx, &page_size);
    if (likely(error_code == 0)) {
        vaddr = address;

        tlb_set_page_with_attrs(cs, vaddr, paddr, attrs, prot, mmu_idx,
                                page_size);
        return true;
    }
    if (probe) {
        return false;
    }
    cpu_loop_exit_restore(cs, retaddr);
}

#endif /* TARGET_SPARC64 */

static int cpu_sparc_get_phys_page(CPUSPARCState *env, hwaddr *phys,
                                   target_ulong addr, int rw, int mmu_idx)
{
    target_ulong page_size;
    int prot, access_index;
    MemTxAttrs attrs = { 0 };

    return get_physical_address(env, phys, &prot, &access_index, &attrs, addr,
                                rw, mmu_idx, &page_size);
}

#if defined(TARGET_SPARC64)
hwaddr cpu_get_phys_page_nofault(CPUSPARCState *env, target_ulong addr,
                                           int mmu_idx)
{
    hwaddr phys_addr;

    if (cpu_sparc_get_phys_page(env, &phys_addr, addr, 4, mmu_idx) != 0) {
        return -1;
    }
    return phys_addr;
}
#endif

hwaddr sparc_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;
    hwaddr phys_addr;
    int mmu_idx = cpu_mmu_index(env, false);

    if (cpu_sparc_get_phys_page(env, &phys_addr, addr, 2, mmu_idx) != 0) {
        if (cpu_sparc_get_phys_page(env, &phys_addr, addr, 0, mmu_idx) != 0) {
            return -1;
        }
    }
    return phys_addr;
}
