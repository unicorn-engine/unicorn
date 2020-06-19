/*
 *  i386 helpers (without register variable usage)
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

#include "cpu.h"
#ifndef CONFIG_USER_ONLY
#include "sysemu/sysemu.h"
#endif

//#define DEBUG_MMU

static void cpu_x86_version(CPUX86State *env, int *family, int *model)
{
    int cpuver = env->cpuid_version;

    if (family == NULL || model == NULL) {
        return;
    }

    *family = (cpuver >> 8) & 0x0f;
    *model = ((cpuver >> 12) & 0xf0) + ((cpuver >> 4) & 0x0f);
}

/* Broadcast MCA signal for processor version 06H_EH and above */
int cpu_x86_support_mca_broadcast(CPUX86State *env)
{
    int family = 0;
    int model = 0;

    cpu_x86_version(env, &family, &model);
    if ((family == 6 && model >= 14) || family > 6) {
        return 1;
    }

    return 0;
}

/***********************************************************/
/* x86 mmu */
/* XXX: add PGE support */

void x86_cpu_set_a20(X86CPU *cpu, int a20_state)
{
    CPUX86State *env = &cpu->env;

    a20_state = (a20_state != 0);
    if (a20_state != ((env->a20_mask >> 20) & 1)) {
        CPUState *cs = CPU(cpu);

#if defined(DEBUG_MMU)
        printf("A20 update: a20=%d\n", a20_state);
#endif
        /* if the cpu is currently executing code, we must unlink it and
           all the potentially executing TB */
        cpu_interrupt(cs, CPU_INTERRUPT_EXITTB);

        /* when a20 is changed, all the MMU mappings are invalid, so
           we must flush everything */
        tlb_flush(cs, 1);
        env->a20_mask = ~(1 << 20) | (a20_state << 20);
    }
}

void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0)
{
    X86CPU *cpu = x86_env_get_cpu(env);
    int pe_state;

#if defined(DEBUG_MMU)
    printf("CR0 update: CR0=0x%08x\n", new_cr0);
#endif
    if ((new_cr0 & (CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK)) !=
        (env->cr[0] & (CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK))) {
        tlb_flush(CPU(cpu), 1);
    }

#ifdef TARGET_X86_64
    if (!(env->cr[0] & CR0_PG_MASK) && (new_cr0 & CR0_PG_MASK) &&
        (env->efer & MSR_EFER_LME)) {
        /* enter in long mode */
        /* XXX: generate an exception */
        if (!(env->cr[4] & CR4_PAE_MASK))
            return;
        env->efer |= MSR_EFER_LMA;
        env->hflags |= HF_LMA_MASK;
    } else if ((env->cr[0] & CR0_PG_MASK) && !(new_cr0 & CR0_PG_MASK) &&
               (env->efer & MSR_EFER_LMA)) {
        /* exit long mode */
        env->efer &= ~MSR_EFER_LMA;
        env->hflags &= ~(HF_LMA_MASK | HF_CS64_MASK);
        env->eip &= 0xffffffff;
    }
#endif
    env->cr[0] = new_cr0 | CR0_ET_MASK;

    /* update PE flag in hidden flags */
    pe_state = (env->cr[0] & CR0_PE_MASK);
    env->hflags = (env->hflags & ~HF_PE_MASK) | (pe_state << HF_PE_SHIFT);
    /* ensure that ADDSEG is always set in real mode */
    env->hflags |= ((pe_state ^ 1) << HF_ADDSEG_SHIFT);
    /* update FPU flags */
    env->hflags = (env->hflags & ~(HF_MP_MASK | HF_EM_MASK | HF_TS_MASK)) |
        ((new_cr0 << (HF_MP_SHIFT - 1)) & (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK));
}

/* XXX: in legacy PAE mode, generate a GPF if reserved bits are set in
   the PDPT */
void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3)
{
    X86CPU *cpu = x86_env_get_cpu(env);

    env->cr[3] = new_cr3;
    if (env->cr[0] & CR0_PG_MASK) {
#if defined(DEBUG_MMU)
        printf("CR3 update: CR3=" TARGET_FMT_lx "\n", new_cr3);
#endif
        tlb_flush(CPU(cpu), 0);
    }
}

void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4)
{
    X86CPU *cpu = x86_env_get_cpu(env);

#if defined(DEBUG_MMU)
    printf("CR4 update: CR4=%08x\n", (uint32_t)env->cr[4]);
#endif
    if ((new_cr4 ^ env->cr[4]) &
        (CR4_PGE_MASK | CR4_PAE_MASK | CR4_PSE_MASK |
         CR4_SMEP_MASK | CR4_SMAP_MASK)) {
        tlb_flush(CPU(cpu), 1);
    }
    /* SSE handling */
    if (!(env->features[FEAT_1_EDX] & CPUID_SSE)) {
        new_cr4 &= ~CR4_OSFXSR_MASK;
    }
    env->hflags &= ~HF_OSFXSR_MASK;
    if (new_cr4 & CR4_OSFXSR_MASK) {
        env->hflags |= HF_OSFXSR_MASK;
    }

    if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SMAP)) {
        new_cr4 &= ~CR4_SMAP_MASK;
    }
    env->hflags &= ~HF_SMAP_MASK;
    if (new_cr4 & CR4_SMAP_MASK) {
        env->hflags |= HF_SMAP_MASK;
    }

    env->cr[4] = new_cr4;
}

#if defined(CONFIG_USER_ONLY)

int x86_cpu_handle_mmu_fault(CPUState *cs, vaddr addr,
                             int is_write, int mmu_idx)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    /* user mode only emulation */
    is_write &= 1;
    env->cr[2] = addr;
    env->error_code = (is_write << PG_ERROR_W_BIT);
    env->error_code |= PG_ERROR_U_MASK;
    cs->exception_index = EXCP0E_PAGE;
    return 1;
}

#else

/* return value:
 * -1 = cannot handle fault
 * 0  = nothing more to do
 * 1  = generate PF fault
 */
int x86_cpu_handle_mmu_fault(CPUState *cs, vaddr addr,
                             int is_write1, int mmu_idx)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;
    uint64_t ptep, pte;
    target_ulong pde_addr, pte_addr;
    int error_code = 0;
    int is_dirty, prot, page_size, is_write, is_user;
    hwaddr paddr;
    uint64_t rsvd_mask = PG_HI_RSVD_MASK;
    //uint32_t page_offset;
    target_ulong vaddr;

    is_user = mmu_idx == MMU_USER_IDX;
#if defined(DEBUG_MMU)
    printf("MMU fault: addr=%" VADDR_PRIx " w=%d u=%d eip=" TARGET_FMT_lx "\n",
           addr, is_write1, is_user, env->eip);
#endif
    is_write = is_write1 & 1;

    if (!(env->cr[0] & CR0_PG_MASK)) {
        pte = addr;
#ifdef TARGET_X86_64
        if (!(env->hflags & HF_LMA_MASK)) {
            /* Without long mode we can only address 32bits in real mode */
            pte = (uint32_t)pte;
        }
#endif
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        page_size = 4096;
        goto do_mapping;
    }

    if (!(env->efer & MSR_EFER_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (env->cr[4] & CR4_PAE_MASK) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = (int64_t)addr >> 47;
            if (sext != 0 && sext != -1) {
                env->error_code = 0;
                cs->exception_index = EXCP0D_GPF;
                return 1;
            }

            pml4e_addr = ((env->cr[3] & ~0xfff) + (((addr >> 39) & 0x1ff) << 3)) &
                env->a20_mask;
            pml4e = ldq_phys(cs->as, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pml4e & (rsvd_mask | PG_PSE_MASK)) {
                goto do_fault_rsvd;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                stl_phys_notdirty(cs->as, pml4e_addr, pml4e);
            }
            ptep = pml4e ^ PG_NX_MASK;
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3)) &
                env->a20_mask;
            pdpe = ldq_phys(cs->as, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pdpe & rsvd_mask) {
                goto do_fault_rsvd;
            }
            ptep &= pdpe ^ PG_NX_MASK;
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                stl_phys_notdirty(cs->as, pdpe_addr, pdpe);
            }
            if (pdpe & PG_PSE_MASK) {
                /* 1 GB page */
                page_size = 1024 * 1024 * 1024;
                pte_addr = pdpe_addr;
                pte = pdpe;
                goto do_check_protect;
            }
        } else
#endif
        {
            /* XXX: load them when cr3 is loaded ? */
            pdpe_addr = ((env->cr[3] & ~0x1f) + ((addr >> 27) & 0x18)) &
                env->a20_mask;
            pdpe = ldq_phys(cs->as, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            rsvd_mask |= PG_HI_USER_MASK;
            if (pdpe & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3)) &
            env->a20_mask;
        pde = ldq_phys(cs->as, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pde & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep &= pde ^ PG_NX_MASK;
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            pte_addr = pde_addr;
            pte = pde;
            goto do_check_protect;
        }
        /* 4 KB page */
        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            stl_phys_notdirty(cs->as, pde_addr, pde);
        }
        pte_addr = ((pde & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3)) &
            env->a20_mask;
        pte = ldq_phys(cs->as, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */
        ptep &= pte ^ PG_NX_MASK;
        page_size = 4096;
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((env->cr[3] & ~0xfff) + ((addr >> 20) & 0xffc)) &
            env->a20_mask;
        pde = ldl_phys(cs->as, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pde | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
            page_size = 4096 * 1024;
            pte_addr = pde_addr;

            /* Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = pde | ((pde & 0x1fe000) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }

        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            stl_phys_notdirty(cs->as, pde_addr, pde);
        }

        /* page directory entry */
        pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) &
            env->a20_mask;
        pte = ldl_phys(cs->as, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep &= pte | PG_NX_MASK;
        page_size = 4096;
        rsvd_mask = 0;
    }

do_check_protect:
    rsvd_mask |= (page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;
    if ((ptep & PG_NX_MASK) && is_write1 == 2) {
        goto do_fault_protect;
    }
    switch (mmu_idx) {
    case MMU_USER_IDX:
        if (!(ptep & PG_USER_MASK)) {
            goto do_fault_protect;
        }
        if (is_write && !(ptep & PG_RW_MASK)) {
            goto do_fault_protect;
        }
        break;

    case MMU_KSMAP_IDX:
        if (is_write1 != 2 && (ptep & PG_USER_MASK)) {
            goto do_fault_protect;
        }
        /* fall through */
    case MMU_KNOSMAP_IDX:
        if (is_write1 == 2 && (env->cr[4] & CR4_SMEP_MASK) &&
            (ptep & PG_USER_MASK)) {
            goto do_fault_protect;
        }
        if ((env->cr[0] & CR0_WP_MASK) &&
            is_write && !(ptep & PG_RW_MASK)) {
            goto do_fault_protect;
        }
        break;

    default: /* cannot happen */
        break;
    }
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        stl_phys_notdirty(cs->as, pte_addr, pte);
    }

    /* the page can be put in the TLB */
    prot = PAGE_READ;
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((env->cr[4] & CR4_SMEP_MASK) && (ptep & PG_USER_MASK)))) {
        prot |= PAGE_EXEC;
    }
    if (pte & PG_DIRTY_MASK) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        if (is_user) {
            if (ptep & PG_RW_MASK)
                prot |= PAGE_WRITE;
        } else {
            if (!(env->cr[0] & CR0_WP_MASK) ||
                (ptep & PG_RW_MASK))
                prot |= PAGE_WRITE;
        }
    }
 do_mapping:

#if 0
    pte = pte & env->a20_mask;

    /* align to page_size */
    pte &= PG_ADDRESS_MASK & ~(page_size - 1);

    /* Even if 4MB pages, we map only one 4KB page in the cache to
       avoid filling it too fast */
    vaddr = addr & TARGET_PAGE_MASK;
    page_offset = vaddr & (page_size - 1);
    paddr = pte + page_offset;
#endif

    // Unicorn: indentity map guest virtual address to host virtual address
    vaddr = addr & TARGET_PAGE_MASK;
    paddr = vaddr;
    //printf(">>> map address %"PRIx64" to %"PRIx64"\n", vaddr, paddr);

    tlb_set_page(cs, vaddr, paddr, prot, mmu_idx, page_size);
    return 0;
 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((env->efer & MSR_EFER_NXE) &&
          (env->cr[4] & CR4_PAE_MASK)) ||
         (env->cr[4] & CR4_SMEP_MASK)))
        error_code |= PG_ERROR_I_D_MASK;
    if (env->intercept_exceptions & (1 << EXCP0E_PAGE)) {
        /* cr2 is not modified in case of exceptions */
        stq_phys(cs->as,
                 env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 addr);
    } else {
        env->cr[2] = addr;
    }
    env->error_code = error_code;
    cs->exception_index = EXCP0E_PAGE;
    return 1;
}

hwaddr x86_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;
    target_ulong pde_addr, pte_addr;
    uint64_t pte;
    uint32_t page_offset;
    int page_size;

    if (!(env->cr[0] & CR0_PG_MASK)) {
        pte = addr & env->a20_mask;
        page_size = 4096;
    } else if (env->cr[4] & CR4_PAE_MASK) {
        target_ulong pdpe_addr;
        uint64_t pde, pdpe;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = (int64_t)addr >> 47;
            if (sext != 0 && sext != -1) {
                return -1;
            }
            pml4e_addr = ((env->cr[3] & ~0xfff) + (((addr >> 39) & 0x1ff) << 3)) &
                env->a20_mask;
            pml4e = ldq_phys(cs->as, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                return -1;
            }
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) +
                         (((addr >> 30) & 0x1ff) << 3)) & env->a20_mask;
            pdpe = ldq_phys(cs->as, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                return -1;
            }
            if (pdpe & PG_PSE_MASK) {
                page_size = 1024 * 1024 * 1024;
                pte = pdpe;
                goto out;
            }

        } else
#endif
        {
            pdpe_addr = ((env->cr[3] & ~0x1f) + ((addr >> 27) & 0x18)) &
                env->a20_mask;
            pdpe = ldq_phys(cs->as, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK))
                return -1;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) +
                    (((addr >> 21) & 0x1ff) << 3)) & env->a20_mask;
        pde = ldq_phys(cs->as, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            return -1;
        }
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            pte = pde;
        } else {
            /* 4 KB page */
            pte_addr = ((pde & PG_ADDRESS_MASK) +
                        (((addr >> 12) & 0x1ff) << 3)) & env->a20_mask;
            page_size = 4096;
            pte = ldq_phys(cs->as, pte_addr);
        }
        if (!(pte & PG_PRESENT_MASK)) {
            return -1;
        }
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((env->cr[3] & ~0xfff) + ((addr >> 20) & 0xffc)) & env->a20_mask;
        pde = ldl_phys(cs->as, pde_addr);
        if (!(pde & PG_PRESENT_MASK))
            return -1;
        if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
            pte = pde | ((pde & 0x1fe000) << (32 - 13));
            page_size = 4096 * 1024;
        } else {
            /* page directory entry */
            pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) & env->a20_mask;
            pte = ldl_phys(cs->as, pte_addr);
            if (!(pte & PG_PRESENT_MASK)) {
                return -1;
            }
            page_size = 4096;
        }
        pte = pte & env->a20_mask;
    }

#ifdef TARGET_X86_64
out:
#endif
    pte &= PG_ADDRESS_MASK & ~(page_size - 1);
    page_offset = (addr & TARGET_PAGE_MASK) & (page_size - 1);
    return pte | page_offset;
}

void hw_breakpoint_insert(CPUX86State *env, int index)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int type = 0, err = 0;

    switch (hw_breakpoint_type(env->dr[7], index)) {
    case DR7_TYPE_BP_INST:
        if (hw_breakpoint_enabled(env->dr[7], index)) {
            err = cpu_breakpoint_insert(cs, env->dr[index], BP_CPU,
                                        &env->cpu_breakpoint[index]);
        }
        break;
    case DR7_TYPE_DATA_WR:
        type = BP_CPU | BP_MEM_WRITE;
        break;
    case DR7_TYPE_IO_RW:
        /* No support for I/O watchpoints yet */
        break;
    case DR7_TYPE_DATA_RW:
        type = BP_CPU | BP_MEM_ACCESS;
        break;
    }

    if (type != 0) {
        err = cpu_watchpoint_insert(cs, env->dr[index],
                                    hw_breakpoint_len(env->dr[7], index),
                                    type, &env->cpu_watchpoint[index]);
    }

    if (err) {
        env->cpu_breakpoint[index] = NULL;
    }
}

void hw_breakpoint_remove(CPUX86State *env, int index)
{
    CPUState *cs;

    if (!env->cpu_breakpoint[index]) {
        return;
    }
    cs = CPU(x86_env_get_cpu(env));
    switch (hw_breakpoint_type(env->dr[7], index)) {
    case DR7_TYPE_BP_INST:
        if (hw_breakpoint_enabled(env->dr[7], index)) {
            cpu_breakpoint_remove_by_ref(cs, env->cpu_breakpoint[index]);
        }
        break;
    case DR7_TYPE_DATA_WR:
    case DR7_TYPE_DATA_RW:
        cpu_watchpoint_remove_by_ref(cs, env->cpu_watchpoint[index]);
        break;
    case DR7_TYPE_IO_RW:
        /* No support for I/O watchpoints yet */
        break;
    }
}

bool check_hw_breakpoints(CPUX86State *env, bool force_dr6_update)
{
    target_ulong dr6;
    int reg;
    bool hit_enabled = false;

    dr6 = env->dr[6] & ~0xf;
    for (reg = 0; reg < DR7_MAX_BP; reg++) {
        bool bp_match = false;
        bool wp_match = false;

        switch (hw_breakpoint_type(env->dr[7], reg)) {
        case DR7_TYPE_BP_INST:
            if (env->dr[reg] == env->eip) {
                bp_match = true;
            }
            break;
        case DR7_TYPE_DATA_WR:
        case DR7_TYPE_DATA_RW:
            if (env->cpu_watchpoint[reg] &&
                env->cpu_watchpoint[reg]->flags & BP_WATCHPOINT_HIT) {
                wp_match = true;
            }
            break;
        case DR7_TYPE_IO_RW:
            break;
        }
        if (bp_match || wp_match) {
            dr6 |= 1ULL << reg;
            if (hw_breakpoint_enabled(env->dr[7], reg)) {
                hit_enabled = true;
            }
        }
    }

    if (hit_enabled || force_dr6_update) {
        env->dr[6] = dr6;
    }

    return hit_enabled;
}

void breakpoint_handler(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;
    CPUBreakpoint *bp;

    if (cs->watchpoint_hit) {
        if (cs->watchpoint_hit->flags & BP_CPU) {
            cs->watchpoint_hit = NULL;
            if (check_hw_breakpoints(env, false)) {
                raise_exception(env, EXCP01_DB);
            } else {
                cpu_resume_from_signal(cs, NULL);
            }
        }
    } else {
        QTAILQ_FOREACH(bp, &cs->breakpoints, entry) {
            if (bp->pc == env->eip) {
                if (bp->flags & BP_CPU) {
                    check_hw_breakpoints(env, true);
                    raise_exception(env, EXCP01_DB);
                }
                break;
            }
        }
    }
}
#endif /* !CONFIG_USER_ONLY */

int cpu_x86_get_descr_debug(CPUX86State *env, unsigned int selector,
                            target_ulong *base, unsigned int *limit,
                            unsigned int *flags)
{
    X86CPU *cpu = x86_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    SegmentCache *dt;
    target_ulong ptr;
    uint32_t e1, e2;
    int index;

    if (selector & 0x4)
        dt = &env->ldt;
    else
        dt = &env->gdt;
    index = selector & ~7;
    ptr = dt->base + index;
    if ((uint32_t)(index + 7) > dt->limit
        || cpu_memory_rw_debug(cs, ptr, (uint8_t *)&e1, sizeof(e1), 0) != 0
        || cpu_memory_rw_debug(cs, ptr+4, (uint8_t *)&e2, sizeof(e2), 0) != 0)
        return 0;

    *base = ((e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000));
    *limit = (e1 & 0xffff) | (e2 & 0x000f0000);
    if (e2 & DESC_G_MASK)
        *limit = (*limit << 12) | 0xfff;
    *flags = e2;

    return 1;
}

#if !defined(CONFIG_USER_ONLY)
void do_cpu_init(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    CPUX86State *save = g_new(CPUX86State, 1);
    int sipi = cs->interrupt_request & CPU_INTERRUPT_SIPI;

    *save = *env;

    cpu_reset(cs);
    cs->interrupt_request = sipi;
    memcpy(&env->start_init_save, &save->start_init_save,
           offsetof(CPUX86State, end_init_save) -
           offsetof(CPUX86State, start_init_save));
    g_free(save);

#if 0
    /* do nothing */
    apic_init_reset(env->uc, cpu->apic_state);
#endif
}

void do_cpu_sipi(X86CPU *cpu)
{
#if 0
    /* do nothing */
    apic_sipi(cpu->apic_state);
#endif
}
#else
void do_cpu_init(X86CPU *cpu)
{
}
void do_cpu_sipi(X86CPU *cpu)
{
}
#endif

/* Frob eflags into and out of the CPU temporary format.  */

void x86_cpu_exec_enter(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->df = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
}

void x86_cpu_exec_exit(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

    env->eflags = cpu_compute_eflags(env);
}
