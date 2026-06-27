/*
 * ARM v8.5-MemTag register-generation operations
 *
 * Copyright (c) 2020 Linaro, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "exec/cpu-common.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/memory.h"
#include "exec/helper-proto.h"
#include "qemu/guest-random.h"
#include "uc_priv.h"

static int choose_nonexcluded_tag(int tag, int offset, uint16_t exclude)
{
    if (exclude == 0xffff) {
        return 0;
    }
    if (offset == 0) {
        while (exclude & (1 << tag)) {
            tag = (tag + 1) & 15;
        }
    } else {
        do {
            do {
                tag = (tag + 1) & 15;
            } while (exclude & (1 << tag));
        } while (--offset > 0);
    }
    return tag;
}

static int allocation_tag_from_addr(uint64_t ptr)
{
    return extract64(ptr, 56, 4);
}

static uint64_t address_with_allocation_tag(uint64_t ptr, int rtag)
{
    return deposit64(ptr, 56, 4, rtag);
}

uint64_t HELPER(irg)(CPUARMState *env, uint64_t rn, uint64_t rm)
{
    uint16_t exclude = extract32(rm | env->cp15.gcr_el1, 0, 16);
    int rrnd = extract32(env->cp15.gcr_el1, 16, 1);
    int start = extract32(env->cp15.rgsr_el1, 0, 4);
    int seed = extract32(env->cp15.rgsr_el1, 8, 16);
    int offset, i, rtag;

    if (unlikely(seed == 0) && rrnd) {
        do {
            uint16_t two;

            if (qemu_guest_getrandom(&two, sizeof(two)) < 0) {
                two = 1;
            }
            seed = two;
        } while (seed == 0);
    }

    for (i = offset = 0; i < 4; ++i) {
        int top = (extract32(seed, 5, 1) ^ extract32(seed, 3, 1) ^
                   extract32(seed, 2, 1) ^ extract32(seed, 0, 1));

        seed = (top << 15) | (seed >> 1);
        offset |= top << i;
    }
    rtag = choose_nonexcluded_tag(start, offset, exclude);
    env->cp15.rgsr_el1 = rtag | (seed << 8);

    return address_with_allocation_tag(rn, rtag);
}

uint64_t HELPER(addsubg)(CPUARMState *env, uint64_t ptr,
                         int32_t offset, uint32_t tag_offset)
{
    int start_tag = allocation_tag_from_addr(ptr);
    uint16_t exclude = extract32(env->cp15.gcr_el1, 0, 16);
    int rtag = choose_nonexcluded_tag(start_tag, tag_offset, exclude);

    return address_with_allocation_tag(ptr + offset, rtag);
}

static uint64_t allocation_tag_clean_addr(uint64_t ptr)
{
    return ptr & ~MAKE_64BIT_MASK(56, 8);
}

static hwaddr memory_region_ram_addr(MemoryRegion *mr, ram_addr_t offset)
{
    hwaddr addr = offset;

    while (mr && mr->container) {
        addr += mr->addr;
        mr = mr->container;
    }

    return addr;
}

static bool allocation_tag_cow(CPUARMState *env, RAMBlock *block,
                               ram_addr_t offset, uint64_t ptr, int size,
                               uintptr_t ra)
{
    struct uc_struct *uc = env->uc;
    MemoryRegion *mr = block->mr;
    hwaddr addr, page, end;
    bool cowed = false;

    if (!uc->snapshot_level || !mr || !mr->ram ||
        mr->priority >= uc->snapshot_level) {
        return false;
    }

    addr = memory_region_ram_addr(mr, offset);
    page = addr & TARGET_PAGE_MASK;
    end = (addr + size + ~TARGET_PAGE_MASK) & TARGET_PAGE_MASK;

    while (page < end) {
        if (!memory_cow(uc, mr, page, TARGET_PAGE_SIZE)) {
            uc->invalid_addr = ptr;
            uc->invalid_error = UC_ERR_NOMEM;
            cpu_loop_exit_restore(env_cpu(env), ra);
        }
        cowed = true;
        page += TARGET_PAGE_SIZE;
    }

    return cowed;
}

static bool allocation_tag_access_enabled(CPUARMState *env, uint64_t ptr,
                                          MMUAccessType access_type,
                                          int mmu_idx)
{
    uintptr_t index = tlb_index(env, mmu_idx, ptr);
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, ptr);
    target_ulong tlb_addr;

    switch (access_type) {
    case MMU_DATA_LOAD:
        tlb_addr = entry->addr_read;
        break;
    case MMU_DATA_STORE:
        tlb_addr = tlb_addr_write(entry);
        break;
    default:
        g_assert_not_reached();
    }

    if (!tlb_hit(env->uc, tlb_addr, ptr)) {
        return false;
    }
    return env_tlb(env)->d[mmu_idx].iotlb[index].attrs.target_tlb_bit1;
}

static void allocation_tag_raise_fault(CPUARMState *env, target_ulong addr,
                                       MMUAccessType access_type,
                                       bool mmu_fault, bool prot,
                                       uintptr_t ra)
{
    struct uc_struct *uc = env->uc;

    uc->invalid_addr = addr;
    if (access_type == MMU_DATA_STORE) {
        uc->invalid_error = mmu_fault ? UC_ERR_MMU_WRITE :
                            prot ? UC_ERR_WRITE_PROT :
                            UC_ERR_WRITE_UNMAPPED;
    } else {
        uc->invalid_error = mmu_fault ? UC_ERR_MMU_READ :
                            prot ? UC_ERR_READ_PROT :
                            UC_ERR_READ_UNMAPPED;
    }
    cpu_exit(uc->cpu);
    cpu_loop_exit_restore(env_cpu(env), ra);
}

static void *allocation_tag_probe_access(CPUARMState *env, target_ulong ptr,
                                         MMUAccessType access_type, int size,
                                         int mmu_idx, uintptr_t ra)
{
    struct uc_struct *uc = env->uc;
    void *host = NULL;
    bool first_page = true;

    while (size > 0) {
        target_ulong page_left = -(ptr | TARGET_PAGE_MASK);
        int probe_size = MIN(size, (int)page_left);
        target_ulong paddr;
        void *page_host;
        MemoryRegion *mr;

        page_host = probe_access(env, ptr, probe_size, access_type, mmu_idx,
                                 ra);
        if (first_page) {
            host = page_host;
            first_page = false;
        }

        if (!tlb_vaddr_to_paddr(env, ptr, access_type, mmu_idx, &paddr)) {
            allocation_tag_raise_fault(env, ptr, access_type, true, false,
                                       ra);
        }

        mr = uc->memory_mapping(uc, paddr);
        if (!mr) {
            allocation_tag_raise_fault(env, paddr, access_type, false, false,
                                       ra);
        }
        if (access_type == MMU_DATA_STORE) {
            if (!(mr->perms & UC_PROT_WRITE)) {
                allocation_tag_raise_fault(env, paddr, access_type, false,
                                           true, ra);
            }
        } else if (!(mr->perms & UC_PROT_READ)) {
            allocation_tag_raise_fault(env, paddr, access_type, false, true,
                                       ra);
        }

        ptr += probe_size;
        size -= probe_size;
    }

    return host;
}

void HELPER(dc_gva_probe)(CPUARMState *env, uint64_t ptr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env, false);

    allocation_tag_probe_access(env, ptr, MMU_DATA_STORE, 1, mmu_idx, ra);
}

void HELPER(mte_probe_data)(CPUARMState *env, uint64_t ptr, uint32_t desc)
{
    uintptr_t ra = GETPC();
    int mmu_idx = FIELD_EX32(desc, MTEDESC, MIDX);
    MMUAccessType access_type;
    uint32_t size;

    access_type = FIELD_EX32(desc, MTEDESC, WRITE) ? MMU_DATA_STORE :
                  MMU_DATA_LOAD;
    size = FIELD_EX32(desc, MTEDESC, SIZEM1) + 1;
    allocation_tag_probe_access(env, ptr, access_type, size, mmu_idx, ra);
}

static uint8_t *allocation_tag_mem(CPUARMState *env, int mmu_idx,
                                   uint64_t ptr, MMUAccessType access_type,
                                   int size, bool allocate, uintptr_t ra)
{
    uint64_t clean_ptr = allocation_tag_clean_addr(ptr);
    void *host;
    RAMBlock *block;
    ram_addr_t offset;

    host = allocation_tag_probe_access(env, clean_ptr, access_type, size,
                                       mmu_idx, ra);
    if (!host) {
        return NULL;
    }

    if (!allocation_tag_access_enabled(env, clean_ptr, access_type, mmu_idx)) {
        return NULL;
    }

    block = qemu_ram_block_from_host(env->uc, host, false, &offset);
    if (!block) {
        return NULL;
    }

    if (allocate && access_type == MMU_DATA_STORE &&
        allocation_tag_cow(env, block, offset, clean_ptr, size, ra)) {
        host = allocation_tag_probe_access(env, clean_ptr, access_type, size,
                                           mmu_idx, ra);
        if (!host) {
            return NULL;
        }
        block = qemu_ram_block_from_host(env->uc, host, false, &offset);
        if (!block) {
            return NULL;
        }
    }

    if (!block->mte_tags) {
        if (!allocate) {
            return NULL;
        }
        block->mte_tags_size = DIV_ROUND_UP(block->max_length,
                                            2 * TAG_GRANULE);
        block->mte_tags = g_malloc0(block->mte_tags_size);
    }

    return block->mte_tags + (offset >> (LOG2_TAG_GRANULE + 1));
}

static int load_tag1(uint64_t ptr, uint8_t *mem)
{
    int ofs = extract32(ptr, LOG2_TAG_GRANULE, 1) * 4;

    return extract32(*mem, ofs, 4);
}

uint64_t HELPER(ldg)(CPUARMState *env, uint64_t ptr, uint64_t xt)
{
    int mmu_idx = cpu_mmu_index(env, false);
    uint8_t *mem;
    int rtag = 0;

    mem = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_LOAD, 1, false,
                             GETPC());
    if (mem) {
        rtag = load_tag1(ptr, mem);
    }

    return address_with_allocation_tag(xt, rtag);
}

static void check_tag_aligned(CPUARMState *env, uint64_t ptr, uintptr_t ra)
{
    if (unlikely(!QEMU_IS_ALIGNED(ptr, TAG_GRANULE))) {
        arm_cpu_do_unaligned_access(env_cpu(env), ptr, MMU_DATA_STORE,
                                    cpu_mmu_index(env, false), ra);
        g_assert_not_reached();
    }
}

static void store_tag1(uint64_t ptr, uint8_t *mem, int tag)
{
    int ofs = extract32(ptr, LOG2_TAG_GRANULE, 1) * 4;

    *mem = deposit32(*mem, ofs, 4, tag);
}

void HELPER(stg)(CPUARMState *env, uint64_t ptr, uint64_t xt)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env, false);
    uint8_t *mem;

    check_tag_aligned(env, ptr, ra);
    mem = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_STORE, TAG_GRANULE,
                             true, ra);
    if (mem) {
        store_tag1(ptr, mem, allocation_tag_from_addr(xt));
    }
}

void HELPER(stg_stub)(CPUARMState *env, uint64_t ptr)
{
    uintptr_t ra = GETPC();
    uint64_t clean_ptr = allocation_tag_clean_addr(ptr);

    check_tag_aligned(env, ptr, ra);
    probe_write(env, clean_ptr, TAG_GRANULE, cpu_mmu_index(env, false), ra);
}

void HELPER(st2g)(CPUARMState *env, uint64_t ptr, uint64_t xt)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env, false);
    int tag = allocation_tag_from_addr(xt);
    uint8_t *mem1, *mem2;

    check_tag_aligned(env, ptr, ra);
    if (ptr & TAG_GRANULE) {
        mem1 = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_STORE,
                                  TAG_GRANULE, true, ra);
        mem2 = allocation_tag_mem(env, mmu_idx, ptr + TAG_GRANULE,
                                  MMU_DATA_STORE, TAG_GRANULE, true, ra);
        if (mem1) {
            store_tag1(TAG_GRANULE, mem1, tag);
        }
        if (mem2) {
            store_tag1(0, mem2, tag);
        }
    } else {
        mem1 = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_STORE,
                                  2 * TAG_GRANULE, true, ra);
        if (mem1) {
            *mem1 = tag | (tag << 4);
        }
    }
}

void HELPER(st2g_stub)(CPUARMState *env, uint64_t ptr)
{
    struct uc_struct *uc = env->uc;
    uintptr_t ra = GETPC();
    uint64_t clean_ptr = allocation_tag_clean_addr(ptr);
    int mmu_idx = cpu_mmu_index(env, false);
    int in_page;

    check_tag_aligned(env, ptr, ra);
    in_page = -(clean_ptr | TARGET_PAGE_MASK);
    if (likely(in_page >= 2 * TAG_GRANULE)) {
        probe_write(env, clean_ptr, 2 * TAG_GRANULE, mmu_idx, ra);
    } else {
        probe_write(env, clean_ptr, TAG_GRANULE, mmu_idx, ra);
        probe_write(env, clean_ptr + TAG_GRANULE, TAG_GRANULE, mmu_idx, ra);
    }
}

#define LDGM_STGM_SIZE (4 << GMID_EL1_BS)

uint64_t HELPER(ldgm)(CPUARMState *env, uint64_t ptr)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env, false);
    uint8_t *mem;

    ptr = QEMU_ALIGN_DOWN(ptr, LDGM_STGM_SIZE);
    mem = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_LOAD,
                             LDGM_STGM_SIZE, false, ra);
    if (!mem) {
        return 0;
    }

    QEMU_BUILD_BUG_ON(GMID_EL1_BS != 6);
    return ldq_le_p(mem);
}

void HELPER(stgm)(CPUARMState *env, uint64_t ptr, uint64_t val)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env, false);
    uint8_t *mem;

    ptr = QEMU_ALIGN_DOWN(ptr, LDGM_STGM_SIZE);
    mem = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_STORE,
                             LDGM_STGM_SIZE, true, ra);
    if (!mem) {
        return;
    }

    QEMU_BUILD_BUG_ON(GMID_EL1_BS != 6);
    stq_le_p(mem, val);
}

void HELPER(stzgm_tags)(CPUARMState *env, uint64_t ptr, uint64_t val)
{
    uintptr_t ra = GETPC();
    ARMCPU *cpu = env_archcpu(env);
    int log2_dcz_bytes = cpu->dcz_blocksize + 2;
    int log2_tag_bytes = log2_dcz_bytes - (LOG2_TAG_GRANULE + 1);
    intptr_t dcz_bytes = (intptr_t)1 << log2_dcz_bytes;
    intptr_t tag_bytes = (intptr_t)1 << log2_tag_bytes;
    int mmu_idx = cpu_mmu_index(env, false);
    uint8_t *mem;

    ptr &= -dcz_bytes;
    mem = allocation_tag_mem(env, mmu_idx, ptr, MMU_DATA_STORE, dcz_bytes,
                             true, ra);
    if (mem) {
        int tag_pair = (val & 0xf) * 0x11;

        memset(mem, tag_pair, tag_bytes);
    }
}

static int mte_reg_el_from_mmu_idx(ARMMMUIdx mmu_idx)
{
    switch (mmu_idx) {
    case ARMMMUIdx_E10_0:
    case ARMMMUIdx_E10_1:
    case ARMMMUIdx_E10_1_PAN:
    case ARMMMUIdx_SE10_0:
    case ARMMMUIdx_SE10_1:
    case ARMMMUIdx_SE10_1_PAN:
        return 1;
    case ARMMMUIdx_E20_0:
    case ARMMMUIdx_E20_2:
    case ARMMMUIdx_E20_2_PAN:
    case ARMMMUIdx_E2:
        return 2;
    case ARMMMUIdx_SE3:
        return 3;
    default:
        return arm_mmu_idx_to_el(mmu_idx);
    }
}

static void mte_sync_check_fail(CPUARMState *env, uint32_t desc,
                                uint64_t dirty_ptr, uintptr_t ra)
{
    int is_write = FIELD_EX32(desc, MTEDESC, WRITE);
    uint32_t syn;

    env->exception.vaddress = dirty_ptr;
    syn = syn_data_abort_no_iss(arm_current_el(env) != 0, 0, 0, 0,
                                is_write, 0x11);
    raise_exception_ra(env, EXCP_DATA_ABORT, syn, exception_target_el(env), ra);
    g_assert_not_reached();
}

static void mte_async_check_fail(CPUARMState *env, uint64_t dirty_ptr,
                                 ARMMMUIdx arm_mmu_idx, int el)
{
    int select = 0;

    if (regime_has_2_ranges(arm_mmu_idx)) {
        select = extract64(dirty_ptr, 55, 1);
    }
    env->cp15.tfsr_el[el] |= 1 << select;
}

static void mte_check_fail(CPUARMState *env, uint32_t desc,
                           uint64_t dirty_ptr, uintptr_t ra)
{
    int mmu_idx = FIELD_EX32(desc, MTEDESC, MIDX);
    ARMMMUIdx arm_mmu_idx = core_to_aa64_mmu_idx(mmu_idx);
    int el, reg_el, tcf;
    uint64_t sctlr;

    reg_el = mte_reg_el_from_mmu_idx(arm_mmu_idx);
    sctlr = env->cp15.sctlr_el[reg_el];

    switch (arm_mmu_idx) {
    case ARMMMUIdx_E10_0:
    case ARMMMUIdx_E20_0:
    case ARMMMUIdx_SE10_0:
        el = 0;
        tcf = extract64(sctlr, 38, 2);
        break;
    default:
        el = reg_el;
        tcf = extract64(sctlr, 40, 2);
        break;
    }

    switch (tcf) {
    case 1:
        mte_sync_check_fail(env, desc, dirty_ptr, ra);
        break;
    case 2:
        mte_async_check_fail(env, dirty_ptr, arm_mmu_idx, el);
        break;
    case 3:
        if (FIELD_EX32(desc, MTEDESC, WRITE)) {
            mte_async_check_fail(env, dirty_ptr, arm_mmu_idx, el);
        } else {
            mte_sync_check_fail(env, desc, dirty_ptr, ra);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static int checkN(uint8_t *mem, int odd, int cmp, int count)
{
    int n = 0;
    int diff;

    cmp *= 0x11;
    diff = *mem++ ^ cmp;

    if (odd) {
        goto start_odd;
    }

    while (1) {
        if (unlikely(diff & 0x0f)) {
            break;
        }
        if (++n == count) {
            break;
        }

    start_odd:
        if (unlikely(diff & 0xf0)) {
            break;
        }
        if (++n == count) {
            break;
        }

        diff = *mem++ ^ cmp;
    }
    return n;
}

static int mte_probe_int(CPUARMState *env, uint32_t desc, uint64_t ptr,
                         uintptr_t ra, uint64_t *fault)
{
    struct uc_struct *uc = env->uc;
    int mmu_idx;
    int ptr_tag, bit55;
    uint64_t ptr_last, prev_page, next_page;
    uint64_t tag_first, tag_last;
    uint64_t tag_byte_first, tag_byte_last;
    uint32_t sizem1, tag_count, tag_size, n, c;
    uint8_t *mem1, *mem2;
    MMUAccessType type;

    bit55 = extract64(ptr, 55, 1);
    *fault = ptr;

    if (unlikely(!tbi_check(desc, bit55))) {
        return -1;
    }

    ptr_tag = allocation_tag_from_addr(ptr);
    if (tcma_check(desc, bit55, ptr_tag)) {
        return 1;
    }

    mmu_idx = FIELD_EX32(desc, MTEDESC, MIDX);
    type = FIELD_EX32(desc, MTEDESC, WRITE) ? MMU_DATA_STORE : MMU_DATA_LOAD;
    sizem1 = FIELD_EX32(desc, MTEDESC, SIZEM1);
    ptr_last = ptr + sizem1;
    tag_first = QEMU_ALIGN_DOWN(ptr, TAG_GRANULE);
    tag_last = QEMU_ALIGN_DOWN(ptr_last, TAG_GRANULE);
    tag_count = ((tag_last - tag_first) / TAG_GRANULE) + 1;
    tag_byte_first = QEMU_ALIGN_DOWN(ptr, 2 * TAG_GRANULE);
    tag_byte_last = QEMU_ALIGN_DOWN(ptr_last, 2 * TAG_GRANULE);

    prev_page = ptr & TARGET_PAGE_MASK;
    next_page = prev_page + TARGET_PAGE_SIZE;

    if (likely(tag_last - prev_page < TARGET_PAGE_SIZE)) {
        mem1 = allocation_tag_mem(env, mmu_idx, ptr, type, sizem1 + 1,
                                  false, ra);
        if (!mem1) {
            return 1;
        }
        n = checkN(mem1, ptr & TAG_GRANULE, ptr_tag, tag_count);
    } else {
        tag_size = (next_page - tag_byte_first) / (2 * TAG_GRANULE);
        mem1 = allocation_tag_mem(env, mmu_idx, ptr, type, next_page - ptr,
                                  false, ra);

        tag_size = ((tag_byte_last - next_page) / (2 * TAG_GRANULE)) + 1;
        mem2 = allocation_tag_mem(env, mmu_idx, next_page, type,
                                  ptr_last - next_page + 1, false, ra);

        n = c = (next_page - tag_first) / TAG_GRANULE;
        if (mem1) {
            n = checkN(mem1, ptr & TAG_GRANULE, ptr_tag, c);
        }
        if (n == c) {
            if (!mem2) {
                return 1;
            }
            n += checkN(mem2, 0, ptr_tag, tag_count - c);
        }
        (void)tag_size;
    }

    if (likely(n == tag_count)) {
        return 1;
    }

    if (n > 0) {
        *fault = tag_first + n * TAG_GRANULE;
    }
    return 0;
}

uint64_t mte_check(CPUARMState *env, uint32_t desc, uint64_t ptr,
                   uintptr_t ra)
{
    uint64_t fault;
    int ret = mte_probe_int(env, desc, ptr, ra, &fault);

    if (unlikely(ret == 0)) {
        mte_check_fail(env, desc, fault, ra);
    } else if (ret < 0) {
        return ptr;
    }
    return allocation_tag_clean_addr(useronly_clean_ptr(ptr));
}

bool mte_probe(CPUARMState *env, uint32_t desc, uint64_t ptr)
{
    uint64_t fault;
    int ret = mte_probe_int(env, desc, ptr, 0, &fault);

    return ret != 0;
}

uint64_t HELPER(mte_check)(CPUARMState *env, uint32_t desc, uint64_t ptr)
{
    return mte_check(env, desc, ptr, GETPC());
}

uint64_t HELPER(mte_check_zva)(CPUARMState *env, uint32_t desc, uint64_t ptr)
{
    uintptr_t ra = GETPC();
    int log2_dcz_bytes = env_archcpu(env)->dcz_blocksize + 2;
    uint64_t dcz_bytes = 1ULL << log2_dcz_bytes;
    uint64_t align_ptr = ptr & -dcz_bytes;
    uint64_t fault;
    int mmu_idx;
    int ret;

    FIELD_DP32(desc, MTEDESC, WRITE, 1, desc);
    FIELD_DP32(desc, MTEDESC, SIZEM1, dcz_bytes - 1, desc);
    mmu_idx = FIELD_EX32(desc, MTEDESC, MIDX);
    (void)allocation_tag_probe_access(env, ptr, MMU_DATA_STORE, 1, mmu_idx,
                                      ra);
    ret = mte_probe_int(env, desc, align_ptr, ra, &fault);

    if (unlikely(ret == 0)) {
        mte_check_fail(env, desc, fault, ra);
    } else if (ret < 0) {
        return ptr;
    }
    return allocation_tag_clean_addr(useronly_clean_ptr(ptr));
}
