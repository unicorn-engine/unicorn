/*
 * QEMU CPU model
 *
 * Copyright (c) 2012-2014 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "uc_priv.h"
#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "sysemu/tcg.h"

bool cpu_paging_enabled(const CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    return cc->get_paging_enabled(cpu);
}

static bool cpu_common_get_paging_enabled(const CPUState *cpu)
{
    return false;
}

void cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->get_memory_mapping(cpu, list);
}

static void cpu_common_get_memory_mapping(CPUState *cpu,
                                          MemoryMappingList *list)
{
    // error_setg(errp, "Obtaining memory mappings is unsupported on this CPU.");
}

/* Resetting the IRQ comes from across the code base so we take the
 * BQL here if we need to.  cpu_interrupt assumes it is held.*/
void cpu_reset_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request &= ~mask;
}

void cpu_exit(CPUState *cpu)
{
    cpu->exit_request = 1;
    cpu->tcg_exit_req = 1;
    cpu->icount_decr_ptr->u16.high = -1;
}

static void cpu_common_noop(CPUState *cpu)
{
}

static bool cpu_common_exec_interrupt(CPUState *cpu, int int_req)
{
    return false;
}

static bool cpu_common_debug_check_watchpoint(CPUState *cpu,
                                              CPUWatchpoint *wp)
{
    return true;
}

static bool cpu_common_debug_check_breakpoint(CPUState *cpu)
{
    return true;
}

static vaddr cpu_adjust_watchpoint_address(CPUState *cpu, vaddr addr, int len)
{
    return addr;
}

static void cpu_legacy_debug_excp_handler(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->debug_excp_handler(cpu);
}

static bool cpu_legacy_debug_check_breakpoint(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    return cc->debug_check_breakpoint(cpu);
}

static bool cpu_legacy_debug_check_watchpoint(CPUState *cpu,
                                              CPUWatchpoint *wp)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    return cc->debug_check_watchpoint(cpu, wp);
}

static vaddr cpu_legacy_adjust_watchpoint_address(CPUState *cpu, vaddr addr,
                                                  int len)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    return cc->adjust_watchpoint_address(cpu, addr, len);
}

static void cpu_legacy_exec_enter(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->cpu_exec_enter(cpu);
}

static void cpu_legacy_exec_exit(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->cpu_exec_exit(cpu);
}

static bool cpu_legacy_exec_interrupt(CPUState *cpu, int interrupt_request)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    return cc->cpu_exec_interrupt(cpu, interrupt_request);
}

static bool cpu_legacy_tlb_fill(CPUState *cpu, vaddr address, int size,
                                MMUAccessType access_type, int mmu_idx,
                                bool probe, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    return cc->tlb_fill(cpu, address, size, access_type, mmu_idx, probe,
                        retaddr);
}

static void cpu_legacy_unaligned_access(CPUState *cpu, vaddr addr,
                                        MMUAccessType access_type,
                                        int mmu_idx, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->do_unaligned_access(cpu, addr, access_type, mmu_idx, retaddr);
}

static void cpu_legacy_transaction_failed(CPUState *cpu, hwaddr physaddr,
                                          vaddr addr, unsigned size,
                                          MMUAccessType access_type,
                                          int mmu_idx, MemTxAttrs attrs,
                                          MemTxResult response,
                                          uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->do_transaction_failed) {
        cc->do_transaction_failed(cpu, physaddr, addr, size, access_type,
                                  mmu_idx, attrs, response, retaddr);
    }
}

static const struct TCGCPUOps cpu_legacy_tcg_ops = {
    .cpu_exec_enter = cpu_legacy_exec_enter,
    .cpu_exec_exit = cpu_legacy_exec_exit,
    .debug_excp_handler = cpu_legacy_debug_excp_handler,
    .debug_check_breakpoint = cpu_legacy_debug_check_breakpoint,
    .debug_check_watchpoint = cpu_legacy_debug_check_watchpoint,
    .cpu_exec_interrupt = cpu_legacy_exec_interrupt,
    .tlb_fill = cpu_legacy_tlb_fill,
    .do_transaction_failed = cpu_legacy_transaction_failed,
    .do_unaligned_access = cpu_legacy_unaligned_access,
    .adjust_watchpoint_address = cpu_legacy_adjust_watchpoint_address,
};

void cpu_reset(CPUState *cpu)
{
    CPUClass *klass = CPU_GET_CLASS(cpu);

    if (klass->reset != NULL) {
        (*klass->reset)(cpu);
    }
}

static void cpu_common_reset(CPUState *dev)
{
    CPUState *cpu = CPU(dev);

    cpu->interrupt_request = 0;
    cpu->halted = 0;
    cpu->mem_io_pc = 0;
    cpu->icount_extra = 0;
    cpu->can_do_io = 1;
    cpu->exception_index = -1;
    cpu->exception_pc_restored = false;
    cpu->crash_occurred = false;
    cpu->cflags_next_tb = -1;

    cpu_tb_jmp_cache_clear(cpu);

    cpu->uc->tcg_flush_tlb(cpu->uc);
}

static bool cpu_common_has_work(CPUState *cs)
{
    return false;
}

static int64_t cpu_common_get_arch_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

void cpu_class_init(struct uc_struct *uc, CPUClass *k)
{
    k->get_arch_id = cpu_common_get_arch_id;
    k->has_work = cpu_common_has_work;
    k->get_paging_enabled = cpu_common_get_paging_enabled;
    k->get_memory_mapping = cpu_common_get_memory_mapping;
    k->debug_excp_handler = cpu_common_noop;
    k->debug_check_watchpoint = cpu_common_debug_check_watchpoint;
    k->debug_check_breakpoint = cpu_common_debug_check_breakpoint;
    k->cpu_exec_enter = cpu_common_noop;
    k->cpu_exec_exit = cpu_common_noop;
    k->cpu_exec_interrupt = cpu_common_exec_interrupt;
    k->adjust_watchpoint_address = cpu_adjust_watchpoint_address;
    k->tcg_ops = &cpu_legacy_tcg_ops;
    /* instead of dc->reset. */
    k->reset = cpu_common_reset;

    return;
}

void cpu_common_initfn(struct uc_struct *uc, CPUState *cs)
{
    CPUState *cpu = CPU(cs);

    cpu->cpu_index = UNASSIGNED_CPU_INDEX;
    cpu->cluster_index = UNASSIGNED_CLUSTER_INDEX;
    /* *-user doesn't have configurable SMP topology */
    /* the default value is changed by qemu_init_vcpu() for softmmu */
    cpu->nr_cores = 1;
    cpu->nr_threads = 1;

    QTAILQ_INIT(&cpu->breakpoints);
    QTAILQ_INIT(&cpu->watchpoints);

    /* cpu_exec_initfn(cpu); */
    cpu->num_ases = 1;
    cpu->as = &(cpu->uc->address_space_memory);
    cpu->memory = cpu->uc->system_memory;
}

void cpu_stop(struct uc_struct *uc)
{
    if (uc->cpu) {
        uc->cpu->stop = false;
        uc->cpu->stopped = true;
        cpu_exit(uc->cpu);
    }
}
