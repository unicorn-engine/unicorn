/*
 * TCG CPU-specific operations
 *
 * Copyright 2021 SUSE LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef TCG_CPU_OPS_H
#define TCG_CPU_OPS_H

#include "hw/core/cpu.h"
#include "exec/exec-all.h"

static inline void cpu_tcg_synchronize_from_tb(CPUState *cpu,
                                               struct TranslationBlock *tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->synchronize_from_tb) {
        cc->tcg_ops->synchronize_from_tb(cpu, tb);
    } else if (cc->synchronize_from_tb) {
        cc->synchronize_from_tb(cpu, tb);
    } else {
        assert(cc->set_pc);
        cc->set_pc(cpu, tb->pc);
    }
}

static inline void cpu_tcg_debug_excp_handler(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->debug_excp_handler) {
        cc->tcg_ops->debug_excp_handler(cpu);
    } else {
        cc->debug_excp_handler(cpu);
    }
}

static inline void cpu_tcg_exec_enter(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->cpu_exec_enter) {
        cc->tcg_ops->cpu_exec_enter(cpu);
    } else {
        cc->cpu_exec_enter(cpu);
    }
}

static inline void cpu_tcg_exec_exit(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->cpu_exec_exit) {
        cc->tcg_ops->cpu_exec_exit(cpu);
    } else {
        cc->cpu_exec_exit(cpu);
    }
}

static inline bool cpu_tcg_exec_interrupt(CPUState *cpu,
                                          int interrupt_request)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->cpu_exec_interrupt) {
        return cc->tcg_ops->cpu_exec_interrupt(cpu, interrupt_request);
    }
    return cc->cpu_exec_interrupt(cpu, interrupt_request);
}

static inline bool cpu_tcg_tlb_fill(CPUState *cpu, vaddr address, int size,
                                    MMUAccessType access_type, int mmu_idx,
                                    bool probe, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->tlb_fill) {
        return cc->tcg_ops->tlb_fill(cpu, address, size, access_type,
                                     mmu_idx, probe, retaddr);
    }
    return cc->tlb_fill(cpu, address, size, access_type, mmu_idx,
                        probe, retaddr);
}

static inline void cpu_tcg_unaligned_access(CPUState *cpu, vaddr addr,
                                            MMUAccessType access_type,
                                            int mmu_idx, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (cc->tcg_ops && cc->tcg_ops->do_unaligned_access) {
        cc->tcg_ops->do_unaligned_access(cpu, addr, access_type,
                                         mmu_idx, retaddr);
    } else {
        cc->do_unaligned_access(cpu, addr, access_type, mmu_idx, retaddr);
    }
}

#endif /* TCG_CPU_OPS_H */
