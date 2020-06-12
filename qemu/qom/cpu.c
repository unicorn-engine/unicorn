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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu-common.h"
#include "qemu/log.h"
#include "uc_priv.h"

bool cpu_paging_enabled(const CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    return cc->get_paging_enabled(cpu);
}

static bool cpu_common_get_paging_enabled(const CPUState *cpu)
{
    return false;
}

void cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    cc->get_memory_mapping(cpu, list);
}

static void cpu_common_get_memory_mapping(CPUState *cpu,
                                          MemoryMappingList *list)
{
}

void cpu_reset_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request &= ~mask;
}

void cpu_exit(CPUState *cpu)
{
    cpu->exit_request = 1;
    cpu->tcg_exit_req = 1;
}

static void cpu_common_noop(CPUState *cpu)
{
}

static bool cpu_common_exec_interrupt(CPUState *cpu, int int_req)
{
    return false;
}

void cpu_reset(CPUState *cpu)
{
    CPUClass *klass = CPU_GET_CLASS(cpu->uc, cpu);

    if (klass->reset != NULL) {
        (*klass->reset)(cpu);
    }
}

static void cpu_common_reset(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (qemu_loglevel_mask(CPU_LOG_RESET)) {
        qemu_log("CPU Reset (CPU %d)\n", cpu->cpu_index);
        log_cpu_state(cpu, cc->reset_dump_flags);
    }

    cpu->interrupt_request = 0;
    cpu->current_tb = NULL;
    cpu->halted = 0;
    cpu->mem_io_pc = 0;
    cpu->mem_io_vaddr = 0;
    cpu->icount_extra = 0;
    cpu->icount_decr.u32 = 0;
    cpu->can_do_io = 0;
    memset(cpu->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof(void *));
}

static bool cpu_common_has_work(CPUState *cs)
{
    return false;
}

static void cpu_common_parse_features(CPUState *cpu, char *features)
{
    char *featurestr; /* Single "key=value" string being parsed */
    char *val;

    featurestr = features ? strtok(features, ",") : NULL;

    while (featurestr) {
        val = strchr(featurestr, '=');
        if (val) {
            *val = 0;
            val++;
        } else {
            return;
        }
        featurestr = strtok(NULL, ",");
    }
}

static int64_t cpu_common_get_arch_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

void cpu_klass_init(struct uc_struct *uc, CPUClass *k)
{
    k->parse_features = cpu_common_parse_features;
    k->reset = cpu_common_reset;
    k->get_arch_id = cpu_common_get_arch_id;
    k->has_work = cpu_common_has_work;
    k->get_paging_enabled = cpu_common_get_paging_enabled;
    k->get_memory_mapping = cpu_common_get_memory_mapping;
    k->debug_excp_handler = cpu_common_noop;
    k->cpu_exec_enter = cpu_common_noop;
    k->cpu_exec_exit = cpu_common_noop;
    k->cpu_exec_interrupt = cpu_common_exec_interrupt;

    return;
}

#ifdef NEED_CPU_INIT_REALIZE
void cpu_object_init(struct uc_struct *uc, CPUState *cs)
{
    return;
}

void cpu_object_realize(struct uc_struct *uc, CPUState *cs)
{
    return;
}
#endif
