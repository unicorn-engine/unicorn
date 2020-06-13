/*
 * QEMU x86 CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */
#ifndef QEMU_I386_CPU_QOM_H
#define QEMU_I386_CPU_QOM_H

#include "qom/cpu.h"
#include "cpu.h"

/**
 * X86CPUDefinition:
 *
 * CPU model definition data that was not converted to QOM per-subclass
 * property defaults yet.
 */
typedef struct X86CPUDefinition X86CPUDefinition;

/**
 * X86CPUClass:
 * @cpu_def: CPU model definition
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * An x86 CPU model or family.
 */
typedef struct X86CPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    /* Should be eventually replaced by subclass-specific property defaults. */
    X86CPUDefinition *cpu_def;

    void (*parent_reset)(CPUState *cpu);
} X86CPUClass;

/**
 * X86CPU:
 * @env: #CPUX86State
 * @migratable: If set, only migratable flags will be accepted when "enforce"
 * mode is used, and only migratable flags will be included in the "host"
 * CPU model.
 *
 * An x86 CPU.
 */
typedef struct X86CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUX86State env;

    bool check_cpuid;
    bool enforce_cpuid;
    bool host_features;

    /* if true the CPUID code directly forward host cache leaves to the guest */
    bool cache_info_passthrough;

    /* Features that were filtered out because of missing host capabilities */
    uint32_t filtered_features[FEATURE_WORDS];

    /* Enable PMU CPUID bits. This can't be enabled by default yet because
     * it doesn't have ABI stability guarantees, as it passes all PMU CPUID
     * bits returned by GET_SUPPORTED_CPUID (that depend on host CPU and kernel
     * capabilities) directly to the guest.
     */
    bool enable_pmu;

    struct X86CPUClass cc;
} X86CPU;

#define X86_CPU(uc, obj) ((X86CPU *)obj)
#define X86_CPU_CLASS(uc, klass) ((X86CPUClass *)klass)
#define X86_CPU_GET_CLASS(uc, obj) (&((X86CPU *)obj)->cc)

static inline X86CPU *x86_env_get_cpu(CPUX86State *env)
{
    return container_of(env, X86CPU, env);
}

#define ENV_GET_CPU(e) CPU(x86_env_get_cpu(e))

#define ENV_OFFSET offsetof(X86CPU, env)

/**
 * x86_cpu_do_interrupt:
 * @cpu: vCPU the interrupt is to be handled by.
 */
void x86_cpu_do_interrupt(CPUState *cpu);
bool x86_cpu_exec_interrupt(CPUState *cpu, int int_req);

void x86_cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list);

hwaddr x86_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);

void x86_cpu_exec_enter(CPUState *cpu);
void x86_cpu_exec_exit(CPUState *cpu);

#endif
