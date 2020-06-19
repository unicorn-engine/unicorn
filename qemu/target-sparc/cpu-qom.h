/*
 * QEMU SPARC CPU
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

#ifndef QEMU_SPARC_CPU_QOM_H
#define QEMU_SPARC_CPU_QOM_H

#include "qom/cpu.h"
#include "cpu.h"

/**
 * SPARCCPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * A SPARC CPU model.
 */
typedef struct SPARCCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    void (*parent_reset)(CPUState *cpu);
} SPARCCPUClass;

/**
 * SPARCCPU:
 * @env: #CPUSPARCState
 *
 * A SPARC CPU.
 */
typedef struct SPARCCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUSPARCState env;

    struct SPARCCPUClass cc;
} SPARCCPU;

#define SPARC_CPU(uc, obj) ((SPARCCPU *)obj)
#define SPARC_CPU_CLASS(uc, klass) ((SPARCCPUClass *)klass)
#define SPARC_CPU_GET_CLASS(uc, obj) (&((SPARCCPU *)obj)->cc)

static inline SPARCCPU *sparc_env_get_cpu(CPUSPARCState *env)
{
    return container_of(env, SPARCCPU, env);
}

#define ENV_GET_CPU(e) CPU(sparc_env_get_cpu(e))

#define ENV_OFFSET offsetof(SPARCCPU, env)

void sparc_cpu_do_interrupt(CPUState *cpu);
hwaddr sparc_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
void QEMU_NORETURN sparc_cpu_do_unaligned_access(CPUState *cpu,
                                                 vaddr addr, int is_write,
                                                 int is_user, uintptr_t retaddr);

#endif
