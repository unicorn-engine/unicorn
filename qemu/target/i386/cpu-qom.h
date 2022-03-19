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
#ifndef QEMU_I386_CPU_QOM_H
#define QEMU_I386_CPU_QOM_H

#include "hw/core/cpu.h"

typedef struct X86CPUModel X86CPUModel;

/**
 * X86CPUClass:
 * @cpu_def: CPU model definition
 * @host_cpuid_required: Whether CPU model requires cpuid from host.
 * @ordering: Ordering on the "-cpu help" CPU model list.
 * @migration_safe: See CpuDefinitionInfo::migration_safe
 * @static_model: See CpuDefinitionInfo::static
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * An x86 CPU model or family.
 */
typedef struct X86CPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    /* CPU definition, automatically loaded by instance_init if not NULL.
     * Should be eventually replaced by subclass-specific property defaults.
     */
    X86CPUModel *model;

    bool host_cpuid_required;
    int ordering;
    bool static_model;

    /* Optional description of CPU model.
     * If unavailable, cpu_def->model_id is used */
    const char *model_description;

    void (*parent_reset)(CPUState *cpu);
} X86CPUClass;

typedef struct X86CPU X86CPU;

#endif
