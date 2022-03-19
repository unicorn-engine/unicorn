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
#ifndef QEMU_SPARC_CPU_QOM_H
#define QEMU_SPARC_CPU_QOM_H

#include "hw/core/cpu.h"

#define SPARC_CPU(obj) ((SPARCCPU *)obj)
#define SPARC_CPU_CLASS(klass) ((SPARCCPUClass *)klass)
#define SPARC_CPU_GET_CLASS(obj) (&((SPARCCPU *)obj)->cc)

typedef struct sparc_def_t sparc_def_t;
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
    const sparc_def_t *cpu_def;
} SPARCCPUClass;

typedef struct SPARCCPU SPARCCPU;

#endif
