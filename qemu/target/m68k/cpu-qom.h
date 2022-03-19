/*
 * QEMU Motorola 68k CPU
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
#ifndef QEMU_M68K_CPU_QOM_H
#define QEMU_M68K_CPU_QOM_H

#include "hw/core/cpu.h"

#define M68K_CPU(obj) ((M68kCPU *)obj)
#define M68K_CPU_CLASS(klass) ((M68kCPUClass *)klass)
#define M68K_CPU_GET_CLASS(obj) (&((M68kCPU *)obj)->cc)

/*
 * M68kCPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * A Motorola 68k CPU model.
 */
typedef struct M68kCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    void (*parent_reset)(CPUState *cpu);
} M68kCPUClass;

typedef struct M68kCPU M68kCPU;

#endif
