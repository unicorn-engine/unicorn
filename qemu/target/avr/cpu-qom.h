/*
 * QEMU AVR CPU
 *
 * Copyright (c) 2016-2020 Michael Rolnik
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

#ifndef QEMU_AVR_QOM_H
#define QEMU_AVR_QOM_H

#include "hw/core/cpu.h"

#define TYPE_AVR_CPU "avr-cpu"

#define AVR_CPU(obj) ((AVRCPU *)obj)
#define AVR_CPU_CLASS(klass) ((AVRCPUClass *)klass)
#define AVR_CPU_GET_CLASS(obj) (&((AVRCPU *)obj)->cc)

typedef struct AVRCPUInfo {
    const char *name;
    void (*initfn)(CPUState *obj);
} AVRCPUInfo;

/**
 * AVRCPUClass: An AVR CPU model.
 * @parent_reset: The parent class' reset handler.
 */
typedef struct AVRCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    const AVRCPUInfo *info;
    void (*parent_reset)(CPUState *cpu);
} AVRCPUClass;


#endif /* !defined (QEMU_AVR_CPU_QOM_H) */
