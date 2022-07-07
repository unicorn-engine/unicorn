/*
 *  Copyright (c) 2012-2014 Bastian Koppelmann C-Lab/University Paderborn
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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
   Modified for Unicorn Engine by Eric Poole <eric.poole@aptiv.com>, 2022
   Copyright 2022 Aptiv 
*/

#ifndef QEMU_TRICORE_CPU_QOM_H
#define QEMU_TRICORE_CPU_QOM_H

#include "hw/core/cpu.h"

#define TYPE_TRICORE_CPU "tricore-cpu"

#define TRICORE_CPU(obj) ((TriCoreCPU *)obj)
#define TRICORE_CPU_CLASS(klass) ((TriCoreCPUClass *)klass)
#define TRICORE_CPU_GET_CLASS(obj) (&((TriCoreCPU *)obj)->cc)

typedef struct TriCoreCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    void (*parent_reset)(CPUState *cpu);
} TriCoreCPUClass;


#endif /* QEMU_TRICORE_CPU_QOM_H */
