#ifndef QEMU_RH850_QOM_H
#define QEMU_RH850_QOM_H

#include "hw/core/cpu.h"

#define TYPE_RH850_CPU "rh850-cpu"

#define RH850_CPU(obj) ((RH850CPU *)obj)
#define RH850_CPU_CLASS(klass) ((RH850CPUClass *)klass)
#define RH850_CPU_GET_CLASS(obj) (&((RH850CPU *)obj)->cc)

typedef struct RH850CPUInfo {
    const char *name;
    void (*initfn)(CPUState *obj);
} RH850CPUInfo;

/**
 * RH850CPUClass:
 * @parent_reset: The parent class' reset handler.
 *
 * An RH850 CPU model.
 */
typedef struct RH850CPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    const RH850CPUInfo *info;
    void (*parent_reset)(CPUState *cpu);
} RH850CPUClass;

#endif
