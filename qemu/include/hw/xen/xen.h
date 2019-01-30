#ifndef QEMU_HW_XEN_H
#define QEMU_HW_XEN_H

#include "qemu-common.h"
#include "exec/cpu-common.h"

static inline bool xen_enabled(void)
{
    // Unicorn: Always return false
    return false;
}

#endif
