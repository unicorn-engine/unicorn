/*
 * QEMU Module Infrastructure
 *
 * Copyright IBM, Corp. 2009
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MODULE_H
#define QEMU_MODULE_H

#include "qemu/osdep.h"

typedef enum {
    MODULE_INIT_MACHINE,
    MODULE_INIT_QOM,
    MODULE_INIT_MAX
} module_init_type;

#define machine_init(function) module_init(function, MODULE_INIT_MACHINE)
#define type_init(function) module_init(function, MODULE_INIT_QOM)

void module_call_init(struct uc_struct *uc, module_init_type type);

#endif
