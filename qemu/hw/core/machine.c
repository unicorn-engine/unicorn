/*
 * QEMU Machine
 *
 * Copyright (C) 2014 Red Hat Inc
 *
 * Authors:
 *   Marcel Apfelbaum <marcel.a@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "hw/boards.h"

static void machine_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
}

static void machine_finalize(struct uc_struct *uc, Object *obj, void *opaque)
{
}

static const TypeInfo machine_info = {
    TYPE_MACHINE,
    TYPE_OBJECT,

    sizeof(MachineClass),
    sizeof(MachineState),
    NULL,

    machine_initfn,
    NULL,
    machine_finalize,

    NULL,

    NULL,
    NULL,
    NULL,

    true,
};

void machine_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &machine_info);
}
