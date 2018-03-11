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

#include "qemu/osdep.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "qemu/cutils.h"

static void machine_class_base_init(ObjectClass *oc, void *data)
{
    if (!object_class_is_abstract(oc)) {
        const char *cname = object_class_get_name(oc);
        assert(g_str_has_suffix(cname, TYPE_MACHINE_SUFFIX));
    }
}

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
    machine_class_base_init,
    NULL,

    true,
};

void machine_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &machine_info);
}
