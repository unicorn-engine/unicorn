/*
 * Device Container
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qom/object.h"
#include "qemu/module.h"
#include <assert.h>

static const TypeInfo container_info = {
    "container",
    TYPE_OBJECT,
    0,
    sizeof(Object),
};

void container_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &container_info);
}

Object *container_get(struct uc_struct *uc, Object *root, const char *path)
{
    Object *obj, *child;
    gchar **parts;
    int i;

    parts = g_strsplit(path, "/", 0);
    assert(parts != NULL && parts[0] != NULL && !parts[0][0]);
    obj = root;

    for (i = 1; parts[i] != NULL; i++, obj = child) {
        child = object_resolve_path_component(uc, obj, parts[i]);
        if (!child) {
            child = object_new(uc, "container");
            object_property_add_child(obj, parts[i], child, NULL);
        }
    }

    g_strfreev(parts);

    return obj;
}
