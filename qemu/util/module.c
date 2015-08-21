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
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu-common.h"
#include "qemu/queue.h"

#include "uc_priv.h"

static void init_lists(struct uc_struct *uc)
{
    int i;

    for (i = 0; i < MODULE_INIT_MAX; i++) {
        QTAILQ_INIT(&uc->init_type_list[i]);
    }
}


static ModuleTypeList *find_type(struct uc_struct *uc, module_init_type type)
{
    ModuleTypeList *l;

    init_lists(uc);

    l = &uc->init_type_list[type];

    return l;
}

static void module_load(module_init_type type)
{
}

void module_call_init(struct uc_struct *uc, module_init_type type)
{
    ModuleTypeList *l;
    ModuleEntry *e;

    module_load(type);
    l = find_type(uc, type);

    QTAILQ_FOREACH(e, l, node) {
        e->init();
    }
}
