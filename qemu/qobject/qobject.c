/*
 * QObject
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1
 * or later.  See the COPYING.LIB file in the top-level directory.
 */

#include "qemu-common.h"
#include "qapi/qmp/qbool.h"
#include "qapi/qmp/qnull.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qstring.h"

static void (*qdestroy[QTYPE__MAX])(QObject *) = {
    NULL,               /* No such object exists */
    NULL,              /* qnull_ is indestructible */
    qnum_destroy_obj,
    qstring_destroy_obj,
    qdict_destroy_obj,
    qlist_destroy_obj,
    qbool_destroy_obj,
};

void qobject_destroy(QObject *obj)
{
    assert(!obj->refcnt);
    assert(QTYPE_QNULL < obj->type && obj->type < QTYPE__MAX);
    qdestroy[obj->type](obj);
}
