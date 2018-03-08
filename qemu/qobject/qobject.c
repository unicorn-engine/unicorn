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

static bool (*qis_equal[QTYPE__MAX])(const QObject *, const QObject *) = {
    NULL,               /* No such object exists */
    qnull_is_equal,
    qnum_is_equal,
    qstring_is_equal,
    qdict_is_equal,
    qlist_is_equal,
    qbool_is_equal,
};

bool qobject_is_equal(const QObject *x, const QObject *y)
{
    /* We cannot test x == y because an object does not need to be
     * equal to itself (e.g. NaN floats are not). */

    if (!x && !y) {
        return true;
    }

    if (!x || !y || x->type != y->type) {
        return false;
    }

    assert(QTYPE_NONE < x->type && x->type < QTYPE__MAX);

    return qis_equal[x->type](x, y);
}

