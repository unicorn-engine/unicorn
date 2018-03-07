/*
 * QNull
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Authors:
 *  Markus Armbruster <armbru@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1
 * or later.  See the COPYING.LIB file in the top-level directory.
 */

#include "qemu-common.h"
#include "qapi/qmp/qobject.h"

QNull qnull_ = {
    {
        QTYPE_QNULL,
        1,
    }
};
