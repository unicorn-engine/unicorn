/*
 * QError Module
 *
 * Copyright (C) 2009 Red Hat Inc.
 *
 * Authors:
 *  Luiz Capitulino <lcapitulino@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qerror.h"
#include "qemu-common.h"


/**
 * qerror_human(): Format QError data into human-readable string.
 */
QString *qerror_human(const QError *qerror)
{
    return qstring_from_str(qerror->err_msg);
}

void qerror_report(ErrorClass eclass, const char *fmt, ...)
{
}

/* Evil... */
struct Error
{
    char *msg;
    ErrorClass err_class;
};

void qerror_report_err(Error *err)
{
}
