/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Schema-defined QAPI visitors
 *
 * Copyright IBM, Corp. 2011
 * Copyright (C) 2014-2018 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"
#include "qapi-visit.h"

void visit_type_QapiErrorClass(Visitor *v, const char *name, QapiErrorClass *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QapiErrorClass_lookup, errp);
    *obj = value;
}
/* Dummy declaration to prevent empty .o file */
char dummy_qapi_qapi_visit_common_c;
