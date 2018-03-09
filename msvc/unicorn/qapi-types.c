/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 * Copyright (c) 2013-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/dealloc-visitor.h"
#include "qapi-types.h"
#include "qapi-visit.h"

const char *const QapiErrorClass_lookup[] = {
    "GenericError",
    "CommandNotFound",
    "DeviceEncrypted",
    "DeviceNotActive",
    "DeviceNotFound",
    "KVMMissingCap",
    NULL,
};

const char *const X86CPURegister32_lookup[] = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESP",
    "EBP",
    "ESI",
    "EDI",
    NULL,
};

void qapi_free_X86CPUFeatureWordInfo(X86CPUFeatureWordInfo *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_X86CPUFeatureWordInfo(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_X86CPUFeatureWordInfoList(X86CPUFeatureWordInfoList *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_X86CPUFeatureWordInfoList(v, NULL, &obj, NULL);
    visit_free(v);
}

void qapi_free_DummyForceArrays(DummyForceArrays *obj)
{
    Visitor *v;

    if (!obj) {
        return;
    }

    v = qapi_dealloc_visitor_new();
    visit_type_DummyForceArrays(v, NULL, &obj, NULL);
    visit_free(v);
}
