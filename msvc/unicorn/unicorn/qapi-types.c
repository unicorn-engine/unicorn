/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * deallocation functions for schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Michael Roth      <mdroth@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qapi/dealloc-visitor.h"
#include "qapi-types.h"
#include "qapi-visit.h"

const char *ErrorClass_lookup[] = {
    "GenericError",
    "CommandNotFound",
    "DeviceEncrypted",
    "DeviceNotActive",
    "DeviceNotFound",
    "KVMMissingCap",
    NULL,
};

const char *X86CPURegister32_lookup[] = {
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


#ifndef QAPI_TYPES_BUILTIN_CLEANUP_DEF_H
#define QAPI_TYPES_BUILTIN_CLEANUP_DEF_H


void qapi_free_strList(strList *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_strList(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_intList(intList *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_intList(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_numberList(numberList *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_numberList(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_boolList(boolList *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_boolList(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_int8List(int8List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_int8List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_int16List(int16List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_int16List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_int32List(int32List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_int32List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_int64List(int64List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_int64List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_uint8List(uint8List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_uint8List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_uint16List(uint16List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_uint16List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_uint32List(uint32List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_uint32List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

void qapi_free_uint64List(uint64List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_uint64List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

#endif /* QAPI_TYPES_BUILTIN_CLEANUP_DEF_H */


void qapi_free_ErrorClassList(ErrorClassList *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_ErrorClassList(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}


void qapi_free_X86CPURegister32List(X86CPURegister32List *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_X86CPURegister32List(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}


void qapi_free_X86CPUFeatureWordInfoList(X86CPUFeatureWordInfoList *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_X86CPUFeatureWordInfoList(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}


void qapi_free_X86CPUFeatureWordInfo(X86CPUFeatureWordInfo *obj)
{
    QapiDeallocVisitor *md;
    Visitor *v;

    if (!obj) {
        return;
    }

    md = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(md);
    visit_type_X86CPUFeatureWordInfo(v, &obj, NULL, NULL);
    qapi_dealloc_visitor_cleanup(md);
}

