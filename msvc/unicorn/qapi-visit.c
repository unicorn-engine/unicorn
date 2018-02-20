/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI visitor functions
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "qapi-visit.h"

static void visit_type_DummyForceArrays_fields(Visitor *v, DummyForceArrays **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_X86CPUFeatureWordInfoList(v, &(*obj)->unused, "unused", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_DummyForceArrays(Visitor *v, DummyForceArrays **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "DummyForceArrays", name, sizeof(DummyForceArrays), &err);

    if (!err) {
        if (*obj) {
            visit_type_DummyForceArrays_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_QType(Visitor *v, QType *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, QType_lookup, "QType", name, errp);
}

void visit_type_QapiErrorClass(Visitor *v, QapiErrorClass *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, QapiErrorClass_lookup, "QapiErrorClass", name, errp);
}

static void visit_type_X86CPUFeatureWordInfo_fields(Visitor *v, X86CPUFeatureWordInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, &(*obj)->cpuid_input_eax, "cpuid-input-eax", &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, &(*obj)->has_cpuid_input_ecx, "cpuid-input-ecx")) {
        visit_type_int(v, &(*obj)->cpuid_input_ecx, "cpuid-input-ecx", &err);
        if (err) {
            goto out;
        }
    }
    visit_type_X86CPURegister32(v, &(*obj)->cpuid_register, "cpuid-register", &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, &(*obj)->features, "features", &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfo(Visitor *v, X86CPUFeatureWordInfo **obj, const char *name, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, (void **)obj, "X86CPUFeatureWordInfo", name, sizeof(X86CPUFeatureWordInfo), &err);

    if (!err) {
        if (*obj) {
            visit_type_X86CPUFeatureWordInfo_fields(v, obj, errp);
        }
        visit_end_struct(v, &err);
    }
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfoList(Visitor *v, X86CPUFeatureWordInfoList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        X86CPUFeatureWordInfoList *native_i = (X86CPUFeatureWordInfoList *)i;
        visit_type_X86CPUFeatureWordInfo(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_X86CPURegister32(Visitor *v, X86CPURegister32 *obj, const char *name, Error **errp)
{
    visit_type_enum(v, (int *)obj, X86CPURegister32_lookup, "X86CPURegister32", name, errp);
}

void visit_type_anyList(Visitor *v, anyList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        anyList *native_i = (anyList *)i;
        visit_type_any(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_boolList(Visitor *v, boolList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        boolList *native_i = (boolList *)i;
        visit_type_bool(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int16List(Visitor *v, int16List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        int16List *native_i = (int16List *)i;
        visit_type_int16(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int32List(Visitor *v, int32List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        int32List *native_i = (int32List *)i;
        visit_type_int32(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int64List(Visitor *v, int64List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        int64List *native_i = (int64List *)i;
        visit_type_int64(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int8List(Visitor *v, int8List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        int8List *native_i = (int8List *)i;
        visit_type_int8(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_intList(Visitor *v, intList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        intList *native_i = (intList *)i;
        visit_type_int(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_numberList(Visitor *v, numberList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        numberList *native_i = (numberList *)i;
        visit_type_number(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_sizeList(Visitor *v, sizeList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        sizeList *native_i = (sizeList *)i;
        visit_type_size(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_strList(Visitor *v, strList **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        strList *native_i = (strList *)i;
        visit_type_str(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint16List(Visitor *v, uint16List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        uint16List *native_i = (uint16List *)i;
        visit_type_uint16(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint32List(Visitor *v, uint32List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        uint32List *native_i = (uint32List *)i;
        visit_type_uint32(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint64List(Visitor *v, uint64List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        uint64List *native_i = (uint64List *)i;
        visit_type_uint64(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint8List(Visitor *v, uint8List **obj, const char *name, Error **errp)
{
    Error *err = NULL;
    GenericList *i, **prev;

    visit_start_list(v, name, &err);
    if (err) {
        goto out;
    }

    for (prev = (GenericList **)obj;
         !err && (i = visit_next_list(v, prev)) != NULL;
         prev = &i) {
        uint8List *native_i = (uint8List *)i;
        visit_type_uint8(v, &native_i->value, NULL, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}
