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

void visit_type_DummyForceArrays_members(Visitor *v, DummyForceArrays *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_X86CPUFeatureWordInfoList(v, "unused", &obj->unused, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_DummyForceArrays(Visitor *v, const char *name, DummyForceArrays **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(DummyForceArrays), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_DummyForceArrays_members(v, *obj, &err);
    error_propagate(errp, err);
    err = NULL;
out_obj:
    visit_end_struct(v, &err);
out:
    error_propagate(errp, err);
}

void visit_type_QType(Visitor *v, const char *name, QType *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QType_lookup, errp);
    *obj = value;
}

void visit_type_QapiErrorClass(Visitor *v, const char *name, QapiErrorClass *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, QapiErrorClass_lookup, errp);
    *obj = value;
}

void visit_type_X86CPUFeatureWordInfo_members(Visitor *v, X86CPUFeatureWordInfo *obj, Error **errp)
{
    Error *err = NULL;

    visit_type_int(v, "cpuid-input-eax", &obj->cpuid_input_eax, &err);
    if (err) {
        goto out;
    }
    if (visit_optional(v, "cpuid-input-ecx", &obj->has_cpuid_input_ecx)) {
        visit_type_int(v, "cpuid-input-ecx", &obj->cpuid_input_ecx, &err);
        if (err) {
            goto out;
        }
    }
    visit_type_X86CPURegister32(v, "cpuid-register", &obj->cpuid_register, &err);
    if (err) {
        goto out;
    }
    visit_type_int(v, "features", &obj->features, &err);
    if (err) {
        goto out;
    }

out:
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfo(Visitor *v, const char *name, X86CPUFeatureWordInfo **obj, Error **errp)
{
    Error *err = NULL;

    visit_start_struct(v, name, (void **)obj, sizeof(X86CPUFeatureWordInfo), &err);
    if (err) {
        goto out;
    }
    if (!*obj) {
        goto out_obj;
    }
    visit_type_X86CPUFeatureWordInfo_members(v, *obj, &err);
    error_propagate(errp, err);
    err = NULL;
out_obj:
    visit_end_struct(v, &err);
out:
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfoList(Visitor *v, const char *name, X86CPUFeatureWordInfoList **obj, Error **errp)
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
        visit_type_X86CPUFeatureWordInfo(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_X86CPURegister32(Visitor *v, const char *name, X86CPURegister32 *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, X86CPURegister32_lookup, errp);
    *obj = value;
}

void visit_type_anyList(Visitor *v, const char *name, anyList **obj, Error **errp)
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
        visit_type_any(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_boolList(Visitor *v, const char *name, boolList **obj, Error **errp)
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
        visit_type_bool(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int16List(Visitor *v, const char *name, int16List **obj, Error **errp)
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
        visit_type_int16(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int32List(Visitor *v, const char *name, int32List **obj, Error **errp)
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
        visit_type_int32(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int64List(Visitor *v, const char *name, int64List **obj, Error **errp)
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
        visit_type_int64(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_int8List(Visitor *v, const char *name, int8List **obj, Error **errp)
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
        visit_type_int8(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_intList(Visitor *v, const char *name, intList **obj, Error **errp)
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
        visit_type_int(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_numberList(Visitor *v, const char *name, numberList **obj, Error **errp)
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
        visit_type_number(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_sizeList(Visitor *v, const char *name, sizeList **obj, Error **errp)
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
        visit_type_size(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_strList(Visitor *v, const char *name, strList **obj, Error **errp)
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
        visit_type_str(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint16List(Visitor *v, const char *name, uint16List **obj, Error **errp)
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
        visit_type_uint16(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint32List(Visitor *v, const char *name, uint32List **obj, Error **errp)
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
        visit_type_uint32(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint64List(Visitor *v, const char *name, uint64List **obj, Error **errp)
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
        visit_type_uint64(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}

void visit_type_uint8List(Visitor *v, const char *name, uint8List **obj, Error **errp)
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
        visit_type_uint8(v, NULL, &native_i->value, &err);
    }

    error_propagate(errp, err);
    err = NULL;
    visit_end_list(v);
out:
    error_propagate(errp, err);
}
