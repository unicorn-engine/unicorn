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
#include "qapi/qapi-visit-misc.h"

void visit_type_X86CPURegister32(Visitor *v, const char *name, X86CPURegister32 *obj, Error **errp)
{
    int value = *obj;
    visit_type_enum(v, name, &value, X86CPURegister32_lookup, errp);
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
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_X86CPUFeatureWordInfo(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

void visit_type_X86CPUFeatureWordInfoList(Visitor *v, const char *name, X86CPUFeatureWordInfoList **obj, Error **errp)
{
    Error *err = NULL;
    X86CPUFeatureWordInfoList *tail;
    size_t size = sizeof(**obj);

    visit_start_list(v, name, (GenericList **)obj, size, &err);
    if (err) {
        goto out;
    }

    for (tail = *obj; tail;
         tail = (X86CPUFeatureWordInfoList *)visit_next_list(v, (GenericList *)tail, size)) {
        visit_type_X86CPUFeatureWordInfo(v, NULL, &tail->value, &err);
        if (err) {
            break;
        }
    }

    if (!err) {
        visit_check_list(v, &err);
    }
    visit_end_list(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_X86CPUFeatureWordInfoList(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}

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
    if (err) {
        goto out_obj;
    }
    visit_check_struct(v, &err);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (err && visit_is_input(v)) {
        qapi_free_DummyForceArrays(*obj);
        *obj = NULL;
    }
out:
    error_propagate(errp, err);
}
/* Dummy declaration to prevent empty .o file */
char dummy_qapi_qapi_visit_misc_c;
