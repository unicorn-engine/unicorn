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

#ifndef QAPI_VISIT_H
#define QAPI_VISIT_H

#include "qapi-builtin-visit.h"
#include "qapi-types.h"

void visit_type_QapiErrorClass(Visitor *v, const char *name, QapiErrorClass *obj, Error **errp);
void visit_type_X86CPURegister32(Visitor *v, const char *name, X86CPURegister32 *obj, Error **errp);

void visit_type_X86CPUFeatureWordInfo_members(Visitor *v, X86CPUFeatureWordInfo *obj, Error **errp);
void visit_type_X86CPUFeatureWordInfo(Visitor *v, const char *name, X86CPUFeatureWordInfo **obj, Error **errp);
void visit_type_X86CPUFeatureWordInfoList(Visitor *v, const char *name, X86CPUFeatureWordInfoList **obj, Error **errp);

void visit_type_DummyForceArrays_members(Visitor *v, DummyForceArrays *obj, Error **errp);
void visit_type_DummyForceArrays(Visitor *v, const char *name, DummyForceArrays **obj, Error **errp);

#endif /* QAPI_VISIT_H */
