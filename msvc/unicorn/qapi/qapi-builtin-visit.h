/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Built-in QAPI visitors
 *
 * Copyright IBM, Corp. 2011
 * Copyright (C) 2014-2018 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QAPI_BUILTIN_VISIT_H
#define QAPI_BUILTIN_VISIT_H

#include "qapi/visitor.h"
#include "qapi-builtin-types.h"

void visit_type_strList(Visitor *v, const char *name, strList **obj, Error **errp);
void visit_type_numberList(Visitor *v, const char *name, numberList **obj, Error **errp);
void visit_type_intList(Visitor *v, const char *name, intList **obj, Error **errp);
void visit_type_int8List(Visitor *v, const char *name, int8List **obj, Error **errp);
void visit_type_int16List(Visitor *v, const char *name, int16List **obj, Error **errp);
void visit_type_int32List(Visitor *v, const char *name, int32List **obj, Error **errp);
void visit_type_int64List(Visitor *v, const char *name, int64List **obj, Error **errp);
void visit_type_uint8List(Visitor *v, const char *name, uint8List **obj, Error **errp);
void visit_type_uint16List(Visitor *v, const char *name, uint16List **obj, Error **errp);
void visit_type_uint32List(Visitor *v, const char *name, uint32List **obj, Error **errp);
void visit_type_uint64List(Visitor *v, const char *name, uint64List **obj, Error **errp);
void visit_type_sizeList(Visitor *v, const char *name, sizeList **obj, Error **errp);
void visit_type_boolList(Visitor *v, const char *name, boolList **obj, Error **errp);
void visit_type_anyList(Visitor *v, const char *name, anyList **obj, Error **errp);
void visit_type_nullList(Visitor *v, const char *name, nullList **obj, Error **errp);
void visit_type_QType(Visitor *v, const char *name, QType *obj, Error **errp);

#endif /* QAPI_BUILTIN_VISIT_H */
