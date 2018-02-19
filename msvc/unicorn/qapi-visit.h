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

#ifndef QAPI_VISIT_H
#define QAPI_VISIT_H

#include "qapi/visitor.h"
#include "qapi-types.h"


#ifndef QAPI_VISIT_BUILTIN
#define QAPI_VISIT_BUILTIN

void visit_type_anyList(Visitor *v, anyList **obj, const char *name, Error **errp);
void visit_type_boolList(Visitor *v, boolList **obj, const char *name, Error **errp);
void visit_type_int16List(Visitor *v, int16List **obj, const char *name, Error **errp);
void visit_type_int32List(Visitor *v, int32List **obj, const char *name, Error **errp);
void visit_type_int64List(Visitor *v, int64List **obj, const char *name, Error **errp);
void visit_type_int8List(Visitor *v, int8List **obj, const char *name, Error **errp);
void visit_type_intList(Visitor *v, intList **obj, const char *name, Error **errp);
void visit_type_numberList(Visitor *v, numberList **obj, const char *name, Error **errp);
void visit_type_sizeList(Visitor *v, sizeList **obj, const char *name, Error **errp);
void visit_type_strList(Visitor *v, strList **obj, const char *name, Error **errp);
void visit_type_uint16List(Visitor *v, uint16List **obj, const char *name, Error **errp);
void visit_type_uint32List(Visitor *v, uint32List **obj, const char *name, Error **errp);
void visit_type_uint64List(Visitor *v, uint64List **obj, const char *name, Error **errp);
void visit_type_uint8List(Visitor *v, uint8List **obj, const char *name, Error **errp);

#endif /* QAPI_VISIT_BUILTIN */

void visit_type_ErrorClass(Visitor *v, ErrorClass *obj, const char *name, Error **errp);
void visit_type_ErrorClassList(Visitor *v, ErrorClassList **obj, const char *name, Error **errp);
void visit_type_X86CPUFeatureWordInfo(Visitor *v, X86CPUFeatureWordInfo **obj, const char *name, Error **errp);
void visit_type_X86CPUFeatureWordInfoList(Visitor *v, X86CPUFeatureWordInfoList **obj, const char *name, Error **errp);
void visit_type_X86CPURegister32(Visitor *v, X86CPURegister32 *obj, const char *name, Error **errp);
void visit_type_X86CPURegister32List(Visitor *v, X86CPURegister32List **obj, const char *name, Error **errp);

#endif
