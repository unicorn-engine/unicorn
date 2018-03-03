/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI types
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

#ifndef QAPI_TYPES_H
#define QAPI_TYPES_H

#include "qemu/typedefs.h"
#include "unicorn/platform.h"

#ifndef QAPI_TYPES_BUILTIN
#define QAPI_TYPES_BUILTIN


typedef enum QType {
    QTYPE_NONE = 0,
    QTYPE_QNULL = 1,
    QTYPE_QNUM = 2,
    QTYPE_QSTRING = 3,
    QTYPE_QDICT = 4,
    QTYPE_QLIST = 5,
    QTYPE_QBOOL = 6,
    QTYPE__MAX = 7,
} QType;
extern const char *const QType_lookup[];

typedef struct anyList anyList;
struct anyList {
    anyList *next;
    QObject *value;
};
void qapi_free_anyList(anyList *obj);

typedef struct boolList boolList;
struct boolList {
    boolList *next;
    bool value;
};
void qapi_free_boolList(boolList *obj);

typedef struct int16List int16List;
struct int16List {
    int16List *next;
    int16_t value;
};
void qapi_free_int16List(int16List *obj);

typedef struct int32List int32List;
struct int32List {
    int32List *next;
    int32_t value;
};
void qapi_free_int32List(int32List *obj);

typedef struct int64List int64List;
struct int64List {
    int64List *next;
    int64_t value;
};
void qapi_free_int64List(int64List *obj);

typedef struct int8List int8List;
struct int8List {
    int8List *next;
    int8_t value;
};
void qapi_free_int8List(int8List *obj);

typedef struct intList intList;
struct intList {
    intList *next;
    int64_t value;
};
void qapi_free_intList(intList *obj);

typedef struct numberList numberList;
struct numberList {
    numberList *next;
    double value;
};
void qapi_free_numberList(numberList *obj);

typedef struct sizeList sizeList;
struct sizeList {
    sizeList *next;
    uint64_t value;
};
void qapi_free_sizeList(sizeList *obj);

typedef struct strList strList;
struct strList {
    strList *next;
    char *value;
};
void qapi_free_strList(strList *obj);

typedef struct uint16List uint16List;
struct uint16List {
    uint16List *next;
    uint16_t value;
};
void qapi_free_uint16List(uint16List *obj);

typedef struct uint32List uint32List;
struct uint32List {
    uint32List *next;
    uint32_t value;
};
void qapi_free_uint32List(uint32List *obj);

typedef struct uint64List uint64List;
struct uint64List {
    uint64List *next;
    uint64_t value;
};
void qapi_free_uint64List(uint64List *obj);

typedef struct uint8List uint8List;
struct uint8List {
    uint8List *next;
    uint8_t value;
};
void qapi_free_uint8List(uint8List *obj);

#endif /* QAPI_TYPES_BUILTIN */


typedef struct DummyForceArrays DummyForceArrays;

typedef enum QapiErrorClass {
    QAPI_ERROR_CLASS_GENERICERROR = 0,
    QAPI_ERROR_CLASS_COMMANDNOTFOUND = 1,
    QAPI_ERROR_CLASS_DEVICEENCRYPTED = 2,
    QAPI_ERROR_CLASS_DEVICENOTACTIVE = 3,
    QAPI_ERROR_CLASS_DEVICENOTFOUND = 4,
    QAPI_ERROR_CLASS_KVMMISSINGCAP = 5,
    QAPI_ERROR_CLASS__MAX = 6,
} QapiErrorClass;
extern const char *const QapiErrorClass_lookup[];

typedef struct X86CPUFeatureWordInfo X86CPUFeatureWordInfo;

typedef struct X86CPUFeatureWordInfoList X86CPUFeatureWordInfoList;

typedef enum X86CPURegister32 {
    X86_CPU_REGISTER32_EAX = 0,
    X86_CPU_REGISTER32_EBX = 1,
    X86_CPU_REGISTER32_ECX = 2,
    X86_CPU_REGISTER32_EDX = 3,
    X86_CPU_REGISTER32_ESP = 4,
    X86_CPU_REGISTER32_EBP = 5,
    X86_CPU_REGISTER32_ESI = 6,
    X86_CPU_REGISTER32_EDI = 7,
    X86_CPU_REGISTER32__MAX = 8,
} X86CPURegister32;
extern const char *const X86CPURegister32_lookup[];

struct DummyForceArrays {
    X86CPUFeatureWordInfoList *unused;
};
void qapi_free_DummyForceArrays(DummyForceArrays *obj);

struct X86CPUFeatureWordInfo {
    int64_t cpuid_input_eax;
    bool has_cpuid_input_ecx;
    int64_t cpuid_input_ecx;
    X86CPURegister32 cpuid_register;
    int64_t features;
};
void qapi_free_X86CPUFeatureWordInfo(X86CPUFeatureWordInfo *obj);
struct X86CPUFeatureWordInfoList {
    X86CPUFeatureWordInfoList *next;
    X86CPUFeatureWordInfo *value;
};
void qapi_free_X86CPUFeatureWordInfoList(X86CPUFeatureWordInfoList *obj);

#endif
