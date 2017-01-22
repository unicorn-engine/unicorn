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

#include "unicorn/platform.h"


#ifndef QAPI_TYPES_BUILTIN_STRUCT_DECL_H
#define QAPI_TYPES_BUILTIN_STRUCT_DECL_H


typedef struct strList
{
    union {
        char *value;
        uint64_t padding;
    };
    struct strList *next;
} strList;

typedef struct intList
{
    union {
        int64_t value;
        uint64_t padding;
    };
    struct intList *next;
} intList;

typedef struct numberList
{
    union {
        double value;
        uint64_t padding;
    };
    struct numberList *next;
} numberList;

typedef struct boolList
{
    union {
        bool value;
        uint64_t padding;
    };
    struct boolList *next;
} boolList;

typedef struct int8List
{
    union {
        int8_t value;
        uint64_t padding;
    };
    struct int8List *next;
} int8List;

typedef struct int16List
{
    union {
        int16_t value;
        uint64_t padding;
    };
    struct int16List *next;
} int16List;

typedef struct int32List
{
    union {
        int32_t value;
        uint64_t padding;
    };
    struct int32List *next;
} int32List;

typedef struct int64List
{
    union {
        int64_t value;
        uint64_t padding;
    };
    struct int64List *next;
} int64List;

typedef struct uint8List
{
    union {
        uint8_t value;
        uint64_t padding;
    };
    struct uint8List *next;
} uint8List;

typedef struct uint16List
{
    union {
        uint16_t value;
        uint64_t padding;
    };
    struct uint16List *next;
} uint16List;

typedef struct uint32List
{
    union {
        uint32_t value;
        uint64_t padding;
    };
    struct uint32List *next;
} uint32List;

typedef struct uint64List
{
    union {
        uint64_t value;
        uint64_t padding;
    };
    struct uint64List *next;
} uint64List;

#endif /* QAPI_TYPES_BUILTIN_STRUCT_DECL_H */


extern const char *ErrorClass_lookup[];
typedef enum ErrorClass
{
    ERROR_CLASS_GENERIC_ERROR = 0,
    ERROR_CLASS_COMMAND_NOT_FOUND = 1,
    ERROR_CLASS_DEVICE_ENCRYPTED = 2,
    ERROR_CLASS_DEVICE_NOT_ACTIVE = 3,
    ERROR_CLASS_DEVICE_NOT_FOUND = 4,
    ERROR_CLASS_KVM_MISSING_CAP = 5,
    ERROR_CLASS_MAX = 6,
} ErrorClass;

typedef struct ErrorClassList
{
    union {
        ErrorClass value;
        uint64_t padding;
    };
    struct ErrorClassList *next;
} ErrorClassList;

extern const char *X86CPURegister32_lookup[];
typedef enum X86CPURegister32
{
    X86_CPU_REGISTER32_EAX = 0,
    X86_CPU_REGISTER32_EBX = 1,
    X86_CPU_REGISTER32_ECX = 2,
    X86_CPU_REGISTER32_EDX = 3,
    X86_CPU_REGISTER32_ESP = 4,
    X86_CPU_REGISTER32_EBP = 5,
    X86_CPU_REGISTER32_ESI = 6,
    X86_CPU_REGISTER32_EDI = 7,
    X86_CPU_REGISTER32_MAX = 8,
} X86CPURegister32;

typedef struct X86CPURegister32List
{
    union {
        X86CPURegister32 value;
        uint64_t padding;
    };
    struct X86CPURegister32List *next;
} X86CPURegister32List;


typedef struct X86CPUFeatureWordInfo X86CPUFeatureWordInfo;

typedef struct X86CPUFeatureWordInfoList
{
    union {
        X86CPUFeatureWordInfo *value;
        uint64_t padding;
    };
    struct X86CPUFeatureWordInfoList *next;
} X86CPUFeatureWordInfoList;

#ifndef QAPI_TYPES_BUILTIN_CLEANUP_DECL_H
#define QAPI_TYPES_BUILTIN_CLEANUP_DECL_H

void qapi_free_strList(strList *obj);
void qapi_free_intList(intList *obj);
void qapi_free_numberList(numberList *obj);
void qapi_free_boolList(boolList *obj);
void qapi_free_int8List(int8List *obj);
void qapi_free_int16List(int16List *obj);
void qapi_free_int32List(int32List *obj);
void qapi_free_int64List(int64List *obj);
void qapi_free_uint8List(uint8List *obj);
void qapi_free_uint16List(uint16List *obj);
void qapi_free_uint32List(uint32List *obj);
void qapi_free_uint64List(uint64List *obj);

#endif /* QAPI_TYPES_BUILTIN_CLEANUP_DECL_H */


void qapi_free_ErrorClassList(ErrorClassList *obj);

void qapi_free_X86CPURegister32List(X86CPURegister32List *obj);

struct X86CPUFeatureWordInfo
{
    int64_t cpuid_input_eax;
    bool has_cpuid_input_ecx;
    int64_t cpuid_input_ecx;
    X86CPURegister32 cpuid_register;
    int64_t features;
};

void qapi_free_X86CPUFeatureWordInfoList(X86CPUFeatureWordInfoList *obj);
void qapi_free_X86CPUFeatureWordInfo(X86CPUFeatureWordInfo *obj);

#endif
