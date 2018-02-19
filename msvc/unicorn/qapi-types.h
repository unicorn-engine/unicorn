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

#ifndef QAPI_TYPES_BUILTIN
#define QAPI_TYPES_BUILTIN


typedef struct boolList boolList;
struct boolList {
    union {
        bool value;
        uint64_t padding;
    };
    struct boolList *next;
};
void qapi_free_boolList(boolList *obj);

typedef struct int16List int16List;
struct int16List {
    union {
        int16_t value;
        uint64_t padding;
    };
    struct int16List *next;
};
void qapi_free_int16List(int16List *obj);

typedef struct int32List int32List;
struct int32List {
    union {
        int32_t value;
        uint64_t padding;
    };
    struct int32List *next;
};
void qapi_free_int32List(int32List *obj);

typedef struct int64List int64List;
struct int64List {
    union {
        int64_t value;
        uint64_t padding;
    };
    struct int64List *next;
};
void qapi_free_int64List(int64List *obj);

typedef struct int8List int8List;
struct int8List {
    union {
        int8_t value;
        uint64_t padding;
    };
    struct int8List *next;
};
void qapi_free_int8List(int8List *obj);

typedef struct intList intList;
struct intList {
    union {
        int64_t value;
        uint64_t padding;
    };
    struct intList *next;
};
void qapi_free_intList(intList *obj);

typedef struct numberList numberList;
struct numberList {
    union {
        double value;
        uint64_t padding;
    };
    struct numberList *next;
};
void qapi_free_numberList(numberList *obj);

typedef struct sizeList sizeList;
struct sizeList {
    union {
        uint64_t value;
        uint64_t padding;
    };
    struct sizeList *next;
};
void qapi_free_sizeList(sizeList *obj);

typedef struct strList strList;
struct strList {
    union {
        char *value;
        uint64_t padding;
    };
    struct strList *next;
};
void qapi_free_strList(strList *obj);

typedef struct uint16List uint16List;
struct uint16List {
    union {
        uint16_t value;
        uint64_t padding;
    };
    struct uint16List *next;
};
void qapi_free_uint16List(uint16List *obj);

typedef struct uint32List uint32List;
struct uint32List {
    union {
        uint32_t value;
        uint64_t padding;
    };
    struct uint32List *next;
};
void qapi_free_uint32List(uint32List *obj);

typedef struct uint64List uint64List;
struct uint64List {
    union {
        uint64_t value;
        uint64_t padding;
    };
    struct uint64List *next;
};
void qapi_free_uint64List(uint64List *obj);

typedef struct uint8List uint8List;
struct uint8List {
    union {
        uint8_t value;
        uint64_t padding;
    };
    struct uint8List *next;
};
void qapi_free_uint8List(uint8List *obj);

#endif /* QAPI_TYPES_BUILTIN */

typedef enum ErrorClass {
    ERROR_CLASS_GENERIC_ERROR = 0,
    ERROR_CLASS_COMMAND_NOT_FOUND = 1,
    ERROR_CLASS_DEVICE_ENCRYPTED = 2,
    ERROR_CLASS_DEVICE_NOT_ACTIVE = 3,
    ERROR_CLASS_DEVICE_NOT_FOUND = 4,
    ERROR_CLASS_KVM_MISSING_CAP = 5,
    ERROR_CLASS_MAX = 6,
} ErrorClass;
extern const char *const ErrorClass_lookup[];

typedef struct ErrorClassList ErrorClassList;

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
    X86_CPU_REGISTER32_MAX = 8,
} X86CPURegister32;
extern const char *const X86CPURegister32_lookup[];

typedef struct X86CPURegister32List X86CPURegister32List;
struct ErrorClassList {
    union {
        ErrorClass value;
        uint64_t padding;
    };
    struct ErrorClassList *next;
};
void qapi_free_ErrorClassList(ErrorClassList *obj);
struct X86CPUFeatureWordInfo {
    int64_t cpuid_input_eax;
    bool has_cpuid_input_ecx;
    int64_t cpuid_input_ecx;
    X86CPURegister32 cpuid_register;
    int64_t features;
};
void qapi_free_X86CPUFeatureWordInfo(X86CPUFeatureWordInfo *obj);
struct X86CPUFeatureWordInfoList {
    union {
        X86CPUFeatureWordInfo *value;
        uint64_t padding;
    };
    struct X86CPUFeatureWordInfoList *next;
};
void qapi_free_X86CPUFeatureWordInfoList(X86CPUFeatureWordInfoList *obj);
struct X86CPURegister32List {
    union {
        X86CPURegister32 value;
        uint64_t padding;
    };
    struct X86CPURegister32List *next;
};
void qapi_free_X86CPURegister32List(X86CPURegister32List *obj);

#endif
