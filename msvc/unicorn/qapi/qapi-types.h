/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * Schema-defined QAPI types
 *
 * Copyright IBM, Corp. 2011
 * Copyright (c) 2013-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QAPI_TYPES_H
#define QAPI_TYPES_H

#include "qapi-builtin-types.h"

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

typedef struct X86CPUFeatureWordInfo X86CPUFeatureWordInfo;

typedef struct X86CPUFeatureWordInfoList X86CPUFeatureWordInfoList;

typedef struct DummyForceArrays DummyForceArrays;

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

struct DummyForceArrays {
    X86CPUFeatureWordInfoList *unused;
};

void qapi_free_DummyForceArrays(DummyForceArrays *obj);

#endif /* QAPI_TYPES_H */
