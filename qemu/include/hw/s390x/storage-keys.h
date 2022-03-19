/*
 * s390 storage key device
 *
 * Copyright 2015 IBM Corp.
 * Author(s): Jason J. Herne <jjherne@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#ifndef S390_STORAGE_KEYS_H
#define S390_STORAGE_KEYS_H

#include "uc_priv.h"

/*
#define TYPE_S390_SKEYS "s390-skeys"
#define S390_SKEYS(obj) \
    OBJECT_CHECK(S390SKeysState, (obj), TYPE_S390_SKEYS)

#define S390_CPU(obj) \
    OBJECT_CHECK(S390CPU, (obj), TYPE_S390_CPU)
#define S390_CPU(obj) ((S390CPU *)obj)
*/

typedef struct S390SKeysState {
    //CPUState parent_obj;
    bool migration_enabled; // Unicorn: Dummy struct member
} S390SKeysState;

/*
#define S390_SKEYS_CLASS(klass) \
    OBJECT_CLASS_CHECK(S390SKeysClass, (klass), TYPE_S390_SKEYS)
*/
#define S390_SKEYS_CLASS(klass) ((S390SKeysClass *)klass)

/*
#define S390_SKEYS_GET_CLASS(obj) \
    OBJECT_GET_CLASS(S390SKeysClass, (obj), TYPE_S390_SKEYS)
*/
#define S390_SKEYS_GET_CLASS(obj) (((QEMUS390SKeysState *)obj)->class)


typedef struct S390SKeysClass {
    //CPUClass parent_class;
    int (*skeys_enabled)(S390SKeysState *ks);
    int (*get_skeys)(S390SKeysState *ks, uint64_t start_gfn, uint64_t count,
                     uint8_t *keys);
    int (*set_skeys)(S390SKeysState *ks, uint64_t start_gfn, uint64_t count,
                     uint8_t *keys);
} S390SKeysClass;

#define TYPE_KVM_S390_SKEYS "s390-skeys-kvm"
#define TYPE_QEMU_S390_SKEYS "s390-skeys-qemu"
#define QEMU_S390_SKEYS(obj) \
    (QEMUS390SKeysState*)(obj)
typedef struct QEMUS390SKeysState {
    S390SKeysState parent_obj;
    uint8_t *keydata;
    uint32_t key_count;

    // Unicorn
    S390SKeysClass *class;
} QEMUS390SKeysState;

void s390_skeys_init(uc_engine *uc);

#endif /* S390_STORAGE_KEYS_H */
