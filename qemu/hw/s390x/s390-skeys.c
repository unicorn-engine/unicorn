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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "target/s390x/cpu.h"
#include "hw/s390x/storage-keys.h"

#define S390_SKEYS_BUFFER_SIZE (128 * KiB)  /* Room for 128k storage keys */
#define S390_SKEYS_SAVE_FLAG_EOS 0x01
#define S390_SKEYS_SAVE_FLAG_SKEYS 0x02
#define S390_SKEYS_SAVE_FLAG_ERROR 0x04

static void s390_skeys_class_init(uc_engine *uc, S390SKeysClass* class);
static void qemu_s390_skeys_class_init(uc_engine *uc, S390SKeysClass* skeyclass);
static void s390_skeys_instance_init(uc_engine *uc, S390SKeysState* ss);
static void qemu_s390_skeys_init(uc_engine *uc, QEMUS390SKeysState *skey);

void s390_skeys_init(uc_engine *uc)
{
    S390CPU *cpu = S390_CPU(uc->cpu);

    s390_skeys_class_init(uc, &cpu->skey);
    qemu_s390_skeys_class_init(uc, &cpu->skey);

    s390_skeys_instance_init(uc, (S390SKeysState*)&cpu->ss);
    qemu_s390_skeys_init(uc, &cpu->ss);

    cpu->ss.class = &cpu->skey;
}

static void qemu_s390_skeys_init(uc_engine *uc, QEMUS390SKeysState *skeys)
{
    //QEMUS390SKeysState *skeys = QEMU_S390_SKEYS(obj);
    //MachineState *machine = MACHINE(qdev_get_machine());

    //skeys->key_count = machine->ram_size / TARGET_PAGE_SIZE;
    // Unicorn: Allow users to configure this value?
    skeys->key_count = 0x20000000 / TARGET_PAGE_SIZE;
    skeys->keydata = g_malloc0(skeys->key_count);
}

static int qemu_s390_skeys_enabled(S390SKeysState *ss)
{
    return 1;
}

/*
 * TODO: for memory hotplug support qemu_s390_skeys_set and qemu_s390_skeys_get
 * will have to make sure that the given gfn belongs to a memory region and not
 * a memory hole.
 */
static int qemu_s390_skeys_set(S390SKeysState *ss, uint64_t start_gfn,
                              uint64_t count, uint8_t *keys)
{
    QEMUS390SKeysState *skeydev = QEMU_S390_SKEYS(ss);
    int i;

    /* Check for uint64 overflow and access beyond end of key data */
    if (start_gfn + count > skeydev->key_count || start_gfn + count < count) {
        // error_report("Error: Setting storage keys for page beyond the end "
        //              "of memory: gfn=%" PRIx64 " count=%" PRId64,
        //              start_gfn, count);
        return -EINVAL;
    }

    for (i = 0; i < count; i++) {
        skeydev->keydata[start_gfn + i] = keys[i];
    }
    return 0;
}

static int qemu_s390_skeys_get(S390SKeysState *ss, uint64_t start_gfn,
                               uint64_t count, uint8_t *keys)
{
    QEMUS390SKeysState *skeydev = QEMU_S390_SKEYS(ss);
    int i;

    /* Check for uint64 overflow and access beyond end of key data */
    if (start_gfn + count > skeydev->key_count || start_gfn + count < count) {
        // error_report("Error: Getting storage keys for page beyond the end "
        //              "of memory: gfn=%" PRIx64 " count=%" PRId64,
        //              start_gfn, count);
        return -EINVAL;
    }

    for (i = 0; i < count; i++) {
        keys[i] = skeydev->keydata[start_gfn + i];
    }
    return 0;
}

static void qemu_s390_skeys_class_init(uc_engine *uc, S390SKeysClass* skeyclass)
{
    // S390SKeysClass *skeyclass = S390_SKEYS_CLASS(oc);
    // DeviceClass *dc = DEVICE_CLASS(oc);

    skeyclass->skeys_enabled = qemu_s390_skeys_enabled;
    skeyclass->get_skeys = qemu_s390_skeys_get;
    skeyclass->set_skeys = qemu_s390_skeys_set;

    /* Reason: Internal device (only one skeys device for the whole memory) */
    // dc->user_creatable = false;
}

static void s390_skeys_instance_init(uc_engine *uc, S390SKeysState* ss)
{
    ss->migration_enabled = true;
}

static void s390_skeys_class_init(uc_engine *uc, S390SKeysClass* class)
{
    // DeviceClass *dc = DEVICE_CLASS(oc);

    // dc->hotpluggable = false;
    // set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}
