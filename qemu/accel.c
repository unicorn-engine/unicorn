/*
 * QEMU System Emulator, accelerator interfaces
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2014 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "sysemu/accel.h"
#include "hw/boards.h"
#include "qemu-common.h"
#include "sysemu/sysemu.h"
#include "qom/object.h"
#include "hw/boards.h"

// use default size for TCG translated block
#define TCG_TB_SIZE 0

static bool tcg_allowed = true;
static int tcg_init(MachineState *ms);
static AccelClass *accel_find(struct uc_struct *uc, const char *opt_name);
static int accel_init_machine(AccelClass *acc, MachineState *ms);
static void tcg_accel_class_init(struct uc_struct *uc, ObjectClass *oc, void *data);

static int tcg_init(MachineState *ms)
{
    ms->uc->tcg_exec_init(ms->uc, TCG_TB_SIZE * 1024 * 1024); // arch-dependent
    return 0;
}

static const TypeInfo accel_type = {
    TYPE_ACCEL,
    TYPE_OBJECT,
    sizeof(AccelClass),
    sizeof(AccelState),
};

#define TYPE_TCG_ACCEL ACCEL_CLASS_NAME("tcg")

static const TypeInfo tcg_accel_type = {
    TYPE_TCG_ACCEL,
    TYPE_ACCEL,
    0,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    tcg_accel_class_init,
};


int configure_accelerator(MachineState *ms)
{
    int ret;
    bool accel_initialised = false;
    AccelClass *acc;

    acc = accel_find(ms->uc, "tcg");
    ret = accel_init_machine(acc, ms);
    if (ret < 0) {
        fprintf(stderr, "failed to initialize %s: %s\n",
                acc->name,
                strerror(-ret));
    } else {
        accel_initialised = true;
    }

    return !accel_initialised;
}

void register_accel_types(struct uc_struct *uc)
{
    type_register_static(uc, &accel_type);
    type_register_static(uc, &tcg_accel_type);
}

static void tcg_accel_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(uc, oc);
    ac->name = "tcg";
    ac->init_machine = tcg_init;
    ac->allowed = &tcg_allowed;
}

/* Lookup AccelClass from opt_name. Returns NULL if not found */
static AccelClass *accel_find(struct uc_struct *uc, const char *opt_name)
{
    char *class_name = g_strdup_printf(ACCEL_CLASS_NAME("%s"), opt_name);
    AccelClass *ac = ACCEL_CLASS(uc, object_class_by_name(uc, class_name));
    g_free(class_name);
    return ac;
}

static int accel_init_machine(AccelClass *acc, MachineState *ms)
{
    ObjectClass *oc = OBJECT_CLASS(acc);
    const char *cname = object_class_get_name(oc);
    AccelState *accel = ACCEL(ms->uc, object_new(ms->uc, cname));
    int ret;
    ms->accelerator = accel;
    *(acc->allowed) = true;
    ret = acc->init_machine(ms);
    if (ret < 0) {
        ms->accelerator = NULL;
        *(acc->allowed) = false;
        object_unref(ms->uc, OBJECT(accel));
    }
    return ret;
}
