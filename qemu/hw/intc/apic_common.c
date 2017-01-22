/*
 *  APIC support - common bits of emulated and KVM kernel model
 *
 *  Copyright (c) 2004-2005 Fabrice Bellard
 *  Copyright (c) 2011      Jan Kiszka, Siemens AG
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */
#include "hw/i386/apic.h"
#include "hw/i386/apic_internal.h"
#include "hw/qdev.h"

#include "uc_priv.h"


void cpu_set_apic_base(struct uc_struct *uc, DeviceState *dev, uint64_t val)
{
    if (dev) {
        APICCommonState *s = APIC_COMMON(uc, dev);
        APICCommonClass *info = APIC_COMMON_GET_CLASS(uc, s);
        info->set_base(s, val);
    }
}

uint64_t cpu_get_apic_base(struct uc_struct *uc, DeviceState *dev)
{
    if (dev) {
        APICCommonState *s = APIC_COMMON(uc, dev);
        return s->apicbase;
    } else {
        return MSR_IA32_APICBASE_BSP;
    }
}

void cpu_set_apic_tpr(struct uc_struct *uc, DeviceState *dev, uint8_t val)
{
    APICCommonState *s;
    APICCommonClass *info;

    if (!dev) {
        return;
    }

    s = APIC_COMMON(uc, dev);
    info = APIC_COMMON_GET_CLASS(uc, s);

    info->set_tpr(s, val);
}

uint8_t cpu_get_apic_tpr(struct uc_struct *uc, DeviceState *dev)
{
    APICCommonState *s;
    APICCommonClass *info;

    if (!dev) {
        return 0;
    }

    s = APIC_COMMON(uc, dev);
    info = APIC_COMMON_GET_CLASS(uc, s);

    return info->get_tpr(s);
}

void apic_enable_vapic(struct uc_struct *uc, DeviceState *dev, hwaddr paddr)
{
    APICCommonState *s = APIC_COMMON(uc, dev);
    APICCommonClass *info = APIC_COMMON_GET_CLASS(uc, s);

    s->vapic_paddr = paddr;
    info->vapic_base_update(s);
}

void apic_handle_tpr_access_report(DeviceState *dev, target_ulong ip,
                                   TPRAccess access)
{
    //APICCommonState *s = APIC_COMMON(NULL, dev);

    //vapic_report_tpr_access(s->vapic, CPU(s->cpu), ip, access);
}

bool apic_next_timer(APICCommonState *s, int64_t current_time)
{
    int64_t d;

    /* We need to store the timer state separately to support APIC
     * implementations that maintain a non-QEMU timer, e.g. inside the
     * host kernel. This open-coded state allows us to migrate between
     * both models. */
    s->timer_expiry = -1;

    if (s->lvt[APIC_LVT_TIMER] & APIC_LVT_MASKED) {
        return false;
    }

    d = (current_time - s->initial_count_load_time) >> s->count_shift;

    if (s->lvt[APIC_LVT_TIMER] & APIC_LVT_TIMER_PERIODIC) {
        if (!s->initial_count) {
            return false;
        }
        d = ((d / ((uint64_t)s->initial_count + 1)) + 1) *
            ((uint64_t)s->initial_count + 1);
    } else {
        if (d >= s->initial_count) {
            return false;
        }
        d = (uint64_t)s->initial_count + 1;
    }
    s->next_time = s->initial_count_load_time + (d << s->count_shift);
    s->timer_expiry = s->next_time;
    return true;
}

void apic_init_reset(struct uc_struct *uc, DeviceState *dev)
{
    APICCommonState *s = APIC_COMMON(uc, dev);
    APICCommonClass *info = APIC_COMMON_GET_CLASS(uc, s);
    int i;

    if (!s) {
        return;
    }
    s->tpr = 0;
    s->spurious_vec = 0xff;
    s->log_dest = 0;
    s->dest_mode = 0xf;
    memset(s->isr, 0, sizeof(s->isr));
    memset(s->tmr, 0, sizeof(s->tmr));
    memset(s->irr, 0, sizeof(s->irr));
    for (i = 0; i < APIC_LVT_NB; i++) {
        s->lvt[i] = APIC_LVT_MASKED;
    }
    s->esr = 0;
    memset(s->icr, 0, sizeof(s->icr));
    s->divide_conf = 0;
    s->count_shift = 0;
    s->initial_count = 0;
    s->initial_count_load_time = 0;
    s->next_time = 0;
    s->wait_for_sipi = !cpu_is_bsp(s->cpu);

    if (s->timer) {
        // timer_del(s->timer);
    }
    s->timer_expiry = -1;

    if (info->reset) {
        info->reset(s);
    }
}

void apic_designate_bsp(struct uc_struct *uc, DeviceState *dev)
{
    APICCommonState *s;

    if (dev == NULL) {
        return;
    }

    s = APIC_COMMON(uc, dev);
    s->apicbase |= MSR_IA32_APICBASE_BSP;
}

static void apic_reset_common(struct uc_struct *uc, DeviceState *dev)
{
    APICCommonState *s = APIC_COMMON(uc, dev);
    APICCommonClass *info = APIC_COMMON_GET_CLASS(uc, s);
    bool bsp;

    bsp = cpu_is_bsp(s->cpu);
    s->apicbase = APIC_DEFAULT_ADDRESS |
        (bsp ? MSR_IA32_APICBASE_BSP : 0) | MSR_IA32_APICBASE_ENABLE;

    s->vapic_paddr = 0;
    info->vapic_base_update(s);

    apic_init_reset(uc, dev);

    if (bsp) {
        /*
         * LINT0 delivery mode on CPU #0 is set to ExtInt at initialization
         * time typically by BIOS, so PIC interrupt can be delivered to the
         * processor when local APIC is enabled.
         */
        s->lvt[APIC_LVT_LINT0] = 0x700;
    }
}

static int apic_common_realize(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    APICCommonState *s = APIC_COMMON(uc, dev);
    APICCommonClass *info;

    if (uc->apic_no >= MAX_APICS) {
        error_setg(errp, "%s initialization failed.",
                   object_get_typename(OBJECT(dev)));
        return -1;
    }
    s->idx = uc->apic_no++;

    info = APIC_COMMON_GET_CLASS(uc, s);
    info->realize(uc, dev, errp);
    if (!uc->mmio_registered) {
        ICCBus *b = ICC_BUS(uc, qdev_get_parent_bus(dev));
        memory_region_add_subregion(b->apic_address_space, 0, &s->io_memory);
        uc->mmio_registered = true;
    }

    /* Note: We need at least 1M to map the VAPIC option ROM */
    if (!uc->vapic && s->vapic_control & VAPIC_ENABLE_MASK) {
        // ram_size >= 1024 * 1024) {	// FIXME
        uc->vapic = NULL;
    }
    s->vapic = uc->vapic;
    if (uc->apic_report_tpr_access && info->enable_tpr_reporting) {
        info->enable_tpr_reporting(s, true);
    }

    return 0;
}

static void apic_common_class_init(struct uc_struct *uc, ObjectClass *klass, void *data)
{
    ICCDeviceClass *idc = ICC_DEVICE_CLASS(uc, klass);
    DeviceClass *dc = DEVICE_CLASS(uc, klass);

    dc->reset = apic_reset_common;
    idc->realize = apic_common_realize;
    /*
     * Reason: APIC and CPU need to be wired up by
     * x86_cpu_apic_create()
     */
    dc->cannot_instantiate_with_device_add_yet = true;
    //printf("... init apic common class\n");
}

static const TypeInfo apic_common_type = {
    TYPE_APIC_COMMON,
    TYPE_DEVICE,

    sizeof(APICCommonClass),
    sizeof(APICCommonState),
    NULL,

    NULL,
    NULL,
    NULL,

    NULL,

    apic_common_class_init,
    NULL,
    NULL,

    true,
};

void apic_common_register_types(struct uc_struct *uc)
{
    //printf("... register apic common\n");
    type_register_static(uc, &apic_common_type);
}
