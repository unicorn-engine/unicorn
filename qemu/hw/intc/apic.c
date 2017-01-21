/*
 *  APIC support
 *
 *  Copyright (c) 2004-2005 Fabrice Bellard
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
#include "qemu/thread.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/apic.h"
#include "qemu/host-utils.h"
#include "hw/i386/pc.h"

#include "exec/address-spaces.h"

#define MAX_APIC_WORDS 8

#define SYNC_FROM_VAPIC                 0x1
#define SYNC_TO_VAPIC                   0x2
#define SYNC_ISR_IRR_TO_VAPIC           0x4

static void apic_update_irq(APICCommonState *s);

/* Find first bit starting from msb */
static int apic_fls_bit(uint32_t value)
{
    return 31 - clz32(value);
}

/* return -1 if no bit is set */
static int get_highest_priority_int(uint32_t *tab)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (tab[i] != 0) {
            return i * 32 + apic_fls_bit(tab[i]);
        }
    }
    return -1;
}

static void apic_sync_vapic(APICCommonState *s, int sync_type)
{
    VAPICState vapic_state;
    //size_t length;
    //off_t start;
    int vector;

    if (!s->vapic_paddr) {
        return;
    }
    if (sync_type & SYNC_FROM_VAPIC) {
        cpu_physical_memory_read(NULL, s->vapic_paddr, &vapic_state,
                                 sizeof(vapic_state));
        s->tpr = vapic_state.tpr;
    }
    if (sync_type & (SYNC_TO_VAPIC | SYNC_ISR_IRR_TO_VAPIC)) {
        //start = offsetof(VAPICState, isr);
        //length = offsetof(VAPICState, enabled) - offsetof(VAPICState, isr);

        if (sync_type & SYNC_TO_VAPIC) {

            vapic_state.tpr = s->tpr;
            vapic_state.enabled = 1;
            //start = 0;
            //length = sizeof(VAPICState);
        }

        vector = get_highest_priority_int(s->isr);
        if (vector < 0) {
            vector = 0;
        }
        vapic_state.isr = vector & 0xf0;

        vapic_state.zero = 0;

        vector = get_highest_priority_int(s->irr);
        if (vector < 0) {
            vector = 0;
        }
        vapic_state.irr = vector & 0xff;

        //cpu_physical_memory_write_rom(&address_space_memory,
        //                              s->vapic_paddr + start,
        //                              ((void *)&vapic_state) + start, length);
        // FIXME qq
    }
}

static void apic_vapic_base_update(APICCommonState *s)
{
    apic_sync_vapic(s, SYNC_TO_VAPIC);
}

#define foreach_apic(apic, deliver_bitmask, code) \
{\
    int __i, __j;\
    for(__i = 0; __i < MAX_APIC_WORDS; __i++) {\
        uint32_t __mask = deliver_bitmask[__i];\
        if (__mask) {\
            for(__j = 0; __j < 32; __j++) {\
                if (__mask & (1U << __j)) {\
                    apic = local_apics[__i * 32 + __j];\
                    if (apic) {\
                        code;\
                    }\
                }\
            }\
        }\
    }\
}

static void apic_set_base(APICCommonState *s, uint64_t val)
{
    s->apicbase = (val & 0xfffff000) |
        (s->apicbase & (MSR_IA32_APICBASE_BSP | MSR_IA32_APICBASE_ENABLE));
    /* if disabled, cannot be enabled again */
    if (!(val & MSR_IA32_APICBASE_ENABLE)) {
        s->apicbase &= ~MSR_IA32_APICBASE_ENABLE;
        cpu_clear_apic_feature(&s->cpu->env);
        s->spurious_vec &= ~APIC_SV_ENABLE;
    }
}

static void apic_set_tpr(APICCommonState *s, uint8_t val)
{
    /* Updates from cr8 are ignored while the VAPIC is active */
    if (!s->vapic_paddr) {
        s->tpr = val << 4;
        apic_update_irq(s);
    }
}

static uint8_t apic_get_tpr(APICCommonState *s)
{
    apic_sync_vapic(s, SYNC_FROM_VAPIC);
    return s->tpr >> 4;
}

/* signal the CPU if an irq is pending */
static void apic_update_irq(APICCommonState *s)
{
}

void apic_poll_irq(DeviceState *dev)
{
}

void apic_sipi(DeviceState *dev)
{
}

int apic_get_interrupt(DeviceState *dev)
{
    return 0;
}

int apic_accept_pic_intr(DeviceState *dev)
{
    return 0;
}

static void apic_pre_save(APICCommonState *s)
{
    apic_sync_vapic(s, SYNC_FROM_VAPIC);
}

static void apic_post_load(APICCommonState *s)
{
#if 0
    if (s->timer_expiry != -1) {
        timer_mod(s->timer, s->timer_expiry);
    } else {
        timer_del(s->timer);
    }
#endif
}

static int apic_realize(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    return 0;
}

static void apic_class_init(struct uc_struct *uc, ObjectClass *klass, void *data)
{
    APICCommonClass *k = APIC_COMMON_CLASS(uc, klass);

    k->realize = apic_realize;
    k->set_base = apic_set_base;
    k->set_tpr = apic_set_tpr;
    k->get_tpr = apic_get_tpr;
    k->vapic_base_update = apic_vapic_base_update;
    k->pre_save = apic_pre_save;
    k->post_load = apic_post_load;
    //printf("... init apic class\n");
}

static const TypeInfo apic_info = {
    "apic",
    TYPE_APIC_COMMON,

    0,
    sizeof(APICCommonState),
    NULL,

    NULL,
    NULL,
    NULL,

    NULL,

    apic_class_init,
};

void apic_register_types(struct uc_struct *uc)
{
    //printf("... register apic types\n");
    type_register_static(uc, &apic_info);
}
