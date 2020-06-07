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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

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

