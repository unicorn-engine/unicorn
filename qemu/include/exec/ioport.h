/*
 * defines ioport related functions
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

/**************************************************************************
 * IO ports API
 */

#ifndef IOPORT_H
#define IOPORT_H

#include "qemu-common.h"
#include "exec/memory.h"

typedef uint32_t pio_addr_t;

void cpu_outb(struct uc_struct *uc, pio_addr_t addr, uint8_t val);
void cpu_outw(struct uc_struct *uc, pio_addr_t addr, uint16_t val);
void cpu_outl(struct uc_struct *uc, pio_addr_t addr, uint32_t val);
uint8_t cpu_inb(struct uc_struct *uc, pio_addr_t addr);
uint16_t cpu_inw(struct uc_struct *uc, pio_addr_t addr);
uint32_t cpu_inl(struct uc_struct *uc, pio_addr_t addr);

#endif /* IOPORT_H */
