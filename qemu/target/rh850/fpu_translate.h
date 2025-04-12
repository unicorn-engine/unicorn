/*
 * QEMU RH850 CPU
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RH850_FPU_H
#define RH850_FPU_H

#include "cpu.h"
#include "translate.h"

void fpu_decode_cat0_instn(CPURH850State *env, DisasContext *ctx);
void fpu_decode_cat1_instn(CPURH850State *env, DisasContext *ctx);

#endif /* RH850_FPU_H */
