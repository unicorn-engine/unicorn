/*
 * RH850 Emulation Helpers for QEMU.
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

#include "exec/exec-all.h"

/* Exceptions processing helpers */
void QEMU_NORETURN do_raise_exception_err(CPURH850State *env,
                                          uint32_t exception, uintptr_t pc)
{
    CPUState *cs = CPU(rh850_env_get_cpu(env));
    qemu_log_mask(CPU_LOG_INT, "%s: %d\n", __func__, exception);
    cs->exception_index = exception;
    cpu_loop_exit_restore(cs, pc);
}

void QEMU_NORETURN do_raise_exception_err_with_cause(CPURH850State *env,
                                          uint32_t exception, uint32_t cause, uintptr_t pc)
{
    CPUState *cs = CPU(rh850_env_get_cpu(env));
    //qemu_log_mask(CPU_LOG_INT, "%s: %d\n", __func__, exception);
    cs->exception_index = exception;
    env->exception_cause = cause; 
    cpu_loop_exit_restore(cs, pc);
}


void helper_raise_exception(CPURH850State *env, uint32_t exception)
{
    do_raise_exception_err(env, exception, 0);
}

void helper_raise_exception_with_cause(CPURH850State *env, uint32_t exception, uint32_t cause)
{
    do_raise_exception_err_with_cause(env, exception, cause, 0);
}
