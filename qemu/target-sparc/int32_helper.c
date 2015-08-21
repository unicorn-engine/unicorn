/*
 * Sparc32 interrupt helpers
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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

#include "cpu.h"
#include "sysemu/sysemu.h"


void sparc_cpu_do_interrupt(CPUState *cs)
{
    SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);
    CPUSPARCState *env = &cpu->env;
    int cwp, intno = cs->exception_index;

    /* Compute PSR before exposing state.  */
    if (env->cc_op != CC_OP_FLAGS) {
        cpu_get_psr(env);
    }

#if !defined(CONFIG_USER_ONLY)
    if (env->psret == 0) {
        if (cs->exception_index == 0x80 &&
            env->def->features & CPU_FEATURE_TA0_SHUTDOWN) {
            qemu_system_shutdown_request();
        } else {
            cpu_abort(cs, "Trap 0x%02x while interrupts disabled, Error state",
                      cs->exception_index);
        }
        return;
    }
#endif
    env->psret = 0;
    cwp = cpu_cwp_dec(env, env->cwp - 1);
    cpu_set_cwp(env, cwp);
    env->regwptr[9] = env->pc;
    env->regwptr[10] = env->npc;
    env->psrps = env->psrs;
    env->psrs = 1;
    env->tbr = (env->tbr & TBR_BASE_MASK) | (intno << 4);
    env->pc = env->tbr;
    env->npc = env->pc + 4;
    cs->exception_index = -1;
}

#if !defined(CONFIG_USER_ONLY)
static void leon3_cache_control_int(CPUSPARCState *env)
{
    uint32_t state = 0;

    if (env->cache_control & CACHE_CTRL_IF) {
        /* Instruction cache state */
        state = env->cache_control & CACHE_STATE_MASK;
        if (state == CACHE_ENABLED) {
            state = CACHE_FROZEN;
            //trace_int_helper_icache_freeze();
        }

        env->cache_control &= ~CACHE_STATE_MASK;
        env->cache_control |= state;
    }

    if (env->cache_control & CACHE_CTRL_DF) {
        /* Data cache state */
        state = (env->cache_control >> 2) & CACHE_STATE_MASK;
        if (state == CACHE_ENABLED) {
            state = CACHE_FROZEN;
            //trace_int_helper_dcache_freeze();
        }

        env->cache_control &= ~(CACHE_STATE_MASK << 2);
        env->cache_control |= (state << 2);
    }
}

void leon3_irq_manager(CPUSPARCState *env, void *irq_manager, int intno)
{
    //leon3_irq_ack(irq_manager, intno);
    leon3_cache_control_int(env);
}
#endif
