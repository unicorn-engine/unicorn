/*
 * Sparc64 interrupt helpers
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
#include "exec/helper-proto.h"


void sparc_cpu_do_interrupt(CPUState *cs)
{
    SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);
    CPUSPARCState *env = &cpu->env;
    int intno = cs->exception_index;
    trap_state *tsptr;

    /* Compute PSR before exposing state.  */
    if (env->cc_op != CC_OP_FLAGS) {
        cpu_get_psr(env);
    }

#if !defined(CONFIG_USER_ONLY)
    if (env->tl >= env->maxtl) {
        cpu_abort(cs, "Trap 0x%04x while trap level (%d) >= MAXTL (%d),"
                  " Error state", cs->exception_index, env->tl, env->maxtl);
        return;
    }
#endif
    if (env->tl < env->maxtl - 1) {
        env->tl++;
    } else {
        env->pstate |= PS_RED;
        if (env->tl < env->maxtl) {
            env->tl++;
        }
    }
    tsptr = cpu_tsptr(env);

    tsptr->tstate = (cpu_get_ccr(env) << 32) |
        ((env->asi & 0xff) << 24) | ((env->pstate & 0xf3f) << 8) |
        cpu_get_cwp64(env);
    tsptr->tpc = env->pc;
    tsptr->tnpc = env->npc;
    tsptr->tt = intno;

    switch (intno) {
    case TT_IVEC:
        cpu_change_pstate(env, PS_PEF | PS_PRIV | PS_IG);
        break;
    case TT_TFAULT:
    case TT_DFAULT:
    case TT_TMISS: case TT_TMISS+1: case TT_TMISS+2: case TT_TMISS+3:
    case TT_DMISS: case TT_DMISS+1: case TT_DMISS+2: case TT_DMISS+3:
    case TT_DPROT: case TT_DPROT+1: case TT_DPROT+2: case TT_DPROT+3:
        cpu_change_pstate(env, PS_PEF | PS_PRIV | PS_MG);
        break;
    default:
        cpu_change_pstate(env, PS_PEF | PS_PRIV | PS_AG);
        break;
    }

    if (intno == TT_CLRWIN) {
        cpu_set_cwp(env, cpu_cwp_dec(env, env->cwp - 1));
    } else if ((intno & 0x1c0) == TT_SPILL) {
        cpu_set_cwp(env, cpu_cwp_dec(env, env->cwp - env->cansave - 2));
    } else if ((intno & 0x1c0) == TT_FILL) {
        cpu_set_cwp(env, cpu_cwp_inc(env, env->cwp + 1));
    }
    env->tbr &= ~0x7fffULL;
    env->tbr |= ((env->tl > 1) ? 1 << 14 : 0) | (intno << 5);
    env->pc = env->tbr;
    env->npc = env->pc + 4;
    cs->exception_index = -1;
}

trap_state *cpu_tsptr(CPUSPARCState* env)
{
    return &env->ts[env->tl & MAXTL_MASK];
}

static bool do_modify_softint(CPUSPARCState *env, uint32_t value)
{
    if (env->softint != value) {
        env->softint = value;
#if !defined(CONFIG_USER_ONLY)
        if (cpu_interrupts_enabled(env)) {
            //cpu_check_irqs(env);
        }
#endif
        return true;
    }
    return false;
}

void helper_set_softint(CPUSPARCState *env, uint64_t value)
{
    if (do_modify_softint(env, env->softint | (uint32_t)value)) {
        //trace_int_helper_set_softint(env->softint);
    }
}

void helper_clear_softint(CPUSPARCState *env, uint64_t value)
{
    if (do_modify_softint(env, env->softint & (uint32_t)~value)) {
        //trace_int_helper_clear_softint(env->softint);
    }
}

void helper_write_softint(CPUSPARCState *env, uint64_t value)
{
    if (do_modify_softint(env, (uint32_t)value)) {
        //trace_int_helper_write_softint(env->softint);
    }
}
