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

#include "qemu/osdep.h"
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

    if (cpu_has_hypervisor(env)) {
        env->htstate[env->tl] = env->hpstate;
        /* XXX OpenSPARC T1 - UltraSPARC T3 have MAXPTL=2
           but this may change in the future */
        if (env->tl > 2) {
            env->hpstate |= HS_PRIV;
        }
    }

    switch (intno) {
    case TT_IVEC:
        if (!cpu_has_hypervisor(env)) {
            cpu_change_pstate(env, PS_PEF | PS_PRIV | PS_IG);
        }
        break;
    case TT_TFAULT:
    case TT_DFAULT:
    case TT_TMISS: case TT_TMISS+1: case TT_TMISS+2: case TT_TMISS+3:
    case TT_DMISS: case TT_DMISS+1: case TT_DMISS+2: case TT_DMISS+3:
    case TT_DPROT: case TT_DPROT+1: case TT_DPROT+2: case TT_DPROT+3:
        if (cpu_has_hypervisor(env)) {
            env->hpstate |= HS_PRIV;
            env->pstate = PS_PEF | PS_PRIV;
        } else {
            cpu_change_pstate(env, PS_PEF | PS_PRIV | PS_MG);
        }
        break;
    case TT_INSN_REAL_TRANSLATION_MISS:
    case TT_DATA_REAL_TRANSLATION_MISS:
    case TT_HTRAP:
    case TT_HTRAP+1:
    case TT_HTRAP+2:
    case TT_HTRAP+3:
    case TT_HTRAP+4:
    case TT_HTRAP+5:
    case TT_HTRAP+6:
    case TT_HTRAP+7:
    case TT_HTRAP+8:
    case TT_HTRAP+9:
    case TT_HTRAP+10:
    case TT_HTRAP+11:
    case TT_HTRAP+12:
    case TT_HTRAP+13:
    case TT_HTRAP+14:
    case TT_HTRAP+15:
    case TT_HTRAP+16:
    case TT_HTRAP+17:
    case TT_HTRAP+18:
    case TT_HTRAP+19:
    case TT_HTRAP+20:
    case TT_HTRAP+21:
    case TT_HTRAP+22:
    case TT_HTRAP+23:
    case TT_HTRAP+24:
    case TT_HTRAP+25:
    case TT_HTRAP+26:
    case TT_HTRAP+27:
    case TT_HTRAP+28:
    case TT_HTRAP+29:
    case TT_HTRAP+30:
    case TT_HTRAP+31:
    case TT_HTRAP+32:
    case TT_HTRAP+33:
    case TT_HTRAP+34:
    case TT_HTRAP+35:
    case TT_HTRAP+36:
    case TT_HTRAP+37:
    case TT_HTRAP+38:
    case TT_HTRAP+39:
    case TT_HTRAP+40:
    case TT_HTRAP+41:
    case TT_HTRAP+42:
    case TT_HTRAP+43:
    case TT_HTRAP+44:
    case TT_HTRAP+45:
    case TT_HTRAP+46:
    case TT_HTRAP+47:
    case TT_HTRAP+48:
    case TT_HTRAP+49:
    case TT_HTRAP+50:
    case TT_HTRAP+51:
    case TT_HTRAP+52:
    case TT_HTRAP+53:
    case TT_HTRAP+54:
    case TT_HTRAP+55:
    case TT_HTRAP+56:
    case TT_HTRAP+57:
    case TT_HTRAP+58:
    case TT_HTRAP+59:
    case TT_HTRAP+60:
    case TT_HTRAP+61:
    case TT_HTRAP+62:
    case TT_HTRAP+63:
    case TT_HTRAP+64:
    case TT_HTRAP+65:
    case TT_HTRAP+66:
    case TT_HTRAP+67:
    case TT_HTRAP+68:
    case TT_HTRAP+69:
    case TT_HTRAP+70:
    case TT_HTRAP+71:
    case TT_HTRAP+72:
    case TT_HTRAP+73:
    case TT_HTRAP+74:
    case TT_HTRAP+75:
    case TT_HTRAP+76:
    case TT_HTRAP+77:
    case TT_HTRAP+78:
    case TT_HTRAP+79:
    case TT_HTRAP+80:
    case TT_HTRAP+81:
    case TT_HTRAP+82:
    case TT_HTRAP+83:
    case TT_HTRAP+84:
    case TT_HTRAP+85:
    case TT_HTRAP+86:
    case TT_HTRAP+87:
    case TT_HTRAP+88:
    case TT_HTRAP+89:
    case TT_HTRAP+90:
    case TT_HTRAP+91:
    case TT_HTRAP+92:
    case TT_HTRAP+93:
    case TT_HTRAP+94:
    case TT_HTRAP+95:
    case TT_HTRAP+96:
    case TT_HTRAP+97:
    case TT_HTRAP+98:
    case TT_HTRAP+99:
    case TT_HTRAP+100:
    case TT_HTRAP+101:
    case TT_HTRAP+102:
    case TT_HTRAP+103:
    case TT_HTRAP+104:
    case TT_HTRAP+105:
    case TT_HTRAP+106:
    case TT_HTRAP+107:
    case TT_HTRAP+108:
    case TT_HTRAP+109:
    case TT_HTRAP+110:
    case TT_HTRAP+111:
    case TT_HTRAP+112:
    case TT_HTRAP+113:
    case TT_HTRAP+114:
    case TT_HTRAP+115:
    case TT_HTRAP+116:
    case TT_HTRAP+117:
    case TT_HTRAP+118:
    case TT_HTRAP+119:
    case TT_HTRAP+120:
    case TT_HTRAP+121:
    case TT_HTRAP+122:
    case TT_HTRAP+123:
    case TT_HTRAP+124:
    case TT_HTRAP+125:
    case TT_HTRAP+126:
    case TT_HTRAP+127:
        env->hpstate |= HS_PRIV;
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

    if (cpu_hypervisor_mode(env)) {
        env->pc = (env->htba & ~0x3fffULL) | (intno << 5);
    } else {
        env->pc = env->tbr  & ~0x7fffULL;
        env->pc |= ((env->tl > 1) ? 1 << 14 : 0) | (intno << 5);
    }
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
