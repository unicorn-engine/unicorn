/*
 *  x86 memory access helpers
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

#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/int128.h"

#include "uc_priv.h"

#define CONFIG_ATOMIC64

/* broken thread support */

void helper_lock(CPUX86State *env)
{
}

void helper_unlock(CPUX86State *env)
{
}


void helper_cmpxchg8b_unlocked(CPUX86State *env, target_ulong a0)
{
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

    oldv = cpu_ldq_data(env, a0);
    newv = (cmpv == oldv ? newv : oldv);
    /* always do the store */
    cpu_stq_data(env, a0, newv);

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b_unlocked(CPUX86State *env, target_ulong a0)
{
    uint64_t o0, o1;
    int eflags;
    bool success;

    if ((a0 & 0xf) != 0) {
        raise_exception(env, EXCP0D_GPF);
    }
    eflags = cpu_cc_compute_all(env, CC_OP);

    Int128 cmpv = {.lo = env->regs[R_EAX], .hi = env->regs[R_EDX]};
    Int128 newv = {.lo = env->regs[R_EBX], .hi = env->regs[R_ECX]};

    o0 = cpu_ldq_data(env, a0 + 0);
    o1 = cpu_ldq_data(env, a0 + 8);

    Int128 oldv = {.lo = o0, .hi = o1};
    success = int128_eq(oldv, cmpv);
    if (!success) {
        newv = oldv;
    }

    cpu_stq_data(env, a0 + 0, newv.lo);
    cpu_stq_data(env, a0 + 8, newv.hi);

    if (success) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = oldv.lo;
        env->regs[R_EDX] = oldv.hi;
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data(env, a0);
    high = cpu_ldsw_data(env, a0 + 2);
    v = (int16_t)v;
    if (v < low || v > high) {
        raise_exception(env, EXCP05_BOUND);
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data(env, a0);
    high = cpu_ldl_data(env, a0 + 4);
    if (v < low || v > high) {
        raise_exception(env, EXCP05_BOUND);
    }
}


#if !defined(CONFIG_USER_ONLY)
/* try to fill the TLB and return an exception if error. If retaddr is
 * NULL, it means that the function was called in C code (i.e. not
 * from generated code or from helper.c)
 */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUState *cs, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr)
{
    int ret;

    ret = x86_cpu_handle_mmu_fault(cs, addr, is_write, mmu_idx);
    if (ret) {
        X86CPU *cpu = X86_CPU(cs->uc, cs);
        CPUX86State *env = &cpu->env;

        if (retaddr) {
            /* now we have a real cpu fault */
            cpu_restore_state(cs, retaddr);
        }
        raise_exception_err(env, cs->exception_index, env->error_code);
    }
}
#endif