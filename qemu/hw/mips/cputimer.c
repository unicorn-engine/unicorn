/*
 * QEMU MIPS timer support
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hw/hw.h"
#include "hw/mips/cpudevs.h"
#include "qemu/timer.h"

#define TIMER_FREQ	100 * 1000 * 1000

/* XXX: do not use a global */
uint32_t cpu_mips_get_random (CPUMIPSState *env)
{
    static uint32_t lfsr = 1;
    static uint32_t prev_idx = 0;
    uint32_t idx;
    /* Don't return same value twice, so get another value */
    do {
        lfsr = (lfsr >> 1) ^ ((0-(lfsr & 1u)) & 0xd0000001u);
        idx = lfsr % (env->tlb->nb_tlb - env->CP0_Wired) + env->CP0_Wired;
    } while (idx == prev_idx);
    prev_idx = idx;
    return idx;
}

/* MIPS R4K timer */
static void cpu_mips_timer_update(CPUMIPSState *env)
{
#if 0
    uint64_t now, next;
    uint32_t wait;

    now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    wait = env->CP0_Compare - env->CP0_Count -
        (uint32_t)muldiv64(now, TIMER_FREQ, get_ticks_per_sec());
    next = now + muldiv64(wait, get_ticks_per_sec(), TIMER_FREQ);
    timer_mod(env->timer, next);
#endif
}

#if 0
/* Expire the timer.  */
static void cpu_mips_timer_expire(CPUMIPSState *env)
{
    cpu_mips_timer_update(env);
    if (env->insn_flags & ISA_MIPS32R2) {
        env->CP0_Cause |= 1 << CP0Ca_TI;
    }
    //qemu_irq_raise(env->irq[(env->CP0_IntCtl >> CP0IntCtl_IPTI) & 0x7]);
}
#endif

uint32_t cpu_mips_get_count (CPUMIPSState *env)
{
    if (env->CP0_Cause & (1 << CP0Ca_DC)) {
        return env->CP0_Count;
    } else {
        uint64_t now;

        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        //if (timer_pending(env->timer)
        //    && timer_expired(env->timer, now)) {
        //    /* The timer has already expired.  */
        //    cpu_mips_timer_expire(env);
        //}

        return env->CP0_Count +
            (uint32_t)muldiv64(now, TIMER_FREQ, get_ticks_per_sec());
    }
}

void cpu_mips_store_count (CPUMIPSState *env, uint32_t count)
{
#if 0
    /*
     * This gets called from cpu_state_reset(), potentially before timer init.
     * So env->timer may be NULL, which is also the case with KVM enabled so
     * treat timer as disabled in that case.
     */
    if (env->CP0_Cause & (1 << CP0Ca_DC) || !env->timer)
        env->CP0_Count = count;
    else {
        /* Store new count register */
        env->CP0_Count =
            count - (uint32_t)muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                       TIMER_FREQ, get_ticks_per_sec());
        /* Update timer timer */
        cpu_mips_timer_update(env);
    }
#endif
}

void cpu_mips_store_compare (CPUMIPSState *env, uint32_t value)
{
    env->CP0_Compare = value;
    if (!(env->CP0_Cause & (1 << CP0Ca_DC)))
        cpu_mips_timer_update(env);
    if (env->insn_flags & ISA_MIPS32R2)
        env->CP0_Cause &= ~(1 << CP0Ca_TI);
    //qemu_irq_lower(env->irq[(env->CP0_IntCtl >> CP0IntCtl_IPTI) & 0x7]);
}

void cpu_mips_start_count(CPUMIPSState *env)
{
    cpu_mips_store_count(env, env->CP0_Count);
}

void cpu_mips_stop_count(CPUMIPSState *env)
{
    /* Store the current value */
    env->CP0_Count += (uint32_t)muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                         TIMER_FREQ, get_ticks_per_sec());
}
