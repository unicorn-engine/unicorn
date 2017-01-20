/*
 *  m68k/ColdFire Semihosting syscall interface
 *
 *  Copyright (c) 2005-2007 CodeSourcery.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "unicorn/platform.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "cpu.h"
#if defined(CONFIG_USER_ONLY)
#include "qemu.h"
#define SEMIHOSTING_HEAP_SIZE (128 * 1024 * 1024)
#else
#include "qemu-common.h"
#include "exec/softmmu-semi.h"
#endif
#include "sysemu/sysemu.h"

#define HOSTED_EXIT  0
#define HOSTED_INIT_SIM 1
#define HOSTED_OPEN 2
#define HOSTED_CLOSE 3
#define HOSTED_READ 4
#define HOSTED_WRITE 5
#define HOSTED_LSEEK 6
#define HOSTED_RENAME 7
#define HOSTED_UNLINK 8
#define HOSTED_STAT 9
#define HOSTED_FSTAT 10
#define HOSTED_GETTIMEOFDAY 11
#define HOSTED_ISATTY 12
#define HOSTED_SYSTEM 13

static void translate_stat(CPUM68KState *env, target_ulong addr, struct stat *s)
{
}

static void m68k_semi_return_u32(CPUM68KState *env, uint32_t ret, uint32_t err)
{
    target_ulong args = env->dregs[1];
    if (put_user_u32(ret, args) ||
        put_user_u32(err, args + 4)) {
        /* The m68k semihosting ABI does not provide any way to report this
         * error to the guest, so the best we can do is log it in qemu.
         * It is always a guest error not to pass us a valid argument block.
         */
        qemu_log_mask(LOG_GUEST_ERROR, "m68k-semihosting: return value "
                      "discarded because argument block not writable\n");
    }
}

static void m68k_semi_return_u64(CPUM68KState *env, uint64_t ret, uint32_t err)
{
    target_ulong args = env->dregs[1];
    if (put_user_u32(ret >> 32, args) ||
        put_user_u32(ret, args + 4) ||
        put_user_u32(err, args + 8)) {
        /* No way to report this via m68k semihosting ABI; just log it */
        qemu_log_mask(LOG_GUEST_ERROR, "m68k-semihosting: return value "
                      "discarded because argument block not writable\n");
    }
}

static int m68k_semi_is_fseek;

static void m68k_semi_cb(CPUState *cs, target_ulong ret, target_ulong err)
{
    M68kCPU *cpu = M68K_CPU(cs->uc, cs);
    CPUM68KState *env = &cpu->env;

    if (m68k_semi_is_fseek) {
        /* FIXME: We've already lost the high bits of the fseek
           return value.  */
        m68k_semi_return_u64(env, ret, err);
        m68k_semi_is_fseek = 0;
    } else {
        m68k_semi_return_u32(env, ret, err);
    }
}

/* Read the input value from the argument block; fail the semihosting
 * call if the memory read fails.
 */
#define GET_ARG(n) do {                                 \
    if (get_user_ual(arg ## n, args + (n) * 4)) {       \
        result = -1;                                    \
        errno = EFAULT;                                 \
        goto failed;                                    \
    }                                                   \
} while (0)

void do_m68k_semihosting(CPUM68KState *env, int nr)
{
}
