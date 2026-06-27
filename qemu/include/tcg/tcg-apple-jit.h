/*
 * Apple Silicon APRR functions for JIT handling
 *
 * Copyright (c) 2020 osy
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Credits to: https://siguza.github.io/APRR/
 * Reversed from /usr/lib/system/libsystem_pthread.dylib
 */

#ifndef TCG_APPLE_JIT_H
#define TCG_APPLE_JIT_H

#include "assert.h"
#include "stdint.h"
#include "stdbool.h"
#include "qemu/compiler.h"

#if defined(__APPLE__) && defined(HAVE_PTHREAD_JIT_PROTECT) && (defined(__arm__) || defined(__aarch64__))

QEMU_UNUSED_FUNC static inline uint8_t thread_mask()
{
    return 0;
}

QEMU_UNUSED_FUNC static inline bool thread_writeable()
{
    return false;
}

QEMU_UNUSED_FUNC static inline bool thread_executable()
{
    return true;
}

static inline void assert_executable(bool executable)
{
    (void)executable;
}

#else

QEMU_UNUSED_FUNC static inline uint8_t thread_mask()
{
    return 0;
}

QEMU_UNUSED_FUNC static inline bool thread_writeable()
{
    return false;
}

QEMU_UNUSED_FUNC static inline bool thread_executable()
{
    return false;
}

static inline void assert_executable(bool executable)
{
}

#endif


#if defined(__APPLE__) && defined(HAVE_PTHREAD_JIT_PROTECT) && (defined(__arm__) || defined(__aarch64__))

/* write protect enable = write disable */
static inline void jit_write_protect(int enabled)
{
    if (pthread_jit_write_protect_supported_np()) {
        pthread_jit_write_protect_np(enabled);
    }
}

#define JIT_CALLBACK_GUARD(x)                       \
{                                                   \
    bool executable = uc->current_executable;       \
    assert_executable(executable);                  \
    x;                                              \
    jit_write_protect(executable);                  \
}                                                   \


#define JIT_CALLBACK_GUARD_VAR(var, x)                  \
{                                                       \
    bool executable = uc->current_executable;           \
    assert_executable(executable);                      \
    var = x;                                            \
    jit_write_protect(executable);                      \
}                                                       \


#else /* defined(__aarch64__) && defined(CONFIG_DARWIN) */

static inline void jit_write_protect(int enabled)
{
    return;
}

#define JIT_CALLBACK_GUARD(x) \
{                             \
    (void)uc;                 \
    x;                        \
}                             \


#define JIT_CALLBACK_GUARD_VAR(var, x)  \
{                                       \
    (void)uc;                           \
    var = x;                            \
}                                       \

#endif

#endif /* define TCG_APPLE_JIT_H */
