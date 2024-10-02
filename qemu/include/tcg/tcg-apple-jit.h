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

#if defined(__APPLE__) && defined(HAVE_PTHREAD_JIT_PROTECT) && defined(HAVE_SPRR) && (defined(__arm__) || defined(__aarch64__))

/* write protect enable = write disable */
static inline void jit_write_protect(int enabled)
{
    return pthread_jit_write_protect_np(enabled);
}

// Returns the S3_6_c15_c1_5 register's value
// Taken from 
// https://stackoverflow.com/questions/70019553/lldb-how-to-read-the-permissions-of-a-memory-region-for-a-thread
// https://blog.svenpeter.dev/posts/m1_sprr_gxf/
static inline uint64_t read_sprr_perm(void)
{
    uint64_t v;
    __asm__ __volatile__("isb sy\n"
                         "mrs %0, S3_6_c15_c1_5\n"
                         : "=r"(v)::"memory");
    return v;
}

__attribute__((unused)) static inline uint8_t thread_mask() 
{
    uint64_t v = read_sprr_perm();

    return (v >> 20) & 3;
}

__attribute__((unused)) static inline bool thread_writeable()
{
    return thread_mask() == 3;
}

__attribute__((unused)) static inline bool thread_executable()
{
    return thread_mask() == 1;
}

#define JIT_CALLBACK_GUARD(x)                       \
{                                                   \
    bool executable = uc->current_executable;       \
    assert (executable == thread_executable());     \
    x;                                              \
    if (executable != thread_executable()) {        \
        jit_write_protect(executable);              \
    }                                               \
}                                                   \


#define JIT_CALLBACK_GUARD_VAR(var, x)                  \
{                                                       \
    bool executable = uc->current_executable;           \
    assert (executable == thread_executable());         \
    var = x;                                            \
    if (executable != thread_executable()) {            \
        jit_write_protect(executable);                  \
    }                                                   \
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