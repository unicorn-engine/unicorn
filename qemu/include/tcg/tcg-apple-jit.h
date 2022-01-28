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

#ifdef HAVE_PTHREAD_JIT_PROTECT

/* write protect enable = write disable */
static inline void jit_write_protect(int enabled)
{
    return pthread_jit_write_protect_np(enabled);
}

#else /* defined(__aarch64__) && defined(CONFIG_DARWIN) */

static inline void jit_write_protect(int enabled)
{
    return;
}

#endif

#endif /* define TCG_APPLE_JIT_H */