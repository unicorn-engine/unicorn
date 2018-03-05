/*
 * OS includes and handling of OS dependencies
 *
 * This header exists to pull in some common system headers that
 * most code in QEMU will want, and to fix up some possible issues with
 * it (missing defines, Windows weirdness, and so on).
 *
 * To avoid getting into possible circular include dependencies, this
 * file should not include any other QEMU headers, with the exceptions
 * of config-host.h, config-target.h, qemu/compiler.h,
 * sysemu/os-posix.h, sysemu/os-win32.h, glib-compat.h and
 * qemu/typedefs.h, all of which are doing a similar job to this file
 * and are under similar constraints.
 *
 * This header also contains prototypes for functions defined in
 * os-*.c and util/oslib-*.c; those would probably be better split
 * out into separate header files.
 *
 * In an ideal world this header would contain only:
 *  (1) things which everybody needs
 *  (2) things without which code would work on most platforms but
 *      fail to compile or misbehave on a minority of host OSes
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_OSDEP_H
#define QEMU_OSDEP_H

#include "config-host.h"
#ifdef NEED_CPU_H
#include "config-target.h"
#endif
#include "qemu/compiler.h"

/* Older versions of C++ don't get definitions of various macros from
 * stdlib.h unless we define these macros before first inclusion of
 * that system header.
 */
#ifndef __STDC_CONSTANT_MACROS
#define __STDC_CONSTANT_MACROS
#endif
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif


#include <stdarg.h>
#include <stddef.h>
#include "unicorn/platform.h"
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <assert.h>
/* setjmp must be declared before sysemu/os-win32.h
 * because it is redefined there. */
#include <setjmp.h>
#include <signal.h>

#ifdef __OpenBSD__
#include <sys/signal.h>
#endif

#ifndef _WIN32
#include <sys/wait.h>
#else
#define WIFEXITED(x)   1
#define WEXITSTATUS(x) (x)
#endif

#ifdef _WIN32
#include "sysemu/os-win32.h"
#endif

#include "glib_compat.h"

#include "qemu/typedefs.h"

/*
 * We have a lot of unaudited code that may fail in strange ways, or
 * even be a security risk during migration, if you disable assertions
 * at compile-time.  You may comment out these safety checks if you
 * absolutely want to disable assertion overhead, but it is not
 * supported upstream so the risk is all yours.  Meanwhile, please
 * submit patches to remove any side-effects inside an assertion, or
 * fixing error handling that should use Error instead of assert.
 */
#ifdef NDEBUG
#error building with NDEBUG is not supported
#endif
#ifdef G_DISABLE_ASSERT
#error building with G_DISABLE_ASSERT is not supported
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef ENOMEDIUM
#define ENOMEDIUM ENODEV
#endif
#if !defined(ENOTSUP)
#define ENOTSUP 4096
#endif
#if !defined(ECANCELED)
#define ECANCELED 4097
#endif
#if !defined(EMEDIUMTYPE)
#define EMEDIUMTYPE 4098
#endif

/* time_t may be either 32 or 64 bits depending on the host OS, and
 * can be either signed or unsigned, so we can't just hardcode a
 * specific maximum value. This is not a C preprocessor constant,
 * so you can't use TIME_MAX in an #ifdef, but for our purposes
 * this isn't a problem.
 */

/* The macros TYPE_SIGNED, TYPE_WIDTH, and TYPE_MAXIMUM are from
 * Gnulib, and are under the LGPL v2.1 or (at your option) any
 * later version.
 */

/* True if the real type T is signed.  */
#define TYPE_SIGNED(t) (!((t)0 < (t)-1))

/* The width in bits of the integer type or expression T.
 * Padding bits are not supported.
 */
#define TYPE_WIDTH(t) (sizeof(t) * CHAR_BIT)

/* The maximum and minimum values for the integer type T.  */
#define TYPE_MAXIMUM(t)                                                \
  ((t) (!TYPE_SIGNED(t)                                                \
        ? (t)-1                                                        \
        : ((((t)1 << (TYPE_WIDTH(t) - 2)) - 1) * 2 + 1)))
#ifndef TIME_MAX
#define TIME_MAX TYPE_MAXIMUM(time_t)
#endif

/* HOST_LONG_BITS is the size of a native pointer in bits. */
#if UINTPTR_MAX == UINT32_MAX
# define HOST_LONG_BITS 32
#elif UINTPTR_MAX == UINT64_MAX
# define HOST_LONG_BITS 64
#else
# error Unknown pointer size
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* Minimum function that returns zero only iff both values are zero.
 * Intended for use with unsigned values only. */
#ifndef MIN_NON_ZERO
#define MIN_NON_ZERO(a, b) ((a) == 0 ? (b) : \
                                ((b) == 0 ? (a) : (MIN(a, b))))
#endif

/* Round number down to multiple */
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))

/* Round number up to multiple. Safe when m is not a power of 2 (see
 * ROUND_UP for a faster version when a power of 2 is guaranteed) */
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

/* Check if n is a multiple of m */
#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)

/* Unfortunately MSVC compatibility means explicit casting */
#ifdef _MSC_VER
/* n-byte align pointer down */
#define QEMU_ALIGN_PTR_DOWN(p, n) \
    (QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))

/* n-byte align pointer up */
#define QEMU_ALIGN_PTR_UP(p, n) \
    (QEMU_ALIGN_UP((uintptr_t)(p), (n)))

/* Check if pointer p is n-bytes aligned */
#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))
#else
/* n-byte align pointer down */
#define QEMU_ALIGN_PTR_DOWN(p, n) \
    ((typeof(p))QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))

/* n-byte align pointer up */
#define QEMU_ALIGN_PTR_UP(p, n) \
    ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))

/* Check if pointer p is n-bytes aligned */
#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))
#endif

/* Round number up to multiple. Requires that d be a power of 2 (see
 * QEMU_ALIGN_UP for a safer but slower version on arbitrary
 * numbers); works even if d is a smaller type than n.  */
#ifndef ROUND_UP
#define ROUND_UP(n, d) (((n) + (d) - 1) & -(0 ? (n) : (d)))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#ifdef _MSC_VER
#define QEMU_IS_ARRAY(x) (x)
#else
/*
 * &(x)[0] is always a pointer - if it's same type as x then the argument is a
 * pointer, not an array.
 */
#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
#endif

void *qemu_try_memalign(size_t alignment, size_t size);
void *qemu_memalign(size_t alignment, size_t size);
void *qemu_anon_ram_alloc(size_t size, uint64_t *align);
void qemu_vfree(void *ptr);
void qemu_anon_ram_free(void *ptr, size_t size);

#if defined(__HAIKU__) && defined(__i386__)
#define FMT_pid "%ld"
#elif defined(WIN64)
#define FMT_pid "%" PRId64
#else
#define FMT_pid "%d"
#endif

/**
 * qemu_getauxval:
 * @type: the auxiliary vector key to lookup
 *
 * Search the auxiliary vector for @type, returning the value
 * or 0 if @type is not present.
 */
unsigned long qemu_getauxval(unsigned long type);

/* Starting on QEMU 2.5, qemu_hw_version() returns "2.5+" by default
 * instead of QEMU_VERSION, so setting hw_version on MachineClass
 * is no longer mandatory.
 *
 * Do NOT change this string, or it will break compatibility on all
 * machine classes that don't set hw_version.
 */
#define QEMU_HW_VERSION "2.5+"

#endif
