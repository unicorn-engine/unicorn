/* public domain */

#ifndef COMPILER_H
#define COMPILER_H

#include "config-host.h"
#include "unicorn/platform.h"

#ifdef _MSC_VER
// MSVC support

#define inline		__inline
#define __func__	__FUNCTION__

#include <math.h>
#include <float.h>

#if _MSC_VER < MSC_VER_VS2013
#define isinf(x) (!_finite(x))
#if defined(_WIN64)
#define isnan	_isnanf
#else
#define isnan	_isnan
#endif
#endif

/* gcc __builtin___clear_cache() */
static inline void __builtin___clear_cache(void *beg, void *e)
{
    unsigned char *start = beg;
    unsigned char *end = e;
    FlushInstructionCache(GetCurrentProcess(), start, end - start);
}

static inline double rint( double x )
{
    return floor(x < 0 ? x - 0.5 : x + 0.5);
}

union MSVC_FLOAT_HACK
{
   unsigned char Bytes[4];
   float Value;
};

#ifndef NAN
static union MSVC_FLOAT_HACK __NAN = {{0x00, 0x00, 0xC0, 0x7F}};
#define NAN (__NAN.Value)
#endif

#define QEMU_DIV0 __pragma(warning(suppress:2124))	// divide by zero error

#define QEMU_GNUC_PREREQ(maj, min) 0

#define QEMU_NORETURN __declspec(noreturn)
#define QEMU_UNUSED_VAR __pragma(warning(suppress:4100))	// unused variables only
#define QEMU_UNUSED_FUNC
#define QEMU_WARN_UNUSED_RESULT
#define QEMU_ARTIFICIAL
#define QEMU_PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )

#define QEMU_ALIGN(A, B) __declspec(align(A)) B

#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)
#define QEMU_BUILD_BUG_ON(x) \
    typedef char cat2(qemu_build_bug_on__,__LINE__)[(x)?-1:1] QEMU_UNUSED_VAR;

#define GCC_FMT_ATTR(n, m)

#else

#ifndef NAN
#define NAN		(0.0 / 0.0)
#endif

/*----------------------------------------------------------------------------
| The macro QEMU_GNUC_PREREQ tests for minimum version of the GNU C compiler.
| The code is a copy of SOFTFLOAT_GNUC_PREREQ, see softfloat-macros.h.
*----------------------------------------------------------------------------*/
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
# define QEMU_GNUC_PREREQ(maj, min) \
         ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
# define QEMU_GNUC_PREREQ(maj, min) 0
#endif

#define QEMU_NORETURN __attribute__ ((__noreturn__))

#define QEMU_UNUSED_VAR __attribute__((unused))
#define QEMU_UNUSED_FUNC __attribute__((unused))

#if QEMU_GNUC_PREREQ(3, 4)
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define QEMU_WARN_UNUSED_RESULT
#endif

#if QEMU_GNUC_PREREQ(4, 3)
#define QEMU_ARTIFICIAL __attribute__((always_inline, artificial))
#else
#define QEMU_ARTIFICIAL
#endif

#if defined(_WIN32)
# define QEMU_PACK( __Declaration__ ) __Declaration__ __attribute__((gcc_struct, packed))
#else
# define QEMU_PACK( __Declaration__ ) __Declaration__ __attribute__((packed))
#endif

#define QEMU_ALIGN(A, B) B __attribute__((aligned(A)))

#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)
#define QEMU_BUILD_BUG_ON(x) \
    typedef char cat2(qemu_build_bug_on__,__LINE__)[(x)?-1:1] __attribute__((unused));

#if defined __GNUC__
# if !QEMU_GNUC_PREREQ(4, 4)
   /* gcc versions before 4.4.x don't support gnu_printf, so use printf. */
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
# else
   /* Use gnu_printf when supported (qemu uses standard format strings). */
#  define GCC_FMT_ATTR(n, m) __attribute__((format(gnu_printf, n, m)))
#  if defined(_WIN32)
    /* Map __printf__ to __gnu_printf__ because we want standard format strings
     * even when MinGW or GLib include files use __printf__. */
#   define __printf__ __gnu_printf__
#  endif
# endif
#else
#define GCC_FMT_ATTR(n, m)
#endif

#endif // _MSC_VER

#endif /* COMPILER_H */
