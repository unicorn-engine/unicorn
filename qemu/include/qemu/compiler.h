/* compiler.h: macros to abstract away compiler specifics
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

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


static double rint( double x )
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

#define QEMU_ALIGNED(A, B) __declspec(align(A)) B

#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)

#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }

#ifdef __COUNTER__
#define QEMU_BUILD_BUG_ON(x) typedef QEMU_BUILD_BUG_ON_STRUCT(x) \
    glue(qemu_build_bug_on__, __COUNTER__) __attribute__((unused))
#else
#define QEMU_BUILD_BUG_ON(x)
#endif

#define GCC_FMT_ATTR(n, m)

#else

#ifndef NAN
#define NAN		(0.0 / 0.0)
#endif

#if defined __clang_analyzer__ || defined __COVERITY__
#define QEMU_STATIC_ANALYSIS 1
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

#define QEMU_ALIGNED(A, B) B __attribute__((aligned(A)))

#ifndef glue
#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)
#define stringify(s)  tostring(s)
#define tostring(s) #s
#endif

#ifndef likely
#if __GNUC__ < 3
#define __builtin_expect(x, n) (x)
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#endif

#ifndef container_of
#ifndef _MSC_VER
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#else
#define container_of(ptr, type, member) ((type *)((char *)(ptr) -offsetof(type,member)))
#endif
#endif

/* Convert from a base type to a parent type, with compile time checking.  */
#ifdef __GNUC__
#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char QEMU_UNUSED_VAR offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#else
#define DO_UPCAST(type, field, dev) container_of(dev, type, field)
#endif

#define typeof_field(type, field) typeof(((type *)0)->field)
#define type_check(t1,t2) ((t1*)0 - (t2*)0)

#ifndef always_inline
#if !((__GNUC__ < 3) || defined(__APPLE__))
#ifdef __OPTIMIZE__
#undef inline
#define inline __attribute__ (( always_inline )) __inline__
#endif
#endif
#else
#undef inline
#define inline always_inline
#endif

#define QEMU_BUILD_BUG_ON(x) \
    typedef char glue(qemu_build_bug_on__,__LINE__)[(x)?-1:1] __attribute__((unused));

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
