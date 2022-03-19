/* compiler.h: macros to abstract away compiler specifics
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef COMPILER_H
#define COMPILER_H

#include "unicorn/platform.h"

#ifndef glue
#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#endif

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
#define QEMU_NOINLINE __declspec(noinline)

#define QEMU_ALIGN(A, B) __declspec(align(A)) B
#define QEMU_ALIGNED(X)

#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)
#define QEMU_BUILD_BUG_ON(x)
#define QEMU_BUILD_BUG_ON_ZERO(x)
#define QEMU_BUILD_BUG_MSG(x, msg)

#define GCC_FMT_ATTR(n, m)

#define likely(x) (x)
#define unlikely(x) (x)

#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#define QEMU_FLATTEN
#define QEMU_ALWAYS_INLINE  __declspec(inline)

#else  // Unix compilers

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

#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))

#define QEMU_SENTINEL __attribute__((sentinel))

#if defined(_WIN32) && (defined(__x86_64__) || defined(__i386__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
# define QEMU_PACK( __Declaration__ ) __Declaration__ __attribute__((gcc_struct, packed))
#else
# define QEMU_PACKED __attribute__((packed))
# define QEMU_PACK( __Declaration__ ) __Declaration__ __attribute__((packed))
#endif

#define QEMU_ALIGN(A, B) B __attribute__((aligned(A)))

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define QEMU_NOINLINE __attribute__((noinline))

#ifndef likely
#if __GNUC__ < 3
#define __builtin_expect(x, n) (x)
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#endif

#define sizeof_field(type, field) sizeof(((type *)0)->field)

/*
 * Calculate the number of bytes up to and including the given 'field' of
 * 'container'.
 */
#define endof(container, field) \
    (offsetof(container, field) + sizeof_field(container, field))

/* Convert from a base type to a parent type, with compile time checking.  */
#ifdef __GNUC__
#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#else
#define DO_UPCAST(type, field, dev) container_of(dev, type, field)
#endif

#define typeof_field(type, field) typeof(((type *)0)->field)
#define type_check(t1,t2) ((t1*)0 - (t2*)0)

#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }

/* QEMU_BUILD_BUG_MSG() emits the message given if _Static_assert is
 * supported; otherwise, it will be omitted from the compiler error
 * message (but as it remains present in the source code, it can still
 * be useful when debugging). */
#if defined(CONFIG_STATIC_ASSERT)
#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)
#elif defined(__COUNTER__)
#define QEMU_BUILD_BUG_MSG(x, msg) typedef QEMU_BUILD_BUG_ON_STRUCT(x) \
    glue(qemu_build_bug_on__, __COUNTER__) __attribute__((unused))
#else
#define QEMU_BUILD_BUG_MSG(x, msg)
#endif

#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)

#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - \
                                   sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))

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

#ifndef __has_warning
#define __has_warning(x) 0 /* compatibility with non-clang compilers */
#endif

#ifndef __has_feature
#define __has_feature(x) 0 /* compatibility with non-clang compilers */
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0 /* compatibility with non-clang compilers */
#endif

#if __has_builtin(__builtin_assume_aligned) || !defined(__clang__)
#define HAS_ASSUME_ALIGNED
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0 /* compatibility with older GCC */
#endif

/*
 * GCC doesn't provide __has_attribute() until GCC 5, but we know all the GCC
 * versions we support have the "flatten" attribute. Clang may not have the
 * "flatten" attribute but always has __has_attribute() to check for it.
 */
#if __has_attribute(flatten) || !defined(__clang__)
# define QEMU_FLATTEN __attribute__((flatten))
#else
# define QEMU_FLATTEN
#endif

/*
 * If __attribute__((error)) is present, use it to produce an error at
 * compile time.  Otherwise, one must wait for the linker to diagnose
 * the missing symbol.
 */
#if __has_attribute(error)
# define QEMU_ERROR(X) __attribute__((error(X)))
#else
# define QEMU_ERROR(X)
#endif

/*
 * The nonstring variable attribute specifies that an object or member
 * declaration with type array of char or pointer to char is intended
 * to store character arrays that do not necessarily contain a terminating
 * NUL character. This is useful in detecting uses of such arrays or pointers
 * with functions that expect NUL-terminated strings, and to avoid warnings
 * when such an array or pointer is used as an argument to a bounded string
 * manipulation function such as strncpy.
 */
#if __has_attribute(nonstring)
# define QEMU_NONSTRING __attribute__((nonstring))
#else
# define QEMU_NONSTRING
#endif

/*
 * Forced inlining may be desired to encourage constant propagation
 * of function parameters.  However, it can also make debugging harder,
 * so disable it for a non-optimizing build.
 */
#if defined(__OPTIMIZE__)
#define QEMU_ALWAYS_INLINE  __attribute__((always_inline))
#else
#define QEMU_ALWAYS_INLINE
#endif

/* Implement C11 _Generic via GCC builtins.  Example:
 *
 *    QEMU_GENERIC(x, (float, sinf), (long double, sinl), sin) (x)
 *
 * The first argument is the discriminator.  The last is the default value.
 * The middle ones are tuples in "(type, expansion)" format.
 */

/* First, find out the number of generic cases.  */
#define QEMU_GENERIC(x, ...) \
    QEMU_GENERIC_(typeof(x), __VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

/* There will be extra arguments, but they are not used.  */
#define QEMU_GENERIC_(x, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, count, ...) \
    QEMU_GENERIC##count(x, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)

/* Two more helper macros, this time to extract items from a parenthesized
 * list.
 */
#define QEMU_FIRST_(a, b) a
#define QEMU_SECOND_(a, b) b

/* ... and a final one for the common part of the "recursion".  */
#define QEMU_GENERIC_IF(x, type_then, else_)                                   \
    __builtin_choose_expr(__builtin_types_compatible_p(x,                      \
                                                       QEMU_FIRST_ type_then), \
                          QEMU_SECOND_ type_then, else_)

/* CPP poor man's "recursion".  */
#define QEMU_GENERIC1(x, a0, ...) (a0)
#define QEMU_GENERIC2(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC1(x, __VA_ARGS__))
#define QEMU_GENERIC3(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC2(x, __VA_ARGS__))
#define QEMU_GENERIC4(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC3(x, __VA_ARGS__))
#define QEMU_GENERIC5(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC4(x, __VA_ARGS__))
#define QEMU_GENERIC6(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC5(x, __VA_ARGS__))
#define QEMU_GENERIC7(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC6(x, __VA_ARGS__))
#define QEMU_GENERIC8(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC7(x, __VA_ARGS__))
#define QEMU_GENERIC9(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC8(x, __VA_ARGS__))
#define QEMU_GENERIC10(x, a0, ...) QEMU_GENERIC_IF(x, a0, QEMU_GENERIC9(x, __VA_ARGS__))

/**
 * qemu_build_not_reached()
 *
 * The compiler, during optimization, is expected to prove that a call
 * to this function cannot be reached and remove it.  If the compiler
 * supports QEMU_ERROR, this will be reported at compile time; otherwise
 * this will be reported at link time due to the missing symbol.
 */
#if defined(__OPTIMIZE__) && !defined(__NO_INLINE__)
extern void QEMU_NORETURN QEMU_ERROR("code path is reachable")
    qemu_build_not_reached(void);
#else
#define qemu_build_not_reached()  g_assert_not_reached()
#endif

#endif // _MSC_VER
#endif /* COMPILER_H */
