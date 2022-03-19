/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

/*
 This file is to support header files that are missing in MSVC and
 other non-standard compilers.
*/
#ifndef UNICORN_PLATFORM_H
#define UNICORN_PLATFORM_H

/*
These are the various MSVC versions as given by _MSC_VER:
MSVC++ 14.0 _MSC_VER == 1900 (Visual Studio 2015)
MSVC++ 12.0 _MSC_VER == 1800 (Visual Studio 2013)
MSVC++ 11.0 _MSC_VER == 1700 (Visual Studio 2012)
MSVC++ 10.0 _MSC_VER == 1600 (Visual Studio 2010)
MSVC++ 9.0  _MSC_VER == 1500 (Visual Studio 2008)
MSVC++ 8.0  _MSC_VER == 1400 (Visual Studio 2005)
MSVC++ 7.1  _MSC_VER == 1310 (Visual Studio 2003)
MSVC++ 7.0  _MSC_VER == 1300
MSVC++ 6.0  _MSC_VER == 1200
MSVC++ 5.0  _MSC_VER == 1100
*/
#define MSC_VER_VS2003 1310
#define MSC_VER_VS2005 1400
#define MSC_VER_VS2008 1500
#define MSC_VER_VS2010 1600
#define MSC_VER_VS2012 1700
#define MSC_VER_VS2013 1800
#define MSC_VER_VS2015 1900

// handle stdbool.h compatibility
#if !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(__MINGW64__) &&  \
    (defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64))
// MSVC

// stdbool.h
#if (_MSC_VER < MSC_VER_VS2013) || defined(_KERNEL_MODE)
// this system does not have stdbool.h
#ifndef __cplusplus
typedef unsigned char bool;
#define false 0
#define true 1
#endif // __cplusplus

#else
// VisualStudio 2013+ -> C99 is supported
#include <stdbool.h>
#endif // (_MSC_VER < MSC_VER_VS2013) || defined(_KERNEL_MODE)

#else
// not MSVC -> C99 is supported
#include <stdbool.h>
#endif // !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(__MINGW64__)
       // && (defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined
       // (_WIN64))

#if (defined(_MSC_VER) && (_MSC_VER < MSC_VER_VS2010)) || defined(_KERNEL_MODE)
// this system does not have stdint.h
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;

typedef signed char int_fast8_t;
typedef int int_fast16_t;
typedef int int_fast32_t;
typedef long long int_fast64_t;
typedef unsigned char uint_fast8_t;
typedef unsigned int uint_fast16_t;
typedef unsigned int uint_fast32_t;
typedef unsigned long long uint_fast64_t;

#if !defined(_W64)
#if !defined(__midl) && (defined(_X86_) || defined(_M_IX86)) && _MSC_VER >= 1300
#define _W64 __w64
#else
#define _W64
#endif
#endif

#ifndef _INTPTR_T_DEFINED
#define _INTPTR_T_DEFINED
#ifdef _WIN64
typedef long long intptr_t;
#else  /* _WIN64 */
typedef _W64 int intptr_t;
#endif /* _WIN64 */
#endif /* _INTPTR_T_DEFINED */

#ifndef _UINTPTR_T_DEFINED
#define _UINTPTR_T_DEFINED
#ifdef _WIN64
typedef unsigned long long uintptr_t;
#else  /* _WIN64 */
typedef _W64 unsigned int uintptr_t;
#endif /* _WIN64 */
#endif /* _UINTPTR_T_DEFINED */

#define INT8_MIN (-127i8 - 1)
#define INT16_MIN (-32767i16 - 1)
#define INT32_MIN (-2147483647i32 - 1)
#define INT64_MIN (-9223372036854775807i64 - 1)
#define INT8_MAX 127i8
#define INT16_MAX 32767i16
#define INT32_MAX 2147483647i32
#define INT64_MAX 9223372036854775807i64
#define UINT8_MAX 0xffui8
#define UINT16_MAX 0xffffui16
#define UINT32_MAX 0xffffffffui32
#define UINT64_MAX 0xffffffffffffffffui64

#define INT_FAST8_MIN INT8_MIN
#define INT_FAST16_MIN INT32_MIN
#define INT_FAST32_MIN INT32_MIN
#define INT_FAST64_MIN INT64_MIN
#define INT_FAST8_MAX INT8_MAX
#define INT_FAST16_MAX INT32_MAX
#define INT_FAST32_MAX INT32_MAX
#define INT_FAST64_MAX INT64_MAX
#define UINT_FAST8_MAX UINT8_MAX
#define UINT_FAST16_MAX UINT32_MAX
#define UINT_FAST32_MAX UINT32_MAX
#define UINT_FAST64_MAX UINT64_MAX

#ifdef _WIN64
#define INTPTR_MIN INT64_MIN
#define INTPTR_MAX INT64_MAX
#define UINTPTR_MAX UINT64_MAX
#else /* _WIN64 */
#define INTPTR_MIN INT32_MIN
#define INTPTR_MAX INT32_MAX
#define UINTPTR_MAX UINT32_MAX
#endif /* _WIN64 */

#else // this system has stdint.h

#if defined(_MSC_VER) && (_MSC_VER == MSC_VER_VS2010)
#define _INTPTR 2
#endif

#include <stdint.h>
#endif // (defined(_MSC_VER) && (_MSC_VER < MSC_VER_VS2010)) ||
       // defined(_KERNEL_MODE)

// handle inttypes.h compatibility
#if (defined(_MSC_VER) && (_MSC_VER < MSC_VER_VS2013)) || defined(_KERNEL_MODE)
// this system does not have inttypes.h

#define __PRI_8_LENGTH_MODIFIER__ "hh"
#define __PRI_64_LENGTH_MODIFIER__ "ll"

#define PRId8 __PRI_8_LENGTH_MODIFIER__ "d"
#define PRIi8 __PRI_8_LENGTH_MODIFIER__ "i"
#define PRIo8 __PRI_8_LENGTH_MODIFIER__ "o"
#define PRIu8 __PRI_8_LENGTH_MODIFIER__ "u"
#define PRIx8 __PRI_8_LENGTH_MODIFIER__ "x"
#define PRIX8 __PRI_8_LENGTH_MODIFIER__ "X"

#define PRId16 "hd"
#define PRIi16 "hi"
#define PRIo16 "ho"
#define PRIu16 "hu"
#define PRIx16 "hx"
#define PRIX16 "hX"

#if defined(_MSC_VER) && (_MSC_VER <= MSC_VER_VS2012)
#define PRId32 "ld"
#define PRIi32 "li"
#define PRIo32 "lo"
#define PRIu32 "lu"
#define PRIx32 "lx"
#define PRIX32 "lX"
#else // OSX
#define PRId32 "d"
#define PRIi32 "i"
#define PRIo32 "o"
#define PRIu32 "u"
#define PRIx32 "x"
#define PRIX32 "X"
#endif // defined(_MSC_VER) && (_MSC_VER <= MSC_VER_VS2012)

#if defined(_MSC_VER) && (_MSC_VER <= MSC_VER_VS2012)
// redefine functions from inttypes.h used in cstool
#define strtoull _strtoui64
#endif

#define PRId64 __PRI_64_LENGTH_MODIFIER__ "d"
#define PRIi64 __PRI_64_LENGTH_MODIFIER__ "i"
#define PRIo64 __PRI_64_LENGTH_MODIFIER__ "o"
#define PRIu64 __PRI_64_LENGTH_MODIFIER__ "u"
#define PRIx64 __PRI_64_LENGTH_MODIFIER__ "x"
#define PRIX64 __PRI_64_LENGTH_MODIFIER__ "X"

#else
// this system has inttypes.h by default
#include <inttypes.h>
#endif // #if defined(_MSC_VER) && (_MSC_VER < MSC_VER_VS2013) ||
       // defined(_KERNEL_MODE)

// sys/time.h compatibility
#if defined(_MSC_VER)
#include <sys/types.h>
#include <sys/timeb.h>
#include <windows.h>

#else
#include <sys/time.h>
#endif

// unistd.h compatibility
#if defined(_MSC_VER)

static int usleep(uint32_t usec)
{
    HANDLE timer;
    LARGE_INTEGER due;

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (!timer)
        return -1;

    due.QuadPart = (-((int64_t)usec)) * 10LL;
    if (!SetWaitableTimer(timer, &due, 0, NULL, NULL, 0)) {
        CloseHandle(timer);
        return -1;
    }
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);

    return 0;
}

#else
#include <unistd.h>
#endif

// misc support
#if defined(_MSC_VER)
#ifdef _WIN64
typedef signed __int64 ssize_t;
#else
typedef _W64 signed int ssize_t;
#endif

#ifndef va_copy
#define va_copy(d, s) ((d) = (s))
#endif
#define strcasecmp _stricmp
#if (_MSC_VER < MSC_VER_VS2015)
#define snprintf _snprintf
#endif
#if (_MSC_VER <= MSC_VER_VS2013)
#define strtoll _strtoi64
#endif
#endif

#endif // UNICORN_PLATFORM_H
