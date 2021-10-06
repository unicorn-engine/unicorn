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
#else
#include "exec/poison.h"
#endif

#include "qemu/compiler.h"

struct uc_struct;


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

#ifdef _WIN32
/* as defined in sdkddkver.h */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* Vista */
#endif
/* reduces the number of implicitly included headers */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

/* enable C99/POSIX format strings (needs mingw32-runtime 3.15 or later) */
#ifdef __MINGW32__
#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif // __USE_MINGW_ANSI_STDIO
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <inttypes.h>
#include <limits.h>

#include <unicorn/platform.h>

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
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

#ifdef CONFIG_POSIX
#include "sys/mman.h"
#endif

/*
 * Only allow MAP_JIT for Mojave or later.
 * 
 * Source: https://github.com/moby/hyperkit/pull/259/files#diff-e6b5417230ff2daff9155d9b15aefae12e89410ec2dca1f59d04be511f6737fcR41
 */
#if defined(__APPLE__)
    #if defined(HAVE_PTHREAD_JIT_PROTECT)
        #define USE_MAP_JIT
    #else
        #include <Availability.h>
        #ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
            #if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101400 && defined(MAP_JIT)
                #define USE_MAP_JIT
            #endif
        #endif
    #endif
#endif

#include <glib_compat.h>
#include "qemu/typedefs.h"


/* Starting on QEMU 2.5, qemu_hw_version() returns "2.5+" by default
 * instead of QEMU_VERSION, so setting hw_version on MachineClass
 * is no longer mandatory.
 *
 * Do NOT change this string, or it will break compatibility on all
 * machine classes that don't set hw_version.
 */
#define QEMU_HW_VERSION "2.5+"


/*
 * For mingw, as of v6.0.0, the function implementing the assert macro is
 * not marked as noreturn, so the compiler cannot delete code following an
 * assert(false) as unused.  We rely on this within the code base to delete
 * code that is unreachable when features are disabled.
 * All supported versions of Glib's g_assert() satisfy this requirement.
 */
// Unfortunately, NDK also has this problem.
#if defined(__MINGW32__ ) || defined(__ANDROID__) || defined(__i386__)
#undef assert
#define assert(x)  g_assert(x)
#endif

/*
 * According to waitpid man page:
 * WCOREDUMP
 *  This  macro  is  not  specified  in POSIX.1-2001 and is not
 *  available on some UNIX implementations (e.g., AIX, SunOS).
 *  Therefore, enclose its use inside #ifdef WCOREDUMP ... #endif.
 */
#ifndef WCOREDUMP
#define WCOREDUMP(status) 0
#endif
/*
 * We have a lot of unaudited code that may fail in strange ways, or
 * even be a security risk during migration, if you disable assertions
 * at compile-time.  You may comment out these safety checks if you
 * absolutely want to disable assertion overhead, but it is not
 * supported upstream so the risk is all yours.  Meanwhile, please
 * submit patches to remove any side-effects inside an assertion, or
 * fixing error handling that should use Error instead of assert.
 */
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
#if !defined(ESHUTDOWN)
#define ESHUTDOWN 4099
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

/* Mac OSX has a <stdint.h> bug that incorrectly defines SIZE_MAX with
 * the wrong type. Our replacement isn't usable in preprocessor
 * expressions, but it is sufficient for our needs. */
#if defined(HAVE_BROKEN_SIZE_MAX) && HAVE_BROKEN_SIZE_MAX
#undef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
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

/* n-byte align pointer down */
#ifdef _MSC_VER
#define QEMU_ALIGN_PTR_DOWN(p, n) (QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))
#else
#define QEMU_ALIGN_PTR_DOWN(p, n) ((typeof(p))QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))
#endif

/* n-byte align pointer up */
#ifndef _MSC_VER
#define QEMU_ALIGN_PTR_UP(p, n) ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))
#else
#define QEMU_ALIGN_PTR_UP(p, n) QEMU_ALIGN_UP((uintptr_t)(p), (n))
#endif

/* Check if pointer p is n-bytes aligned */
#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))

/* Round number up to multiple. Requires that d be a power of 2 (see
 * QEMU_ALIGN_UP for a safer but slower version on arbitrary
 * numbers); works even if d is a smaller type than n.  */
#ifndef ROUND_UP
#ifdef _MSC_VER
#define ROUND_UP(n, d) (((n) + (d) - 1) & (0 - (0 ? (n) : (d))))
#else
#define ROUND_UP(n, d) (((n) + (d) - 1) & -(0 ? (n) : (d)))
#endif
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

/*
 * &(x)[0] is always a pointer - if it's same type as x then the argument is a
 * pointer, not an array.
 */
#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))
#ifndef ARRAY_SIZE
#ifndef _MSC_VER
#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
#else
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif
#endif

void *qemu_try_memalign(size_t alignment, size_t size);
void *qemu_memalign(size_t alignment, size_t size);
void *qemu_anon_ram_alloc(struct uc_struct *uc, size_t size, uint64_t *align);
void qemu_vfree(void *ptr);
void qemu_anon_ram_free(struct uc_struct *uc, void *ptr, size_t size);

#define QEMU_MADV_INVALID -1

#if defined(CONFIG_MADVISE)

#define QEMU_MADV_WILLNEED  MADV_WILLNEED
#define QEMU_MADV_DONTNEED  MADV_DONTNEED
#ifdef MADV_DONTFORK
#define QEMU_MADV_DONTFORK  MADV_DONTFORK
#else
#define QEMU_MADV_DONTFORK  QEMU_MADV_INVALID
#endif
#ifdef MADV_MERGEABLE
#define QEMU_MADV_MERGEABLE MADV_MERGEABLE
#else
#define QEMU_MADV_MERGEABLE QEMU_MADV_INVALID
#endif
#ifdef MADV_UNMERGEABLE
#define QEMU_MADV_UNMERGEABLE MADV_UNMERGEABLE
#else
#define QEMU_MADV_UNMERGEABLE QEMU_MADV_INVALID
#endif
#ifdef MADV_DODUMP
#define QEMU_MADV_DODUMP MADV_DODUMP
#else
#define QEMU_MADV_DODUMP QEMU_MADV_INVALID
#endif
#ifdef MADV_DONTDUMP
#define QEMU_MADV_DONTDUMP MADV_DONTDUMP
#else
#define QEMU_MADV_DONTDUMP QEMU_MADV_INVALID
#endif
#ifdef MADV_HUGEPAGE
#define QEMU_MADV_HUGEPAGE MADV_HUGEPAGE
#else
#define QEMU_MADV_HUGEPAGE QEMU_MADV_INVALID
#endif
#ifdef MADV_NOHUGEPAGE
#define QEMU_MADV_NOHUGEPAGE MADV_NOHUGEPAGE
#else
#define QEMU_MADV_NOHUGEPAGE QEMU_MADV_INVALID
#endif
#ifdef MADV_REMOVE
#define QEMU_MADV_REMOVE MADV_REMOVE
#else
#define QEMU_MADV_REMOVE QEMU_MADV_INVALID
#endif

#elif defined(CONFIG_POSIX_MADVISE)

#define QEMU_MADV_WILLNEED  POSIX_MADV_WILLNEED
#define QEMU_MADV_DONTNEED  POSIX_MADV_DONTNEED
#define QEMU_MADV_DONTFORK  QEMU_MADV_INVALID
#define QEMU_MADV_MERGEABLE QEMU_MADV_INVALID
#define QEMU_MADV_UNMERGEABLE QEMU_MADV_INVALID
#define QEMU_MADV_DODUMP QEMU_MADV_INVALID
#define QEMU_MADV_DONTDUMP QEMU_MADV_INVALID
#define QEMU_MADV_HUGEPAGE  QEMU_MADV_INVALID
#define QEMU_MADV_NOHUGEPAGE  QEMU_MADV_INVALID
#define QEMU_MADV_REMOVE QEMU_MADV_INVALID

#else /* no-op */

#define QEMU_MADV_WILLNEED  QEMU_MADV_INVALID
#define QEMU_MADV_DONTNEED  QEMU_MADV_INVALID
#define QEMU_MADV_DONTFORK  QEMU_MADV_INVALID
#define QEMU_MADV_MERGEABLE QEMU_MADV_INVALID
#define QEMU_MADV_UNMERGEABLE QEMU_MADV_INVALID
#define QEMU_MADV_DODUMP QEMU_MADV_INVALID
#define QEMU_MADV_DONTDUMP QEMU_MADV_INVALID
#define QEMU_MADV_HUGEPAGE  QEMU_MADV_INVALID
#define QEMU_MADV_NOHUGEPAGE  QEMU_MADV_INVALID
#define QEMU_MADV_REMOVE QEMU_MADV_INVALID

#endif

#ifdef _WIN32
#define HAVE_CHARDEV_SERIAL 1
#elif defined(__linux__) || defined(__sun__) || defined(__FreeBSD__)    \
    || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) \
    || defined(__GLIBC__)
#define HAVE_CHARDEV_SERIAL 1
#endif

#if defined(__linux__) || defined(__FreeBSD__) ||               \
    defined(__FreeBSD_kernel__) || defined(__DragonFly__)
#define HAVE_CHARDEV_PARPORT 1
#endif

#if defined(CONFIG_LINUX)
#ifndef BUS_MCEERR_AR
#define BUS_MCEERR_AR 4
#endif
#ifndef BUS_MCEERR_AO
#define BUS_MCEERR_AO 5
#endif
#endif

#if defined(__linux__) && \
    (defined(__x86_64__) || defined(__arm__) || defined(__aarch64__) \
     || defined(__powerpc64__))
   /* Use 2 MiB alignment so transparent hugepages can be used by KVM.
      Valgrind does not support alignments larger than 1 MiB,
      therefore we need special code which handles running on Valgrind. */
#  define QEMU_VMALLOC_ALIGN (512 * 4096)
#elif defined(__linux__) && defined(__s390x__)
   /* Use 1 MiB (segment size) alignment so gmap can be used by KVM. */
#  define QEMU_VMALLOC_ALIGN (256 * 4096)
#elif defined(__linux__) && defined(__sparc__)
#include <sys/shm.h>
#  define QEMU_VMALLOC_ALIGN MAX(uc->qemu_real_host_page_size, SHMLBA)
#else
#  define QEMU_VMALLOC_ALIGN uc->qemu_real_host_page_size
#endif

#ifdef CONFIG_POSIX
struct qemu_signalfd_siginfo {
    uint32_t ssi_signo;   /* Signal number */
    int32_t  ssi_errno;   /* Error number (unused) */
    int32_t  ssi_code;    /* Signal code */
    uint32_t ssi_pid;     /* PID of sender */
    uint32_t ssi_uid;     /* Real UID of sender */
    int32_t  ssi_fd;      /* File descriptor (SIGIO) */
    uint32_t ssi_tid;     /* Kernel timer ID (POSIX timers) */
    uint32_t ssi_band;    /* Band event (SIGIO) */
    uint32_t ssi_overrun; /* POSIX timer overrun count */
    uint32_t ssi_trapno;  /* Trap number that caused signal */
    int32_t  ssi_status;  /* Exit status or signal (SIGCHLD) */
    int32_t  ssi_int;     /* Integer sent by sigqueue(2) */
    uint64_t ssi_ptr;     /* Pointer sent by sigqueue(2) */
    uint64_t ssi_utime;   /* User CPU time consumed (SIGCHLD) */
    uint64_t ssi_stime;   /* System CPU time consumed (SIGCHLD) */
    uint64_t ssi_addr;    /* Address that generated signal
                             (for hardware-generated signals) */
    uint8_t  pad[48];     /* Pad size to 128 bytes (allow for
                             additional fields in the future) */
};

#endif

int qemu_madvise(void *addr, size_t len, int advice);
int qemu_mprotect_rwx(void *addr, size_t size);
int qemu_mprotect_none(void *addr, size_t size);

#if defined(__HAIKU__) && defined(__i386__)
#define FMT_pid "%ld"
#elif defined(WIN64)
#define FMT_pid "%" PRId64
#else
#define FMT_pid "%d"
#endif

int qemu_get_thread_id(void);

#ifdef _WIN32
static inline void qemu_timersub(const struct timeval *val1,
                                 const struct timeval *val2,
                                 struct timeval *res)
{
    res->tv_sec = val1->tv_sec - val2->tv_sec;
    if (val1->tv_usec < val2->tv_usec) {
        res->tv_sec--;
        res->tv_usec = val1->tv_usec - val2->tv_usec + 1000 * 1000;
    } else {
        res->tv_usec = val1->tv_usec - val2->tv_usec;
    }
}
#else
#define qemu_timersub timersub
#endif

/**
 * qemu_getauxval:
 * @type: the auxiliary vector key to lookup
 *
 * Search the auxiliary vector for @type, returning the value
 * or 0 if @type is not present.
 */
unsigned long qemu_getauxval(unsigned long type);

#endif
