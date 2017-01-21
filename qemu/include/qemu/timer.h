#ifndef QEMU_TIMER_H
#define QEMU_TIMER_H

#include "qemu/typedefs.h"
#include "qemu-common.h"

/* timers */

#define SCALE_MS 1000000
#define SCALE_US 1000
#define SCALE_NS 1

/**
 * QEMUClockType:
 *
 * The following clock types are available:
 *
 * @QEMU_CLOCK_REALTIME: Real time clock
 *
 * The real time clock should be used only for stuff which does not
 * change the virtual machine state, as it is run even if the virtual
 * machine is stopped. The real time clock has a frequency of 1000
 * Hz.
 *
 * @QEMU_CLOCK_VIRTUAL: virtual clock
 *
 * The virtual clock is only run during the emulation. It is stopped
 * when the virtual machine is stopped. Virtual timers use a high
 * precision clock, usually cpu cycles (use ticks_per_sec).
 *
 * @QEMU_CLOCK_HOST: host clock
 *
 * The host clock should be use for device models that emulate accurate
 * real time sources. It will continue to run when the virtual machine
 * is suspended, and it will reflect system time changes the host may
 * undergo (e.g. due to NTP). The host clock has the same precision as
 * the virtual clock.
 */

typedef enum {
    QEMU_CLOCK_REALTIME = 0,
    QEMU_CLOCK_VIRTUAL = 1,
    QEMU_CLOCK_HOST = 2,
    QEMU_CLOCK_MAX
} QEMUClockType;

typedef struct QEMUTimerList QEMUTimerList;

struct QEMUTimerListGroup {
    QEMUTimerList *tl[QEMU_CLOCK_MAX];
};

typedef void QEMUTimerCB(void *opaque);
typedef void QEMUTimerListNotifyCB(void *opaque);

struct QEMUTimer {
    int64_t expire_time;        /* in nanoseconds */
    QEMUTimerList *timer_list;
    QEMUTimerCB *cb;
    void *opaque;
    QEMUTimer *next;
    int scale;
};

/*
 * QEMUClockType
 */

/*
 * qemu_clock_get_ns;
 * @type: the clock type
 *
 * Get the nanosecond value of a clock with
 * type @type
 *
 * Returns: the clock value in nanoseconds
 */
int64_t qemu_clock_get_ns(QEMUClockType type);

/**
 * qemu_clock_get_ms;
 * @type: the clock type
 *
 * Get the millisecond value of a clock with
 * type @type
 *
 * Returns: the clock value in milliseconds
 */
static inline int64_t qemu_clock_get_ms(QEMUClockType type)
{
    return qemu_clock_get_ns(type) / SCALE_MS;
}

/**
 * qemu_clock_get_us;
 * @type: the clock type
 *
 * Get the microsecond value of a clock with
 * type @type
 *
 * Returns: the clock value in microseconds
 */
static inline int64_t qemu_clock_get_us(QEMUClockType type)
{
    return qemu_clock_get_ns(type) / SCALE_US;
}

/**
 * qemu_timeout_ns_to_ms:
 * @ns: nanosecond timeout value
 *
 * Convert a nanosecond timeout value (or -1) to
 * a millisecond value (or -1), always rounding up.
 *
 * Returns: millisecond timeout value
 */
int qemu_timeout_ns_to_ms(int64_t ns);

/**
 * qemu_soonest_timeout:
 * @timeout1: first timeout in nanoseconds (or -1 for infinite)
 * @timeout2: second timeout in nanoseconds (or -1 for infinite)
 *
 * Calculates the soonest of two timeout values. -1 means infinite, which
 * is later than any other value.
 *
 * Returns: soonest timeout value in nanoseconds (or -1 for infinite)
 */
static inline int64_t qemu_soonest_timeout(int64_t timeout1, int64_t timeout2)
{
    /* we can abuse the fact that -1 (which means infinite) is a maximal
     * value when cast to unsigned. As this is disgusting, it's kept in
     * one inline function.
     */
    return ((uint64_t) timeout1 < (uint64_t) timeout2) ? timeout1 : timeout2;
}

/**
 * initclocks:
 *
 * Initialise the clock & timer infrastructure
 */
void init_clocks(void);

int64_t cpu_get_ticks(void);
/* Caller must hold BQL */
void cpu_enable_ticks(void);
/* Caller must hold BQL */
void cpu_disable_ticks(void);

static inline int64_t get_ticks_per_sec(void)
{
    return 1000000000LL;
}

/*
 * Low level clock functions
 */

/* real time host monotonic timer */
static inline int64_t get_clock_realtime(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
}

/* Warning: don't insert tracepoints into these functions, they are
   also used by simpletrace backend and tracepoints would cause
   an infinite recursion! */
#ifdef _WIN32
extern int64_t clock_freq;

static inline int64_t get_clock(void)
{
    LARGE_INTEGER ti;
    QueryPerformanceCounter(&ti);
    return muldiv64(ti.QuadPart, (uint32_t)get_ticks_per_sec(), (uint32_t)clock_freq);
}

#else

static inline int64_t get_clock(void)
{
    return get_clock_realtime();
}
#endif

/* icount */
int64_t cpu_get_icount(void);
int64_t cpu_get_clock(void);
int64_t cpu_get_clock_offset(void);
int64_t cpu_icount_to_ns(int64_t icount);

/*******************************************/
/* host CPU ticks (if available) */

#if defined(_ARCH_PPC)

static inline int64_t cpu_get_real_ticks(void)
{
    int64_t retval;
#ifdef _ARCH_PPC64
    /* This reads timebase in one 64bit go and includes Cell workaround from:
       http://ozlabs.org/pipermail/linuxppc-dev/2006-October/027052.html
    */
    __asm__ __volatile__ ("mftb    %0\n\t"
                          "cmpwi   %0,0\n\t"
                          "beq-    $-8"
                          : "=r" (retval));
#else
    /* http://ozlabs.org/pipermail/linuxppc-dev/1999-October/003889.html */
    unsigned long junk;
    __asm__ __volatile__ ("mfspr   %1,269\n\t"  /* mftbu */
                          "mfspr   %L0,268\n\t" /* mftb */
                          "mfspr   %0,269\n\t"  /* mftbu */
                          "cmpw    %0,%1\n\t"
                          "bne     $-16"
                          : "=r" (retval), "=r" (junk));
#endif
    return retval;
}

#elif defined(__i386__)

static inline int64_t cpu_get_real_ticks(void)
{
#ifdef _MSC_VER
    return __rdtsc();
#else
    int64_t val;
    asm volatile ("rdtsc" : "=A" (val));
    return val;
#endif
}

#elif defined(__x86_64__)

static inline int64_t cpu_get_real_ticks(void)
{
#ifdef _MSC_VER
    return __rdtsc();
#else
    uint32_t low,high;
    int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
#endif
}

#elif defined(__hppa__)

static inline int64_t cpu_get_real_ticks(void)
{
    int val;
    asm volatile ("mfctl %%cr16, %0" : "=r"(val));
    return val;
}

#elif defined(__ia64)

static inline int64_t cpu_get_real_ticks(void)
{
    int64_t val;
    asm volatile ("mov %0 = ar.itc" : "=r"(val) :: "memory");
    return val;
}

#elif defined(__s390__)

static inline int64_t cpu_get_real_ticks(void)
{
    int64_t val;
    asm volatile("stck 0(%1)" : "=m" (val) : "a" (&val) : "cc");
    return val;
}

#elif defined(__sparc__)

static inline int64_t cpu_get_real_ticks (void)
{
#if defined(_LP64)
    uint64_t        rval;
    asm volatile("rd %%tick,%0" : "=r"(rval));
    return rval;
#else
    /* We need an %o or %g register for this.  For recent enough gcc
       there is an "h" constraint for that.  Don't bother with that.  */
    union {
        uint64_t i64;
        struct {
            uint32_t high;
            uint32_t low;
        }       i32;
    } rval;
    asm volatile("rd %%tick,%%g1; srlx %%g1,32,%0; mov %%g1,%1"
                 : "=r"(rval.i32.high), "=r"(rval.i32.low) : : "g1");
    return rval.i64;
#endif
}

#elif defined(__mips__) && \
    ((defined(__mips_isa_rev) && __mips_isa_rev >= 2) || defined(__linux__))
/*
 * binutils wants to use rdhwr only on mips32r2
 * but as linux kernel emulate it, it's fine
 * to use it.
 *
 */
#define MIPS_RDHWR(rd, value) {                         \
        __asm__ __volatile__ (".set   push\n\t"         \
                              ".set mips32r2\n\t"       \
                              "rdhwr  %0, "rd"\n\t"     \
                              ".set   pop"              \
                              : "=r" (value));          \
    }

static inline int64_t cpu_get_real_ticks(void)
{
    /* On kernels >= 2.6.25 rdhwr <reg>, $2 and $3 are emulated */
    uint32_t count;
    static uint32_t cyc_per_count = 0;

    if (!cyc_per_count) {
        MIPS_RDHWR("$3", cyc_per_count);
    }

    MIPS_RDHWR("$2", count);
    return (int64_t)(count * cyc_per_count);
}

#elif defined(__alpha__)

static inline int64_t cpu_get_real_ticks(void)
{
    uint64_t cc;
    uint32_t cur, ofs;

    asm volatile("rpcc %0" : "=r"(cc));
    cur = cc;
    ofs = cc >> 32;
    return cur - ofs;
}

#else
/* The host CPU doesn't have an easily accessible cycle counter.
   Just return a monotonically increasing value.  This will be
   totally wrong, but hopefully better than nothing.  */
static inline int64_t cpu_get_real_ticks (void)
{
    static int64_t ticks = 0;
    return ticks++;
}
#endif

#ifdef CONFIG_PROFILER
static inline int64_t profile_getclock(void)
{
    return cpu_get_real_ticks();
}

extern int64_t qemu_time, qemu_time_start;
extern int64_t tlb_flush_time;
extern int64_t dev_time;
#endif

#endif
