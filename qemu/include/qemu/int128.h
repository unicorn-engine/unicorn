#ifndef INT128_H
#define INT128_H

#include "qemu/bswap.h"
#ifdef CONFIG_INT128

typedef __int128_t Int128;

static inline Int128 int128_make64(uint64_t a)
{
    return a;
}

static inline Int128 int128_make128(uint64_t lo, uint64_t hi)
{
    return (__uint128_t)hi << 64 | lo;
}

static inline uint64_t int128_get64(Int128 a)
{
    uint64_t r = a;
    assert(r == a);
    return r;
}

static inline uint64_t int128_getlo(Int128 a)
{
    return a;
}

static inline int64_t int128_gethi(Int128 a)
{
    return a >> 64;
}

static inline Int128 int128_zero(void)
{
    return 0;
}

static inline Int128 int128_one(void)
{
    return 1;
}

static inline Int128 int128_2_64(void)
{
    return (Int128)1 << 64;
}

static inline Int128 int128_exts64(int64_t a)
{
    return a;
}

static inline Int128 int128_and(Int128 a, Int128 b)
{
    return a & b;
}

static inline Int128 int128_rshift(Int128 a, int n)
{
    return a >> n;
}

static inline Int128 int128_add(Int128 a, Int128 b)
{
    return a + b;
}

static inline Int128 int128_neg(Int128 a)
{
    return -a;
}

static inline Int128 int128_sub(Int128 a, Int128 b)
{
    return a - b;
}

static inline bool int128_nonneg(Int128 a)
{
    return a >= 0;
}

static inline bool int128_eq(Int128 a, Int128 b)
{
    return a == b;
}

static inline bool int128_ne(Int128 a, Int128 b)
{
    return a != b;
}

static inline bool int128_ge(Int128 a, Int128 b)
{
    return a >= b;
}

static inline bool int128_lt(Int128 a, Int128 b)
{
    return a < b;
}

static inline bool int128_le(Int128 a, Int128 b)
{
    return a <= b;
}

static inline bool int128_gt(Int128 a, Int128 b)
{
    return a > b;
}

static inline bool int128_nz(Int128 a)
{
    return a != 0;
}

static inline Int128 int128_min(Int128 a, Int128 b)
{
    return a < b ? a : b;
}

static inline Int128 int128_max(Int128 a, Int128 b)
{
    return a > b ? a : b;
}

static inline void int128_addto(Int128 *a, Int128 b)
{
    *a += b;
}

static inline void int128_subfrom(Int128 *a, Int128 b)
{
    *a -= b;
}

static inline Int128 bswap128(Int128 a)
{
    return int128_make128(bswap64(int128_gethi(a)), bswap64(int128_getlo(a)));
}

#else /* !CONFIG_INT128 */

typedef struct Int128 Int128;
typedef Int128 __int128_t;

struct Int128 {
    uint64_t lo;
    int64_t hi;
};

static inline Int128 int128_make64(uint64_t a)
{
    return (Int128) { a, 0 };
}

static inline Int128 int128_make128(uint64_t lo, uint64_t hi)
{
    return (Int128) { lo, hi };
}

static inline uint64_t int128_get64(Int128 a)
{
    assert(!a.hi);
    return a.lo;
}

static inline uint64_t int128_getlo(Int128 a)
{
    return a.lo;
}

static inline int64_t int128_gethi(Int128 a)
{
    return a.hi;
}

static inline Int128 int128_zero(void)
{
    return int128_make64(0);
}

static inline Int128 int128_one(void)
{
    return int128_make64(1);
}

static inline Int128 int128_2_64(void)
{
    return (Int128) { 0, 1 };
}

static inline Int128 int128_exts64(int64_t a)
{
    return (Int128) { .lo = a, .hi = (a < 0) ? -1 : 0 };
}

static inline Int128 int128_and(Int128 a, Int128 b)
{
    return (Int128) { a.lo & b.lo, a.hi & b.hi };
}

static inline Int128 int128_rshift(Int128 a, int n)
{
    int64_t h;
    if (!n) {
        return a;
    }
    h = a.hi >> (n & 63);
    if (n >= 64) {
        return int128_make128(h, h >> 63);
    } else {
        return int128_make128((a.lo >> n) | ((uint64_t)a.hi << (64 - n)), h);
    }
}

static inline Int128 int128_add(Int128 a, Int128 b)
{
    uint64_t lo = a.lo + b.lo;

    /* a.lo <= a.lo + b.lo < a.lo + k (k is the base, 2^64).  Hence,
     * a.lo + b.lo >= k implies 0 <= lo = a.lo + b.lo - k < a.lo.
     * Similarly, a.lo + b.lo < k implies a.lo <= lo = a.lo + b.lo < k.
     *
     * So the carry is lo < a.lo.
     */
    return int128_make128(lo, (uint64_t)a.hi + b.hi + (lo < a.lo));
}

static inline Int128 int128_neg(Int128 a)
{
#ifdef _MSC_VER
    uint64_t lo = a.lo;
    lo = 0 - lo;
#else
    uint64_t lo = (uint64_t)(-a.lo);
#endif
    return int128_make128(lo, ~(uint64_t)a.hi + !lo);
}

static inline Int128 int128_sub(Int128 a, Int128 b)
{
    return int128_make128(a.lo - b.lo, (uint64_t)a.hi - b.hi - (a.lo < b.lo));
}

static inline bool int128_nonneg(Int128 a)
{
    return a.hi >= 0;
}

static inline bool int128_eq(Int128 a, Int128 b)
{
    return a.lo == b.lo && a.hi == b.hi;
}

static inline bool int128_ne(Int128 a, Int128 b)
{
    return !int128_eq(a, b);
}

static inline bool int128_ge(Int128 a, Int128 b)
{
    return a.hi > b.hi || (a.hi == b.hi && a.lo >= b.lo);
}

static inline bool int128_lt(Int128 a, Int128 b)
{
    return !int128_ge(a, b);
}

static inline bool int128_le(Int128 a, Int128 b)
{
    return int128_ge(b, a);
}

static inline bool int128_gt(Int128 a, Int128 b)
{
    return !int128_le(a, b);
}

static inline bool int128_nz(Int128 a)
{
    return a.lo || a.hi;
}

static inline Int128 int128_min(Int128 a, Int128 b)
{
    return int128_le(a, b) ? a : b;
}

static inline Int128 int128_max(Int128 a, Int128 b)
{
    return int128_ge(a, b) ? a : b;
}

static inline void int128_addto(Int128 *a, Int128 b)
{
    *a = int128_add(*a, b);
}

static inline void int128_subfrom(Int128 *a, Int128 b)
{
    *a = int128_sub(*a, b);
}

static inline Int128 bswap128(Int128 a)
{
    return int128_make128(bswap64(int128_gethi(a)), bswap64(int128_getlo(a)));
}

#endif /* CONFIG_INT128 */
#endif /* INT128_H */
