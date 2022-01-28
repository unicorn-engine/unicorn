/*
 * Simple interface for atomic operations.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * Author: Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * See docs/atomics.txt for discussion about the guarantees each
 * atomic primitive is meant to provide.
 */

#ifndef QEMU_ATOMIC_H
#define QEMU_ATOMIC_H

#include "qemu/compiler.h"

// we do not really support multiple CPUs, so we dont care
#define smp_mb()
#define smp_wmb()
#define smp_rmb()
#define barrier()

/* The variable that receives the old value of an atomically-accessed
 * variable must be non-qualified, because atomic builtins return values
 * through a pointer-type argument as in __atomic_load(&var, &old, MODEL).
 *
 * This macro has to handle types smaller than int manually, because of
 * implicit promotion.  int and larger types, as well as pointers, can be
 * converted to a non-qualified type just by applying a binary operator.
 */
#define typeof_strip_qual(expr)                                                    \
  typeof(                                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), bool) ||                          \
        __builtin_types_compatible_p(typeof(expr), const bool) ||                  \
        __builtin_types_compatible_p(typeof(expr), volatile bool) ||               \
        __builtin_types_compatible_p(typeof(expr), const volatile bool),           \
        (bool)1,                                                                   \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed char) ||                   \
        __builtin_types_compatible_p(typeof(expr), const signed char) ||           \
        __builtin_types_compatible_p(typeof(expr), volatile signed char) ||        \
        __builtin_types_compatible_p(typeof(expr), const volatile signed char),    \
        (signed char)1,                                                            \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned char) ||                 \
        __builtin_types_compatible_p(typeof(expr), const unsigned char) ||         \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned char) ||      \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned char),  \
        (unsigned char)1,                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed short) ||                  \
        __builtin_types_compatible_p(typeof(expr), const signed short) ||          \
        __builtin_types_compatible_p(typeof(expr), volatile signed short) ||       \
        __builtin_types_compatible_p(typeof(expr), const volatile signed short),   \
        (signed short)1,                                                           \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned short) ||                \
        __builtin_types_compatible_p(typeof(expr), const unsigned short) ||        \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned short) ||     \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned short), \
        (unsigned short)1,                                                         \
      (expr)+0))))))

#ifdef __ATOMIC_RELAXED
/* For C11 atomic ops */

/* Sanity check that the size of an atomic operation isn't "overly large".
 * Despite the fact that e.g. i686 has 64-bit atomic operations, we do not
 * want to use them because we ought not need them, and this lets us do a
 * bit of sanity checking that other 32-bit hosts might build.
 *
 * That said, we have a problem on 64-bit ILP32 hosts in that in order to
 * sync with TCG_OVERSIZED_GUEST, this must match TCG_TARGET_REG_BITS.
 * We'd prefer not want to pull in everything else TCG related, so handle
 * those few cases by hand.
 *
 * Note that x32 is fully detected with __x86_64__ + _ILP32, and that for
 * Sparc we always force the use of sparcv9 in configure. MIPS n32 (ILP32) &
 * n64 (LP64) ABIs are both detected using __mips64.
 */
#if defined(__x86_64__) || defined(__sparc__) || defined(__mips64)
# define ATOMIC_REG_SIZE  8
#else
# define ATOMIC_REG_SIZE  sizeof(void *)
#endif

/* Weak atomic operations prevent the compiler moving other
 * loads/stores past the atomic operation load/store. However there is
 * no explicit memory barrier for the processor.
 *
 * The C11 memory model says that variables that are accessed from
 * different threads should at least be done with __ATOMIC_RELAXED
 * primitives or the result is undefined. Generally this has little to
 * no effect on the generated code but not using the atomic primitives
 * will get flagged by sanitizers as a violation.
 */
#define atomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)

#define atomic_read(ptr)                          \
    ({                                            \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_read__nocheck(ptr);                        \
    })

#define atomic_set__nocheck(ptr, i) \
    __atomic_store_n(ptr, i, __ATOMIC_RELAXED)

#define atomic_set(ptr, i)  do {                  \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    atomic_set__nocheck(ptr, i);                      \
} while(0)

/* All the remaining operations are fully sequentially consistent */

#define atomic_xchg__nocheck(ptr, i)    ({                  \
    __atomic_exchange_n(ptr, (i), __ATOMIC_SEQ_CST);        \
})

#define atomic_xchg(ptr, i)    ({                           \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);      \
    atomic_xchg__nocheck(ptr, i);                           \
})

/* Returns the eventual value, failed or not */
#define atomic_cmpxchg__nocheck(ptr, old, new)    ({                    \
    typeof_strip_qual(*ptr) _old = (old);                               \
    (void)__atomic_compare_exchange_n(ptr, &_old, new, false,           \
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);      \
    _old;                                                               \
})

#define atomic_cmpxchg(ptr, old, new)    ({                             \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);                  \
    atomic_cmpxchg__nocheck(ptr, old, new);                             \
})

/* Provide shorter names for GCC atomic builtins, return old value */
#define atomic_fetch_inc(ptr)  __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_dec(ptr)  __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_fetch_add(ptr, n) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub(ptr, n) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_and(ptr, n) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_or(ptr, n)  __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor(ptr, n) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST)

#define atomic_inc_fetch(ptr)    __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_dec_fetch(ptr)    __atomic_sub_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define atomic_add_fetch(ptr, n) __atomic_add_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_sub_fetch(ptr, n) __atomic_sub_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_and_fetch(ptr, n) __atomic_and_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_or_fetch(ptr, n)  __atomic_or_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_xor_fetch(ptr, n) __atomic_xor_fetch(ptr, n, __ATOMIC_SEQ_CST)

/* And even shorter names that return void.  */
#define atomic_inc(ptr)    ((void) __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST))
#define atomic_dec(ptr)    ((void) __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST))
#define atomic_add(ptr, n) ((void) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_sub(ptr, n) ((void) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_and(ptr, n) ((void) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_or(ptr, n)  ((void) __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST))
#define atomic_xor(ptr, n) ((void) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST))

#else /* __ATOMIC_RELAXED */

#if defined(__i386__) || defined(__x86_64__) || defined(__s390x__)
/*
 * __sync_lock_test_and_set() is documented to be an acquire barrier only,
 * but it is a full barrier at the hardware level.  Add a compiler barrier
 * to make it a full barrier also at the compiler level.
 */
#ifndef _MSC_VER
#if defined(__clang__)
#define atomic_xchg(ptr, i)    __sync_swap(ptr, i)
#else
#define atomic_xchg(ptr, i)    (__sync_lock_test_and_set(ptr, i))
#endif
#endif

#endif

/* These will only be atomic if the processor does the fetch or store
 * in a single issue memory operation
 */
#define atomic_read__nocheck(p)   (*(__typeof__(*(p)) volatile*) (p))
#define atomic_set__nocheck(p, i) ((*(__typeof__(*(p)) volatile*) (p)) = (i))

#define atomic_read(ptr)       atomic_read__nocheck(ptr)
#define atomic_set(ptr, i)     atomic_set__nocheck(ptr,i)

#define atomic_xchg__nocheck  atomic_xchg

/* Provide shorter names for GCC atomic builtins.  */
#ifdef _MSC_VER
// these return the new value (so we make it return the previous value)
#define atomic_fetch_inc(ptr)         ((InterlockedIncrement(ptr))-1)
#define atomic_fetch_dec(ptr)         ((InterlockedDecrement(ptr))+1)
#define atomic_fetch_add(ptr, n)      ((InterlockedAdd(ptr,  n))-n)
#define atomic_fetch_sub(ptr, n)      ((InterlockedAdd(ptr, -n))+n)
#define atomic_fetch_and(ptr, n)      ((InterlockedAnd(ptr, n)))
#define atomic_fetch_or(ptr, n)       ((InterlockedOr(ptr, n)))
#define atomic_fetch_xor(ptr, n)      ((InterlockedXor(ptr, n)))

#define atomic_inc_fetch(ptr)         (InterlockedIncrement((long*)(ptr)))
#define atomic_dec_fetch(ptr)         (InterlockedDecrement((long*)(ptr)))
#define atomic_add_fetch(ptr, n)      (InterlockedExchangeAdd((long*)ptr, n) + n)
#define atomic_sub_fetch(ptr, n)      (InterlockedExchangeAdd((long*)ptr, n) - n)
#define atomic_and_fetch(ptr, n)      (InterlockedAnd((long*)ptr, n) & n)
#define atomic_or_fetch(ptr, n)       (InterlockedOr((long*)ptr, n) | n)
#define atomic_xor_fetch(ptr, n)      (InterlockedXor((long*)ptr, n) ^ n)

#define atomic_cmpxchg(ptr, old, new) ((InterlockedCompareExchange(ptr, old, new)))
#define atomic_cmpxchg__nocheck(ptr, old, new)  atomic_cmpxchg(ptr, old, new)

#define atomic_inc(ptr)        ((void) InterlockedIncrement(ptr))
#define atomic_dec(ptr)        ((void) InterlockedDecrement(ptr))
#define atomic_add(ptr, n)     ((void) InterlockedAdd(ptr, n))
#define atomic_sub(ptr, n)     ((void) InterlockedAdd(ptr, -n))
#define atomic_and(ptr, n)     ((void) InterlockedAnd(ptr, n))
#define atomic_or(ptr, n)      ((void) InterlockedOr(ptr, n))
#define atomic_xor(ptr, n)     ((void) InterlockedXor(ptr, n))
#else // GCC/clang
// these return the previous value
#define atomic_fetch_inc(ptr)  __sync_fetch_and_add(ptr, 1)
#define atomic_fetch_dec(ptr)  __sync_fetch_and_add(ptr, -1)
#define atomic_fetch_add(ptr, n) __sync_fetch_and_add(ptr, n)
#define atomic_fetch_sub(ptr, n) __sync_fetch_and_sub(ptr, n)
#define atomic_fetch_and(ptr, n) __sync_fetch_and_and(ptr, n)
#define atomic_fetch_or(ptr, n) __sync_fetch_and_or(ptr, n)
#define atomic_fetch_xor(ptr, n) __sync_fetch_and_xor(ptr, n)

#define atomic_inc_fetch(ptr)  __sync_add_and_fetch(ptr, 1)
#define atomic_dec_fetch(ptr)  __sync_add_and_fetch(ptr, -1)
#define atomic_add_fetch(ptr, n) __sync_add_and_fetch(ptr, n)
#define atomic_sub_fetch(ptr, n) __sync_sub_and_fetch(ptr, n)
#define atomic_and_fetch(ptr, n) __sync_and_and_fetch(ptr, n)
#define atomic_or_fetch(ptr, n) __sync_or_and_fetch(ptr, n)
#define atomic_xor_fetch(ptr, n) __sync_xor_and_fetch(ptr, n)

#define atomic_cmpxchg(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)
#define atomic_cmpxchg__nocheck(ptr, old, new)  atomic_cmpxchg(ptr, old, new)

#define atomic_inc(ptr)        ((void) __sync_fetch_and_add(ptr, 1))
#define atomic_dec(ptr)        ((void) __sync_fetch_and_add(ptr, -1))
#define atomic_add(ptr, n)     ((void) __sync_fetch_and_add(ptr, n))
#define atomic_sub(ptr, n)     ((void) __sync_fetch_and_sub(ptr, n))
#define atomic_and(ptr, n)     ((void) __sync_fetch_and_and(ptr, n))
#define atomic_or(ptr, n)      ((void) __sync_fetch_and_or(ptr, n))
#define atomic_xor(ptr, n)     ((void) __sync_fetch_and_xor(ptr, n))
#endif

#endif /* __ATOMIC_RELAXED */

#endif /* QEMU_ATOMIC_H */
