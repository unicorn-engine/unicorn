/*
 * Bitmap Module
 *
 * Copyright (C) 2010 Corentin Chary <corentin.chary@gmail.com>
 *
 * Mostly inspired by (stolen from) linux/bitmap.h and linux/bitops.h
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef BITMAP_H
#define BITMAP_H

#include "glib_compat.h"
#include <string.h>
#include <stdlib.h>

#include "qemu/osdep.h"
#include "qemu/bitops.h"

/*
 * The available bitmap operations and their rough meaning in the
 * case that the bitmap is a single unsigned long are thus:
 *
 * Note that nbits should be always a compile time evaluable constant.
 * Otherwise many inlines will generate horrible code.
 *
 * bitmap_set(dst, pos, nbits)			Set specified bit area
 * bitmap_set_atomic(dst, pos, nbits)   Set specified bit area with atomic ops
 * bitmap_clear(dst, pos, nbits)		Clear specified bit area
 * bitmap_test_and_clear_atomic(dst, pos, nbits)    Test and clear area
 */

/*
 * Also the following operations apply to bitmaps.
 *
 * set_bit(bit, addr)			*addr |= bit
 * clear_bit(bit, addr)			*addr &= ~bit
 */

#define BITMAP_LAST_WORD_MASK(nbits)                                    \
    (                                                                   \
        ((nbits) % BITS_PER_LONG) ?                                     \
        (1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL                       \
        )

#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]

long slow_bitmap_count_one(const unsigned long *bitmap, long nbits);

static inline unsigned long *bitmap_try_new(long nbits)
{
    long len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    return g_try_malloc0(len);
}

static inline unsigned long *bitmap_new(long nbits)
{
    unsigned long *ptr = bitmap_try_new(nbits);
    if (ptr == NULL) {
        abort();
    }
    return ptr;
}

static inline long bitmap_count_one(const unsigned long *bitmap, long nbits)
{
    if (small_nbits(nbits)) {
        return ctpopl(*bitmap & BITMAP_LAST_WORD_MASK(nbits));
    } else {
        return slow_bitmap_count_one(bitmap, nbits);
    }
}

void bitmap_set(unsigned long *map, long i, long len);
void bitmap_set_atomic(unsigned long *map, long i, long len);
void bitmap_clear(unsigned long *map, long start, long nr);
bool bitmap_test_and_clear_atomic(unsigned long *map, long start, long nr);
void bitmap_copy_and_clear_atomic(unsigned long *dst, unsigned long *src,
                                  long nr);

static inline unsigned long *bitmap_zero_extend(unsigned long *old,
                                                long old_nbits, long new_nbits)
{
    long new_len = BITS_TO_LONGS(new_nbits) * sizeof(unsigned long);
    unsigned long *new = g_realloc(old, new_len);
    bitmap_clear(new, old_nbits, new_nbits - old_nbits);
    return new;
}

#endif /* BITMAP_H */
