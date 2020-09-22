/*
 * Bitmap Module
 *
 * Stolen from linux/src/lib/bitmap.c
 *
 * Copyright (C) 2010 Corentin Chary
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.
 */

#include "qemu/bitops.h"
#include "qemu/bitmap.h"

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) % BITS_PER_LONG))

void qemu_bitmap_set(unsigned long *map, long start, long nr)
{
    unsigned long *p = map + BIT_WORD(start);
    const long size = start + nr;
    int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
    unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

    while (nr - bits_to_set >= 0) {
        *p |= mask_to_set;
        nr -= bits_to_set;
        bits_to_set = BITS_PER_LONG;
        mask_to_set = ~0UL;
        p++;
    }
    if (nr) {
        mask_to_set &= BITMAP_LAST_WORD_MASK(size);
        *p |= mask_to_set;
    }
}

void qemu_bitmap_clear(unsigned long *map, long start, long nr)
{
    unsigned long *p = map + BIT_WORD(start);
    const long size = start + nr;
    int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
    unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

    while (nr - bits_to_clear >= 0) {
        *p &= ~mask_to_clear;
        nr -= bits_to_clear;
        bits_to_clear = BITS_PER_LONG;
        mask_to_clear = ~0UL;
        p++;
    }
    if (nr) {
        mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
        *p &= ~mask_to_clear;
    }
}
