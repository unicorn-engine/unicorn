/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/* Originally developed and coded by Makoto Matsumoto and Takuji
 * Nishimura.  Please mail <matumoto@math.keio.ac.jp>, if you're using
 * code from this file in your own programs or libraries.
 * Further information on the Mersenne Twister can be found at
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 * This code was adapted to glib by Sebastian Wilhelmi.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */

/*
 * MT safe
 */

#define _CRT_RAND_S

#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifndef _MSC_VER
#include <unistd.h>
#include <sys/time.h>
#else
#include <windows.h>
#endif

#include "grand.h"
#include "gmem.h"
#include "gmessages.h"

#define G_USEC_PER_SEC 1000000

#if defined(__MINGW64_VERSION_MAJOR) || defined(_WIN32)
errno_t rand_s(unsigned int* randomValue);
#endif

#define G_GINT64_CONSTANT(val) (val##L)

/* Period parameters */  
#define N 624
#define M 397
#define MATRIX_A 0x9908b0df   /* constant vector a */
#define UPPER_MASK 0x80000000 /* most significant w-r bits */
#define LOWER_MASK 0x7fffffff /* least significant r bits */

/* Tempering parameters */   
#define TEMPERING_MASK_B 0x9d2c5680
#define TEMPERING_MASK_C 0xefc60000
#define TEMPERING_SHIFT_U(y)  (y >> 11)
#define TEMPERING_SHIFT_S(y)  (y << 7)
#define TEMPERING_SHIFT_T(y)  (y << 15)
#define TEMPERING_SHIFT_L(y)  (y >> 18)

struct _GRand
{
    guint32 mt[N]; /* the array for the state vector  */
    guint mti; 
};

static guint get_random_version (void)
{
    static gsize initialized = FALSE;
    static guint random_version;

    if (!initialized)
    {
        // g_warning ("Unknown G_RANDOM_VERSION \"%s\". Using version 2.2.", version_string);
        random_version = 22;
        initialized = TRUE;
    }

    return random_version;
}

/**
 * g_rand_set_seed:
 * @rand_: a #GRand
 * @seed: a value to reinitialize the random number generator
 *
 * Sets the seed for the random number generator #GRand to @seed.
 */
void g_rand_set_seed (GRand *rand, guint32  seed)
{
    g_return_if_fail (rand != NULL);

    switch (get_random_version ())
    {
        case 20:
            /* setting initial seeds to mt[N] using         */
            /* the generator Line 25 of Table 1 in          */
            /* [KNUTH 1981, The Art of Computer Programming */
            /*    Vol. 2 (2nd Ed.), pp102]                  */

            if (seed == 0) /* This would make the PRNG produce only zeros */
                seed = 0x6b842128; /* Just set it to another number */

            rand->mt[0]= seed;
            for (rand->mti=1; rand->mti<N; rand->mti++)
                rand->mt[rand->mti] = (69069 * rand->mt[rand->mti-1]);

            break;
        case 22:
            /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
            /* In the previous version (see above), MSBs of the    */
            /* seed affect only MSBs of the array mt[].            */

            rand->mt[0]= seed;
            for (rand->mti=1; rand->mti<N; rand->mti++)
                rand->mt[rand->mti] = 1812433253UL * 
                    (rand->mt[rand->mti-1] ^ (rand->mt[rand->mti-1] >> 30)) + rand->mti; 
            break;
        default:
            // g_assert_not_reached ();
            break;
    }
}

/**
 * g_rand_new_with_seed:
 * @seed: a value to initialize the random number generator
 * 
 * Creates a new random number generator initialized with @seed.
 * 
 * Returns: the new #GRand
 **/
GRand* g_rand_new_with_seed (guint32 seed)
{
    GRand *rand = g_new0 (GRand, 1);
    g_rand_set_seed (rand, seed);
    return rand;
}

/**
 * g_rand_set_seed_array:
 * @rand_: a #GRand
 * @seed: array to initialize with
 * @seed_length: length of array
 *
 * Initializes the random number generator by an array of longs.
 * Array can be of arbitrary size, though only the first 624 values
 * are taken.  This function is useful if you have many low entropy
 * seeds, or if you require more then 32 bits of actual entropy for
 * your application.
 *
 * Since: 2.4
 */
void g_rand_set_seed_array (GRand *rand, const guint32 *seed, guint seed_length)
{
    guint i, j, k;

    g_return_if_fail (rand != NULL);
    g_return_if_fail (seed_length >= 1);

    g_rand_set_seed (rand, 19650218UL);

    i=1; j=0;
    k = (N>seed_length ? N : seed_length);
    for (; k; k--)
    {
        rand->mt[i] = (rand->mt[i] ^
                ((rand->mt[i-1] ^ (rand->mt[i-1] >> 30)) * 1664525UL))
            + seed[j] + j; /* non linear */
        rand->mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */
        i++; j++;
        if (i>=N)
        {
            rand->mt[0] = rand->mt[N-1];
            i=1;
        }
        if (j>=seed_length)
            j=0;
    }
    for (k=N-1; k; k--)
    {
        rand->mt[i] = (rand->mt[i] ^
                ((rand->mt[i-1] ^ (rand->mt[i-1] >> 30)) * 1566083941UL))
            - i; /* non linear */
        rand->mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */
        i++;
        if (i>=N)
        {
            rand->mt[0] = rand->mt[N-1];
            i=1;
        }
    }

    rand->mt[0] = 0x80000000UL; /* MSB is 1; assuring non-zero initial array */ 
}

/**
 * g_rand_new_with_seed_array:
 * @seed: an array of seeds to initialize the random number generator
 * @seed_length: an array of seeds to initialize the random number
 *     generator
 * 
 * Creates a new random number generator initialized with @seed.
 * 
 * Returns: the new #GRand
 *
 * Since: 2.4
 */
GRand *g_rand_new_with_seed_array (const guint32 *seed, guint seed_length)
{
    GRand *rand = g_new0 (GRand, 1);
    g_rand_set_seed_array (rand, seed, seed_length);
    return rand;
}

gint64 g_get_real_time (void)
{
#if defined(unix) || defined(__unix__) || defined(__unix) || defined (__MINGW32__) || defined(__APPLE__) || defined(__HAIKU__)
    struct timeval r;

    /* this is required on alpha, there the timeval structs are ints
     * not longs and a cast only would fail horribly */
    gettimeofday (&r, NULL);

    return (((gint64) r.tv_sec) * 1000000) + r.tv_usec;
#else
    FILETIME ft;
    guint64 time64;

    GetSystemTimeAsFileTime (&ft);
    memmove (&time64, &ft, sizeof (FILETIME));

    /* Convert from 100s of nanoseconds since 1601-01-01
     * to Unix epoch. This is Y2038 safe.
     */
    time64 -= G_GINT64_CONSTANT (116444736000000000);
    time64 /= 10;

    return time64;
#endif
}

/**
 * g_rand_new:
 * 
 * Creates a new random number generator initialized with a seed taken
 * either from `/dev/urandom` (if existing) or from the current time
 * (as a fallback).
 *
 * On Windows, the seed is taken from rand_s().
 * 
 * Returns: the new #GRand
 */
GRand *g_rand_new (void)
{
    guint32 seed[4];
#if defined(unix) || defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__HAIKU__)
    static gboolean dev_urandom_exists = TRUE;

    if (dev_urandom_exists)
    {
        FILE* dev_urandom;

        do
        {
            dev_urandom = fopen("/dev/urandom", "rb");
        }
        while (dev_urandom == NULL && errno == EINTR);

        if (dev_urandom)
        {
            int r;

            setvbuf (dev_urandom, NULL, _IONBF, 0);
            do
            {
                errno = 0;
                r = fread (seed, sizeof (seed), 1, dev_urandom);
            }
            while (errno == EINTR);

            if (r != 1)
                dev_urandom_exists = FALSE;

            fclose (dev_urandom);
        }	
        else
            dev_urandom_exists = FALSE;
    }

    if (!dev_urandom_exists)
    {
        gint64 now_us = g_get_real_time ();
        seed[0] = now_us / G_USEC_PER_SEC;
        seed[1] = now_us % G_USEC_PER_SEC;
        seed[2] = getpid ();
        seed[3] = getppid ();
    }
#else /* G_OS_WIN32 */
    /* rand_s() is only available since Visual Studio 2005 and
     * MinGW-w64 has a wrapper that will emulate rand_s() if it's not in msvcrt
     */
#if (defined(_MSC_VER) && _MSC_VER >= 1400) || defined(__MINGW64_VERSION_MAJOR)
    gint i;

    for (i = 0; i < 4;/* array size of seed */ i++) {
        rand_s(&seed[i]);
    }
#else
#warning Using insecure seed for random number generation because of missing rand_s() in Windows XP
    GTimeVal now;

    g_get_current_time (&now);
    seed[0] = now.tv_sec;
    seed[1] = now.tv_usec;
    seed[2] = getpid ();
    seed[3] = 0;
#endif

#endif

    return g_rand_new_with_seed_array (seed, 4);
}

/**
 * g_rand_int:
 * @rand_: a #GRand
 *
 * Returns the next random #guint32 from @rand_ equally distributed over
 * the range [0..2^32-1].
 *
 * Returns: a random number
 */
guint32 g_rand_int (GRand *rand)
{
    guint32 y;
    static const guint32 mag01[2]={0x0, MATRIX_A};
    /* mag01[x] = x * MATRIX_A  for x=0,1 */

    g_return_val_if_fail (rand != NULL, 0);

    if (rand->mti >= N) { /* generate N words at one time */
        int kk;

        for (kk = 0; kk < N - M; kk++) {
            y = (rand->mt[kk]&UPPER_MASK)|(rand->mt[kk+1]&LOWER_MASK);
            rand->mt[kk] = rand->mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1];
        }
        for (; kk < N - 1; kk++) {
            y = (rand->mt[kk]&UPPER_MASK)|(rand->mt[kk+1]&LOWER_MASK);
            rand->mt[kk] = rand->mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1];
        }
        y = (rand->mt[N-1]&UPPER_MASK)|(rand->mt[0]&LOWER_MASK);
        rand->mt[N-1] = rand->mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1];

        rand->mti = 0;
    }

    y = rand->mt[rand->mti++];
    y ^= TEMPERING_SHIFT_U(y);
    y ^= TEMPERING_SHIFT_S(y) & TEMPERING_MASK_B;
    y ^= TEMPERING_SHIFT_T(y) & TEMPERING_MASK_C;
    y ^= TEMPERING_SHIFT_L(y);

    return y; 
}

