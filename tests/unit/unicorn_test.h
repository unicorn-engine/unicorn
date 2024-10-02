#ifndef UNICORN_TEST_H
#define UNICORN_TEST_H

#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include "acutest.h"
#include "endian.h"

// Copied from glibc-2.29

/* Swap bytes in 32 bit value.  */
#define bswap_32(x)                                                            \
    ((((x)&0xff000000u) >> 24) | (((x)&0x00ff0000u) >> 8) |                    \
     (((x)&0x0000ff00u) << 8) | (((x)&0x000000ffu) << 24))

/* Swap bytes in 64 bit value.  */
#define bswap_64(x)                                                            \
    ((((x)&0xff00000000000000ull) >> 56) |                                     \
     (((x)&0x00ff000000000000ull) >> 40) |                                     \
     (((x)&0x0000ff0000000000ull) >> 24) |                                     \
     (((x)&0x000000ff00000000ull) >> 8) | (((x)&0x00000000ff000000ull) << 8) | \
     (((x)&0x0000000000ff0000ull) << 24) |                                     \
     (((x)&0x000000000000ff00ull) << 40) |                                     \
     (((x)&0x00000000000000ffull) << 56))

/**
 * Assert that err matches expect
 */
#define uc_assert_err(expect, err)                                             \
    do {                                                                       \
        uc_err __err = err;                                                    \
        if (!TEST_CHECK(__err == expect)) {                                    \
            TEST_MSG("%s", uc_strerror(__err));                                \
        }                                                                      \
    } while (0)

/**
 * Assert that err is UC_ERR_OK
 */
#define OK(stat) uc_assert_err(UC_ERR_OK, stat)

#ifdef BOOST_LITTLE_ENDIAN
#define LEINT32(x) (x)
#define LEINT64(x) (x)
#define BEINT32(x) (bswap_32(x))
#define BEINT64(x) (bswap_64(x))
#else
#define LEINT32(x) (bswap_32(x))
#define LEINT64(x) (bswap_64(x))
#define BEINT32(x) (x)
#define BEINT64(x) (x)
#endif

#endif /* UNICORN_TEST_H */
