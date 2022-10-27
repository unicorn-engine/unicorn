#ifndef UNICORN_TEST_H
#define UNICORN_TEST_H

#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include "acutest.h"
#include "endian.h"
#include "bswap.h"

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
