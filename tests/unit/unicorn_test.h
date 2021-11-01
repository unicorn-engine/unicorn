#ifndef UNICORN_TEST_H
#define UNICORN_TEST_H

#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include "acutest.h"

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

#endif /* UNICORN_TEST_H */
