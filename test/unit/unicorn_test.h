#ifndef UNICORN_TEST_H
#define UNICORN_TEST_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unicorn/unicorn.h>

#define uc_assert_success(err)              \
do {                                        \
    uc_err __err = err;                     \
    if (__err != UC_ERR_OK) {               \
        fail_msg("%s", uc_strerror(__err)); \
    }                                       \
} while (0)
    



#endif /* UNICORN_TEST_H */
