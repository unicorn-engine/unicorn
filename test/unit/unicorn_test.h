#ifndef UNICORN_TEST_H
#define UNICORN_TEST_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unicorn/unicorn.h>

static void uc_assert_success(uc_err err)
{
    assert_int_equal(err, 0);
    // uc_strerror(err)
}

#endif /* UNICORN_TEST_H */
