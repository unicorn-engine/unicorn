#include "unicorn_test.h"

/* Make sure the uc_assert macros work with constants */
static void test_uc_assert_macros_constants(void **state)
{
    const uc_err nomem = UC_ERR_NOMEM;

    uc_assert_success(UC_ERR_OK);
    uc_assert_err(UC_ERR_NOMEM, nomem);
    uc_assert_fail(UC_ERR_VERSION);
}

/******************************************************************************/

static uc_err feedback(uc_err err, int *callcount)
{
    assert_int_equal(++(*callcount), 1);
    return err;
}

/**
 * Make sure the uc_assert macros work with function calls
 * and only evaluate them once!
 */
static void test_uc_assert_macros_func_calls(void **state)
{
    int callcount;

    callcount = 0;
    uc_assert_success(feedback(UC_ERR_OK, &callcount));

    callcount = 0;
    uc_assert_err(UC_ERR_NOMEM, feedback(UC_ERR_NOMEM, &callcount));

    callcount = 0;
    uc_assert_fail(feedback(UC_ERR_VERSION, &callcount));
}

/******************************************************************************/

static void fail_uc_assert_success(void **state)
{
    uc_assert_success(UC_ERR_NOMEM);
}

static void fail_uc_assert_err(void **state)
{
    const uc_err ok = UC_ERR_OK;
    uc_assert_err(UC_ERR_VERSION, ok);
}

static void fail_uc_assert_fail(void **state)
{
    uc_assert_fail(UC_ERR_OK);
}

static void test_uc_assert_macros_fail(void **state)
{
    /* A test-inside-a-test */

    const struct CMUnitTest tests[] = {
        /* these should all fail */
        cmocka_unit_test(fail_uc_assert_success),
        cmocka_unit_test(fail_uc_assert_err),
        cmocka_unit_test(fail_uc_assert_fail),
    };

    print_message("\n\n--------------------------------------------------------------------------------\n");
    print_message("START: Failure of the following tests is expected.\n\n");

    assert_int_not_equal(0, cmocka_run_group_tests(tests, NULL, NULL));

    print_message("\n\nEND: Failure of the preceding tests was expected.\n");
    print_message("--------------------------------------------------------------------------------\n\n");
}

/******************************************************************************/

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_uc_assert_macros_constants),
        cmocka_unit_test(test_uc_assert_macros_func_calls),
        cmocka_unit_test(test_uc_assert_macros_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
