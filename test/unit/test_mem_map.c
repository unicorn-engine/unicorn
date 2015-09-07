#include "unicorn_test.h"
#include <stdio.h>

static int setup(void **state)
{
    fprintf(stderr, "~~~ setup() ~~~\n");

    uc_engine *uc;

    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    *state = uc;
    return 0;
}

static int teardown(void **state)
{
    uc_engine *uc = *state;
    fprintf(stderr, "~~~ teardown() ~~~\n");

    uc_assert_success(uc_close(uc));
    return 0;
}


static void test_basic(void **state)
{
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic),
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
