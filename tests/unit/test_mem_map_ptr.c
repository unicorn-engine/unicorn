/**
 * Unicorn memory API tests
 *
 * This tests manual pointer-backed memory.
 */
#include "unicorn_test.h"
#include <stdio.h>
#include <string.h>

/* Called before every test to set up a new instance */
static int setup(void **state)
{
    uc_engine *uc;

    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    *state = uc;
    return 0;
}

/* Called after every test to clean up */
static int teardown(void **state)
{
    uc_engine *uc = *state;

    uc_assert_success(uc_close(uc));

    *state = NULL;
    return 0;
}

/******************************************************************************/


/**
 * A basic test showing mapping of memory, and reading/writing it
 */
static void test_basic(void **state)
{
    uc_engine *uc = *state;
    const uint64_t mem_start = 0x1000;
    const uint64_t mem_len   = 0x1000;
    const uint64_t test_addr = mem_start;

    void *host_mem = calloc(1, mem_len);

    /* Map a region */
    uc_assert_success(uc_mem_map_ptr(uc, mem_start, mem_len, UC_PROT_ALL, host_mem));

    /* Write some data to it */
    uc_assert_success(uc_mem_write(uc, test_addr, "test", 4));

    uint8_t buf[4];
    memset(buf, 0xCC, sizeof(buf));

    /* Read it back */
    uc_assert_success(uc_mem_read(uc, test_addr, buf, sizeof(buf)));

    /* And make sure it matches what we expect */
    assert_memory_equal(buf, "test", 4);

    /* Unmap the region */
    uc_assert_success(uc_mem_unmap(uc, mem_start, mem_len));

    assert_memory_equal(buf, host_mem, 4);

    free(host_mem);
}

int main(void) {
#define test(x)     cmocka_unit_test_setup_teardown(x, setup, teardown)
    const struct CMUnitTest tests[] = {
        test(test_basic),
    };
#undef test
    return cmocka_run_group_tests(tests, NULL, NULL);
}
