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
    const uint64_t test_addr = mem_start + 0x100;

    /* Map a region */
    uc_assert_success(uc_mem_map(uc, mem_start, mem_len, UC_PROT_NONE));

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
}

/**
 * Verify that we can read/write across memory map region boundaries
 */
static void test_rw_across_boundaries(void **state)
{
    uc_engine *uc = *state;

    /* Map in two adjacent regions */
    uc_assert_success(uc_mem_map(uc, 0,      0x1000, 0));   /* 0x0000 - 0x1000 */
    uc_assert_success(uc_mem_map(uc, 0x1000, 0x1000, 0));   /* 0x1000 - 0x2000 */

    const uint64_t addr = 0x1000 - 2;                       /* 2 bytes before end of block */

    /* Write some data across the boundary */
    uc_assert_success(uc_mem_write(uc, addr, "test", 4));

    uint8_t buf[4];
    memset(buf, 0xCC, sizeof(buf));

    /* Read the data across the boundary */
    uc_assert_success(uc_mem_read(uc, addr, buf, sizeof(buf)));

    assert_memory_equal(buf, "test", 4);
}

static void test_bad_unmap(void **state)
{
    uc_engine *uc = *state;
    uc_err err;

    /* Try to unmap memory that has not been mapped */
    err = uc_mem_unmap(uc, 0x0, 0x1000);
    assert_int_not_equal(err, UC_ERR_OK);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_basic, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bad_unmap, setup, teardown),
        cmocka_unit_test_setup_teardown(test_rw_across_boundaries, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
