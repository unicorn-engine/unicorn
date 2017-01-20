/**
 * Unicorn memory API tests
 *
 * This tests memory read/write and map/unmap functionality.
 * One is necessary for doing the other.
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
    //uc_assert_success(uc_mem_unmap(uc, mem_start, mem_len));
}

static void test_bad_read(void **state)
{
    uc_engine *uc = *state;

    uint8_t readbuf[0x10];
    memset(readbuf, 0xCC, sizeof(readbuf));

    uint8_t checkbuf[0x10];
    memset(checkbuf, 0xCC, sizeof(checkbuf));

    /* Reads to unmapped addresses should fail */
    /* TODO: Which error? */
    uc_assert_fail(uc_mem_read(uc, 0x1000, readbuf, sizeof(readbuf)));

    /* And our buffer should be unchanged */
    assert_memory_equal(readbuf, checkbuf, sizeof(checkbuf));
}

static void test_bad_write(void **state)
{
    uc_engine *uc = *state;

    uint8_t writebuf[0x10];
    memset(writebuf, 0xCC, sizeof(writebuf));

    /* Writes to unmapped addresses should fail */
    /* TODO: Which error? */
    uc_assert_fail(uc_mem_write(uc, 0x1000, writebuf, sizeof(writebuf)));
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

/* Try to unmap memory that has not been mapped */
static void test_bad_unmap(void **state)
{
    uc_engine *uc = *state;

    /* TODO: Which error should this return? */
    uc_assert_fail(uc_mem_unmap(uc, 0x0, 0x1000));
}


/* Try to map overlapped memory range */
static void test_unmap_double_map(void **state)
{
    uc_engine *uc = *state;

    uc_assert_success(uc_mem_map(uc, 0,      0x4000, 0));   /* 0x0000 - 0x4000 */
    uc_assert_fail(uc_mem_map(uc, 0x0000, 0x1000, 0));   /* 0x1000 - 0x1000 */
}

static void test_overlap_unmap_double_map(void **state)
{
    uc_engine *uc = *state;
    uc_mem_map(  uc, 0x1000, 0x2000, 0);
    uc_mem_map(  uc, 0x1000, 0x1000, 0);
    uc_mem_unmap(uc, 0x2000, 0x1000);
}

static void test_strange_map(void **state)
{
    uc_engine *uc = *state;
    uc_mem_map(  uc, 0x0,0x3000,0); 
    uc_mem_unmap(uc, 0x1000,0x1000); 
    uc_mem_map(  uc, 0x3000,0x1000,0); 
    uc_mem_map(  uc, 0x4000,0x1000,0); 
    uc_mem_map(  uc, 0x1000,0x1000,0); 
    uc_mem_map(  uc, 0x5000,0x1000,0); 
    uc_mem_unmap(uc, 0x0,0x1000); 
}

static void test_query_page_size(void **state)
{
    uc_engine *uc = *state;

    size_t page_size;
    uc_assert_success(uc_query(uc, UC_QUERY_PAGE_SIZE, &page_size));
    assert_int_equal(4096, page_size);
}

void mem_write(uc_engine* uc, uint64_t addr, uint64_t len){
  uint8_t* buff = alloca(len);
  memset(buff,0,len);
  uc_mem_write(uc, addr, buff, len);

}

void mem_read(uc_engine* uc, uint64_t addr, uint64_t len){
  uint8_t* buff = alloca(len);
  uc_mem_read(uc, addr, buff, len);
}

void map(uc_engine* uc, uint64_t addr, uint64_t len){
    uc_mem_map(uc, addr, len, UC_PROT_READ | UC_PROT_WRITE);
}

void unmap(uc_engine* uc, uint64_t addr, uint64_t len){
    uc_mem_unmap(uc, addr, len);
}

//most likely same bug as in test_strange_map, but looked different in fuzzer (sefault instead of assertion fail)
static void test_assertion_fail(void **state){
  uc_engine *uc = *state;

  map(uc,0x2000,0x4000); //5
  unmap(uc,0x3000,0x2000); //11
  map(uc,0x0,0x2000); //23
  map(uc,0x3000,0x2000); //24
  map(uc,0x9000,0x4000); //32
  map(uc,0x8000,0x1000); //34
  unmap(uc,0x1000,0x4000); //35
}

static void test_bad_offset(void **state){
  uc_engine *uc = *state;
  map(uc,0x9000,0x4000); //17
  map(uc,0x4000,0x2000); //32
  unmap(uc,0x5000,0x1000); //35
  map(uc,0x0,0x1000); //42
  map(uc,0x5000,0x4000); //51
  map(uc,0x2000,0x1000); //53
  map(uc,0x1000,0x1000); //55
  unmap(uc,0x7000,0x3000); //58
  unmap(uc,0x5000,0x1000); //59
  unmap(uc,0x4000,0x2000); //70
}



int main(void) {
#define test(x)     cmocka_unit_test_setup_teardown(x, setup, teardown)
    const struct CMUnitTest tests[] = {
        test(test_basic),
        //test(test_bad_read),
        //test(test_bad_write),
        test(test_bad_offset),
        test(test_assertion_fail),
        test(test_bad_unmap),
        test(test_rw_across_boundaries),
        test(test_unmap_double_map),
        test(test_overlap_unmap_double_map),
        test(test_strange_map),
        test(test_query_page_size),
    };
#undef test
    return cmocka_run_group_tests(tests, NULL, NULL);
}
