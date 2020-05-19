/**
 * Unicorn memory API tests
 *
 * This tests memory read/write and map/unmap functionality.
 * One is necessary for doing the other.
 */
#include "unicorn_test.h"
#include <stdio.h>
#include <string.h>
#include "unicorn/unicorn.h"

/* Called before every test to set up a new instance */
static int setup(void **state)
{
    uc_engine *uc;

    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

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

// mapping the last pages will silently fail
static void test_last_page_map(void **state)
{
    uc_engine *uc = *state;

    uint8_t writebuf[0x10];
    memset(writebuf, 0xCC, sizeof(writebuf));

    const uint64_t mem_len   = 0x1000;
    const uint64_t last_page = 0xfffffffffffff000;
    uc_assert_success(uc_mem_map(uc, last_page, mem_len, UC_PROT_NONE));
    uc_assert_success(uc_mem_write(uc, last_page, writebuf, sizeof(writebuf)));
}

// segfaults with NULL-deref (caused by UC_PROT_NONE)
static void test_nullptr_deref_wrong_perms(void **state){
    uc_engine *uc = *state;
    const uint64_t base_addr = 0x400000;
    uc_assert_success(uc_mem_map(uc, base_addr, 4096, UC_PROT_NONE));
    uc_emu_start(uc, base_addr, base_addr + 1, 0, 0); 
}

static int number_of_memory_reads = 0;

static void hook_mem64(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
  number_of_memory_reads += 1;
  printf(">>> Memory is being accessed at 0x%"PRIx64 ", data size = %u\n", address, size);
}

//if a read is performed from a big address whith a non-zero last digit, multiple read events are triggered
static void test_high_address_reads(void **state)
{
    uc_engine *uc = *state;
    uc_hook trace2;

    uint64_t addr = 0x0010000000000001; 
    //addr = 0x0010000000000000; // uncomment to fix wrong? behaviour
    //addr = 90000000; // uncomment to fix wrong? behaviour
    //
    uc_mem_map(uc, addr-(addr%4096), 4096*2, UC_PROT_ALL);
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RAX, &addr));
    const uint64_t base_addr = 0x40000;
    uint8_t code[] = {0x48,0x8b,0x00,0x90,0x90,0x90,0x90}; // mov rax, [rax], nops
    uc_assert_success(uc_mem_map(uc, base_addr, 4096, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, base_addr, code, 7));
    uc_assert_success(uc_hook_add(uc, &trace2, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0));
    uc_assert_success(uc_emu_start(uc, base_addr, base_addr + 3, 0, 0));
    if(number_of_memory_reads != 1) {
        fail_msg("wrong number of memory reads for instruction %i", number_of_memory_reads);
    }
}

//if a read is performed from a big address whith a non-zero last digit, 0 will be read
static void test_high_address_read_values(void **state)
{
    uc_engine *uc = *state;
    struct stat info;
    char * code = read_file("high_address.bin", &info);
    if (code == NULL) {
        return;
    }

    uint64_t addr = 0x0010000000000001; 
    //addr = 0x000ffffffffffff8; // uncomment to fix wrong behaviour
    //addr = 90000000; // uncomment to fix wrong behaviour
    //
    uint8_t content[] = {0x42,0x42,0x42,0x42, 0x42,0x42,0x42,0x42};
    uc_assert_success(uc_mem_map(uc, addr-(addr%4096), 4096*2, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, addr, content, 8));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RAX, &addr));
    const uint64_t base_addr = 0x40000;
    uc_assert_success(uc_mem_map(uc, base_addr, 4096, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, base_addr, code, info.st_size));
    uc_assert_success(uc_emu_start(uc, base_addr, base_addr + 3, 0, 0));
    uint64_t rax = 0;
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    if(rax != 0x4242424242424242) {
        fail_msg("wrong memory read from code %"PRIx64, rax);
    }

    free(code);
}


int main(void) {
#define test(x)     cmocka_unit_test_setup_teardown(x, setup, teardown)
    const struct CMUnitTest tests[] = {
        test(test_last_page_map),
        test(test_high_address_reads),
        test(test_high_address_read_values),
        test(test_nullptr_deref_wrong_perms),
    };
#undef test
    return cmocka_run_group_tests(tests, NULL, NULL);
}
