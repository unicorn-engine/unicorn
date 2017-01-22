#include "unicorn_test.h"
#include "unicorn/unicorn.h"

#define OK(x)   uc_assert_success(x)

/* Called before every test to set up a new instance */
static int setup32(void **state)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    *state = uc;
    return 0;
}

/* Called after every test to clean up */
static int teardown(void **state)
{
    uc_engine *uc = *state;

    OK(uc_close(uc));

    *state = NULL;
    return 0;
}

/******************************************************************************/

struct bb {
    uint64_t    addr;
    size_t      size;
};

struct bbtest {
    const struct bb *blocks;
    unsigned int     blocknum;
};


static void test_basic_blocks_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    struct bbtest *bbtest = user_data;
    const struct bb *bb = &bbtest->blocks[bbtest->blocknum];

    printf("block hook 1: %d == %zu\n", size, bb->size);
    assert_int_equal(address, bb->addr);
    assert_int_equal((size_t)size, bb->size);
}

static void test_basic_blocks_hook2(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    struct bbtest *bbtest = user_data;
    const struct bb *bb = &bbtest->blocks[bbtest->blocknum++];

    printf("block hook 2: %d == %zu\n", size, bb->size);
    assert_int_equal(address, bb->addr);
    assert_int_equal((size_t)size, bb->size);
}

static void test_basic_blocks(void **state)
{
    uc_engine *uc = *state;
    uc_hook trace1, trace2;

#define BASEADDR    0x1000000

    uint64_t address = BASEADDR;
    const uint8_t code[] = {
        0x33, 0xC0,     // xor  eax, eax
        0x90,           // nop
        0x90,           // nop
        0xEB, 0x00,     // jmp  $+2
        0x90,           // nop
        0x90,           // nop
        0x90,           // nop
    };

    static const struct bb blocks[] = {
        {BASEADDR,      6},
        {BASEADDR+ 6,   3},
    };

    struct bbtest bbtest = {
        .blocks = blocks,
        .blocknum = 0,
    };


#undef BASEADDR

    // map 2MB memory for this emulation
    OK(uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL));

    // write machine code to be emulated to memory
    OK(uc_mem_write(uc, address, code, sizeof(code)));

    // trace all basic blocks
    OK(uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, test_basic_blocks_hook, &bbtest, 1, 0));
    OK(uc_hook_add(uc, &trace2, UC_HOOK_BLOCK, test_basic_blocks_hook2, &bbtest, 1, 0));

    OK(uc_emu_start(uc, address, address+sizeof(code), 0, 0));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_basic_blocks, setup32, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
