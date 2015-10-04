// Test hook evocation count
//
// Objective is to demonstrate finer duration control of
// emulation by counts of instruction code
//
#include "unicorn_test.h"
#include <inttypes.h>

#define OK(x)   uc_assert_success(x)

volatile int expected_instructions = 0;
volatile int total_instructions = 0;


//  NOTE: It would appear that this UC_HOOK_CODE is being done before the
//  uc_count_fb hook.
//  So, termination by uc->emu_count has not been done yet here...
static void test_code_hook(uc_engine *uc,
                           uint64_t address,
                           uint32_t size,
                           void *user_data)
{

    ++total_instructions;
    if (total_instructions > expected_instructions)
    {
        uc_emu_stop(uc);
    }

#ifdef DEBUG
    printf("instruction at 0x%"PRIx64": ", address);
    if (!uc_mem_read(uc, address, tmp, size)) {
        uint8_t tmp[256];
        uint32_t i;

        for (i = 0; i < size; i++) {
            printf("0x%x ", tmp[i]);
        }
        printf("\n");
    }
#endif // DEBUG
}


/* Called before every test to set up a new instance */
static int setup32(void **state)
{
    uc_hook trace1;
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    *state = uc;

    // trace all instructions
    OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, test_code_hook, NULL, 1, 0));

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

static void
test_hook_count(uc_engine *uc,
                const uint8_t *code,
                int start_offset,
                int expected_instructions)
{

#define BASEADDR    0x1000000
#define MEMSIZE     (2 * 1024 * 1024)

    uint64_t address = BASEADDR + (expected_instructions * MEMSIZE);
    total_instructions = 0;

#undef BASEADDR

    // map a new 2MB memory for this emulation
    OK(uc_mem_map(uc, address, MEMSIZE, UC_PROT_ALL));

    // write machine code to be emulated to memory
    OK(uc_mem_write(uc, address, code, expected_instructions));

    OK(uc_emu_start(uc,
                    address,
                    address+start_offset,
                    0,
                    expected_instructions));

    assert_int_equal(expected_instructions, total_instructions);

    // map 2MB memory for this emulation
    OK(uc_mem_unmap(uc, address, MEMSIZE));
}


/* Perform fine-grain emulation control of exactly 1 instruction */
static void test_hook_count_1(void **state)
{
    uc_engine *uc = *state;
    const uint8_t code[] = {
        0x41,           // inc ECX @0x1000000
        0x41,           // inc ECX
        0x41,           // inc ECX
        0x41,           // inc ECX @0x1000003
        0x41,           // inc ECX
        0x41,           // inc ECX

        0x42,           // inc EDX @0x1000006
        0x42,           // inc EDX
    };
    test_hook_count(uc, code, 0, 1);
}


/* Perform fine-grain emulation control over a range of */
/* varied instruction steps. */
static void test_hook_count_range(void **state)
{
    int i;
    uc_engine *uc = *state;
    const uint8_t code[] = {
        0x41,           // inc ECX @0x1000000
        0x41,           // inc ECX
        0x41,           // inc ECX
        0x41,           // inc ECX @0x1000003
        0x41,           // inc ECX
        0x41,           // inc ECX
        0x42,           // inc EDX @0x1000006
        0x42,           // inc EDX
    };
    for (i = 2; i < 7; i++)
    {
        test_hook_count(uc, code, 1, i);
    }
}


static void test_hook_count_end(void **state)
{
    uc_engine *uc = *state;
    const uint8_t code[] = {
        0x41,           // inc ECX @0x1000000
        0x41,           // inc ECX
        0x41,           // inc ECX
        0x41,           // inc ECX @0x1000003
        0x41,           // inc ECX
        0x41,           // inc ECX

        0x42,           // inc EDX @0x1000006
        0x42,           // inc EDX
    };
    test_hook_count(uc, code, sizeof(code)-1, 1);
}


static void test_hook_count_midpoint(void **state)
{
    uc_engine *uc = *state;
    const uint8_t code[] = {
        0x41,           // inc ECX @0x1000000
        0x41,           // inc ECX
        0x41,           // inc ECX
        0x41,           // inc ECX @0x1000003
        0x41,           // inc ECX
        0x41,           // inc ECX

        0x42,           // inc EDX @0x1000006
        0x42,           // inc EDX
    };
    test_hook_count(uc, code, sizeof(code)/2, 2);
    test_hook_count(uc, code, 2, sizeof(code)-2);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_hook_count_1, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_range, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_midpoint, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_end, setup32, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

