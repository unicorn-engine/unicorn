// Test hook evocation count
//
// Objective is to demonstrate finer duration control of
// emulation by counts of instruction code
//
#include "unicorn_test.h"
#include "unicorn/unicorn.h"

#define DEBUG 1

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
    if (total_instructions == expected_instructions)
    {
        uc_emu_stop(uc);
    }

#ifdef DEBUG
    printf("instruction at 0x%"PRIx64": ", address);
    uint8_t tmp[256];
    if (!uc_mem_read(uc, address, tmp, size)) {
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
                int code_length,
                int count)
{

#define BASEADDR    0x1000000
#define MEMSIZE     (2 * 1024 * 1024)

    uint64_t address = BASEADDR + (count * MEMSIZE);
    total_instructions = 0;

#undef BASEADDR

    // map a new 2MB memory for this emulation
    OK(uc_mem_map(uc, address, MEMSIZE, UC_PROT_ALL));

    // write machine code to be emulated to memory
    OK(uc_mem_write(uc, address, code, code_length));

#ifdef DEBUG
    printf("Address: %"PRIx64"\n", address);
    printf("Start  : %"PRIx64"\n", address + start_offset);
    printf("End    : %"PRIx64"\n", address + code_length - 1);
    printf("Count  : %d\n", count);
#endif
    expected_instructions = count;
    OK(uc_emu_start(uc,
                    address+start_offset,
                    address+code_length,
                    0,
                    count));

    assert_int_equal(expected_instructions, total_instructions);

    // map 2MB memory for this emulation
    OK(uc_mem_unmap(uc, address, MEMSIZE));
}


/* Perform fine-grain emulation control of exactly 1 instruction */
/* of 1-opcode code space*/
static void test_hook_count_1_begin(void **state)
{
    uc_engine *uc = *state;
    const uint8_t code[] = {
        0x41,           // inc ECX @0x1000000
    };
    int code_length = sizeof(code);
    int start_offset = 0;
    int ins_count = 1;

    test_hook_count(uc, code, start_offset, code_length, ins_count);
}


/* Perform fine-grain emulation control of exactly 1 instruction */
static void test_hook_count_1_midpoint(void **state)
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
    int code_length = sizeof(code);
    int start_offset = code_length/2;
    int ins_count = 1;

    test_hook_count(uc, code, start_offset, code_length, ins_count);
}


/* Perform fine-grain emulation control of exactly 1 instruction */
static void test_hook_count_1_end(void **state)
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
    int code_length = sizeof(code);
    int start_offset = code_length - 1;
    int ins_count = 1;

    test_hook_count(uc, code, start_offset, code_length, ins_count);
}


/* Perform fine-grain emulation control over a range of */
/* varied instruction steps. */
static void test_hook_count_range(void **state)
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
    int code_length = sizeof(code);
    int start_offset;
    int ins_count = 2;

    for (start_offset = 2; start_offset < (code_length - ins_count); start_offset++)
    {
        printf("Iteration %d\n", start_offset);
        test_hook_count(uc, code, start_offset, code_length, ins_count);
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
    int code_length = sizeof(code);
    int ins_count = 3;
    int start_offset = sizeof(code) - ins_count;

    test_hook_count(uc, code, start_offset, code_length, ins_count);
}


static void test_hook_count_begins(void **state)
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
    int code_length = sizeof(code);
    int ins_count = 3;
    int start_offset = 0;

    test_hook_count(uc, code, start_offset, code_length, ins_count);
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
    int code_length = sizeof(code);
    int ins_count = 3;
    int start_offset = 2;

    test_hook_count(uc, code, start_offset, code_length, ins_count);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_hook_count_1_begin, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_1_midpoint, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_1_end, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_begins, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_range, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_midpoint, setup32, teardown),
        cmocka_unit_test_setup_teardown(test_hook_count_end, setup32, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

