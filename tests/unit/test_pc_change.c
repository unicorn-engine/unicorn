// Test PC change during the callback. by Nguyen Anh Quynh, 2016
#include "unicorn_test.h"
#include "unicorn/unicorn.h"
#include "sys/stat.h"

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

static void test_code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint8_t tmp[256];
    int32_t r_eip = 0x1000006;
    printf("instruction at 0x%"PRIx64": ", address);

    if (!uc_mem_read(uc, address, tmp, size)) {
        uint32_t i;

        for (i = 0; i < size; i++) {
            printf("0x%x ", tmp[i]);
        }
        printf("\n");
    }

    if (address == 0x1000003) {
        // change the PC to "inc EDX"
        uc_reg_write(uc, UC_X86_REG_EIP, &r_eip);
    }
}

static void test_pc_change(void **state)
{
    uc_engine *uc = *state;
    uc_hook trace1;
    int32_t r_ecx = 3, r_edx = 15;
    struct stat info;
    char *code = read_file("pc_change.bin", &info);
    if (code == NULL) {
        return;
    }

#define BASEADDR    0x1000000

    uint64_t address = BASEADDR;

#undef BASEADDR

    // map 2MB memory for this emulation
    OK(uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL));

    // write machine code to be emulated to memory
    OK(uc_mem_write(uc, address, code, info.st_size));

    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    printf("ECX = %u, EDX = %u\n", r_ecx, r_edx);

    // trace all instructions
    OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, test_code_hook, NULL, 1, 0));

    OK(uc_emu_start(uc, address, address+info.st_size, 0, 0));

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);

    printf("ECX = %u, EDX = %u\n", r_ecx, r_edx);
    assert_int_equal(r_ecx, 6);
    assert_int_equal(r_edx, 17);
    free(code);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pc_change, setup32, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
