#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <cmocka.h>
#include <unicorn/unicorn.h>

// callback for tracing basic blocks
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    //printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    //int eflags;
    //printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    //uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    //printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

static void uc_assert_success(uc_err err)
{
    assert_int_equal(err, 0);
    // uc_strerror(err)
}

static void test_i386(void **state)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;

    const uint8_t code[] = "\x41\x4a"; // INC ecx; DEC edx
    const uint64_t address = 0x1000000;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code)-1);
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    uc_assert_success(err);

    // tracing all basic blocks with customized callback
    err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, (uint64_t)1, (uint64_t)0);
    uc_assert_success(err);

    // tracing all instruction by having @begin > @end
    err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)1, (uint64_t)0);
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code)-1, 0, 0);
    uc_assert_success(err);

    // now print out some registers
    //printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);

    assert_int_equal(r_ecx, 0x1235);
    assert_int_equal(r_edx, 0x788F);

    // read from memory
    err = uc_mem_read(uc, address, (uint8_t *)&tmp, 4);
    uc_assert_success(err);
    //printf(">>> Read 4 bytes from [0x%"PRIX64"] = 0x%x\n", address, tmp);

    uc_close(uc);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_i386),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
