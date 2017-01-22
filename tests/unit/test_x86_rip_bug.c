#include <unicorn/unicorn.h>

#include "unicorn_test.h"

/**
 *  Initialize i386 Unicorn Instance
 */
static int setup_i386(void **state)
{
    uc_engine *uc;

    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    *state = uc;
    return 0;
}

/**
 *  Initialize amd64 Unicorn Instance
 */
static int setup_amd64(void **state)
{
    uc_engine *uc;

    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    *state = uc;
    return 0;
}

/**
 *  Shutdown a Unicorn Instance
 */
static int teardown(void **state)
{
    uc_engine *uc = *state;

    uc_assert_success(uc_close(uc));

    *state = NULL;
    return 0;
}

/***********************************************************************************/
  
typedef struct {
    bool good;
    uint64_t actual;
    uint64_t expected;
} TestData;

const uint64_t CodePage = 0x10000;
const uint64_t CodeSize = 0x4000;

/**
 *  Hook for reading unmapped memory in the i386 Unicorn Instance.
 *
 *  BUG: EIP from uc_reg_read does not match expected value.
 */
static bool mem_hook_i386(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    TestData *data = user_data;
    if (type == UC_MEM_READ_UNMAPPED)
    {
        uint32_t eip;
        uint32_t eax;

        uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);

        data->actual = eip;
        data->expected = CodePage + 0x05;

        /**
         *  Code:
         *  0x10000: mov eax, 0x41414141 ;; <- Returned EIP
         *  0x10005: mov ecx, [eax]      ;; <- Expected EIP
         */
        if ((eax == 0x41414141) &&       // Proof we're at 0x10005.
            (eip != (CodePage + 0x5)))   // Proof uc_reg_read is wrong
        {
            data->good = false;
        }
        else
            data->good = true;
    }
    return false;
}

/**
 *  Hook for reading unmapped memory in the amd64 Unicorn Instance.
 *
 *  BUG: RIP from uc_reg_read does not match expected value.
 */
static bool mem_hook_amd64(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    TestData *data = user_data;
    if (type == UC_MEM_READ_UNMAPPED)
    {
        uint64_t rip;
        uint64_t rax;

        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        uc_reg_read(uc, UC_X86_REG_RAX, &rax);

        data->actual = rip;
        data->expected = CodePage + 0x0A;

        /**
         *  Code:
         *  0x10000: mov rax, 0x4141414141414141 ;; <- Returned RIP
         *  0x10005: mov rcx, [rax]              ;; <- Expected RIP
         */
        if ((rax == 0x4141414141414141) &&       // Proof we're at 0x10005
            (rip != (CodePage + 0xA)))           // Proof uc_reg_read is wrong
        {
            data->good = false;
        }
        else
            data->good = true;
    }
    return false;
}

/**
 *  Empty Code Hook. 
 */
static void code_hook(uc_engine *uc, uint64_t addr, uint32_t size, void *user)
{
    (void) uc;
    (void) addr;
    (void) size;
    (void) user;
}

/**
 *  Test the bug for i386. 
 *  
 *  1. Map Code Page
 *  2. Write Code to page.
 *  3. Install Unmapped Read hook.
 *  4. Run the VM.
 */
static void test_i386(void **state)
{
    TestData data;
    uc_engine *uc = *state;
    uc_hook trace1;

    const uint8_t i386_bug[] = {
        0xb8, 0x41, 0x41, 0x41, 0x41,  // mov eax, 0x41414141
        0x8b, 0x08                     // mov ecx, [eax]
    };

    uc_assert_success(uc_mem_map(uc, CodePage, CodeSize, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, CodePage, i386_bug, sizeof(i386_bug)));
    uc_assert_success(uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED, mem_hook_i386, &data, 1, 0));
    uc_assert_fail(uc_emu_start(uc, CodePage, CodePage + sizeof(i386_bug), 0, 0));

    if (!data.good)
        fail_msg("De-synced RIP value. 0x%"PRIX64" != 0x%"PRIX64"\n", data.expected, data.actual);
}

/**
 *  Test the bug for amd64.. 
 *  
 *  1. Map Code Page
 *  2. Write Code to page.
 *  3. Install Unmapped Read hook.
 *  4. Run the VM.
 */
static void test_amd64(void **state)
{
    TestData data;
    uc_engine *uc = *state;
    uc_hook trace1;

    const uint8_t amd64_bug[] = {
        0x48, 0xb8, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x48, 0x8b, 0x08
    };

    uc_assert_success(uc_mem_map(uc, CodePage, CodeSize, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, CodePage, amd64_bug, sizeof(amd64_bug)));
    uc_assert_success(uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED, mem_hook_amd64, &data, 1, 0));
    uc_assert_fail(uc_emu_start(uc, CodePage, CodePage + sizeof(amd64_bug), 0, 0));

    if (!data.good)
        fail_msg("De-synced RIP value. 0x%"PRIX64" != 0x%"PRIX64"\n", data.expected, data.actual);
}

/**
 *  Test temporary fix for bug for i386. 
 *  
 *  1. Map Code Page
 *  2. Write Code to page.
 *  3. Install Unmapped Read hook.
 *  4. Install Code hook.
 *  5. Run the VM.
 */
static void test_i386_fix(void **state)
{
    TestData data;
    uc_engine *uc = *state;
    uc_hook trace1, trace2;

    const uint8_t i386_bug[] = {
        0xb8, 0x41, 0x41, 0x41, 0x41,  // mov eax, 0x41414141
        0x8b, 0x08                     // mov ecx, [eax]
    };

    uc_assert_success(uc_mem_map(uc, CodePage, CodeSize, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, CodePage, i386_bug, sizeof(i386_bug)));
    uc_assert_success(uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED, mem_hook_i386, &data, 1, 0));
    uc_assert_success(uc_hook_add(uc, &trace2, UC_HOOK_CODE, code_hook, NULL, 1, 0));
    uc_assert_fail(uc_emu_start(uc, CodePage, CodePage + sizeof(i386_bug), 0, 0));

    if (!data.good)
        fail_msg("De-synced RIP value. 0x%"PRIX64" != 0x%"PRIX64"\n", data.expected, data.actual);
}

/**
 *  Test temporary fix for bug for amd64.. 
 *  
 *  1. Map Code Page
 *  2. Write Code to page.
 *  3. Install Unmapped Read hook.
 *  4. Install Code hook.
 *  5. Run the VM.
 */
static void test_amd64_fix(void **state)
{
    TestData data;
    uc_engine *uc = *state;
    uc_hook trace1, trace2;

    const uint8_t amd64_bug[] = {
        0x48, 0xb8, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x48, 0x8b, 0x08
    };

    uc_assert_success(uc_mem_map(uc, CodePage, CodeSize, UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc, CodePage, amd64_bug, sizeof(amd64_bug)));
    uc_assert_success(uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED, mem_hook_amd64, &data, 1, 0));
    uc_assert_success(uc_hook_add(uc, &trace2, UC_HOOK_CODE, code_hook, NULL, 1, 0));
    uc_assert_fail(uc_emu_start(uc, CodePage, CodePage + sizeof(amd64_bug), 0, 0));

    if (!data.good)
        fail_msg("De-synced RIP value. 0x%"PRIX64" != 0x%"PRIX64"\n", data.expected, data.actual);
}

/**
 *  Run all tests
 */
int main(int argc, char **argv, char **envp)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_i386, setup_i386, teardown),
        cmocka_unit_test_setup_teardown(test_amd64, setup_amd64, teardown),
        cmocka_unit_test_setup_teardown(test_i386_fix, setup_i386, teardown),
        cmocka_unit_test_setup_teardown(test_amd64_fix, setup_amd64, teardown)
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
