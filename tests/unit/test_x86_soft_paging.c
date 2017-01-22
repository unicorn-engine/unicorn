#include "unicorn_test.h"
#include "unicorn/unicorn.h"

/*
    Two tests here for software paging
    Low paging: Test paging using virtual addresses already mapped by Unicorn
    High paging: Test paging using virtual addresses not mapped by Unicorn
*/

static void test_low_paging(void **state) {
    uc_engine *uc;
    uc_err err;
    int r_eax;

    /*  The following x86 code will map emulated physical memory
        to virtual memory using pages and attempt
        to read/write from virtual memory 

        Specifically, the virtual memory address range
        has been mapped by Unicorn (0x7FF000 - 0x7FFFFF)

        Memory area purposes:
        0x1000 = page directory
        0x2000 = page table (identity map first 4 MiB)
        0x3000 = page table (0x007FF000 -> 0x00004000)
        0x4000 = data area (0xBEEF)
     */
    const uint8_t code[] = {
        /* Zero memory for page directories and page tables */
        0xBF, 0x00, 0x10, 0x00, 0x00, /* MOV EDI, 0x1000 */
        0xB9, 0x00, 0x10, 0x00, 0x00, /* MOV ECX, 0x1000 */
        0x31, 0xC0,                   /* XOR EAX, EAX */
        0xF3, 0xAB,                   /* REP STOSD */

        /* Load DWORD [0x4000] with 0xDEADBEEF to retrieve later */
        0xBF, 0x00, 0x40, 0x00, 0x00, /* MOV EDI, 0x4000 */
        0xB8, 0xEF, 0xBE, 0x00, 0x00, /* MOV EAX, 0xBEEF */
        0x89, 0x07,                   /* MOV [EDI], EAX */

        /* Identity map the first 4MiB of memory */
        0xB9, 0x00, 0x04, 0x00, 0x00, /* MOV ECX, 0x400 */
        0xBF, 0x00, 0x20, 0x00, 0x00, /* MOV EDI, 0x2000 */
        0xB8, 0x03, 0x00, 0x00, 0x00, /* MOV EAX, 3 */
        /* aLoop: */
        0xAB,                         /* STOSD */
        0x05, 0x00, 0x10, 0x00, 0x00, /* ADD EAX, 0x1000 */
        0xE2, 0xF8,                   /* LOOP aLoop */

        /* Map physical address 0x4000 to virtual address 0x7FF000 */
        0xBF, 0xFC, 0x3F, 0x00, 0x00, /* MOV EDI, 0x3FFC */
        0xB8, 0x03, 0x40, 0x00, 0x00, /* MOV EAX, 0x4003 */
        0x89, 0x07,                   /* MOV [EDI], EAX */

        /* Add page tables into page directory */
        0xBF, 0x00, 0x10, 0x00, 0x00, /* MOV EDI, 0x1000 */
        0xB8, 0x03, 0x20, 0x00, 0x00, /* MOV EAX, 0x2003 */
        0x89, 0x07,                   /* MOV [EDI], EAX */
        0xBF, 0x04, 0x10, 0x00, 0x00, /* MOV EDI, 0x1004 */
        0xB8, 0x03, 0x30, 0x00, 0x00, /* MOV EAX, 0x3003 */
        0x89, 0x07,                   /* MOV [EDI], EAX */

        /* Load the page directory register */
        0xB8, 0x00, 0x10, 0x00, 0x00, /* MOV EAX, 0x1000 */
        0x0F, 0x22, 0xD8,             /* MOV CR3, EAX */

        /* Enable paging */
        0x0F, 0x20, 0xC0,             /* MOV EAX, CR0 */
        0x0D, 0x00, 0x00, 0x00, 0x80, /* OR EAX, 0x80000000 */
        0x0F, 0x22, 0xC0,             /* MOV CR0, EAX */

        /* Clear EAX */
        0x31, 0xC0,                   /* XOR EAX, EAX */

        /* Load using virtual memory address; EAX = 0xBEEF */
        0xBE, 0x00, 0xF0, 0x7F, 0x00, /* MOV ESI, 0x7FF000 */
        0x8B, 0x06,                   /* MOV EAX, [ESI] */
        0xF4,                         /* HLT */
    };

    /* Initialise X86-32bit mode */
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    /* Map 8MB of memory at base address 0 */
    err = uc_mem_map(uc, 0, (8 * 1024 * 1024), UC_PROT_ALL);
    uc_assert_success(err);

    /* Write code into memory at address 0 */
    err = uc_mem_write(uc, 0, code, sizeof(code));
    uc_assert_success(err);

    /* Start emulation */
    err = uc_emu_start(uc, 0, sizeof(code), 0, 0);
    uc_assert_success(err);

    /* The code should have loaded 0xBEEF into EAX */
    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    assert_int_equal(r_eax, 0xBEEF);

    uc_close(uc);
}


/****************************************************************************/


static void test_high_paging(void **state) {
    uc_engine *uc;
    uc_err err;
    int r_eax;

    /*  The following x86 code will map emulated physical memory
        to virtual memory using pages and attempt
        to read/write from virtual memory 

        Specifically, the virtual memory address range
        has not been mapped by UC (0xFFFFF000 - 0xFFFFFFFF)

        Memory area purposes:
        0x1000 = page directory
        0x2000 = page table (identity map first 4 MiB)
        0x3000 = page table (0xFFFFF000 -> 0x00004000)
        0x4000 = data area (0xDEADBEEF)
     */
    const uint8_t code[] = {
        /* Zero memory for page directories and page tables */
        0xBF, 0x00, 0x10, 0x00, 0x00, /* MOV EDI, 0x1000 */
        0xB9, 0x00, 0x10, 0x00, 0x00, /* MOV ECX, 0x1000 */
        0x31, 0xC0,                   /* XOR EAX, EAX */
        0xF3, 0xAB,                   /* REP STOSD */

        /* Load DWORD [0x4000] with 0xDEADBEEF to retrieve later */
        0xBF, 0x00, 0x40, 0x00, 0x00, /* MOV EDI, 0x4000 */
        0xB8, 0xEF, 0xBE, 0x00, 0x00, /* MOV EAX, 0xBEEF */
        0x89, 0x07,                   /* MOV [EDI], EAX */

        /* Identity map the first 4MiB of memory */
        0xB9, 0x00, 0x04, 0x00, 0x00, /* MOV ECX, 0x400 */
        0xBF, 0x00, 0x20, 0x00, 0x00, /* MOV EDI, 0x2000 */
        0xB8, 0x03, 0x00, 0x00, 0x00, /* MOV EAX, 3 */
        /* aLoop: */
        0xAB,                         /* STOSD */
        0x05, 0x00, 0x10, 0x00, 0x00, /* ADD EAX, 0x1000 */
        0xE2, 0xF8,                   /* LOOP aLoop */

        /* Map physical address 0x4000 to virtual address 0xFFFFF000 */
        0xBF, 0xFC, 0x3F, 0x00, 0x00, /* MOV EDI, 0x3FFC */
        0xB8, 0x03, 0x40, 0x00, 0x00, /* MOV EAX, 0x4003 */
        0x89, 0x07,                   /* MOV [EDI], EAX */

        /* Add page tables into page directory */
        0xBF, 0x00, 0x10, 0x00, 0x00, /* MOV EDI, 0x1000 */
        0xB8, 0x03, 0x20, 0x00, 0x00, /* MOV EAX, 0x2003 */
        0x89, 0x07,                   /* MOV [EDI], EAX */
        0xBF, 0xFC, 0x1F, 0x00, 0x00, /* MOV EDI, 0x1FFC */
        0xB8, 0x03, 0x30, 0x00, 0x00, /* MOV EAX, 0x3003 */
        0x89, 0x07,                   /* MOV [EDI], EAX */

        /* Load the page directory register */
        0xB8, 0x00, 0x10, 0x00, 0x00, /* MOV EAX, 0x1000 */
        0x0F, 0x22, 0xD8,             /* MOV CR3, EAX */

        /* Enable paging */
        0x0F, 0x20, 0xC0,             /* MOV EAX, CR0 */
        0x0D, 0x00, 0x00, 0x00, 0x80, /* OR EAX, 0x80000000 */
        0x0F, 0x22, 0xC0,             /* MOV CR0, EAX */

        /* Clear EAX */
        0x31, 0xC0,                   /* XOR EAX, EAX */

        /* Load using virtual memory address; EAX = 0xBEEF */
        0xBE, 0x00, 0xF0, 0xFF, 0xFF, /* MOV ESI, 0xFFFFF000 */
        0x8B, 0x06,                   /* MOV EAX, [ESI] */
        0xF4,                         /* HLT */
    };

    /* Initialise X86-32bit mode */
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    /* Map 4MB of memory at base address 0 */
    err = uc_mem_map(uc, 0, (4 * 1024 * 1024), UC_PROT_ALL);
    uc_assert_success(err);

    /* Write code into memory at address 0 */
    err = uc_mem_write(uc, 0, code, sizeof(code));
    uc_assert_success(err);

    /* Start emulation */
    err = uc_emu_start(uc, 0, sizeof(code), 0, 0);
    uc_assert_success(err);

    /* The code should have loaded 0xBEEF into EAX */
    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    assert_int_equal(r_eax, 0xBEEF);

    uc_close(uc);
}


/****************************************************************************/


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_low_paging),
        cmocka_unit_test(test_high_paging),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
