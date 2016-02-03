#include <unicorn/unicorn.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * Assert that err matches expect
 */
#define uc_assert_err(expect, err)                                  \
do {                                                                \
    uc_err __err = err;                                             \
    if (__err != expect) {                                          \
        fprintf(stderr, "%s", uc_strerror(__err));                  \
        exit(1);                                                    \
    }                                                               \
} while (0)

/**
 * Assert that err is UC_ERR_OK
 */
#define uc_assert_success(err)  uc_assert_err(UC_ERR_OK, err)

/**
 * Assert that err is anything but UC_ERR_OK
 *
 * Note: Better to use uc_assert_err(<specific error>, err),
 * as this serves to document which errors a function will return
 * in various scenarios.
 */
#define uc_assert_fail(err)                                         \
do {                                                                \
    uc_err __err = err;                                             \
    if (__err == UC_ERR_OK) {                                       \
        fprintf(stderr, "%s", uc_strerror(__err));                  \
        exit(1);                                                    \
    }                                                               \
} while (0)

#define OK(x)   uc_assert_success(x)

/******************************************************************************/

static void test_idt_gdt_i386(/*void **state*/)
{
    uc_engine *uc;
    uc_err err;
    uint8_t buf[6];

    const uint8_t code[] = "\x0f\x01\x0c\x24\x0f\x01\x44\x24\x06"; // sidt [esp]; sgdt [esp+6]
    const uint64_t address = 0x1000000;

    int r_esp = address + 0x1000 - 0x100;     // initial esp

    int idt_base = 0x12345678;  
    int idt_limit = 0xabcd;     
    int gdt_base = 0x87654321;  
    int gdt_limit = 0xdcba;     

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 1 page memory for this emulation
    err = uc_mem_map(uc, address, 0x1000, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code)-1);
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_IDTR_BASE, &idt_base);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_IDTR_LIMIT, &idt_limit);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_GDTR_BASE, &gdt_base);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_GDTR_LIMIT, &gdt_limit);
    uc_assert_success(err);

    idt_base = 0;
    idt_limit = 0;
    gdt_base = 0;
    gdt_limit = 0;

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code)-1, 0, 0);
    uc_assert_success(err);


    uc_reg_read(uc, UC_X86_REG_IDTR_BASE, &idt_base);
    assert(idt_base == 0x12345678);
    
    uc_reg_read(uc, UC_X86_REG_IDTR_LIMIT, &idt_limit);
    assert(idt_limit == 0xabcd);

    uc_reg_read(uc, UC_X86_REG_GDTR_BASE, &gdt_base);
    assert(gdt_base == 0x87654321);

    uc_reg_read(uc, UC_X86_REG_GDTR_LIMIT, &gdt_limit);
    assert(gdt_limit == 0xdcba);

    // read from memory
    err = uc_mem_read(uc, r_esp, buf, 6);
    uc_assert_success(err);

    assert(memcmp(buf, "\xcd\xab\x78\x56\x34\x12", 6) == 0);

    // read from memory
    err = uc_mem_read(uc, r_esp + 6, buf, 6);
    uc_assert_success(err);

    assert(memcmp(buf, "\xba\xdc\x21\x43\x65\x87", 6) == 0);

    uc_close(uc);
    
}

/******************************************************************************/

int main(void) {
/*
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_idt_gdt_i386)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
*/
   test_idt_gdt_i386();
   
   fprintf(stderr, "success\n");
   
   return 0;
}
