#include "unicorn_test.h"
#include <unicorn/unicorn.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void test_idt_gdt_i386(/*void **state*/)
{
    uc_engine *uc;
    uc_err err;
    uint8_t buf[6];
    uc_x86_mmr idt;
    uc_x86_mmr gdt;
    uc_x86_mmr ldt;
    uc_x86_mmr tr;

    struct stat info;
    char * code = read_file("gdt_idx.bin", &info);

    const uint64_t address = 0x1000000;

    int r_esp = address + 0x1000 - 0x100;     // initial esp

    idt.base = 0x12345678;  
    idt.limit = 0xabcd;     
    gdt.base = 0x87654321;  
    gdt.limit = 0xdcba;     

    ldt.base = 0xfedcba98;  
    ldt.limit = 0x11111111;     
    ldt.selector = 0x3333;     
    ldt.flags = 0x55555555;     

    tr.base = 0x22222222;  
    tr.limit = 0x33333333;     
    tr.selector = 0x4444;     
    tr.flags = 0x66666666;     

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 1 page memory for this emulation
    err = uc_mem_map(uc, address, 0x1000, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, info.st_size);
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_IDTR, &idt);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdt);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_LDTR, &ldt);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_TR, &tr);
    uc_assert_success(err);

    memset(&idt, 0, sizeof(idt));
    memset(&gdt, 0, sizeof(gdt));
    memset(&ldt, 0, sizeof(ldt));
    memset(&tr, 0, sizeof(tr));

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code)-1, 0, 0);
    uc_assert_success(err);


    uc_reg_read(uc, UC_X86_REG_IDTR, &idt);
    assert(idt.base == 0x12345678);
    assert(idt.limit == 0xabcd);

    uc_reg_read(uc, UC_X86_REG_GDTR, &gdt);
    assert(gdt.base == 0x87654321);
    assert(gdt.limit == 0xdcba);

    //userspace can only set ldt selector, remainder are loaded from 
    //GDT/LDT, but we allow all to emulator user
    uc_reg_read(uc, UC_X86_REG_LDTR, &ldt);
    assert(ldt.base == 0xfedcba98);
    assert(ldt.limit == 0x11111111);
    assert(ldt.selector == 0x3333);
    assert(ldt.flags == 0x55555555);

    //userspace can only set tr selector, remainder are loaded from 
    //GDT/LDT, but we allow all to emulator user
    uc_reg_read(uc, UC_X86_REG_TR, &tr);
    assert(tr.base == 0x22222222);
    assert(tr.limit == 0x33333333);
    assert(tr.selector == 0x4444);
    assert(tr.flags == 0x66666666);

    // read from memory
    err = uc_mem_read(uc, r_esp, buf, 6);
    uc_assert_success(err);

    assert(memcmp(buf, "\xcd\xab\x78\x56\x34\x12", 6) == 0);

    // read from memory
    err = uc_mem_read(uc, r_esp + 6, buf, 6);
    uc_assert_success(err);

    assert(memcmp(buf, "\xba\xdc\x21\x43\x65\x87", 6) == 0);

    uc_close(uc);
    free(code);
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
