/* Unicorn Emulator Engine */
/* By Loi Anh Tuan, 2015 */

/* Sample code to demonstrate how to emulate m68k code */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define M68K_CODE "\x76\xed" // movq #-19, %d3

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

static void test_m68k(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    int d0 = 0x0000;     // d0 data register
    int d1 = 0x0000;     // d1 data register
    int d2 = 0x0000;     // d2 data register
    int d3 = 0x0000;     // d3 data register
    int d4 = 0x0000;     // d4 data register
    int d5 = 0x0000;     // d5 data register
    int d6 = 0x0000;     // d6 data register
    int d7 = 0x0000;     // d7 data register

    int a0 = 0x0000;     // a0 address register
    int a1 = 0x0000;     // a1 address register
    int a2 = 0x0000;     // a2 address register
    int a3 = 0x0000;     // a3 address register
    int a4 = 0x0000;     // a4 address register
    int a5 = 0x0000;     // a5 address register
    int a6 = 0x0000;     // a6 address register
    int a7 = 0x0000;     // a6 address register

    int pc = 0x0000;     // program counter
    int sr = 0x0000;     // status register

    printf("Emulate M68K code\n");

    // Initialize emulator in M68K mode
    err = uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, M68K_CODE, sizeof(M68K_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_M68K_REG_D0, &d0);
    uc_reg_write(uc, UC_M68K_REG_D1, &d1);
    uc_reg_write(uc, UC_M68K_REG_D2, &d2);
    uc_reg_write(uc, UC_M68K_REG_D3, &d3);
    uc_reg_write(uc, UC_M68K_REG_D4, &d4);
    uc_reg_write(uc, UC_M68K_REG_D5, &d5);
    uc_reg_write(uc, UC_M68K_REG_D6, &d6);
    uc_reg_write(uc, UC_M68K_REG_D7, &d7);

    uc_reg_write(uc, UC_M68K_REG_A0, &a0);
    uc_reg_write(uc, UC_M68K_REG_A1, &a1);
    uc_reg_write(uc, UC_M68K_REG_A2, &a2);
    uc_reg_write(uc, UC_M68K_REG_A3, &a3);
    uc_reg_write(uc, UC_M68K_REG_A4, &a4);
    uc_reg_write(uc, UC_M68K_REG_A5, &a5);
    uc_reg_write(uc, UC_M68K_REG_A6, &a6);
    uc_reg_write(uc, UC_M68K_REG_A7, &a7);

    uc_reg_write(uc, UC_M68K_REG_PC, &pc);
    uc_reg_write(uc, UC_M68K_REG_SR, &sr);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(M68K_CODE)-1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_M68K_REG_D0, &d0);
    uc_reg_read(uc, UC_M68K_REG_D1, &d1);
    uc_reg_read(uc, UC_M68K_REG_D2, &d2);
    uc_reg_read(uc, UC_M68K_REG_D3, &d3);
    uc_reg_read(uc, UC_M68K_REG_D4, &d4);
    uc_reg_read(uc, UC_M68K_REG_D5, &d5);
    uc_reg_read(uc, UC_M68K_REG_D6, &d6);
    uc_reg_read(uc, UC_M68K_REG_D7, &d7);

    uc_reg_read(uc, UC_M68K_REG_A0, &a0);
    uc_reg_read(uc, UC_M68K_REG_A1, &a1);
    uc_reg_read(uc, UC_M68K_REG_A2, &a2);
    uc_reg_read(uc, UC_M68K_REG_A3, &a3);
    uc_reg_read(uc, UC_M68K_REG_A4, &a4);
    uc_reg_read(uc, UC_M68K_REG_A5, &a5);
    uc_reg_read(uc, UC_M68K_REG_A6, &a6);
    uc_reg_read(uc, UC_M68K_REG_A7, &a7);

    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &sr);

    printf(">>> A0 = 0x%x\t\t>>> D0 = 0x%x\n", a0, d0);
    printf(">>> A1 = 0x%x\t\t>>> D1 = 0x%x\n", a1, d1);
    printf(">>> A2 = 0x%x\t\t>>> D2 = 0x%x\n", a2, d2);
    printf(">>> A3 = 0x%x\t\t>>> D3 = 0x%x\n", a3, d3);
    printf(">>> A4 = 0x%x\t\t>>> D4 = 0x%x\n", a4, d4);
    printf(">>> A5 = 0x%x\t\t>>> D5 = 0x%x\n", a5, d5);
    printf(">>> A6 = 0x%x\t\t>>> D6 = 0x%x\n", a6, d6);
    printf(">>> A7 = 0x%x\t\t>>> D7 = 0x%x\n", a7, d7);
    printf(">>> PC = 0x%x\n", pc);
    printf(">>> SR = 0x%x\n", sr);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    // dynamically load shared library
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif
    
    test_m68k();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
