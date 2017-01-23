/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate Sparc code */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define SPARC_CODE "\x86\x00\x40\x02" // add %g1, %g2, %g3;
//#define SPARC_CODE "\xbb\x70\x00\x00" // illegal code

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

static void test_sparc(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int g1 = 0x1230;     // G1 register
    int g2 = 0x6789;     // G2 register
    int g3 = 0x5555;     // G3 register

    printf("Emulate SPARC code\n");

    // Initialize emulator in Sparc mode
    err = uc_open(UC_ARCH_SPARC, UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, SPARC_CODE, sizeof(SPARC_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_SPARC_REG_G1, &g1);
    uc_reg_write(uc, UC_SPARC_REG_G2, &g2);
    uc_reg_write(uc, UC_SPARC_REG_G3, &g3);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(SPARC_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_SPARC_REG_G3, &g3);
    printf(">>> G3 = 0x%x\n", g3);

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
    
    test_sparc();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
