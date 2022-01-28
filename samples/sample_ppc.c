/* Unicorn Emulator Engine */
/* By simigo79, 2020 */

/* Sample code to demonstrate how to emulate PPC code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define PPC_CODE "\x7F\x46\x1A\x14" //  add       r26, r6, r3

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    printf(">>> Tracing basic block at 0x%" PRIx64 ", block size = 0x%x\n",
           address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64
           ", instruction size = 0x%x\n",
           address, size);
}

static void test_ppc(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r3 = 0x1234;  // R3 register
    int r6 = 0x6789;  // R6 register
    int r26 = 0x8877; // R26 register	(result)

    printf("Emulate PPC code\n");

    // Initialize emulator in PPC mode
    err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, PPC_CODE, sizeof(PPC_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_PPC_REG_3, &r3);
    uc_reg_write(uc, UC_PPC_REG_6, &r6);
    uc_reg_write(uc, UC_PPC_REG_26, &r26);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(PPC_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
        return;
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_PPC_REG_26, &r26);
    printf(">>> r26 = 0x%x\n", r26);

    // close engine when done
    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_ppc();

    return 0;
}
