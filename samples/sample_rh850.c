/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2021 */

/* Sample code to demonstrate how to emulate S390X code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define RH850_CODE "\x01\x0e\x06\x00\xc1\x11" 

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

static void test_rh850(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint64_t r1 = 2, r2 = 3;

    printf("Emulate RH850 code\n");

    // Initialize emulator in S390X mode
    err = uc_open(UC_ARCH_RH850, UC_MODE_LITTLE_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 1MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, RH850_CODE, sizeof(RH850_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RH850_REG_R1, &r1);
    uc_reg_write(uc, UC_RH850_REG_R2, &r2);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(RH850_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err,
               uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RH850_REG_R1, &r1);
    uc_reg_read(uc, UC_RH850_REG_R2, &r2);

    printf(">>> R1 = 0x%" PRIx64 "\t\t>>> R2 = 0x%" PRIx64 "\n", r1, r2);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_rh850();

    return 0;
}
