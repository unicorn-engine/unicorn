/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2021 */

/* Sample code to demonstrate how to emulate S390X code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define S390X_CODE "\x18\x23" // lr %r2, %r3

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

static void test_s390x(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint64_t r2 = 2, r3 = 3;

    printf("Emulate S390X code\n");

    // Initialize emulator in S390X mode
    err = uc_open(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 1MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, S390X_CODE, sizeof(S390X_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_S390X_REG_R2, &r2);
    uc_reg_write(uc, UC_S390X_REG_R3, &r3);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(S390X_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err,
               uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_S390X_REG_R2, &r2);
    uc_reg_read(uc, UC_S390X_REG_R3, &r3);

    printf(">>> R2 = 0x%" PRIx64 "\t\t>>> R3 = 0x%" PRIx64 "\n", r2, r3);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_s390x();

    return 0;
}
