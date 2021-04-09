/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM code */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define ARM_CODE "\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3
#define THUMB_CODE "\x83\xb0" // sub    sp, #0xc

#define ARM_THUM_COND_CODE "\x9a\x42\x14\xbf\x68\x22\x4d\x22" // 'cmp r2, r3\nit ne\nmov r2, #0x68\nmov r2, #0x4d'

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

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r0 = 0x1234;     // R0 register
    int r2 = 0x6789;     // R1 register
    int r3 = 0x3333;     // R2 register
    int r1;     // R1 register

    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE) -1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    printf(">>> R0 = 0x%x\n", r0);
    printf(">>> R1 = 0x%x\n", r1);

    uc_close(uc);
}

static void test_thumb(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int sp = 0x1234;     // R0 register

    printf("Emulate THUMB code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, THUMB_CODE, sizeof(THUMB_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    // Note we start at ADDRESS | 1 to indicate THUMB mode.
    err = uc_emu_start(uc, ADDRESS | 1, ADDRESS + sizeof(THUMB_CODE) -1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    printf(">>> SP = 0x%x\n", sp);

    uc_close(uc);
}

static void test_thumb_ite_internal(bool step, uint32_t *r2_out, uint32_t *r3_out) 
{
    uc_engine *uc;
    uc_err err;

    uint32_t sp = 0x1234;
    uint32_t r2 = 0, r3 = 1;

    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return;
    }

    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    uc_mem_write(uc, ADDRESS, ARM_THUM_COND_CODE, sizeof(ARM_THUM_COND_CODE) - 1);

    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);

    if (!step) {
        err = uc_emu_start(uc, ADDRESS | 1, ADDRESS + sizeof(ARM_THUM_COND_CODE) - 1, 0, 0);
        if (err) {
            printf("Failed on uc_emu_start() with error returned: %u\n", err);
        }
    } else {
        int i, addr = ADDRESS;
        for (i = 0; i < sizeof(ARM_THUM_COND_CODE) / 2; i++) {
            err = uc_emu_start(uc, addr | 1, ADDRESS + sizeof(ARM_THUM_COND_CODE) - 1, 0, 1);
            if (err) {
                printf("Failed on uc_emu_start() with error returned: %u\n", err);
            }
            uc_reg_read(uc, UC_ARM_REG_PC, &addr);
        }
    }

    uc_reg_read(uc, UC_ARM_REG_R2, &r2);
    uc_reg_read(uc, UC_ARM_REG_R3, &r3);

    uc_close(uc);

    *r2_out = r2;
    *r3_out = r3;
}

static void test_thumb_ite() 
{
    uint32_t r2, r3;
    uint32_t step_r2, step_r3;

    printf("Emulate a THUMB ITE block as a whole or per instruction.\n");
    
    // Run once.
    printf("Running the entire binary.\n");
    test_thumb_ite_internal(false, &r2, &r3);
    printf(">>> R2: %d\n", r2);
    printf(">>> R3: %d\n\n", r3);

    // Step each instruction.
    printf("Running the binary one instruction at a time.\n");
    test_thumb_ite_internal(true, &step_r2, &step_r3);
    printf(">>> R2: %d\n", step_r2);
    printf(">>> R3: %d\n\n", step_r3);

    if (step_r2 != r2 || step_r3 != r3) {
        printf("Failed with ARM ITE blocks stepping!\n");
    }
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
    
    test_arm();
    printf("==========================\n");
    test_thumb();
    printf("==========================\n");
    test_thumb_ite();
    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
