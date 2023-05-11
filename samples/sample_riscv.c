/* Unicorn Emulator Engine */

/* Sample code to demonstrate how to emulate RISCV code */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#if 0
$ cstool riscv64 1305100093850502
 0  13 05 10 00  addi	a0, zero, 1
 4  93 85 05 02  addi	a1, a1, 0x20
#endif
// #define RISCV_CODE "\x13\x05\x10\x00\x93\x85\x05\x02\x93\x85\x05\x02"
#define RISCV_CODE "\x13\x05\x10\x00\x93\x85\x05\x02"

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

static void hook_code3(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64
           ", instruction size = 0x%x\n",
           address, size);
    if (address == ADDRESS) {
        printf("stop emulation\n");
        uc_emu_stop(uc);
    }
}

static void test_riscv(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint32_t a0 = 0x1234;
    uint32_t a1 = 0x7890;

    printf("Emulate RISCV code\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_write(uc, UC_RISCV_REG_A1, &a1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(RISCV_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);

    printf(">>> A0 = 0x%x\n", a0);
    printf(">>> A1 = 0x%x\n", a1);

    uc_close(uc);
}

static void test_riscv2(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint32_t a0 = 0x1234;
    uint32_t a1 = 0x7890;

    printf("Emulate RISCV code: split emulation\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_write(uc, UC_RISCV_REG_A1, &a1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate 1 instruction
    err = uc_emu_start(uc, ADDRESS, ADDRESS + 4, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);

    printf(">>> A0 = 0x%x\n", a0);
    printf(">>> A1 = 0x%x\n", a1);

    // emulate one more instruction
    err = uc_emu_start(uc, ADDRESS + 4, ADDRESS + 8, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);

    printf(">>> A0 = 0x%x\n", a0);
    printf(">>> A1 = 0x%x\n", a1);

    uc_close(uc);
}

static void test_riscv3(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint32_t a0 = 0x1234;
    uint32_t a1 = 0x7890;

    printf("Emulate RISCV code: early stop\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_write(uc, UC_RISCV_REG_A1, &a1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code3, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(RISCV_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);

    printf(">>> A0 = 0x%x\n", a0);
    printf(">>> A1 = 0x%x\n", a1);

    uc_close(uc);
}

static void test_riscv_step(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint32_t a0 = 0x1234;
    uint32_t a1 = 0x7890;
    uint32_t pc = 0x0000;

    printf("Emulate RISCV code: step\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_write(uc, UC_RISCV_REG_A1, &a1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate 1 instruction
    err = uc_emu_start(uc, ADDRESS, ADDRESS + 12, 0, 1);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);
    uc_reg_read(uc, UC_RISCV_REG_PC, &pc);

    printf(">>> A0 = 0x%x\n", a0);
    printf(">>> A1 = 0x%x\n", a1);

    if (pc != 0x10004) {
        printf("Error after step: PC is: 0x%x, expected was 0x10004\n", pc);
    }

    // emulate one more instruction
    err = uc_emu_start(uc, ADDRESS + 4, ADDRESS + 8, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);

    printf(">>> A0 = 0x%x\n", a0);
    printf(">>> A1 = 0x%x\n", a1);

    uc_close(uc);
}

static void test_riscv_timeout(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint32_t a0 = 0x1234;
    uint32_t a1 = 0x7890;
    uint32_t pc = 0x0000;

    printf("Emulate RISCV code: timeout\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);

    // initialize machine registers
    uc_reg_write(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_write(uc, UC_RISCV_REG_A1, &a1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate 1 instruction with timeout
    err = uc_emu_start(uc, ADDRESS, ADDRESS + 4, 1000, 1);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    uc_reg_read(uc, UC_RISCV_REG_PC, &pc);

    if (pc != 0x10000) {
        printf("Error after step: PC is: 0x%x, expected was 0x10004\n", pc);
    }

    // emulate 1 instruction with timeout
    err = uc_emu_start(uc, ADDRESS, ADDRESS + 4, 1000, 1);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }
    uc_reg_read(uc, UC_RISCV_REG_PC, &pc);

    if (pc != 0x10000) {
        printf("Error after step: PC is: 0x%x, expected was 0x10004\n", pc);
    }

    // now print out some registers
    printf(">>> Emulation done\n");

    uc_close(uc);
}

static void test_riscv_sd64(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint64_t reg;

    /*
       00813823    sd  s0,16(sp)
       00000013    nop
     */
#define CODE64 "\x23\x38\x81\x00\x13\x00\x00\x00"

    printf("Emulate RISCV code: sd64 instruction\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, CODE64, sizeof(CODE64) - 1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    reg = ADDRESS + 0x100;
    uc_reg_write(uc, UC_RISCV_REG_SP, &reg);

    reg = 0x11223344;
    uc_reg_write(uc, UC_RISCV_REG_S0, &reg);

    // execute instruction
    err = uc_emu_start(uc, 0x10000, -1, 0, 1);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done.\n");

    uc_close(uc);
}

static bool hook_memalloc(uc_engine *uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, void *user_data)
{
    uint64_t algined_address = address & 0xFFFFFFFFFFFFF000ULL;
    int aligned_size = ((int)(size / 0x1000) + 1) * 0x1000;

    printf(">>> Allocating block at 0x%" PRIx64 " (0x%" PRIx64
           "), block size = 0x%x (0x%x)\n",
           address, algined_address, size, aligned_size);

    uc_mem_map(uc, algined_address, aligned_size, UC_PROT_ALL);

    // this recovers from missing memory, so we return true
    return true;
}

static void test_recover_from_illegal(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2, mem_alloc;
    uc_err err;
    uint64_t a0 = 0x1234;
    uint64_t a1 = 0x7890;

    printf("Emulate RISCV code: recover_from_illegal\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    uc_reg_write(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_write(uc, UC_RISCV_REG_A1, &a1);

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // auto-allocate memory on access
    uc_hook_add(uc, &mem_alloc, UC_HOOK_MEM_UNMAPPED, hook_memalloc, NULL, 1,
                0);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, RISCV_CODE, sizeof(RISCV_CODE) - 1);

    // emulate 1 instruction, wrong address, illegal code
    err = uc_emu_start(uc, 0x1000, -1, 0, 1);
    if (err != UC_ERR_INSN_INVALID) {
        printf("Expected Illegal Instruction error, got: %u\n", err);
    }

    // emulate 1 instruction, correct address, valid code
    err = uc_emu_start(uc, ADDRESS, -1, 0, 1);

    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_RISCV_REG_A0, &a0);
    uc_reg_read(uc, UC_RISCV_REG_A1, &a1);

    printf(">>> A0 = 0x%" PRIx64 "\n", a0);
    printf(">>> A1 = 0x%" PRIx64 "\n", a1);

    uc_close(uc);
}

static void test_riscv_func_return(void)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    uint64_t pc = 0, ra = 0;

    // 10000: 00008067     ret
    // 10004: 8082         c.ret
    // 10006: 0001         nop
    // 10008: 0001         nop

#define CODE "\x67\x80\x00\x00\x82\x80\x01\x00\x01\x00"

    printf("Emulate RISCV code: return from func\n");

    // Initialize emulator in RISCV64 mode
    err = uc_open(UC_ARCH_RISCV, UC_MODE_RISCV64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, CODE, sizeof(CODE) - 1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

#if 1
    // set return address register
    // RET instruction will return to address in RA
    // so after RET, PC == RA
    ra = 0x10006;
    uc_reg_write(uc, UC_RISCV_REG_RA, &ra);

    // execute ret instruction
    err = uc_emu_start(uc, 0x10000, -1, 0, 1);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uc_reg_read(uc, UC_RISCV_REG_PC, &pc);
    if (pc != ra) {
        printf("Error after execution: PC is: 0x%" PRIx64
               ", expected was 0x%" PRIx64 "\n",
               pc, ra);
        if (pc == 0x10000) {
            printf("  PC did not change during execution\n");
        }
    } else {
        printf("Good, PC == RA\n");
    }
#endif

    // set return address register
    // C.RET instruction will return to address in RA
    // so after C.RET, PC == RA
    ra = 0x10006;
    uc_reg_write(uc, UC_RISCV_REG_RA, &ra);

    printf("========\n");
    // execute c.ret instruction
    err = uc_emu_start(uc, 0x10004, -1, 0, 1);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uc_reg_read(uc, UC_RISCV_REG_PC, &pc);
    if (pc != ra) {
        printf("Error after execution: PC is: 0x%" PRIx64
               ", expected was 0x%" PRIx64 "\n",
               pc, ra);
        if (pc == 0x10004) {
            printf("  PC did not change during execution\n");
        }
    } else {
        printf("Good, PC == RA\n");
    }

    // now print out some registers
    printf(">>> Emulation done.\n");

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_recover_from_illegal();

    printf("------------------\n");
    test_riscv();

    printf("------------------\n");
    test_riscv2();

    printf("------------------\n");
    test_riscv3();

    printf("------------------\n");
    test_riscv_step();

    printf("------------------\n");
    test_riscv_timeout();

    printf("------------------\n");
    test_riscv_sd64();

    printf("------------------\n");
    test_riscv_func_return();

    return 0;
}
