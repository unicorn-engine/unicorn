/*
   Created for Unicorn Engine by Glenn Baker <glenn.baker@gmx.com>, 2024
*/

/* Sample code to demonstrate how to emulate AVR code */

#include <stdio.h>
#include <string.h>
#include <unicorn/unicorn.h>

// Code to be emulated
static const uint32_t CODE_BASE = 0x0000;
static const uint8_t CODE[] =
    "\x86\x0f"          // add  r24, r22
    "\x97\x1f"          // adc  r25, r23
    "\x88\x0f"          // add  r24, r24
    "\x99\x1f"          // adc  r25, r25
    "\x01\x96"          // adiw r24, 0x01
    "\x08\x95"          // ret
    ;
static const uint32_t CODE_SIZE = sizeof(CODE) - 1;
static const uint32_t CODE_SIZE_ALIGNED = (CODE_SIZE + 0xff) & -0x100;

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

static bool is_error(uc_err err, const char *what)
{
    if (err != UC_ERR_OK) {
        fprintf(stderr, "error: failed on %s() with error %u: %s\n",
                what, err, uc_strerror(err));
        return true;
    }
    return false;
}

static bool test_avr(void)
{
    uc_engine *uc = NULL;
    uc_hook trace1, trace2;
    bool success = false;

    printf("Emulate AVR code\n");
    do {
        // Initialize emulator in AVR mode
        uc_err err = uc_open(UC_ARCH_AVR, UC_MODE_LITTLE_ENDIAN, &uc);
        if (is_error(err, "uc_open"))
            break;

        // Map program code
        err = uc_mem_map(uc, CODE_BASE, CODE_SIZE_ALIGNED, UC_PROT_READ|UC_PROT_EXEC);
        if (is_error(err, "uc_mem_map"))
            break;

        // Write machine code to be emulated to memory
        err = uc_mem_write(uc, CODE_BASE, CODE, CODE_SIZE);
        if (is_error(err, "uc_mem_write"))
            break;

        // Tracing all basic blocks with customized callback
        err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
        if (is_error(err, "uc_hook_add[UC_HOOK_BLOCK]"))
            break;

        // Tracing one instruction at CODE_BASE with customized callback
        err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, CODE_BASE,
            CODE_BASE + 1);
        if (is_error(err, "uc_hook_add[UC_HOOK_CODE]"))
            break;

        // Initialize registers
        uint8_t regs[32];
        memset(regs, 0, sizeof(regs));
        regs[25] = 0; regs[24] = 1;
        regs[23] = 0; regs[22] = 2;

        int reg_ids[32];
        void *reg_vals[32];
        for (unsigned i = 0; i < 4; i++) {
            reg_ids[i] = UC_AVR_REG_R0 + 22 + i;
            reg_vals[i] = &regs[22 + i];
        }
        err = uc_reg_write_batch(uc, reg_ids, reg_vals, 4);
        if (is_error(err, "uc_reg_write_batch"))
            break;

        // Emulate machine code in infinite time (last param = 0), or
        // when finishing all the code.
        err = uc_emu_start(uc, CODE_BASE, CODE_BASE + 4, 0, 0);
        if (is_error(err, "uc_emu_start"))
            break;

        // now print out some registers
        printf(">>> Emulation done. Below is the CPU context\n");

        uc_reg_read(uc, UC_AVR_REG_R25, &regs[25]);
        uc_reg_read(uc, UC_AVR_REG_R24, &regs[24]);
        uc_reg_read(uc, UC_AVR_REG_R23, &regs[23]);
        uc_reg_read(uc, UC_AVR_REG_R22, &regs[22]);
        printf(">>> r25,r24 = 0x%02x%02x\n", regs[25], regs[24]);
        if (regs[25] == 0 && regs[24] == 3 && regs[23] == 0 && regs[22] == 2)
            success = true;
    } while (0);

    if (uc)
        uc_close(uc);
    return success;
}

int main(int argc, char **argv, char **envp)
{
    if (!test_avr())
        abort();
    return 0;
}
