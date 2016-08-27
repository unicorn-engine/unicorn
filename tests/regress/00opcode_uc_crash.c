#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <unicorn/unicorn.h>

#define X86_CODE32 "\x00" // add byte ptr ds:[eax],al
#define ADDRESS 0x1000000

static void VM_exec()
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    unsigned int r_eax;

    r_eax = 0x1000008;

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if(err)
    {
        printf("Failed on uc_open() with error returned: %s\n", uc_strerror(err));
        return;
    }

    err = uc_mem_map(uc, ADDRESS, (4 * 1024 * 1024), UC_PROT_ALL);
    if(err != UC_ERR_OK)
    {
        printf("Failed to map memory %s\n", uc_strerror(err));
        return;
    }

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1);
    if(err != UC_ERR_OK)
    {
        printf("Failed to write emulation code to memory, quit!: %s(len %zu)\n", uc_strerror(err), sizeof(X86_CODE32) - 1);
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + (sizeof(X86_CODE32) - 1), 0, 0);
    if(err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));

        uc_close(uc);
        return;
    }

    if (!uc_mem_read(uc, ADDRESS+8, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%08X] = 0x%08X\n", ADDRESS+8, tmp); //should contain the byte '8'
    else
        printf(">>> Failed to read 4 bytes from [0x%08X]\n", ADDRESS+8);

    uc_close(uc);

    puts("No crash. Yay!");
}

int main(int argc, char *argv[])
{
    VM_exec();
    return 0;
}
