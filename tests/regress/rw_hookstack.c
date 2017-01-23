#include <stdlib.h>
#include <stdio.h>
#include <unicorn/unicorn.h>

#define ADDRESS 0x1000000
#define STACK 0x0020D000
#define STACK2 0x0030D000
#define STACK_SIZE 16384
#define SIZE (2 * 1024 * 1024)
#define CODE32 "\x8B\x04\x24\xA3\x40\x00\x00\x01\xA1\x40\x00\x00\x01"

bool hook_mem_rw(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    unsigned int EIP;

    uc_reg_read(uc, UC_X86_REG_EIP, &EIP);
    switch(type)
    {
        default:
            return false;
        break;
        case UC_MEM_WRITE:
            printf("Hooked write to address 0x%08"PRIX64" with value 0x%08"PRIX64" at EIP %08X\n", address, value, EIP);

            return true;
        break;
        case UC_MEM_READ:
            printf("Hooked read from address 0x%08"PRIX64" with value 0x%08"PRIX64" at EIP %08X\n", address, value, EIP);

            return true;
        break;
    }
}

int main(int argc, char *argv[])
{
    uc_engine *uc;
    uc_hook trace;
    uc_err err;
    unsigned int EAX, ESP, val = 0x0c0c0c0c, stkval = STACK;

    EAX = 0;
    ESP = STACK+0x4;

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if(err) {
        printf("Failed on uc_open() with error returned: %s\n", uc_strerror(err));
        return 1;
    }

    err = uc_mem_map(uc, ADDRESS, SIZE, UC_PROT_ALL);
    if(err != UC_ERR_OK) {
        printf("Failed to map memory %s\n", uc_strerror(err));
        return 1;
    }

    err = uc_mem_write(uc, ADDRESS, CODE32, sizeof(CODE32) - 1);
    if(err != UC_ERR_OK) {
        printf("Failed to write to memory %s\n", uc_strerror(err));
        return 1;
    }

loop:
    err = uc_mem_map(uc, stkval, STACK_SIZE, UC_PROT_ALL);
    if(err != UC_ERR_OK) {
        printf("Failed to map memory %s\n", uc_strerror(err));
        return 1;
    }

    err = uc_mem_write(uc, ESP, &val, sizeof(val));
    if(err != UC_ERR_OK) {
        printf("Failed to write to memory %s\n", uc_strerror(err));
        return 1;
    }


    uc_hook_add(uc, &trace, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, (void *)hook_mem_rw, NULL, 1, 0);

    uc_reg_write(uc, UC_X86_REG_EAX, &EAX);
    uc_reg_write(uc, UC_X86_REG_ESP, &ESP);

    err = uc_emu_start(uc, ADDRESS, ADDRESS + (sizeof(CODE32) - 1), 0, 0);
    if(err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));

        uc_close(uc);
        return 1;
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &EAX);

    printf(">>> EAX = %08X\n", EAX);

    if(stkval != STACK2)
    {
        printf("=== Beginning test two ===\n");
        ESP = STACK2+0x4;
        EAX = 0;
        stkval = STACK2;
        goto loop;
    }

    uc_close(uc);
    return 0;
}
