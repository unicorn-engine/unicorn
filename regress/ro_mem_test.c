#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <unicorn/unicorn.h>

#define PROGRAM "\xeb\x08\x58\xc7\x00\x78\x56\x34\x12\x90\xe8\xf3\xff\xff\xff"

/*
bits 32

   jmp short bottom
top:
   pop eax
   mov dword [eax], 0x12345678
   nop
bottom:
   call top
*/

int main(int argc, char **argv, char **envp) {
    uch handle;
    uc_err err;
    uint8_t bytes[8];

    printf("Memory mapping test\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &handle);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    uc_mem_map(handle, 0x100000, 0x1000);
    uc_mem_map(handle, 0x200000, 0x2000);
    uc_mem_map(handle, 0x300000, 0x3000);
    uc_mem_map_ex(handle, 0x400000, 0x4000, UC_PROT_READ | UC_PROT_EXEC);

    // write machine code to be emulated to memory
    if (uc_mem_write(handle, 0x400000, PROGRAM, sizeof(PROGRAM))) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }
    else {
        printf("Allowed to write to read only memory via uc_mem_write\n");
    }

    // emulate machine code in infinite time
    printf("BEGIN execution\n");
    err = uc_emu_start(handle, 0x400000, 0x400000 + sizeof(PROGRAM), 0, 5);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }
    printf("END execution\n");

    if (!uc_mem_read(handle, 0x400000 + sizeof(PROGRAM) - 1, bytes, 4))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0x400000 + sizeof(PROGRAM) - 1,*(uint32_t*) bytes);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", 0x400000 + sizeof(PROGRAM) - 1);

    uc_close(&handle);
}
