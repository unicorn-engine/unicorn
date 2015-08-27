#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <unicorn/unicorn.h>

const uint8_t PROGRAM[] = "\xeb\x08\x58\xc7\x00\x78\x56\x34\x12\x90\xe8\xf3\xff\xff\xff";

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

// callback for tracing instruction
static void hook_code(uch handle, uint64_t address, uint32_t size, void *user_data)
{
    uint32_t esp;
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    uc_reg_read(handle, UC_X86_REG_ESP, &esp);
    printf(">>> --- ESP is 0x%x\n", esp);

}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uch handle, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    uint32_t esp;
    uc_reg_read(handle, UC_X86_REG_ESP, &esp);

    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_WRITE:
            //if this is a push, esp has not been adjusted yet
            if (esp == (address + size)) {
                 uint32_t upper;
                 upper = (esp + 0xfff) & ~0xfff;
                 printf(">>> Stack appears to be missing at 0x%"PRIx64 ", allocating now\n", address);
                 // map this memory in with 2MB in size
                 uc_mem_map(handle, upper - 0x8000, 0x8000);
                 // return true to indicate we want to continue
                 return true;
            }
            printf(">>> Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                   address, size, value);
            return false;
    }
}


#define STACK 0x500000
#define STACK_SIZE 0x5000

int main(int argc, char **argv, char **envp) {
    uch handle, trace1, trace2;
    uc_err err;
    uint8_t bytes[8];
    uint32_t esp;
    int result;
    int map_stack = 0;
    
    if (argc == 2 && strcmp(argv[1], "--map-stack") == 0) {
        map_stack = 1;
    }

    printf("Memory mapping test\n");

    if (map_stack) {
        printf("Pre-mapping stack\n");
    }
    else {
        printf("Mapping stack on first invalid memory access\n");
    }

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &handle);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return 1;
    }

    uc_mem_map(handle, 0x100000, 0x1000);
    uc_mem_map(handle, 0x200000, 0x2000);
    uc_mem_map(handle, 0x300000, 0x3000);
    uc_mem_map_ex(handle, 0x400000, 0x4000, UC_PROT_READ | UC_PROT_EXEC);
    
    if (map_stack) {
       uc_mem_map_ex(handle, STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    }

    esp = STACK + STACK_SIZE;

    uc_reg_write(handle, UC_X86_REG_ESP, &esp); 

    // write machine code to be emulated to memory
    if (uc_mem_write(handle, 0x400000, PROGRAM, sizeof(PROGRAM))) {
        printf("Failed to write emulation code to memory, quit!\n");
        return 2;
    }
    else {
        printf("Allowed to write to read only memory via uc_mem_write\n");
    }

    //uc_hook_add(handle, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)0x400000, (uint64_t)0x400fff);

    // intercept invalid memory events
    uc_hook_add(handle, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL);

    // emulate machine code in infinite time
    printf("BEGIN execution\n");
    err = uc_emu_start(handle, 0x400000, 0x400000 + sizeof(PROGRAM), 0, 5);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
        return 3;
    }
    printf("END execution\n");

    printf("Verifying content at bottom of stack is readable and correct\n");
    if (!uc_mem_read(handle, esp - 4, bytes, 4)) {
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", (uint32_t)(esp - 4), *(uint32_t*) bytes);
    }
    else {
        printf(">>> Failed to read 4 bytes from [0x%x]\n", (uint32_t)(esp - 4));
        return 4;
    }

    uc_close(&handle);
    
    return 0;
}
