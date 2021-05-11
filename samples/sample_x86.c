/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to demonstrate how to emulate X86 code */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define X86_CODE32 "\x41\x4a\x66\x0f\xef\xc1" // INC ecx; DEC edx; PXOR xmm0, xmm1
#define X86_CODE32_JUMP "\xeb\x02\x90\x90\x90\x90\x90\x90" // jmp 4; nop; nop; nop; nop; nop; nop
// #define X86_CODE32_SELF "\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41"
//#define X86_CODE32 "\x51\x51\x51\x51" // PUSH ecx;
#define X86_CODE32_LOOP "\x41\x4a\xeb\xfe" // INC ecx; DEC edx; JMP self-loop
#define X86_CODE32_MEM_WRITE "\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" // mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
#define X86_CODE32_MEM_READ "\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a" // mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
#define X86_CODE32_MEM_READ_IN_TB "\x40\x8b\x1d\x00\x00\x10\x00\x42" // inc eax; mov ebx, [0x100000]; inc edx

#define X86_CODE32_JMP_INVALID "\xe9\xe9\xee\xee\xee\x41\x4a" //  JMP outside; INC ecx; DEC edx
#define X86_CODE32_INOUT "\x41\xE4\x3F\x4a\xE6\x46\x43" // INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
#define X86_CODE32_INC "\x40"   // INC eax

//#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A \x49\x0F\xC9 \x90 \x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9" // <== still crash
//#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9"
#define X86_CODE64 "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"
#define X86_CODE16 "\x00\x00"   // add   byte ptr [bx + si], al
#define X86_CODE64_SYSCALL "\x0f\x05" // SYSCALL

// memory address where emulation starts
#define ADDRESS 0x1000000

// callback for tracing basic blocks
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int eflags;
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

// callback for tracing instruction
static void hook_code64(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
    printf(">>> RIP is 0x%"PRIx64 "\n", rip);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_WRITE_UNMAPPED:
                 printf(">>> Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
                 // map this memory in with 2MB in size
                 uc_mem_map(uc, 0xaaaa0000, 2 * 1024*1024, UC_PROT_ALL);
                 // return true to indicate we want to continue
                 return true;
    }
}

// dummy callback
static bool hook_mem_invalid_dummy(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    // Stop emulation.
    return false;
}

static void hook_mem64(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default: break;
        case UC_MEM_READ:
                 printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n",
                         address, size);
                 break;
        case UC_MEM_WRITE:
                 printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
                 break;
    }
}

// callback for IN instruction (X86).
// this returns the data read from the port
static uint32_t hook_in(uc_engine *uc, uint32_t port, int size, void *user_data)
{
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- reading from port 0x%x, size: %u, address: 0x%x\n", port, size, eip);

    switch(size) {
        default:
            return 0;   // should never reach this
        case 1:
            // read 1 byte to AL
            return 0xf1;
        case 2:
            // read 2 byte to AX
            return 0xf2;
            break;
        case 4:
            // read 4 byte to EAX
            return 0xf4;
    }
}

// callback for OUT instruction (X86).
static void hook_out(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
    uint32_t tmp = 0;
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x\n", port, size, value, eip);

    // confirm that value is indeed the value of AL/AX/EAX
    switch(size) {
        default:
            return;   // should never reach this
        case 1:
            uc_reg_read(uc, UC_X86_REG_AL, &tmp);
            break;
        case 2:
            uc_reg_read(uc, UC_X86_REG_AX, &tmp);
            break;
        case 4:
            uc_reg_read(uc, UC_X86_REG_EAX, &tmp);
            break;
    }

    printf("--- register value = 0x%x\n", tmp);
}

// callback for SYSCALL instruction (X86).
static void hook_syscall(uc_engine *uc, void *user_data)
{
    uint64_t rax;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    if (rax == 0x100) {
        rax = 0x200;
        uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    } else
        printf("ERROR: was not expecting rax=0x%"PRIx64 " in syscall\n", rax);
}

static void test_i386(void)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register
    // XMM0 and XMM1 registers, low qword then high qword
    uint64_t r_xmm0[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};
    uint64_t r_xmm1[2] = {0x8090a0b0c0d0e0f0, 0x0010203040506070};

    printf("Emulate i386 code\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_write(uc, UC_X86_REG_XMM0, &r_xmm0);
    uc_reg_write(uc, UC_X86_REG_XMM1, &r_xmm1);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);
    printf(">>> XMM0 = 0x%.16"PRIx64"%.16"PRIx64"\n", r_xmm0[1], r_xmm0[0]);

    // read from memory
    if (!uc_mem_read(uc, ADDRESS, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);

    uc_close(uc);
}

static void test_i386_map_ptr(void)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;
    void *mem;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code - use uc_mem_map_ptr()\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // malloc 2MB memory for this emulation
    mem = calloc(1, 2 * 1024 * 1024);
    if (mem == NULL) {
        printf("Failed to malloc()\n");
        return;
    }

    uc_mem_map_ptr(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL, mem);

    // write machine code to be emulated to memory
    if (!memcpy(mem, X86_CODE32, sizeof(X86_CODE32) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    // read from memory
    if (!uc_mem_read(uc, ADDRESS, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);

    uc_close(uc);
    free(mem);
}

static void test_i386_jump(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    printf("===================================\n");
    printf("Emulate i386 code with jump\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_JUMP,
          sizeof(X86_CODE32_JUMP) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // tracing 1 basic block with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, ADDRESS, ADDRESS);

    // tracing 1 instruction at ADDRESS
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_JUMP) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf(">>> Emulation done. Below is the CPU context\n");

    uc_close(uc);
}

// emulate code that loop forever
static void test_i386_loop(void)
{
    uc_engine *uc;
    uc_err err;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that loop forever\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_LOOP, sizeof(X86_CODE32_LOOP) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // emulate machine code in 2 seconds, so we can quit even
    // if the code loops
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_LOOP) - 1, 2 * UC_SECOND_SCALE, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);
}

// emulate code that read invalid memory
static void test_i386_invalid_mem_read(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that read from invalid memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_MEM_READ, sizeof(X86_CODE32_MEM_READ) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_MEM_READ) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);
}

// emulate code that write invalid memory
static void test_i386_invalid_mem_write(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3;
    uint32_t tmp;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that write to invalid memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_MEM_WRITE, sizeof(X86_CODE32_MEM_WRITE) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // intercept invalid memory events
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_MEM_WRITE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    // read from memory
    if (!uc_mem_read(uc, 0xaaaaaaaa, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xaaaaaaaa, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", 0xaaaaaaaa);

    if (!uc_mem_read(uc, 0xffffffaa, &tmp, sizeof(tmp)))
        printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xffffffaa, tmp);
    else
        printf(">>> Failed to read 4 bytes from [0x%x]\n", 0xffffffaa);

    uc_close(uc);
}

// emulate code that jump to invalid memory
static void test_i386_jump_invalid(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    printf("===================================\n");
    printf("Emulate i386 code that jumps to invalid memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_JMP_INVALID, sizeof(X86_CODE32_JMP_INVALID) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_JMP_INVALID) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);

    uc_close(uc);
}

static void test_i386_inout(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;


    int r_eax = 0x1234;     // EAX register
    int r_ecx = 0x6789;     // ECX register

    printf("===================================\n");
    printf("Emulate i386 code with IN/OUT instructions\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_INOUT, sizeof(X86_CODE32_INOUT) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // uc IN instruction
    uc_hook_add(uc, &trace3, UC_HOOK_INSN, hook_in, NULL, 1, 0, UC_X86_INS_IN);
    // uc OUT instruction
    uc_hook_add(uc, &trace4, UC_HOOK_INSN, hook_out, NULL, 1, 0, UC_X86_INS_OUT);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INOUT) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    printf(">>> EAX = 0x%x\n", r_eax);
    printf(">>> ECX = 0x%x\n", r_ecx);

    uc_close(uc);
}

// emulate code and save/restore the CPU context
static void test_i386_context_save(void)
{
    uc_engine *uc;
    uc_context *context;
    uc_err err;

    int r_eax = 0x1;    // EAX register

    printf("===================================\n");
    printf("Save/restore CPU context in opaque blob\n");

    // initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 8KB memory for this emulation
    uc_mem_map(uc, ADDRESS, 8 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_INC, sizeof(X86_CODE32_INC) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);

    // emulate machine code in infinite time
    printf(">>> Running emulation for the first time\n");

    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INC) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    printf(">>> EAX = 0x%x\n", r_eax);

    // allocate and save the CPU context
    printf(">>> Saving CPU context\n");

    err = uc_context_alloc(uc, &context);
    if (err) {
        printf("Failed on uc_context_alloc() with error returned: %u\n", err);
        return;
    }

    err = uc_context_save(uc, context);
    if (err) {
        printf("Failed on uc_context_save() with error returned: %u\n", err);
        return;
    }

    // emulate machine code again
    printf(">>> Running emulation for the second time\n");

    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INC) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    printf(">>> EAX = 0x%x\n", r_eax);

    // restore CPU context
    err = uc_context_restore(uc, context);
    if (err) {
        printf("Failed on uc_context_restore() with error returned: %u\n", err);
        return;
    }

    // now print out some registers
    printf(">>> CPU context restored. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    printf(">>> EAX = 0x%x\n", r_eax);

    // free the CPU context
    err = uc_context_free(context);
    if (err) {
        printf("Failed on uc_free() with error returned: %u\n", err);
        return;
    }

    uc_close(uc);
}

#if 0
static void test_i386_invalid_c6c7(void)
{
    uc_engine *uc;
    uc_err err;
    uint8_t codebuf[16] = { 0 };
    uint8_t opcodes[] = { 0xc6, 0xc7 };
    bool valid_masks[4][8] = {
        { true, false, false, false, false, false, false, false },
        { true, false, false, false, false, false, false, false },
        { true, false, false, false, false, false, false, false },
        { true, false, false, false, false, false, false, true  },
    };
    int i, j, k;

    printf("===================================\n");
    printf("Emulate i386 C6/C7 opcodes\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    for (i = 0; i < 2; ++i) {
        // set opcode
        codebuf[0] = opcodes[i];

        for (j = 0; j < 4; ++j) {
            for (k = 0; k < 8; ++k) {
                // set Mod bits
                codebuf[1]  = (uint8_t) (j << 6);
                // set Reg bits
                codebuf[1] |= (uint8_t) (k << 3);

                // perform validation
                if (uc_mem_write(uc, ADDRESS, codebuf, sizeof(codebuf))) {
                    printf("Failed to write emulation code to memory, quit!\n");
                    return;
                }
                err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(codebuf), 0, 0);
                if ((err != UC_ERR_INSN_INVALID) ^ valid_masks[j][k]) {
                    printf("Unexpected uc_emu_start() error returned %u: %s\n",
                           err, uc_strerror(err));
                    return;
                }
            }
        }
    }

    printf(">>> Emulation done.\n");

    uc_close(uc);
}
#endif

static void test_x86_64(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int64_t rax = 0x71f3029efd49d41d;
    int64_t rbx = 0xd87b45277f133ddb;
    int64_t rcx = 0xab40d1ffd8afc461;
    int64_t rdx = 0x919317b4a733f01;
    int64_t rsi = 0x4c24e753a17ea358;
    int64_t rdi = 0xe509a57d2571ce96;
    int64_t r8 = 0xea5b108cc2b9ab1f;
    int64_t r9 = 0x19ec097c8eb618c1;
    int64_t r10 = 0xec45774f00c5f682;
    int64_t r11 = 0xe17e9dbec8c074aa;
    int64_t r12 = 0x80f86a8dc0f6d457;
    int64_t r13 = 0x48288ca5671c5492;
    int64_t r14 = 0x595f72f6e4017f6e;
    int64_t r15 = 0x1efd97aea331cccc;

    int64_t rsp = ADDRESS + 0x200000;


    printf("Emulate x86_64 code\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64, sizeof(X86_CODE64) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_write(uc, UC_X86_REG_R8, &r8);
    uc_reg_write(uc, UC_X86_REG_R9, &r9);
    uc_reg_write(uc, UC_X86_REG_R10, &r10);
    uc_reg_write(uc, UC_X86_REG_R11, &r11);
    uc_reg_write(uc, UC_X86_REG_R12, &r12);
    uc_reg_write(uc, UC_X86_REG_R13, &r13);
    uc_reg_write(uc, UC_X86_REG_R14, &r14);
    uc_reg_write(uc, UC_X86_REG_R15, &r15);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing all instructions in the range [ADDRESS, ADDRESS+20]
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code64, NULL, ADDRESS, ADDRESS+20);

    // tracing all memory WRITE access (with @begin > @end)
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1, 0);

    // tracing all memory READ access (with @begin > @end)
    uc_hook_add(uc, &trace4, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);
    printf(">>> RBX = 0x%" PRIx64 "\n", rbx);
    printf(">>> RCX = 0x%" PRIx64 "\n", rcx);
    printf(">>> RDX = 0x%" PRIx64 "\n", rdx);
    printf(">>> RSI = 0x%" PRIx64 "\n", rsi);
    printf(">>> RDI = 0x%" PRIx64 "\n", rdi);
    printf(">>> R8 = 0x%" PRIx64 "\n", r8);
    printf(">>> R9 = 0x%" PRIx64 "\n", r9);
    printf(">>> R10 = 0x%" PRIx64 "\n", r10);
    printf(">>> R11 = 0x%" PRIx64 "\n", r11);
    printf(">>> R12 = 0x%" PRIx64 "\n", r12);
    printf(">>> R13 = 0x%" PRIx64 "\n", r13);
    printf(">>> R14 = 0x%" PRIx64 "\n", r14);
    printf(">>> R15 = 0x%" PRIx64 "\n", r15);

    uc_close(uc);
}

static void test_x86_64_syscall(void)
{
    uc_engine *uc;
    uc_hook trace1;
    uc_err err;

    int64_t rax = 0x100;

    printf("===================================\n");
    printf("Emulate x86_64 code with 'syscall' instruction\n");

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE64_SYSCALL, sizeof(X86_CODE64_SYSCALL) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // hook interrupts for syscall
    uc_hook_add(uc, &trace1, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE64_SYSCALL) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);

    printf(">>> RAX = 0x%" PRIx64 "\n", rax);

    uc_close(uc);
}

static void test_x86_16(void)
{
    uc_engine *uc;
    uc_err err;
    uint8_t tmp;

    int32_t eax = 7;
    int32_t ebx = 5;
    int32_t esi = 6;

    printf("Emulate x86 16-bit code\n");

    // Initialize emulator in X86-16bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 8KB memory for this emulation
    uc_mem_map(uc, 0, 8 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0, X86_CODE16, sizeof(X86_CODE16) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_write(uc, UC_X86_REG_ESI, &esi);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, 0, sizeof(X86_CODE16) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    // read from memory
    if (!uc_mem_read(uc, 11, &tmp, 1))
        printf(">>> Read 1 bytes from [0x%x] = 0x%x\n", 11, tmp);
    else
        printf(">>> Failed to read 1 bytes from [0x%x]\n", 11);

    uc_close(uc);
}

static void test_i386_invalid_mem_read_in_tb(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1;

    int r_eax = 0x1234;     // EAX register
    int r_edx = 0x7890;     // EDX register
    int r_eip = 0;

    printf("===================================\n");
    printf("Emulate i386 code that read invalid memory in the middle of a TB\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_MEM_READ_IN_TB, sizeof(X86_CODE32_MEM_READ_IN_TB) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

    // Add a dummy callback.
    uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ, hook_mem_invalid_dummy, NULL, 1, 0);
    
    // Let it crash by design.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_MEM_READ_IN_TB) - 1, 0, 0);
    if (err) {
        printf("uc_emu_start() failed BY DESIGN with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    printf(">>> EIP = 0x%x\n", r_eip);

    if (r_eip != ADDRESS + 1) {
        printf(">>> ERROR: Wrong PC 0x%x when reading unmapped memory in the middle of TB!\n", r_eip);
    } else {
        printf(">>> The PC is correct after reading unmapped memory in the middle of TB.\n");
    }

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    if (argc == 2) {
        if (!strcmp(argv[1], "-16")) {
            test_x86_16();
        }
        else if (!strcmp(argv[1], "-32")) {
            test_i386();
            test_i386_map_ptr();
            test_i386_inout();
            test_i386_context_save();
            test_i386_jump();
            test_i386_loop();
            test_i386_invalid_mem_read();
            test_i386_invalid_mem_write();
            test_i386_jump_invalid();
            //test_i386_invalid_c6c7();
        }
        else if (!strcmp(argv[1], "-64")) {
            test_x86_64();
            test_x86_64_syscall();
        }
        else if (!strcmp(argv[1], "-h")) {
            printf("Syntax: %s <-16|-32|-64>\n", argv[0]);
        }
   }
   else {
        test_x86_16();
        test_i386();
        test_i386_map_ptr();
        test_i386_inout();
        test_i386_context_save();
        test_i386_jump();
        test_i386_loop();
        test_i386_invalid_mem_read();
        test_i386_invalid_mem_write();
        test_i386_jump_invalid();
        //test_i386_invalid_c6c7();
        test_x86_64();
        test_x86_64_syscall();
        test_i386_invalid_mem_read_in_tb();
    }

    return 0;
}
