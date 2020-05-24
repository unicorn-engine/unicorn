#include "unicorn_test.h"
#include "unicorn/unicorn.h"

#define OK(x)   uc_assert_success(x)

/* Called before every test to set up a new instance */
static int setup32(void **state)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    *state = uc;
    return 0;
}

/* Called after every test to clean up */
static int teardown(void **state)
{
    uc_engine *uc = *state;

    OK(uc_close(uc));

    *state = NULL;
    return 0;
}

/******************************************************************************/

struct bb {
    uint64_t    addr;
    size_t      size;
};

struct bbtest {
    const struct bb *blocks;
    unsigned int     blocknum;
};


static void test_basic_blocks_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    struct bbtest *bbtest = user_data;
    const struct bb *bb = &bbtest->blocks[bbtest->blocknum++];

    assert_int_equal(address, bb->addr);
    assert_int_equal((size_t)size, bb->size);
}

static void test_basic_blocks(void **state)
{
    uc_engine *uc = *state;
    uc_hook trace1;

#define BASEADDR    0x1000000

    uint64_t address = BASEADDR;
    const uint8_t code[] = {
        0x33, 0xC0,     // xor  eax, eax
        0x90,           // nop
        0x90,           // nop
        0xEB, 0x00,     // jmp  $+2
        0x90,           // nop
        0x90,           // nop
        0x90,           // nop
    };

    static const struct bb blocks[] = {
        {BASEADDR,      6},
        {BASEADDR+ 6,   3},
    };

    struct bbtest bbtest = {
        .blocks = blocks,
        .blocknum = 0,
    };


#undef BASEADDR

    // map 2MB memory for this emulation
    OK(uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL));

    // write machine code to be emulated to memory
    OK(uc_mem_write(uc, address, code, sizeof(code)));

    // trace all basic blocks
    OK(uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, test_basic_blocks_hook, &bbtest, 1, 0));

    OK(uc_emu_start(uc, address, address+sizeof(code), 0, 0));
}

/******************************************************************************/

// callback for tracing basic blocks
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    //printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    //int eflags;
    //printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    //uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    //printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

static void test_i386(void **state)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;

    const uint8_t code[] = "\x41\x4a\x66\x0f\xef\xc1"; // INC ecx; DEC edx; PXOR xmm0, xmm1
    const uint64_t address = 0x1000000;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register
    // XMM0 and XMM1 registers, low qword then high qword
    uint64_t r_xmm0[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};
    uint64_t r_xmm1[2] = {0x8090a0b0c0d0e0f0, 0x0010203040506070};

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code)-1);
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_XMM0, &r_xmm0);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_XMM1, &r_xmm1);
    uc_assert_success(err);

    // tracing all basic blocks with customized callback
    err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
    uc_assert_success(err);

    // tracing all instruction by having @begin > @end
    err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code)-1, 0, 0);
    uc_assert_success(err);

    // now print out some registers
    //printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0);

    assert_int_equal(r_ecx, 0x1235);
    assert_int_equal(r_edx, 0x788F);
    uint64_t r_xmm0_expected[2] = {0x8899aabbccddeeff, 0x0011223344556677};
    assert_memory_equal(r_xmm0, r_xmm0_expected, sizeof(r_xmm0));

    // read from memory
    err = uc_mem_read(uc, address, (uint8_t *)&tmp, 4);
    uc_assert_success(err);
    //printf(">>> Read 4 bytes from [0x%"PRIX64"] = 0x%x\n", address, tmp);

    uc_close(uc);
}

static void test_i386_jump(void **state)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    const uint8_t code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop; nop; nop; nop
    const uint64_t address = 0x1000000;

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code)-1);
    uc_assert_success(err);

    // tracing 1 basic block with customized callback
    err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, address, address);
    uc_assert_success(err);

    // tracing 1 instruction at address
    err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, address, address);
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code)-1, 0, 0);
    uc_assert_success(err);

    err = uc_close(uc);
    uc_assert_success(err);
}

/******************************************************************************/

// callback for IN instruction (X86).
// this returns the data read from the port
static uint32_t hook_in(uc_engine *uc, uint32_t port, int size, void *user_data)
{
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    //printf("--- reading from port 0x%x, size: %u, address: 0x%x\n", port, size, eip);

    switch(size) {
        default:
            return 0;   // should never reach this
        case 1:
            // read 1 byte to AL
            return 0xf1;
        case 2:
            // read 2 byte to AX
            return 0xf2;
        case 4:
            // read 4 byte to EAX
            return 0xf4;
    }
}

// callback for OUT instruction (X86).
static void hook_out(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
    uint32_t tmp;
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    //printf("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x\n", port, size, value, eip);

    // TODO: confirm that value is indeed the value of AL/AX/EAX
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

    //printf("--- register value = 0x%x\n", tmp);
}

static void test_i386_inout(void **state)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int r_eax = 0x1234;     // EAX register
    int r_ecx = 0x6789;     // ECX register

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = {
        0x41,           // inc  ecx
        0xE4, 0x3F,     // in   al, 0x3F
        0x4A,           // dec  edx
        0xE6, 0x46,     // out  0x46, al
        0x43,           // inc  ebx
    };


    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_assert_success(err);

    // tracing all basic blocks with customized callback
    err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
    uc_assert_success(err);

    // tracing all instructions
    err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    uc_assert_success(err);

    // uc IN instruction
    err = uc_hook_add(uc, &trace3, UC_HOOK_INSN, hook_in, NULL, 1, 0, UC_X86_INS_IN);
    uc_assert_success(err);

    // uc OUT instruction
    err = uc_hook_add(uc, &trace4, UC_HOOK_INSN, hook_out, NULL, 1, 0, UC_X86_INS_OUT);
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code), 0, 0);
    uc_assert_success(err);

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    //printf(">>> EAX = 0x%x\n", r_eax);
    //printf(">>> ECX = 0x%x\n", r_ecx);
    // TODO: Assert on the register values here

    uc_assert_success(uc_close(uc));
}

/******************************************************************************/

// emulate code that loop forever
static void test_i386_loop(void **state)
{
    uc_engine *uc;
    uc_err err;

    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = {
        0x41,           // inc ecx
        0x4a,           // dec edx
        0xEB, 0xFE,     // jmp $
    };

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    uc_assert_success(err);

    // emulate machine code in 2 seconds, so we can quit even
    // if the code loops
    err = uc_emu_start(uc, address, address+sizeof(code), 2*UC_SECOND_SCALE, 0);
    uc_assert_success(err);

    // verify register values
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    assert_int_equal(r_ecx, 0x1235);
    assert_int_equal(r_edx, 0x788F);

    uc_assert_success(uc_close(uc));
}

/******************************************************************************/

// emulate code that reads invalid memory
static void test_i386_invalid_mem_read(void **state)
{
    uc_engine *uc;
    uc_err err;

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = {
        0x8b, 0x0D, 0xAA, 0xAA, 0xAA, 0xAA,     // mov  ecx, [0xAAAAAAAA]
    };

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code), 0, 0);
    uc_assert_err(UC_ERR_READ_UNMAPPED, err);

    uc_assert_success(uc_close(uc));
}

// emulate code that writes invalid memory
static void test_i386_invalid_mem_write(void **state)
{
    uc_engine *uc;
    uc_err err;

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = {
        0x89, 0x0D, 0xAA, 0xAA, 0xAA, 0xAA,     // mov  [0xAAAAAAAA], ecx
    };

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code), 0, 0);
    uc_assert_err(UC_ERR_WRITE_UNMAPPED, err);


    uc_assert_success(uc_close(uc));
}

// emulate code that jumps to invalid memory
static void test_i386_jump_invalid(void **state)
{
    uc_engine *uc;
    uc_err err;

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = {
        0xE9, 0xE9, 0xEE, 0xEE, 0xEE,   // jmp 0xEEEEEEEE
    };

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, address, address+sizeof(code), 0, 0);
    uc_assert_err(UC_ERR_FETCH_UNMAPPED, err);


    uc_assert_success(uc_close(uc));
}


/******************************************************************************/

static void hook_mem64(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default: break;
        case UC_MEM_READ:
                 //printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n",
                 //        address, size);
                 break;
        case UC_MEM_WRITE:
                 //printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                 //        address, size, value);
                 break;
    }
}

// callback for tracing instruction
static void hook_code64(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint64_t rip;

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    //printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
    //printf(">>> RIP is 0x%"PRIx64 "\n", rip);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

static void test_x86_64(void **state)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59";

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

    int64_t rsp = address + 0x200000;


    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code) - 1);
    uc_assert_success(err);

    // initialize machine registers
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RSP, &rsp));

    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RBX, &rbx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RSI, &rsi));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RDI, &rdi));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R8,  &r8));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R9,  &r9));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R10, &r10));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R11, &r11));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R12, &r12));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R13, &r13));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R14, &r14));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_R15, &r15));

    // tracing all basic blocks with customized callback
    err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
    uc_assert_success(err);

    // tracing all instructions in the range [address, address+20]
    err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code64, NULL, address, address+20);
    uc_assert_success(err);

    // tracing all memory WRITE access (with @begin > @end)
    err = uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1, 0);
    uc_assert_success(err);

    // tracing all memory READ access (with @begin > @end)
    err = uc_hook_add(uc, &trace4, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0);
    uc_assert_success(err);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, address, address+sizeof(code) - 1, 0, 0);
    uc_assert_success(err);

    // Read registers
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_R8,  &r8);
    uc_reg_read(uc, UC_X86_REG_R9,  &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);

#if 0
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
#endif

    uc_assert_success(uc_close(uc));
}

/******************************************************************************/

// callback for SYSCALL instruction (X86).
static void hook_syscall(uc_engine *uc, void *user_data)
{
    uint64_t rax;

    uc_assert_success(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    assert_int_equal(0x100, rax);

    rax = 0x200;
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
}

static void test_x86_64_syscall(void **state)
{
    uc_engine *uc;
    uc_hook trace1;
    uc_err err;

    static const uint64_t address = 0x1000000;
    static const uint8_t code[] = {
        0x0F, 0x05,     // SYSCALL
    };

    int64_t rax = 0x100;

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    uc_assert_success(err);

    // map 2MB memory for this emulation
    err = uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // hook interrupts for syscall
    err = uc_hook_add(uc, &trace1, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);
    uc_assert_success(err);

    // initialize machine registers
    err = uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_assert_success(err);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, address, address + sizeof(code), 0, 0);
    uc_assert_success(err);

    // verify register values
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    assert_int_equal(0x200, rax);

    uc_assert_success(uc_close(uc));
}

/******************************************************************************/

static void test_x86_16(void **state)
{
    uc_engine *uc;
    uc_err err;
    uint8_t tmp;

    static const uint64_t address = 0;
    static const uint8_t code[] = {
        0x00, 0x00,         // add   byte ptr [bx + si], al
    };

    int32_t eax = 7;
    int32_t ebx = 5;
    int32_t esi = 6;

    // Initialize emulator in X86-16bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    uc_assert_success(err);

    // map 8KB memory for this emulation
    err = uc_mem_map(uc, address, 8 * 1024, UC_PROT_ALL);
    uc_assert_success(err);

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, address, code, sizeof(code));
    uc_assert_success(err);

    // initialize machine registers
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EBX, &ebx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_ESI, &esi));

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, address, address+sizeof(code), 0, 0);
    uc_assert_success(err);

    // read from memory
    uc_assert_success(uc_mem_read(uc, 11, &tmp, 1));
    assert_int_equal(7, tmp);

    uc_assert_success(uc_close(uc));
}

/******************************************************************************/

static void test_i386_reg_save(void **state)
{
    uc_engine *uc;
    uc_context *saved_context;

    static const uint64_t address = 0;
    static const uint8_t code[] = {
        0x40       // inc eax
    };
    int32_t eax = 1;

    // Initialize emulator
    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    // map 8KB memory for this emulation
    uc_assert_success(uc_mem_map(uc, address, 8 * 1024, UC_PROT_ALL));

    // write machine code to be emulated to memory
    uc_assert_success(uc_mem_write(uc, address, code, sizeof(code)));

    // set eax to 1
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EAX, &eax));

    // step one instruction
    uc_assert_success(uc_emu_start(uc, address, address+1, 0, 0));

    // grab a buffer to use for state saving
    uc_assert_success(uc_context_alloc(uc, &saved_context));

    // save the state
    uc_assert_success(uc_context_save(uc, saved_context));

    // step one instruction
    uc_assert_success(uc_emu_start(uc, address, address+1, 0, 0));

    // check that eax == 3
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    assert_int_equal(eax, 3);

    // restore the state
    uc_context_restore(uc, saved_context);

    // check that eax == 2
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    assert_int_equal(eax, 2);

    // step one instruction
    uc_assert_success(uc_emu_start(uc, address, address+1, 0, 0));

    // check that eax == 3
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    assert_int_equal(eax, 3);

    // restore the state
    uc_context_restore(uc, saved_context);

    // check that eax == 2
    uc_assert_success(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    assert_int_equal(eax, 2);

    // clean up;
    uc_free(saved_context);
    uc_assert_success(uc_close(uc));
}
/******************************************************************************/

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_i386),
        cmocka_unit_test(test_i386_jump),
        cmocka_unit_test(test_i386_inout),
        cmocka_unit_test(test_i386_loop),
        cmocka_unit_test(test_i386_invalid_mem_read),
        cmocka_unit_test(test_i386_invalid_mem_write),
        cmocka_unit_test(test_i386_jump_invalid),
        cmocka_unit_test(test_i386_reg_save),

        cmocka_unit_test(test_x86_64),
        cmocka_unit_test(test_x86_64_syscall),

        cmocka_unit_test(test_x86_16),

        cmocka_unit_test_setup_teardown(test_basic_blocks, setup32, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
