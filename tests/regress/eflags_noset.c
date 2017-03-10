#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <unicorn/unicorn.h>

#define X86_CODE32 "\x9C\x68\xFF\xFE\xFF\xFF\x9D\x9C\x58\x9D" // pushf; push ffffffeff; popf; pushf; pop eax; popf
#define ADDRESS 0x1000000
#define PAGE_8K (1 << 13)
#define PAGE_4K (1 << 12)
#define TARGET_PAGE_MASK ~(PAGE_4K - 1)
#define TARGET_PAGE_PREPARE(addr) (((addr) + PAGE_4K - 1) & TARGET_PAGE_MASK)
#define TARGET_PAGE_ALIGN(addr) (addr - (TARGET_PAGE_PREPARE(addr) - addr) & TARGET_PAGE_MASK)

#if defined(__i386__)
typedef uint32_t puint;
#define PRIX3264 PRIX32
#else
typedef uint64_t puint;
#define PRIX3264 PRIX64
#endif

uint32_t realEflags()
{
    puint val = 0;

#if defined(__i386__)
    puint i = 0xFFFFFEFF; //attempt to set ALL bits except trap flag.

    __asm__("pushf\n\t"
    "push %0\n\t"
    "popf\n\t" 
    "pushf\n\t"
    "pop %0\n\t"
    "popf"
    : "=r"(val)
    : "r"(i)
    : "%0");
#elif defined(__x86_64__)
    puint i = 0xFFFFFEFF; //attempt to set ALL bits except trap flag.

    __asm__("pushfq\n\t"
    "pushq %0\n\t"
    "popfq\n\t" 
    "pushfq\n\t"
    "popq %0\n\t"
    "popfq"
    : "=r"(val)
    : "r"(i)
    : "%0"); 
#endif

    printf("Real system eflags: 0x%08"PRIX3264"\n", val);

    return (uint32_t)val & 0xFFFFFFFF;
}

static void VM_exec()
{
#if defined(__i386__) || defined(__x86_64__)
    uc_engine *uc;
    uc_err err;
    unsigned int r_eax, eflags, r_esp, realflags = 0;

    r_eax = 0;
    r_esp = ADDRESS+0x100; //some safe distance from main code.
    eflags = 0x00000206;

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if(err)
    {
        printf("Failed on uc_open() with error returned: %s\n", uc_strerror(err));
        return;
    }

    err = uc_mem_map(uc, ADDRESS, (2 * 1024 * 1024), UC_PROT_ALL);
    if(err != UC_ERR_OK)
    {
        printf("Failed to map memory %s\n", uc_strerror(err));
        return;
    }

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1);
    if(err != UC_ERR_OK)
    {
        printf("Failed to write emulation code to memory, quit!: %s(len %lu)\n", uc_strerror(err), (unsigned long)sizeof(X86_CODE32) - 1);
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp); //make stack pointer point to already mapped memory so we don't need to hook.
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + (sizeof(X86_CODE32) - 1), 0, 0);
    if(err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));

        uc_close(uc);
        return;
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    uc_close(uc);

    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> EAX = 0x%08X\n", r_eax);
    printf(">>> EFLAGS = 0x%08X\n", eflags);

    realflags = realEflags();

    assert(r_eax == realflags);
#endif
}

int main(int argc, char *argv[])
{
    VM_exec();
    return 0;
}
