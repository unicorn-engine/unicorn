#include <stdlib.h>
#include <stdio.h>

#include <unicorn/unicorn.h>

#define X86_CODE32 "\xf3\xab" // rep stosd dword ptr es:[edi], eax -> Fill (E)CX doublewords at ES:[(E)DI] with EAX
#define ADDRESS 0x1000000
#define ECX_OPS 2
static long unsigned int hook_called = 0;

void hook_ins(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    hook_called++;
    printf("hook called\n");
}

static void VM_exec()
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace;
    unsigned int r_eax, eflags, r_esp, r_edi, r_ecx;

    r_eax = 0xbaadbabe;
    r_esp = ADDRESS+0x20;
    r_edi = ADDRESS+0x300; //some safe distance from main code.
    eflags = 0x00000206;
    r_ecx = ECX_OPS;

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
    uc_reg_write(uc, UC_X86_REG_EDI, &r_edi);
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp); //make stack pointer point to already mapped memory so we don't need to hook.
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

    uc_hook_add(uc, &trace, UC_HOOK_CODE, (void *)hook_ins, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + (sizeof(X86_CODE32) - 1), 0, 0);
    if(err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));

        uc_close(uc);
        return;
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDI, &r_edi);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    uc_close(uc);

    printf("\n>>> Emulation done. Below is the CPU context\n");
    printf(">>> EAX = 0x%08X\n", r_eax);
    printf(">>> ECX = 0x%08X\n", r_ecx);
    printf(">>> EDI = 0x%08X\n", r_edi);
    printf(">>> EFLAGS = 0x%08X\n", eflags);

    printf("\nHook called %lu times. Test %s\n", hook_called, (hook_called == ECX_OPS ? "PASSED!!" : "FAILED!!!"));

}

int main(int argc, char *argv[])
{
    VM_exec();
    return 0;
}
