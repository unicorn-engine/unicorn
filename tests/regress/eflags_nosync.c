#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <unicorn/unicorn.h>

#define X86_CODE32 "\x33\xD2\x8A\xD4\x8B\xC8\x81\xE1\xFF\x00\x00\x00" // XOR edx,edx; MOV dl,ah; MOV ecx,eax; AND ecx,FF
#define ADDRESS 0x1000000
#define PAGE_8K (1 << 13)
#define PAGE_4K (1 << 12)
#define TARGET_PAGE_MASK ~(PAGE_4K - 1)
#define TARGET_PAGE_PREPARE(addr) (((addr) + PAGE_4K - 1) & TARGET_PAGE_MASK)
#define TARGET_PAGE_ALIGN(addr) ((addr - (TARGET_PAGE_PREPARE(addr) - addr)) & TARGET_PAGE_MASK)

static uint64_t instructions = 0;

static void hook_ins(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    instructions++;
}

static bool hook_invalid_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    uc_err err;
    uint64_t address_align = TARGET_PAGE_ALIGN(address);

    if(address == 0)
    {
        printf("Address is 0, proof 0x%" PRIx64 "\n", address);
        return false;
    }

    switch(type)
    {
        default:
            return false;
            break;
        case UC_MEM_WRITE_UNMAPPED:
            printf("Mapping write address 0x%" PRIx64 " to aligned 0x%" PRIx64 "\n", address, address_align);

            err = uc_mem_map(uc, address_align, PAGE_8K, UC_PROT_ALL);
            if(err != UC_ERR_OK)
            {
                printf("Failed to map memory on UC_MEM_WRITE_UNMAPPED %s\n", uc_strerror(err));
                return false;
            }

            return true;
            break;
        case UC_MEM_READ_UNMAPPED:

            printf("Mapping read address 0x%" PRIx64 " to aligned 0x%" PRIx64 "\n", address, address_align);


            err = uc_mem_map(uc, address_align, PAGE_8K, UC_PROT_ALL);
            if(err != UC_ERR_OK)
            {
                printf("Failed to map memory on UC_MEM_READ_UNMAPPED %s\n", uc_strerror(err));
                return false;
            }

            return true;
            break;
    }
}

static void VM_exec()
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    unsigned int r_eax, r_ebx, r_ecx, r_edx, r_ebp, r_esp, r_esi, r_edi, r_eip, eflags;
    unsigned int tr_eax, tr_ebx, tr_ecx, tr_edx, tr_ebp, tr_esp, tr_esi, tr_edi, tr_eip, t_eflags;


    r_eax = tr_eax = 0x1DB10106;
    r_ebx = tr_ebx = 0x7EFDE000;
    r_ecx = tr_ecx = 0x7EFDE000;
    r_edx = tr_edx = 0x00001DB1;
    r_ebp = tr_ebp = 0x0018FF88;
    r_esp = tr_esp = 0x0018FF14;
    r_esi = tr_esi = 0x0;
    r_edi = tr_edi = 0x0;
    r_eip = tr_eip = 0x004939F3;
    t_eflags = eflags = 0x00000206;

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if(err)
    {
        printf("Failed on uc_open() with error returned: %s", uc_strerror(err));
        return;
    }

    err = uc_mem_map(uc, ADDRESS, (4 * 1024 * 1024), UC_PROT_ALL);
    if(err != UC_ERR_OK)
    {
        printf("Failed to map memory %s", uc_strerror(err));
        return;
    }

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1);
    if(err != UC_ERR_OK)
    {
        printf("Failed to write emulation code to memory, quit!: %s(len %zu)", uc_strerror(err), sizeof(X86_CODE32) - 1);
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_write(uc, UC_X86_REG_EBX, &r_ebx);
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_write(uc, UC_X86_REG_EBP, &r_ebp);
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);
    uc_reg_write(uc, UC_X86_REG_ESI, &r_esi);
    uc_reg_write(uc, UC_X86_REG_EDI, &r_edi);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

    uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, (void *)hook_invalid_mem, NULL, 1, 0);

    // tracing all instruction by having @begin > @end
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_ins, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + (sizeof(X86_CODE32) - 1), 0, 0);
    if(err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s", err, uc_strerror(err));
        instructions = 0;

        uc_close(uc);
        return;
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &r_ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_read(uc, UC_X86_REG_EBP, &r_ebp);
    uc_reg_read(uc, UC_X86_REG_ESP, &r_esp);
    uc_reg_read(uc, UC_X86_REG_ESI, &r_esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &r_edi);
    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    uc_close(uc);

    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> EAX = 0x%08X %s\n", r_eax, (r_eax == tr_eax ? "" : "(m)"));
    printf(">>> EBX = 0x%08X %s\n", r_ebx, (r_ebx == tr_ebx ? "" : "(m)"));
    printf(">>> ECX = 0x%08X %s\n", r_ecx, (r_ecx == tr_ecx ? "" : "(m)"));
    printf(">>> EDX = 0x%08X %s\n", r_edx, (r_edx == tr_edx ? "" : "(m)"));
    printf(">>> EBP = 0x%08X %s\n", r_ebp, (r_ebp == tr_ebp ? "" : "(m)"));
    printf(">>> ESP = 0x%08X %s\n", r_esp, (r_esp == tr_esp ? "" : "(m)"));
    printf(">>> ESI = 0x%08X %s\n", r_esi, (r_esi == tr_esi ? "" : "(m)"));
    printf(">>> EDI = 0x%08X %s\n", r_edi, (r_edi == tr_edi ? "" : "(m)"));
    printf(">>> EIP = 0x%08X %s\n", (r_eip - ADDRESS) + tr_eip, (r_eip == tr_eip ? "" : "(m)\n"));
    printf(">>> EFLAGS = 0x%08X %s\n", eflags, (eflags == t_eflags ? "" : "(m)"));

    printf(">>> Instructions executed %" PRIu64 "\n", instructions);

    assert(r_eax == 0x1DB10106);
    assert(r_ebx == 0x7EFDE000);
    assert(r_ecx == 0x00000006);
    assert(r_edx == 0x00000001);
    assert(r_ebp == 0x0018FF88);
    assert(r_esp == 0x0018FF14);
    assert(r_esi == 0x00000000);
    assert(r_edi == 0x00000000);
    assert(eflags == 0x00000206); //we shouldn't fail this assert, eflags should be 0x00000206 because the last AND instruction produces a non-zero result.

    instructions = 0;
}


int main(int argc, char *argv[])
{
    VM_exec();
    return 0;
}
