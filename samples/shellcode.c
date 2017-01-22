/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to trace code with Linux code with syscall */

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define X86_CODE32 "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f"

#define X86_CODE32_SELF "\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41\x41\x41\x41\x41"

// memory address where emulation starts
#define ADDRESS 0x1000000

#define MIN(a, b) (a < b? a : b)
// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int r_eip;
    uint8_t tmp[16];

    printf("Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    printf("*** EIP = %x ***: ", r_eip);

    size = MIN(sizeof(tmp), size);
    if (!uc_mem_read(uc, address, tmp, size)) {
        uint32_t i;
        for (i=0; i<size; i++) {
            printf("%x ", tmp[i]);
        }
        printf("\n");
    }
}

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    int32_t r_eax, r_ecx, r_eip;
    uint32_t r_edx, size;
    unsigned char buffer[256];

    // only handle Linux syscall
    if (intno != 0x80)
        return;

    uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);

    switch(r_eax) {
        default:
            printf(">>> 0x%x: interrupt 0x%x, EAX = 0x%x\n", r_eip, intno, r_eax);
            break;
        case 1: // sys_exit
            printf(">>> 0x%x: interrupt 0x%x, SYS_EXIT. quit!\n\n", r_eip, intno);
            uc_emu_stop(uc);
            break;
        case 4: // sys_write
            // ECX = buffer address
            uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);

            // EDX = buffer size
            uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);

            // read the buffer in
            size = MIN(sizeof(buffer)-1, r_edx);

            if (!uc_mem_read(uc, r_ecx, buffer, size)) {
                buffer[size] = '\0';
                printf(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = '%s'\n",
                        r_eip, intno, r_ecx, r_edx, buffer);
            } else {
                printf(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u (cannot get content)\n",
                        r_eip, intno, r_ecx, r_edx);
            }
            break;
    }
}

static void test_i386(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r_esp = ADDRESS + 0x200000;  // ESP register

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
    if (uc_mem_write(uc, ADDRESS, X86_CODE32_SELF, sizeof(X86_CODE32_SELF) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // handle interrupt ourself
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, hook_intr, NULL, 1, 0);

    printf("\n>>> Start tracing this Linux code\n");

    // emulate machine code in infinite time
    // err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_SELF), 0, 12); <--- emulate only 12 instructions
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_SELF) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf("\n>>> Emulation done.\n");

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    // dynamically load shared library
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif
    
    if (argc == 2) {
        if (!strcmp(argv[1], "-32")) {
            test_i386();
        }
        else if (!strcmp(argv[1], "-h")) {
            printf("Syntax: %s <-32|-64>\n", argv[0]);
        }
    } else {
        test_i386();
    }

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
