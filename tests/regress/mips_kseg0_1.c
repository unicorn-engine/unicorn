#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Test for the MIPS kseg0 and kseg1 memory segments.
// See issue https://github.com/unicorn-engine/unicorn/issues/217
// The kseg0 address range 0x80000000-0x9FFFFFFF is not mapped through the MMU,
// but instead is directly translated to low ram by masking off the high address bit.
// Similarly, the address range kseg1 0xA00000000-0xBFFFFFF is translated directly to
// low ram by masking off the top 3 address bits.
// Qemu handles these address ranges correctly, but there are issues with the way Unicorn checks for
// a valid memory mapping when executing code in the kseg0 or kseg1 memory range.
// In particular, Unicorn checks for a valid mapping using the virtual address when executing from kseg0/1, 
// when it should probably use the real address in low ram.

#define KSEG0_VIRT_ADDRESS 0x80001000 //Virtual address in kseg0, mapped by processor (and QEMU) to 0x1000
#define KSEG1_VIRT_ADDRESS 0xA0001000 //Virtual address in kseg1, mapped by processor (and QEMU) to 0x1000
#define KSEG0_1_REAL_ADDRESS 0x1000 //Real address corresponding to the above addresses in kseg0/1

#define MIPS_CODE_EL "\x56\x34\x21\x34" // ori $at, $at, 0x3456;

int main() 
{

    uc_engine *uc;
    uc_err err;

    err = uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32, &uc);
    if (err) {
        printf("uc_open %d\n", err);
        return 1;
    }

    // map 4Kb memory for this emulation, into the real address space
    err = uc_mem_map(uc, KSEG0_1_REAL_ADDRESS, 4 * 1024, UC_PROT_ALL);
    if (err) {
        printf("uc_mem_map %d\n", err);
        return 1;
    }

    // write machine code to be emulated to memory
    err = uc_mem_write(uc, KSEG0_1_REAL_ADDRESS, MIPS_CODE_EL, sizeof(MIPS_CODE_EL) - 1);
    if (err) {
        printf("uc_mem_map %s\n", uc_strerror(err));
        return 1;
    }

    //Start emulation at real address, this currently succeeds
    err = uc_emu_start(uc, KSEG0_1_REAL_ADDRESS, KSEG0_1_REAL_ADDRESS + 4, 0, 0);
    if (err) {
        printf("uc_emu_start at real address: %s\n", uc_strerror(err));
        return 1;
    }

    //Start emulation at virtual address in kseg0, this cuurently fails
    err = uc_emu_start(uc, KSEG0_VIRT_ADDRESS, KSEG0_VIRT_ADDRESS + 4, 0, 0);
    if (err) {
        printf("uc_emu_start at kseg0 address: %s\n", uc_strerror(err));
        return 1;
    }

    //Start emulation at virtual address in kseg1, this currently fails
    err = uc_emu_start(uc, KSEG1_VIRT_ADDRESS, KSEG1_VIRT_ADDRESS + 4, 0, 0);
    if (err) {
        printf("uc_emu_start at kseg1 address: %s\n", uc_strerror(err));
        return 1;
    }

    uc_close(uc);

    printf("Good, this bug is fixed!\n");

    return 0;
}
