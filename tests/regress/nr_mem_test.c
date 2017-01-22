/*
Non-readable memory test case

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#include <string.h>

#include <unicorn/unicorn.h>

const uint8_t PROGRAM[] =  
   "\x8b\x1d\x00\x00\x30\x00\xa1\x00\x00\x40\x00";
// total size: 11 bytes

/*
bits 32

   mov ebx, [0x300000]
   mov eax, [0x400000]
*/

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{

    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_READ_PROT:
            printf(">>> non-readable memory is being read at 0x%"PRIx64 ", data size = %u\n",
                   address, size);
            return false;
    }
}


int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_hook trace1;
    uc_err err;
    uint32_t eax, ebx;
    
    printf("Memory protections test\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return 1;
    }

    uc_mem_map(uc, 0x100000, 0x1000, UC_PROT_READ);
    uc_mem_map(uc, 0x300000, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
    uc_mem_map(uc, 0x400000, 0x1000, UC_PROT_WRITE);
    
    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0x100000, PROGRAM, sizeof(PROGRAM))) {
        printf("Failed to write emulation code to memory, quit!\n");
        return 2;
    } else {
        printf("Allowed to write to read only memory via uc_mem_write\n");
    }

    uc_mem_write(uc, 0x300000, (const uint8_t*)"\x41\x41\x41\x41", 4);
    uc_mem_write(uc, 0x400000, (const uint8_t*)"\x42\x42\x42\x42", 4);

    //uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 0x400000, 0x400fff);

    // intercept invalid memory events
    uc_hook_add(uc, &trace1, UC_MEM_READ_PROT, hook_mem_invalid, NULL, 1, 0);

    // emulate machine code in infinite time
    printf("BEGIN execution\n");
    err = uc_emu_start(uc, 0x100000, 0x100000 + sizeof(PROGRAM), 0, 2);
    if (err) {
        printf("Expected failure on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    } else {
        printf("UNEXPECTED uc_emu_start returned UC_ERR_OK\n");
    }
    printf("END execution\n");

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    printf("Final eax = 0x%x\n", eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    printf("Final ebx = 0x%x\n", ebx);

    uc_close(uc);
    
    return 0;
}
