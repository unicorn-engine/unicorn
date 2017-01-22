/*
   Executable memory regions demo / unit test

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

#define __STDC_FORMAT_MACROS
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unicorn/unicorn.h>

unsigned char PROGRAM[] =
    "\xeb\x45\x5e\x81\xe6\x00\xf0\xff\xff\x40\x40\x40\x40\x40\x40\x40"
    "\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40"
    "\x40\x40\x40\x40\x40\x40\x40\x89\xf7\x81\xc7\x00\x00\x10\x00\xb9"
    "\x4c\x00\x00\x00\x81\xff\x00\x00\x40\x00\x75\x01\xf4\xf3\xa4\x81"
    "\xe7\x00\xf0\xff\xff\xff\xe7\xe8\xb6\xff\xff\xff";
    // total size: 76 bytes

/*
   bits 32

   ; assumes r-x section at 0x100000
   ; assumes rw- section at 0x200000
   ; assumes r-- section at 0x300000
   ; also needs an initialized stack

start:
jmp bottom
top:
pop esi
and esi, ~0xfff
times 30 inc eax
mov edi, esi
add edi, 0x100000
mov ecx, end - start
rep movsb
and edi, ~0xfff
cmp edi, 0x400000
jnz next_block
hlt
next_block:
jmp edi
bottom:
call top
end:
 */

int test_num  = 0;
uint32_t tests[] = {
    0x41414141,
    0x43434343,
    0x45454545
};

static int log_num = 1;

#define CODE_SECTION 0x100000
#define CODE_SIZE 0x1000

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data)
{
    uint8_t opcode;

    if (uc_mem_read(uc, addr, &opcode, 1) != UC_ERR_OK) {
        printf("not ok %d - uc_mem_read fail during hook_code callback, addr: 0x%" PRIx64 "\n", log_num++, addr);
    }

    //   printf("ok %d - uc_mem_read for opcode at address 0x%" PRIx64 "\n", log_num++, addr);
    switch (opcode) {
        case 0xf4:  //hlt
            printf("# Handling HLT\n");
            if (uc_emu_stop(uc) != UC_ERR_OK) {
                printf("not ok %d - uc_emu_stop fail during hook_code callback, addr: 0x%" PRIx64 "\n", log_num++, addr);
                _exit(-1);
            } else {
                printf("ok %d - hlt encountered, uc_emu_stop called\n", log_num++);
            }
            break;
        default:  //all others
            //         printf("# Handling OTHER\n");
            break;
    }
}

// callback for tracing memory access (READ or WRITE)
static void hook_mem_write(uc_engine *uc, uc_mem_type type,
        uint64_t addr, int size, int64_t value, void *user_data)
{
    printf("# write to memory at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
}

// callback for tracing invalid memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t addr, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            printf("not ok %d - memory invalid type: %d at 0x%" PRIx64 "\n", log_num++, type, addr);
            return false;
        case UC_MEM_FETCH_PROT:
            printf("# Fetch from non-executable memory at 0x%"PRIx64 "\n", addr);

            //make page executable
            if (uc_mem_protect(uc, addr & ~0xfffL, 0x1000, UC_PROT_READ | UC_PROT_EXEC) != UC_ERR_OK) {
                printf("not ok %d - uc_mem_protect fail for address: 0x%" PRIx64 "\n", log_num++, addr);
            } else {
                printf("ok %d - uc_mem_protect success at 0x%" PRIx64 "\n", log_num++, addr);
            }
            return true;
        case UC_MEM_WRITE_PROT:
            printf("# write to non-writeable memory at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);

            if (uc_mem_protect(uc, addr & ~0xfffL, 0x1000, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) {
                printf("not ok %d - uc_mem_protect fail during hook_mem_invalid callback, addr: 0x%" PRIx64 "\n", log_num++, addr);
            } else {
                printf("ok %d - uc_mem_protect success\n", log_num++);
            }
            return true;
    }
}

int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;
    uint32_t esp, eip;
    int32_t buf1[1024], buf2[1024], readbuf[1024];
    int i;

    //don't really care about quality of randomness
    srand(time(NULL));
    for (i = 0; i < 1024; i++) {
        buf1[i] = rand();
        buf2[i] = rand();
    }

    printf("# Memory protect test\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("not ok %d - Failed on uc_open() with error returned: %u\n", log_num++, err);
        return 1;
    } else {
        printf("ok %d - uc_open() success\n", log_num++);
    }

    uc_mem_map(uc, 0x100000, 0x1000, UC_PROT_READ | UC_PROT_EXEC);
    uc_mem_map(uc, 0x1ff000, 0x2000, UC_PROT_READ | UC_PROT_WRITE);
    uc_mem_map(uc, 0x300000, 0x2000, UC_PROT_READ);
    uc_mem_map(uc, 0xf00000, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

    esp = 0xf00000 + 0x1000;

    // Setup stack pointer
    if (uc_reg_write(uc, UC_X86_REG_ESP, &esp)) {
        printf("not ok %d - Failed to set esp. quit!\n", log_num++);
        return 2;
    } else {
        printf("ok %d - ESP set\n", log_num++);
    }

    // fill in sections that shouldn't get touched
    if (uc_mem_write(uc, 0x1ff000, buf1, sizeof(buf1))) {
        printf("not ok %d - Failed to write random buffer 1 to memory, quit!\n", log_num++);
        return 3;
    } else {
        printf("ok %d - Random buffer 1 written to memory\n", log_num++);
    }

    if (uc_mem_write(uc, 0x301000, buf2, sizeof(buf2))) {
        printf("not ok %d - Failed to write random buffer 2 to memory, quit!\n", log_num++);
        return 4;
    } else {
        printf("ok %d - Random buffer 2 written to memory\n", log_num++);
    }

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0x100000, PROGRAM, sizeof(PROGRAM))) {
        printf("not ok %d - Failed to write emulation code to memory, quit!\n", log_num++);
        return 5;
    } else {
        printf("ok %d - Program written to memory\n", log_num++);
    }

    if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok %d - Failed to install UC_HOOK_CODE ucr\n", log_num++);
        return 6;
    } else {
        printf("ok %d - UC_HOOK_CODE installed\n", log_num++);
    }

    // intercept memory write events
    if (uc_hook_add(uc, &trace1, UC_HOOK_MEM_WRITE, hook_mem_write, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok %d - Failed to install UC_HOOK_MEM_WRITE ucr\n", log_num++);
        return 7;
    } else {
        printf("ok %d - UC_HOOK_MEM_WRITE installed\n", log_num++);
    }

    // intercept invalid memory events
    if (uc_hook_add(uc, &trace1, UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT, hook_mem_invalid, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok %d - Failed to install memory invalid handler\n", log_num++);
        return 8;
    } else {
        printf("ok %d - memory invalid handler installed\n", log_num++);
    }

    // emulate machine code until told to stop by hook_code
    printf("# BEGIN execution\n");
    err = uc_emu_start(uc, 0x100000, 0x400000, 0, 0);
    if (err != UC_ERR_OK) {
        printf("not ok %d - Failure on uc_emu_start() with error %u:%s\n", log_num++, err, uc_strerror(err));
        return 9;
    } else {
        printf("ok %d - uc_emu_start complete\n", log_num++);
    }
    printf("# END execution\n");

    // get ending EIP
    if (uc_reg_read(uc, UC_X86_REG_EIP, &eip)) {
        printf("not ok %d - Failed to read eip.\n", log_num++);
    } else {
        printf("ok %d - Ending EIP 0x%x\n", log_num++, eip);
    }

    //make sure that random blocks didn't get nuked
    // fill in sections that shouldn't get touched
    if (uc_mem_read(uc, 0x1ff000, readbuf, sizeof(readbuf))) {
        printf("not ok %d - Failed to read random buffer 1 from memory\n", log_num++);
    } else {
        printf("ok %d - Random buffer 1 read from memory\n", log_num++);
        if (memcmp(buf1, readbuf, 4096)) {
            printf("not ok %d - Random buffer 1 contents are incorrect\n", log_num++);
        } else {
            printf("ok %d - Random buffer 1 contents are correct\n", log_num++);
        }
    }

    if (uc_mem_read(uc, 0x301000, readbuf, sizeof(readbuf))) {
        printf("not ok %d - Failed to read random buffer 2 from memory\n", log_num++);
    } else {
        printf("ok %d - Random buffer 2 read from memory\n", log_num++);
        if (memcmp(buf2, readbuf, 4096)) {
            printf("not ok %d - Random buffer 2 contents are incorrect\n", log_num++);
        } else {
            printf("ok %d - Random buffer 2 contents are correct\n", log_num++);
        }
    }

    if (uc_close(uc) == UC_ERR_OK) {
        printf("ok %d - uc_close complete\n", log_num++);
    } else {
        printf("not ok %d - uc_close complete\n", log_num++);
    }

    return 0;
}
