/*
   uc_mem_protect demo / unit test

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
    "\xc7\x05\x00\x00\x20\x00\x41\x41\x41\x41\x90\xc7\x05\x00\x00\x20"
    "\x00\x42\x42\x42\x42\xc7\x05\x00\x00\x30\x00\x43\x43\x43\x43\x90"
    "\xc7\x05\x00\x00\x30\x00\x44\x44\x44\x44\xc7\x05\x00\x00\x40\x00"
    "\x45\x45\x45\x45\x90\xc7\x05\x00\x00\x40\x00\x46\x46\x46\x46\xc7"
    "\x05\x00\xf8\x3f\x00\x47\x47\x47\x47\xc7\x05\x00\x18\x40\x00\x48"
    "\x48\x48\x48\xf4";
    // total size: 84 bytes

/*
   bits 32

   ; assumes code section at 0x100000
   ; assumes data section at 0x200000, initially rw
   ; assumes data section at 0x300000, initially rw
   ; assumes data section at 0x400000, initially rw

   ; with installed hooks unmaps or maps on each nop

   mov dword [0x200000], 0x41414141 
   nop                              ; mark it RO 
   mov dword [0x200000], 0x42424242

   mov dword [0x300000], 0x43434343
   nop                              ; mark it RO 
   mov dword [0x300000], 0x44444444

   mov dword [0x400000], 0x45454545
   nop                              ; mark it RO 
   mov dword [0x400000], 0x46464646
   mov dword [0x3ff800], 0x47474747 ; make sure surrounding areas remained RW
   mov dword [0x401800], 0x48484848 ; make sure surrounding areas remained RW

   hlt    ; tell hook function we are done
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
    uint32_t testval;
    if (uc_mem_read(uc, addr, &opcode, 1) != UC_ERR_OK) {
        printf("not ok %d - uc_mem_read fail during hook_code callback, addr: 0x%" PRIx64 "\n", log_num++, addr);
    }
    printf("ok %d - uc_mem_read for opcode at address 0x%" PRIx64 "\n", log_num++, addr);
    switch (opcode) {
        case 0x90:  //nop
            printf("# Handling NOP\n");
            if (uc_mem_read(uc, 0x200000 + test_num * 0x100000, &testval, sizeof(testval)) != UC_ERR_OK) {
                printf("not ok %d - uc_mem_read fail for address: 0x%x\n", log_num++, 0x200000 + test_num * 0x100000);
            } else {
                printf("ok %d - good uc_mem_read for address: 0x%x\n", log_num++, 0x200000 + test_num * 0x100000);
                printf("# uc_mem_read for test %d\n", test_num);

                if (testval == tests[test_num]) {
                    printf("ok %d - passed test %d\n", log_num++, test_num);
                } else {
                    printf("not ok %d - failed test %d\n", log_num++, test_num);
                    printf("# Expected: 0x%x\n",tests[test_num]);
                    printf("# Received: 0x%x\n", testval);
                }
            }
            if (uc_mem_protect(uc, 0x200000 + test_num * 0x100000, 0x1000, UC_PROT_READ) != UC_ERR_OK) {
                printf("not ok %d - uc_mem_protect fail during hook_code callback, addr: 0x%x\n", log_num++, 0x200000 + test_num * 0x100000);
            } else {
                printf("ok %d - uc_mem_protect success\n", log_num++);
            }
            test_num++;
            break;
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
            printf("# Handling OTHER\n");
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
    uint32_t testval;
    switch(type) {
        default:
            printf("not ok %d - memory invalid type: %d at 0x%" PRIx64 "\n", log_num++, type, addr);
            return false;
        case UC_MEM_WRITE_PROT:
            printf("# write to non-writeable memory at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);

            if (uc_mem_read(uc, addr, &testval, sizeof(testval)) != UC_ERR_OK) {
                printf("not ok %d - uc_mem_read fail for address: 0x%" PRIx64 "\n", log_num++, addr);
            } else {
                printf("ok %d - uc_mem_read success after mem_protect at test %d\n", log_num++, test_num - 1);
            }

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
    uint32_t addr, testval;
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

    uc_mem_map(uc, CODE_SECTION, CODE_SIZE, UC_PROT_READ | UC_PROT_EXEC);
    uc_mem_map(uc, 0x200000, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
    uc_mem_map(uc, 0x300000, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
    uc_mem_map(uc, 0x3ff000, 0x3000, UC_PROT_READ | UC_PROT_WRITE);

    // fill in sections that shouldn't get touched
    if (uc_mem_write(uc, 0x3ff000, buf1, sizeof(buf1))) {
        printf("not ok %d - Failed to write random buffer 1 to memory, quit!\n", log_num++);
        return 2;
    } else {
        printf("ok %d - Random buffer 1 written to memory\n", log_num++);
    }

    if (uc_mem_write(uc, 0x401000, buf2, sizeof(buf2))) {
        printf("not ok %d - Failed to write random buffer 2 to memory, quit!\n", log_num++);
        return 3;
    } else {
        printf("ok %d - Random buffer 2 written to memory\n", log_num++);
    }

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, CODE_SECTION, PROGRAM, sizeof(PROGRAM))) {
        printf("not ok %d - Failed to write emulation code to memory, quit!\n", log_num++);
        return 4;
    } else {
        printf("ok %d - Program written to memory\n", log_num++);
    }

    if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok %d - Failed to install UC_HOOK_CODE ucr\n", log_num++);
        return 5;
    } else {
        printf("ok %d - UC_HOOK_CODE installed\n", log_num++);
    }

    // intercept memory write events
    if (uc_hook_add(uc, &trace1, UC_HOOK_MEM_WRITE, hook_mem_write, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok %d - Failed to install UC_HOOK_MEM_WRITE ucr\n", log_num++);
        return 6;
    } else {
        printf("ok %d - UC_HOOK_MEM_WRITE installed\n", log_num++);
    }

    // intercept invalid memory events
    if (uc_hook_add(uc, &trace1, UC_HOOK_MEM_WRITE_PROT, hook_mem_invalid, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok %d - Failed to install memory invalid handler\n", log_num++);
        return 7;
    } else {
        printf("ok %d - memory invalid handler installed\n", log_num++);
    }

    // emulate machine code until told to stop by hook_code
    printf("# BEGIN execution\n");
    err = uc_emu_start(uc, CODE_SECTION, CODE_SECTION + CODE_SIZE, 0, 0);
    if (err != UC_ERR_OK) {
        printf("not ok %d - Failure on uc_emu_start() with error %u:%s\n", log_num++, err, uc_strerror(err));
        return 8;
    } else {
        printf("ok %d - uc_emu_start complete\n", log_num++);
    }
    printf("# END execution\n");

    //read from the remapped memory
    testval = 0x42424242;
    for (addr = 0x200000; addr <= 0x400000; addr += 0x100000) {
        uint32_t val;
        if (uc_mem_read(uc, addr, &val, sizeof(val)) != UC_ERR_OK) {
            printf("not ok %d - Failed uc_mem_read for address 0x%x\n", log_num++, addr);
        } else {
            printf("ok %d - Good uc_mem_read from 0x%x\n", log_num++, addr);
        }
        if (val != testval) {
            printf("not ok %d - Read 0x%x, expected 0x%x\n", log_num++, val, testval);
        } else {
            printf("ok %d - Correct value retrieved\n", log_num++);
        }
        testval += 0x02020202;
    }

    //account for the two mods made by the machine code
    buf1[512] = 0x47474747;
    buf2[512] = 0x48484848;

    //make sure that random blocks didn't get nuked
    // fill in sections that shouldn't get touched
    if (uc_mem_read(uc, 0x3ff000, readbuf, sizeof(readbuf))) {
        printf("not ok %d - Failed to read random buffer 1 from memory\n", log_num++);
    } else {
        printf("ok %d - Random buffer 1 read from memory\n", log_num++);
        if (memcmp(buf1, readbuf, 4096)) {
            printf("not ok %d - Random buffer 1 contents are incorrect\n", log_num++);
        } else {
            printf("ok %d - Random buffer 1 contents are correct\n", log_num++);
        }
    }

    if (uc_mem_read(uc, 0x401000, readbuf, sizeof(readbuf))) {
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
