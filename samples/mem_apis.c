/*
   Sample use of uc_mem_unmap, uc_mem_protect, and memory permissions

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


#include <unicorn/unicorn.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


static int insts_executed;

// callback for tracing instructions, detect HLT and terminate emulation
static void hook_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data)
{
    uint8_t opcode;
    unsigned char buf[256];

    insts_executed++;

    if (uc_mem_read(uc, addr, buf, size) != UC_ERR_OK) {
        printf("not ok - uc_mem_read fail during hook_code callback, addr: 0x%" PRIx64 "\n", addr);
        if (uc_emu_stop(uc) != UC_ERR_OK) {
            printf("not ok - uc_emu_stop fail during hook_code callback, addr: 0x%" PRIx64 "\n", addr);
            _exit(-1);
        }
    }

    opcode = buf[0];
    switch (opcode) {
        case 0x41:  // inc ecx
            if (uc_mem_protect(uc, 0x101000, 0x1000, UC_PROT_READ) != UC_ERR_OK) {
                printf("not ok - uc_mem_protect fail during hook_code callback, addr: 0x%" PRIx64 "\n", addr);
                _exit(-1);
            }
            break;
        case 0x42:  // inc edx
            if (uc_mem_unmap(uc, 0x101000, 0x1000) != UC_ERR_OK) {
                printf("not ok - uc_mem_unmap fail during hook_code callback, addr: 0x%" PRIx64 "\n", addr);
                _exit(-1);
            }
            break;
        case 0xf4:  // hlt
            if (uc_emu_stop(uc) != UC_ERR_OK) {
                printf("not ok - uc_emu_stop fail during hook_code callback, addr: 0x%" PRIx64 "\n", addr);
                _exit(-1);
            }
            break;
        default:  // all others
            break;
    }
}

// callback for tracing invalid memory access (READ/WRITE/EXEC)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t addr, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            printf("not ok - UC_HOOK_MEM_INVALID type: %d at 0x%" PRIx64 "\n", type, addr);
            return false;
        case UC_MEM_READ_UNMAPPED:
            printf("not ok - Read from invalid memory at 0x%"PRIx64 ", data size = %u\n", addr, size);
            return false;
        case UC_MEM_WRITE_UNMAPPED:
            printf("not ok - Write to invalid memory at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
            return false;
        case UC_MEM_FETCH_PROT:
            printf("not ok - Fetch from non-executable memory at 0x%"PRIx64 "\n", addr);
            return false;
        case UC_MEM_WRITE_PROT:
            printf("not ok - Write to non-writeable memory at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
            return false;
        case UC_MEM_READ_PROT:
            printf("not ok - Read from non-readable memory at 0x%"PRIx64 ", data size = %u\n", addr, size);
            return false;
    }
}

static void do_nx_demo(bool cause_fault)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;
    uint8_t code_buf[0x3000];

    insts_executed = 0;

    printf("===================================\n");
    printf("# Example of marking memory NX (%s)\n", cause_fault ? "faulting" : "non-faulting");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("not ok - Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    uc_mem_map(uc, 0x100000, 0x3000, UC_PROT_READ | UC_PROT_EXEC);

    /*
       bits 32
    page0: @0
        times 4091 inc eax
        jmp page2
    page1: @1000
        times 4095 inc eax  (or INC ECX)
        hlt
    page2: @2000
        jmp page1
     */
    memset(code_buf, 0x40, sizeof(code_buf));  // fill with inc eax
    memcpy(code_buf + 0x1000 - 5, "\xe9\x00\x10\x00\x00", 5); // jump to 0x102000
    memcpy(code_buf + 0x2000, "\xe9\xfb\xef\xff\xff", 5); // jump to 0x101000
    code_buf[0x1fff] = 0xf4;   //hlt

    if (cause_fault) {
        // insert instruction to trigger U_PROT_EXEC change (see hook_code function)
        code_buf[0x1000] = 0x41;   // inc ecx at page1
    }

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0x100000, code_buf, sizeof(code_buf))) {
        printf("not ok - Failed to write emulation code to memory, quit!\n");
        return;
    }

    // intercept code and invalid memory events
    if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK ||
            uc_hook_add(uc, &trace1, UC_HOOK_MEM_INVALID,
                hook_mem_invalid, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok - Failed to install hooks\n");
        return;
    }

    // emulate machine code until told to stop by hook_code
    printf("BEGINNING EXECUTION\n");
    err = uc_emu_start(uc, 0x100000, 0x103000, 0, 0);
    if (err != UC_ERR_OK) {
        printf("not ok - Failure on uc_emu_start() with error %u: %s\n", err, uc_strerror(err));
        printf("FAILED EXECUTION\n");
    } else {
        printf("SUCCESSFUL EXECUTION\n");
    }

    printf("Executed %d instructions\n\n", insts_executed);

    uc_close(uc);
}

static void nx_test()
{
    printf("NX demo - step 1: show that code runs to completion\n");
    do_nx_demo(false);
    printf("NX demo - step 2: show that code fails without UC_PROT_EXEC\n");
    do_nx_demo(true);
}

static const uint8_t WRITE_DEMO[] =
    "\x90\xc7\x05\x00\x20\x10\x00\x78\x56\x34\x12\xc7\x05\xfc\x0f\x10"
    "\x00\x78\x56\x34\x12\xc7\x05\x00\x10\x10\x00\x21\x43\x65\x87";

static void do_perms_demo(bool change_perms)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;
    uint8_t code_buf[0x3000];

    insts_executed = 0;

    printf("===================================\n");
    printf("# Example of manipulating memory permissions\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("not ok - Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    uc_mem_map(uc, 0x100000, 0x3000, UC_PROT_ALL);

    /*
       bits 32
       nop
       mov dword [0x102000], 0x12345678
       mov dword [0x100ffc], 0x12345678
       mov dword [0x101000], 0x87654321    ; crashing case crashes here
       times 1000 nop
       hlt
     */
    memcpy(code_buf, WRITE_DEMO, sizeof(WRITE_DEMO) - 1);
    memset(code_buf + sizeof(WRITE_DEMO) - 1, 0x90, 1000);
    code_buf[sizeof(WRITE_DEMO) - 1 + 1000] = 0xf4;    // hlt

    if (change_perms) {
        // write protect memory area [0x101000, 0x101fff]. see hook_code function
        code_buf[0] = 0x41;  // inc ecx
    }

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0x100000, code_buf, sizeof(code_buf))) {
        printf("not ok - Failed to write emulation code to memory, quit!\n");
        return;
    }

    // intercept code and invalid memory events
    if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK ||
            uc_hook_add(uc, &trace1,
                UC_HOOK_MEM_INVALID,
                hook_mem_invalid, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok - Failed to install hooks\n");
        return;
    }

    // emulate machine code until told to stop by hook_code
    printf("BEGINNING EXECUTION\n");
    err = uc_emu_start(uc, 0x100000, 0x103000, 0, 0);
    if (err != UC_ERR_OK) {
        printf("FAILED EXECUTION\n");
        printf("not ok - Failure on uc_emu_start() with error %u: %s\n", err, uc_strerror(err));
    } else {
        printf("SUCCESSFUL EXECUTION\n");
    }

    printf("Executed %d instructions\n\n", insts_executed);

    uc_close(uc);
}

static void perms_test()
{
    printf("Permissions demo - step 1: show that area is writeable\n");
    do_perms_demo(false);
    printf("Permissions demo - step 2: show that code fails when memory marked unwriteable\n");
    do_perms_demo(true);
}


static void do_unmap_demo(bool do_unmap)
{
    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;
    uint8_t code_buf[0x3000];

    insts_executed = 0;

    printf("===================================\n");
    printf("# Example of unmapping memory\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("not ok - Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    uc_mem_map(uc, 0x100000, 0x3000, UC_PROT_ALL);

    /*
       bits 32
       nop
       mov dword [0x102000], 0x12345678
       mov dword [0x100ffc], 0x12345678
       mov dword [0x101000], 0x87654321  ; crashing case crashes here
       times 1000 nop
       hlt
     */
    memcpy(code_buf, WRITE_DEMO, sizeof(WRITE_DEMO) - 1);
    memset(code_buf + sizeof(WRITE_DEMO) - 1, 0x90, 1000);
    code_buf[sizeof(WRITE_DEMO) - 1 + 1000] = 0xf4;    // hlt

    if (do_unmap) {
        // unmap memory area [0x101000, 0x101fff]. see hook_code function
        code_buf[0] = 0x42;  // inc edx  (see hook_code function)
    }

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, 0x100000, code_buf, 0x1000)) {
        printf("not ok - Failed to write emulation code to memory, quit!\n");
        return;
    }

    // intercept code and invalid memory events
    if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0) != UC_ERR_OK ||
            uc_hook_add(uc, &trace1,
                UC_HOOK_MEM_INVALID,
                hook_mem_invalid, NULL, 1, 0) != UC_ERR_OK) {
        printf("not ok - Failed to install hooks\n");
        return;
    }

    // emulate machine code until told to stop by hook_code
    printf("BEGINNING EXECUTION\n");
    err = uc_emu_start(uc, 0x100000, 0x103000, 0, 0);
    if (err != UC_ERR_OK) {
        printf("FAILED EXECUTION\n");
        printf("not ok - Failure on uc_emu_start() with error %u: %s\n", err, uc_strerror(err));
    } else {
        printf("SUCCESSFUL EXECUTION\n");
    }

    printf("Executed %d instructions\n\n", insts_executed);

    uc_close(uc);
}

static void unmap_test()
{
    printf("Unmap demo - step 1: show that area is writeable\n");
    do_unmap_demo(false);
    printf("Unmap demo - step 2: show that code fails when memory is unmapped\n");
    do_unmap_demo(true);
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
    
    nx_test();
    perms_test();
    unmap_test();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
