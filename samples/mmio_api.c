/*
   Sample use of uc_mmio_map

   Copyright(c) 2017 Kitlith

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

static const int registers[] = { UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                 UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                 UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                                 UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC };

static void print_ctx(uc_engine *emu) {

    int64_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = r10 = r11 = r12 = sp = lr = pc = 0;
    int64_t *reg_array[] = {&r0, &r1, &r2, &r3, &r4, &r5, &r6, &r7, &r8, &r9, &r10, &r11, &r12, &sp, &lr, &pc};
    // No error checking wrapper because this can be called from inside...
    // Don't want to infinitely loop and stackoverflow.
    // There is a way to read a bunch of registers at once! But is this everything...
    uc_reg_read_batch(emu, (int*)registers, (void**)reg_array, 16);
    printf( "R0 > 0x%08" PRIx64 " | R1 > 0x%08" PRIx64 " | R2 > 0x%08" PRIx64 " | R3 > 0x%08" PRIx64 "\n"
            "R4 > 0x%08" PRIx64 " | R5 > 0x%08" PRIx64 " | R6 > 0x%08" PRIx64 " | R7 > 0x%08" PRIx64 "\n"
            "R8 > 0x%08" PRIx64 " | R9 > 0x%08" PRIx64 " | R10> 0x%08" PRIx64 " | R11> 0x%08" PRIx64 "\n"
            "R12> 0x%08" PRIx64 " | SP > 0x%08" PRIx64 " | LR > 0x%08" PRIx64 " | PC > 0x%08" PRIx64 "\n",
            r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc);
}

static uint64_t read_cb(struct uc_struct* uc, void *opaque, uint64_t addr, unsigned size) {
    static uint64_t count = 0;
    switch (addr) {
        case 0x0:
            printf(">>> IO counter value: %08" PRIu64 "\n", count);
            return count++;
        case 0x4:
            printf(">>> Requested magic value!\n");
            return 0xDEADBEEF;
        default:
            return 0;
    }
    return 0;
}

static void write_cb(struct uc_struct* uc, void *opaque, uint64_t addr, uint64_t data, unsigned size) {
    printf(">>> Recieved 0x%08" PRIx64 " via 0x%08" PRIx64 "\n", data, addr);
    switch(addr) {
        case 0x8:
            if (data) {
                printf(">>> Halting execution!\n");
                uc_emu_stop(uc);
            }

        default:
            break;
    }
}

const uint8_t prog[] = {
    0x01, 0xDA, 0xA0, 0xE3, 0x03, 0x00, 0x00, 0xEB, 0x01, 0x3A, 0xA0, 0xE3, 0x01, 0x20, 0xA0, 0xE3,
    0x08, 0x20, 0x83, 0xE5, 0x1E, 0xFF, 0x2F, 0xE1, 0x01, 0x3A, 0xA0, 0xE3, 0x2C, 0x20, 0x9F, 0xE5,
    0x04, 0x10, 0x93, 0xE5, 0x02, 0x00, 0x51, 0xE1, 0x01, 0x00, 0x00, 0x0A, 0x01, 0x20, 0xA0, 0xE3,
    0x08, 0x20, 0x83, 0xE5, 0x00, 0x20, 0x93, 0xE5, 0x04, 0x00, 0x52, 0xE3, 0xFA, 0xFF, 0xFF, 0x8A,
    0x00, 0x20, 0x93, 0xE5, 0x04, 0x00, 0x52, 0xE3, 0xF9, 0xFF, 0xFF, 0x9A, 0xF6, 0xFF, 0xFF, 0xEA,
    0xEF, 0xBE, 0xAD, 0xDE
};

// prog checks for the magic value, loops until the counter is at 5, and then tells the emulator to halt.

int main() {
    #ifdef DYNLOAD
        if (!uc_dyn_load(NULL, 0)) {
            printf("Error dynamically loading shared library.\n");
            printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
            printf("any other dependent dll/so files.\n");
            printf("The easiest way is to place them in the same directory as this app.\n");
            return 1;
        }
    #endif

    uc_engine *uc;
    uc_err err;

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        printf("not ok - Failed on uc_open() with error: %s\n", uc_strerror(err));
        return 1;
    }

    // Map a page for execution and stack.
    uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL);
    if (uc_mem_write(uc, 0x0, prog, sizeof(prog))) {
        printf("not ok - Failed to write emulation code to memory, quit!\n");
        return 1;
    }
    // Map a page for IO
    uc_mmio_map(uc, 0x1000, 0x1000, read_cb, write_cb, NULL);

    printf("BEGINNING EXECUTION\n");
    err = uc_emu_start(uc, 0x0, 0x1000, 0, 0);
    printf("Execution stopped with: %s\n", uc_strerror(err));
    print_ctx(uc);

    // Unmap the IO page.
    uc_mem_unmap(uc, 0x1000, 0x1000);
    uc_close(uc);

    #ifdef DYNLOAD
        uc_dyn_free();
    #endif

    return 0;
}
