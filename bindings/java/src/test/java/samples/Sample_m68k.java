/*

Java bindings for the Unicorn Emulator Engine

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

/* Unicorn Emulator Engine */
/* By Loi Anh Tuan, 2015 */

/* Sample code to demonstrate how to emulate m68k code */

package samples;

import unicorn.*;

public class Sample_m68k implements UnicornConst, M68kConst {

    // code to be emulated
    public static final byte[] M68K_CODE = { 118, -19 }; // movq #-19, %d3

    // memory address where emulation starts
    public static final int ADDRESS = 0x10000;

    // callback for tracing basic blocks
    private static final BlockHook hook_block =
        (uc, address, size, user_data) -> {
            System.out.format(
                ">>> Tracing basic block at 0x%x, block size = 0x%x\n",
                address, size);
        };

    // callback for tracing instructions
    private static final CodeHook hook_code =
        (uc, address, size, user_data) -> {
            System.out.format(
                ">>> Tracing instruction at 0x%x, instruction size = 0x%x\n",
                address, size);
        };

    public static void test_m68k() {
        long d0 = 0x0000L;     // d0 data register
        long d1 = 0x0000L;     // d1 data register
        long d2 = 0x0000L;     // d2 data register
        long d3 = 0x0000L;     // d3 data register
        long d4 = 0x0000L;     // d4 data register
        long d5 = 0x0000L;     // d5 data register
        long d6 = 0x0000L;     // d6 data register
        long d7 = 0x0000L;     // d7 data register

        long a0 = 0x0000L;     // a0 address register
        long a1 = 0x0000L;     // a1 address register
        long a2 = 0x0000L;     // a2 address register
        long a3 = 0x0000L;     // a3 address register
        long a4 = 0x0000L;     // a4 address register
        long a5 = 0x0000L;     // a5 address register
        long a6 = 0x0000L;     // a6 address register
        long a7 = 0x0000L;     // a6 address register

        long pc = 0x0000L;     // program counter
        long sr = 0x0000L;     // status register

        System.out.print("Emulate M68K code\n");

        // Initialize emulator in M68K mode
        Unicorn u = new Unicorn(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, M68K_CODE);

        // initialize machine registers
        u.reg_write(UC_M68K_REG_D0, d0);
        u.reg_write(UC_M68K_REG_D1, d1);
        u.reg_write(UC_M68K_REG_D2, d2);
        u.reg_write(UC_M68K_REG_D3, d3);
        u.reg_write(UC_M68K_REG_D4, d4);
        u.reg_write(UC_M68K_REG_D5, d5);
        u.reg_write(UC_M68K_REG_D6, d6);
        u.reg_write(UC_M68K_REG_D7, d7);

        u.reg_write(UC_M68K_REG_A0, a0);
        u.reg_write(UC_M68K_REG_A1, a1);
        u.reg_write(UC_M68K_REG_A2, a2);
        u.reg_write(UC_M68K_REG_A3, a3);
        u.reg_write(UC_M68K_REG_A4, a4);
        u.reg_write(UC_M68K_REG_A5, a5);
        u.reg_write(UC_M68K_REG_A6, a6);
        u.reg_write(UC_M68K_REG_A7, a7);

        u.reg_write(UC_M68K_REG_PC, pc);
        u.reg_write(UC_M68K_REG_SR, sr);

        // tracing all basic blocks with customized callback
        u.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        u.hook_add(hook_code, 1, 0, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        u.emu_start(ADDRESS, ADDRESS + M68K_CODE.length, 0, 0);

        // now print out some registers
        System.out.print(">>> Emulation done. Below is the CPU context\n");

        d0 = u.reg_read(UC_M68K_REG_D0);
        d1 = u.reg_read(UC_M68K_REG_D1);
        d2 = u.reg_read(UC_M68K_REG_D2);
        d3 = u.reg_read(UC_M68K_REG_D3);
        d4 = u.reg_read(UC_M68K_REG_D4);
        d5 = u.reg_read(UC_M68K_REG_D5);
        d6 = u.reg_read(UC_M68K_REG_D6);
        d7 = u.reg_read(UC_M68K_REG_D7);

        a0 = u.reg_read(UC_M68K_REG_A0);
        a1 = u.reg_read(UC_M68K_REG_A1);
        a2 = u.reg_read(UC_M68K_REG_A2);
        a3 = u.reg_read(UC_M68K_REG_A3);
        a4 = u.reg_read(UC_M68K_REG_A4);
        a5 = u.reg_read(UC_M68K_REG_A5);
        a6 = u.reg_read(UC_M68K_REG_A6);
        a7 = u.reg_read(UC_M68K_REG_A7);

        pc = u.reg_read(UC_M68K_REG_PC);
        sr = u.reg_read(UC_M68K_REG_SR);

        System.out.format(">>> A0 = 0x%x\t\t>>> D0 = 0x%x\n", a0, d0);
        System.out.format(">>> A1 = 0x%x\t\t>>> D1 = 0x%x\n", a1, d1);
        System.out.format(">>> A2 = 0x%x\t\t>>> D2 = 0x%x\n", a2, d2);
        System.out.format(">>> A3 = 0x%x\t\t>>> D3 = 0x%x\n", a3, d3);
        System.out.format(">>> A4 = 0x%x\t\t>>> D4 = 0x%x\n", a4, d4);
        System.out.format(">>> A5 = 0x%x\t\t>>> D5 = 0x%x\n", a5, d5);
        System.out.format(">>> A6 = 0x%x\t\t>>> D6 = 0x%x\n", a6, d6);
        System.out.format(">>> A7 = 0x%x\t\t>>> D7 = 0x%x\n", a7, d7);
        System.out.format(">>> PC = 0x%x\n", pc);
        System.out.format(">>> SR = 0x%x\n", sr);
    }

    public static void main(String args[]) {
        test_m68k();
    }
}
