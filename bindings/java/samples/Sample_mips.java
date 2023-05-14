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
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate Mips code (big endian) */

package samples;

import unicorn.*;

public class Sample_mips implements UnicornConst, MipsConst {

    // code to be emulated
    public static final byte[] MIPS_CODE_EB = { 52, 33, 52, 86 }; // ori $at, $at, 0x3456
    public static final byte[] MIPS_CODE_EL = { 86, 52, 33, 52 }; // ori $at, $at, 0x3456

    // memory address where emulation starts
    public static final int ADDRESS = 0x10000;

    // callback for tracing basic blocks
    private static class MyBlockHook implements BlockHook {
        public void hook(Unicorn u, long address, int size, Object user_data) {
            System.out.format(
                ">>> Tracing basic block at 0x%x, block size = 0x%x\n", address,
                size);
        }
    }

    // callback for tracing instruction
    private static class MyCodeHook implements CodeHook {
        public void hook(Unicorn u, long address, int size, Object user_data) {
            System.out.format(
                ">>> Tracing instruction at 0x%x, instruction size = 0x%x\n",
                address, size);
        }
    }

    public static void test_mips_eb() {

        long r1 = 0x6789L;     // R1 register

        System.out.println("Emulate MIPS code (big-endian)");

        // Initialize emulator in MIPS mode
        Unicorn u =
            new Unicorn(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, MIPS_CODE_EB);

        // initialize machine registers
        u.reg_write(UC_MIPS_REG_1, r1);

        // tracing all basic blocks with customized callback
        u.hook_add(new MyBlockHook(), 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        u.emu_start(ADDRESS, ADDRESS + MIPS_CODE_EB.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        r1 = u.reg_read(UC_MIPS_REG_1);
        System.out.format(">>> R1 = 0x%x\n", r1);
    }

    public static void test_mips_el() {
        long r1 = 0x6789L;     // R1 register

        System.out.println("Emulate MIPS code (little-endian)");

        // Initialize emulator in MIPS mode
        Unicorn u = new Unicorn(UC_ARCH_MIPS,
            UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, MIPS_CODE_EL);

        // initialize machine registers
        u.reg_write(UC_MIPS_REG_1, r1);

        // tracing all basic blocks with customized callback
        u.hook_add(new MyBlockHook(), 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        u.emu_start(ADDRESS, ADDRESS + MIPS_CODE_EL.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        r1 = u.reg_read(UC_MIPS_REG_1);
        System.out.format(">>> R1 = 0x%x\n", r1);
    }

    public static void main(String args[]) {
        test_mips_eb();
        System.out.println("===========================");
        test_mips_el();
    }
}
