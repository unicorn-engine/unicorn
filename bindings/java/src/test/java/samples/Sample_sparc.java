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

/* Sample code to demonstrate how to emulate Sparc code */

package samples;

import unicorn.*;

public class Sample_sparc implements UnicornConst, SparcConst {

    /** code to be emulated:
     * {@code add %g1, %g2, %g3}
     */
    private static final byte[] SPARC_CODE = Utils.hexToBytes("86004002");
    //public static final byte[] SPARC_CODE = Utils.hexToBytes("bb700000"); //illegal code

    // memory address where emulation starts
    private static final int ADDRESS = 0x10000;

    private static final BlockHook hook_block =
        (uc, address, size, user_data) -> {
            System.out.format(
                ">>> Tracing basic block at 0x%x, block size = 0x%x\n",
                address, size);
        };

    private static final CodeHook hook_code =
        (uc, address, size, user_data) -> {
            System.out.format(
                ">>> Tracing instruction at 0x%x, instruction size = 0x%x\n",
                address, size);
        };

    public static void test_sparc() {
        long g1 = 0x1230L;     // G1 register
        long g2 = 0x6789L;     // G2 register
        long g3 = 0x5555L;     // G3 register

        System.out.print("Emulate SPARC code\n");

        // Initialize emulator in Sparc mode
        Unicorn u = new Unicorn(UC_ARCH_SPARC, UC_MODE_32 | UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, SPARC_CODE);

        // initialize machine registers
        u.reg_write(UC_SPARC_REG_G1, g1);
        u.reg_write(UC_SPARC_REG_G2, g2);
        u.reg_write(UC_SPARC_REG_G3, g3);

        // tracing all basic blocks with customized callback
        u.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        u.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        u.emu_start(ADDRESS, ADDRESS + SPARC_CODE.length, 0, 0);

        // now print out some registers
        System.out.print(">>> Emulation done. Below is the CPU context\n");
        System.out.format(">>> G3 = 0x%x\n", u.reg_read(UC_SPARC_REG_G3));
    }

    public static void main(String args[]) {
        test_sparc();
    }
}
