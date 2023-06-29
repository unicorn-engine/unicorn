/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2023 Robert Xiao

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

/* Sample code to demonstrate how to emulate TriCore code
 * Ported from the C version originally by Eric Poole <eric.poole@aptiv.com>, 2022
 */

package samples;

import unicorn.*;

public class Sample_tricore implements UnicornConst, TriCoreConst {
    /** code to be emulated:
     * {@code mov d1, #0x1; mov.u d0, #0x8000}
     */
    private static final byte[] CODE = Utils.hexToBytes("8211bb000008");

    // memory address where emulation starts
    private static final long ADDRESS = 0x10000;

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

    public static void test_tricore() {
        System.out.println("Emulate TriCore code");

        Unicorn uc = new Unicorn(UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS + CODE.length, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + CODE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> d0 = 0x%x\n", uc.reg_read(UC_TRICORE_REG_D0));
        System.out.format(">>> d1 = 0x%x\n", uc.reg_read(UC_TRICORE_REG_D1));
    }

    public static final void main(String[] args) {
        test_tricore();
    }
}
