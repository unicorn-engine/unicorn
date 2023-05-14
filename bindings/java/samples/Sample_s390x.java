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

/* Sample code to demonstrate how to emulate S390X code */

package samples;

import unicorn.*;

public class Sample_s390x implements UnicornConst, S390xConst {
    /** code to be emulated:
     * {@code lr %r2, %r3}
     */
    private static final byte[] CODE = Utils.hexToBytes("1823");

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

    public static void test_s390x() {
        long r2 = 2, r3 = 3;

        System.out.println("Emulate S390X code");

        Unicorn uc = new Unicorn(UC_ARCH_S390X, UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // initialize machine registers
        uc.reg_write(UC_S390X_REG_R2, r2);
        uc.reg_write(UC_S390X_REG_R3, r3);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS + CODE.length, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + CODE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> R2 = 0x%x\t\t>>> R3 = 0x%x\n",
            uc.reg_read(UC_S390X_REG_R2), uc.reg_read(UC_S390X_REG_R3));
    }

    public static final void main(String[] args) {
        test_s390x();
    }
}
