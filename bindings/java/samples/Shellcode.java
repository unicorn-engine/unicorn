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
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to trace code with Linux code with syscall */

package samples;

import unicorn.*;

public class Shellcode implements UnicornConst, X86Const {

    public static final byte[] X86_CODE32_SELF = Utils.hexToBytes(
        "eb1c5a89d68b02663dca7d75066605030389" +
            "02fec23d4141414175e9ffe6e8dfffffff31" +
            "d26a0b589952682f2f7368682f62696e89e3" +
            "525389e1ca7d4141414141414141");

    // memory address where emulation starts
    public static final int ADDRESS = 0x1000000;

    public static CodeHook hook_code = (u, address, size, user) -> {
        System.out.format(
            "Tracing instruction at 0x%x, instruction size = 0x%x\n",
            address, size);

        long r_eip = u.reg_read(UC_X86_REG_EIP);
        System.out.format("*** EIP = %x ***: ", r_eip);

        byte[] tmp = u.mem_read(address, size);
        for (int i = 0; i < tmp.length; i++) {
            System.out.format("%x ", 0xff & tmp[i]);
        }
        System.out.println();
    };

    public static InterruptHook hook_intr = (u, intno, user) -> {
        // only handle Linux syscall
        if (intno != 0x80) {
            return;
        }

        long r_eax = u.reg_read(UC_X86_REG_EAX);
        long r_eip = u.reg_read(UC_X86_REG_EIP);

        switch ((int) r_eax) {
        default:
            System.out.format(">>> 0x%x: interrupt 0x%x, EAX = 0x%x\n",
                r_eip, intno, r_eax);
            break;
        case 1: // sys_exit
            System.out.format(
                ">>> 0x%x: interrupt 0x%x, SYS_EXIT. quit!\n\n",
                r_eip, intno);
            u.emu_stop();
            break;
        case 4: { // sys_write
            // ECX = buffer address
            long r_ecx = u.reg_read(UC_X86_REG_ECX);

            // EDX = buffer size
            long r_edx = u.reg_read(UC_X86_REG_EDX);

            // read the buffer in
            int size = (int) Math.min(256, r_edx);

            try {
                byte[] buffer = u.mem_read(r_ecx, size);
                System.out.format(
                    ">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = '%s'\n",
                    r_eip, intno, r_ecx, r_edx, new String(buffer));
            } catch (UnicornException e) {
                System.out.format(
                    ">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u (cannot get content)\n",
                    r_eip, intno, r_ecx, r_edx);
            }
            break;
        }
        }
    };

    public static void test_i386() {
        long r_esp = ADDRESS + 0x200000L;  // ESP register

        System.out.println("Emulate i386 code");

        // Initialize emulator in X86-32bit mode
        Unicorn u = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, X86_CODE32_SELF);

        // initialize machine registers
        u.reg_write(UC_X86_REG_ESP, r_esp);

        // tracing all instructions by having @begin > @end
        u.hook_add(hook_code, 1, 0, null);

        // handle interrupt ourself
        u.hook_add(hook_intr, null);

        System.out.println("\n>>> Start tracing this Linux code");

        // emulate machine code in infinite time
        // u.emu_start(ADDRESS, ADDRESS + X86_CODE32_SELF.length, 0, 12); <--- emulate only 12 instructions
        u.emu_start(ADDRESS, ADDRESS + X86_CODE32_SELF.length, 0, 0);

        System.out.println("\n>>> Emulation done.");
    }

    public static void main(String args[]) {
        if (args.length == 1) {
            if ("-32".equals(args[0])) {
                test_i386();
            }
        } else {
            System.out.println("Syntax: java Shellcode <-32|-64>");
        }

    }

}
