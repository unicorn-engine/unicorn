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

/* Sample code to demonstrate how to emulate ARM64 code */

package samples;

import java.util.Arrays;

import unicorn.*;

public class Sample_arm64 implements UnicornConst, Arm64Const {

    /** code to be emulated {@code str w11, [x13], #0; ldrb w15, [x13], #0} */
    private static final byte[] ARM64_CODE =
        Utils.hexToBytes("ab0500b8af054038");

    /** code to be emulated {@code str w11, [x13]; ldrb w15, [x13]} */
    //private static final byte[]   ARM64_CODE_EB = Utils.hexToBytes("b80005ab384005af"); // str w11, [x13];

    private static final byte[] ARM64_CODE_EB = ARM64_CODE;

    /** code to be emulated {@code mrs x2, tpidrro_el0} */
    private static final byte[] ARM64_MRS_CODE = Utils.hexToBytes("62d03bd5");

    /** code to be emulated {@code paciza x1} */
    private static final byte[] ARM64_PAC_CODE = Utils.hexToBytes("e123c1da");

    // memory address where emulation starts
    public static final int ADDRESS = 0x10000;

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

    public static void test_arm64_mem_fetch() {
        // msr x0, CurrentEL
        byte[] shellcode0 = { 64, 66, 56, (byte) 213 };
        // .text:00000000004002C0                 LDR             X1, [SP,#arg_0]
        byte[] shellcode = { (byte) 0xE1, 0x03, 0x40, (byte) 0xF9 };
        long shellcode_address = 0x4002C0L;
        long data_address = 0x10000000000000L;

        System.out.format(
            ">>> Emulate ARM64 fetching stack data from high address %x\n",
            data_address);

        // Initialize emulator in ARM mode
        Unicorn uc = new Unicorn(UC_ARCH_ARM64, UC_MODE_ARM);

        uc.mem_map(data_address, 0x30000, UC_PROT_ALL);
        uc.mem_map(0x400000, 0x1000, UC_PROT_ALL);

        uc.reg_write(UC_ARM64_REG_SP, data_address);
        byte[] data = new byte[8];
        Arrays.fill(data, (byte) 0xc8);
        uc.mem_write(data_address, data);
        uc.mem_write(shellcode_address, shellcode0);
        uc.mem_write(shellcode_address + 4, shellcode);

        uc.emu_start(shellcode_address, shellcode_address + 4, 0, 0);

        long x0 = uc.reg_read(UC_ARM64_REG_X0);
        System.out.format(">>> x0(Exception Level)=%x\n", x0 >> 2);

        uc.emu_start(shellcode_address + 4, shellcode_address + 8, 0, 0);

        long x1 = uc.reg_read(UC_ARM64_REG_X1);

        System.out.format(">>> X1 = 0x%x\n", x1);
    }

    public static void test_arm64() {
        long x11 = 0x12345678;    // X11 register
        long x13 = 0x10000 + 0x8; // X13 register
        long x15 = 0x33;          // X15 register

        System.out.println("Emulate ARM64 code");

        // Initialize emulator in ARM mode
        Unicorn uc = new Unicorn(UC_ARCH_ARM64, UC_MODE_ARM);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, ARM64_CODE);

        // initialize machine registers
        uc.reg_write(UC_ARM64_REG_X11, x11);
        uc.reg_write(UC_ARM64_REG_X13, x13);
        uc.reg_write(UC_ARM64_REG_X15, x15);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + ARM64_CODE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.println(">>> As little endian, X15 should be 0x78:");
        System.out.format(">>> X15 = 0x%x\n", uc.reg_read(UC_ARM64_REG_X15));
    }

    public static void test_arm64eb() {
        long x11 = 0x12345678;    // X11 register
        long x13 = 0x10000 + 0x8; // X13 register
        long x15 = 0x33;          // X15 register

        System.out.println("Emulate ARM64 Big-Endian code");

        // Initialize emulator in ARM mode
        Unicorn uc =
            new Unicorn(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, ARM64_CODE_EB);

        // initialize machine registers
        uc.reg_write(UC_ARM64_REG_X11, x11);
        uc.reg_write(UC_ARM64_REG_X13, x13);
        uc.reg_write(UC_ARM64_REG_X15, x15);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + ARM64_CODE_EB.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.println(">>> As big endian, X15 should be 0x78:");
        System.out.format(">>> X15 = 0x%x\n", uc.reg_read(UC_ARM64_REG_X15));
    }

    public static void test_arm64_sctlr() {
        long val;
        System.out.println("Read the SCTLR register.");

        Unicorn uc =
            new Unicorn(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM);

        // SCTLR_EL1. See arm reference.
        Arm64_CP reg = new Arm64_CP(1, 0, 3, 0, 0);

        val = (long) uc.reg_read(UC_ARM64_REG_CP_REG, reg);
        System.out.format(">>> SCTLR_EL1 = 0x%x\n", val);

        reg.op1 = 0b100;
        val = (long) uc.reg_read(UC_ARM64_REG_CP_REG, reg);
        System.out.format(">>> SCTLR_EL2 = 0x%x\n", val);
    }

    private static final Arm64SysHook hook_mrs =
        (uc, reg, cp_reg, user_data) -> {
            System.out
                    .println(">>> Hook MSR instruction. Write 0x114514 to X2.");

            uc.reg_write(reg, 0x114514L);

            // Skip
            return 1;
        };

    public static void test_arm64_hook_mrs() {
        System.out.println("Hook MRS instruction.");

        Unicorn uc =
            new Unicorn(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN | UC_MODE_ARM);
        uc.mem_map(0x1000, 0x1000, UC_PROT_ALL);
        uc.mem_write(0x1000, ARM64_MRS_CODE);
        uc.hook_add(hook_mrs, UC_ARM64_INS_MRS, 1, 0, null);
        uc.emu_start(0x1000, 0x1000 + ARM64_MRS_CODE.length, 0, 0);
        System.out.format(">>> X2 = 0x%x\n", uc.reg_read(UC_ARM64_REG_X2));
    }

    /* Test PAC support in the emulator. Code adapted from
    https://github.com/unicorn-engine/unicorn/issues/1789#issuecomment-1536320351 */
    public static void test_arm64_pac() {
        long x1 = 0x0000aaaabbbbccccL;

        System.out.println("Try ARM64 PAC");

        // Initialize emulator in ARM mode
        Unicorn uc = new Unicorn(UC_ARCH_ARM64, UC_MODE_ARM);
        uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX);
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
        uc.mem_write(ADDRESS, ARM64_PAC_CODE);
        uc.reg_write(UC_ARM64_REG_X1, x1);

        /** Initialize PAC support **/
        Arm64_CP reg;

        // SCR_EL3
        reg = new Arm64_CP(1, 1, 3, 6, 0);
        reg.val = (Long) uc.reg_read(UC_ARM64_REG_CP_REG, reg);
        // NS && RW && API
        reg.val |= (1 | (1L << 10) | (1L << 17));
        uc.reg_write(UC_ARM64_REG_CP_REG, reg);

        // SCTLR_EL1
        reg = new Arm64_CP(1, 0, 3, 0, 0);
        reg.val = (Long) uc.reg_read(UC_ARM64_REG_CP_REG, reg);
        // EnIA && EnIB
        reg.val |= (1L << 31) | (1L << 30);
        uc.reg_write(UC_ARM64_REG_CP_REG, reg);

        // HCR_EL2
        reg = new Arm64_CP(1, 1, 3, 4, 0);
        reg.val = (Long) uc.reg_read(UC_ARM64_REG_CP_REG, reg);
        // HCR.API
        reg.val |= (1L << 41);
        uc.reg_write(UC_ARM64_REG_CP_REG, reg);

        /** Check that PAC worked **/
        uc.emu_start(ADDRESS, ADDRESS + ARM64_PAC_CODE.length, 0, 0);
        long new_x1 = uc.reg_read(UC_ARM64_REG_X1);

        System.out.format("X1 = 0x%x\n", new_x1);
        if (new_x1 == x1) {
            System.out.println("FAIL: No PAC tag added!");
        } else {
            // Expect 0x1401aaaabbbbccccULL with the default key
            System.out.println("SUCCESS: PAC tag found.");
        }
    }

    public static void main(String args[]) {
        test_arm64_mem_fetch();

        System.out.println("-------------------------");
        test_arm64();

        System.out.println("-------------------------");
        test_arm64eb();

        System.out.println("-------------------------");
        test_arm64_sctlr();

        System.out.println("-------------------------");
        test_arm64_hook_mrs();

        System.out.println("-------------------------");
        test_arm64_pac();
    }
}
