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

public class Sample_riscv implements UnicornConst, RiscvConst {
    /** code to be emulated:
     * <pre>
     * $ cstool riscv64 1305100093850502
     *  0  13 05 10 00  addi   a0, zero, 1
     *  4  93 85 05 02  addi   a1, a1, 0x20
     * </pre>
     */
    private static final byte[] CODE = Utils.hexToBytes("1305100093850502");

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

    private static final CodeHook hook_code3 =
        (uc, address, size, user_data) -> {
            System.out.format(
                ">>> Tracing instruction at 0x%x, instruction size = 0x%x\n",
                address, size);
            if (address == ADDRESS) {
                System.out.println("stop emulation");
                uc.emu_stop();
            }
        };

    /*
       00813823    sd  s0,16(sp)
       00000013    nop
     */
    private static final byte[] CODE64 = Utils.hexToBytes("2338810013000000");

    // 10000: 00008067     ret
    // 10004: 8082         c.ret
    // 10006: 0001         nop
    // 10008: 0001         nop

    private static final byte[] FUNC_CODE =
        Utils.hexToBytes("67800000828001000100");

    public static void test_riscv() {
        long a0 = 0x1234L;
        long a1 = 0x7890L;

        System.out.println("Emulate RISCV code");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // initialize machine registers
        uc.reg_write(UC_RISCV_REG_A0, a0);
        uc.reg_write(UC_RISCV_REG_A1, a1);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + CODE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));
    }

    public static void test_riscv2() {
        long a0 = 0x1234L;
        long a1 = 0x7890L;

        System.out.println("Emulate RISCV code: split emulation");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // initialize machine registers
        uc.reg_write(UC_RISCV_REG_A0, a0);
        uc.reg_write(UC_RISCV_REG_A1, a1);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        // emulate 1 instruction
        uc.emu_start(ADDRESS, ADDRESS + 4, 0, 0);

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));

        // emulate one more instruction
        uc.emu_start(ADDRESS + 4, ADDRESS + 8, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));
    }

    public static void test_riscv3() {
        long a0 = 0x1234L;
        long a1 = 0x7890L;

        System.out.println("Emulate RISCV code: early stop");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // initialize machine registers
        uc.reg_write(UC_RISCV_REG_A0, a0);
        uc.reg_write(UC_RISCV_REG_A1, a1);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code3, 1, 0, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + CODE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));
    }

    public static void test_riscv_step() {
        long a0 = 0x1234L;
        long a1 = 0x7890L;
        long pc = 0x0000L;

        System.out.println("Emulate RISCV code: step");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // initialize machine registers
        uc.reg_write(UC_RISCV_REG_A0, a0);
        uc.reg_write(UC_RISCV_REG_A1, a1);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        // emulate 1 instruction
        uc.emu_start(ADDRESS, ADDRESS + CODE.length, 0, 1);

        pc = uc.reg_read(UC_RISCV_REG_PC);

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));

        if (pc != 0x10004) {
            System.out.format(
                "Error after step: PC is: 0x%x, expected was 0x10004\n", pc);
        }

        // emulate one more instruction
        uc.emu_start(ADDRESS + 4, ADDRESS + 8, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));
    }

    public static void test_riscv_timeout() {
        long a0 = 0x1234L;
        long a1 = 0x7890L;
        long pc = 0x0000L;

        System.out.println("Emulate RISCV code: timeout");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        // TODO(nneonneo): what code was meant to go here? sample_riscv.c
        // has all zeros, but that just crashes without running into the
        // timeout...
        uc.mem_write(ADDRESS, new byte[8]);

        // initialize machine registers
        uc.reg_write(UC_RISCV_REG_A0, a0);
        uc.reg_write(UC_RISCV_REG_A1, a1);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        // emulate 1 instruction with timeout
        uc.emu_start(ADDRESS, ADDRESS + 4, 1000, 1);
        pc = uc.reg_read(UC_RISCV_REG_PC);

        if (pc != 0x10000) {
            System.out.format(
                "Error after step: PC is: 0x%x, expected was 0x10004\n", pc);
        }

        // emulate 1 instruction with timeout
        uc.emu_start(ADDRESS, ADDRESS + 4, 1000, 1);
        pc = uc.reg_read(UC_RISCV_REG_PC);

        if (pc != 0x10000) {
            System.out.format(
                "Error after step: PC is: 0x%x, expected was 0x10004\n", pc);
        }

        // now print out some registers
        System.out.println(">>> Emulation done");
    }

    public static void test_riscv_sd64() {
        long reg;

        System.out.println("Emulate RISCV code: sd64 instruction");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV64);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE64);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        reg = ADDRESS + 0x100;
        uc.reg_write(UC_RISCV_REG_SP, reg);

        reg = 0x11223344;
        uc.reg_write(UC_RISCV_REG_S0, reg);

        // execute instruction
        uc.emu_start(0x10000, -1, 0, 1);

        // now print out some registers
        System.out.println(">>> Emulation done.");
    }

    private static final EventMemHook hook_memalloc =
        (uc, type, address, size, value, user_data) -> {
            long aligned_address = address & ~0xFFFL;
            int aligned_size = ((int) (size / 0x1000) + 1) * 0x1000;

            System.out.format(
                ">>> Allocating block at 0x%x (0x%x), block size = 0x%x (0x%x)\n",
                address, aligned_address, size, aligned_size);

            uc.mem_map(aligned_address, aligned_size, UC_PROT_ALL);

            // this recovers from missing memory, so we return true
            return true;
        };

    public static void test_recover_from_illegal() {
        long a0 = 0x1234L;
        long a1 = 0x7890L;

        System.out.println("Emulate RISCV code: recover_from_illegal");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV64);

        uc.reg_write(UC_RISCV_REG_A0, a0);
        uc.reg_write(UC_RISCV_REG_A1, a1);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // auto-allocate memory on access
        uc.hook_add(hook_memalloc, UC_HOOK_MEM_UNMAPPED, 1, 0, null);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, CODE);

        // emulate 1 instruction, wrong address, illegal code
        try {
            uc.emu_start(0x1000, -1, 0, 1);
            throw new RuntimeException("emu_start should have failed!");
        } catch (UnicornException e) {
            System.out.println("Expected Illegal Instruction error, got: " + e);
        }

        // emulate 1 instruction, correct address, valid code
        uc.emu_start(ADDRESS, -1, 0, 1);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> A0 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A0));
        System.out.format(">>> A1 = 0x%x\n", uc.reg_read(UC_RISCV_REG_A1));
    }

    public static void test_riscv_func_return() {
        long pc = 0, ra = 0;

        System.out.println("Emulate RISCV code: return from func");

        // Initialize emulator in RISCV64 mode
        Unicorn uc = new Unicorn(UC_ARCH_RISCV, UC_MODE_RISCV64);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, FUNC_CODE);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction
        uc.hook_add(hook_code, 1, 0, null);

        // set return address register
        // RET instruction will return to address in RA
        // so after RET, PC == RA
        ra = 0x10006;
        uc.reg_write(UC_RISCV_REG_RA, ra);

        // execute ret instruction
        uc.emu_start(0x10000, -1, 0, 1);

        pc = uc.reg_read(UC_RISCV_REG_PC);
        if (pc != ra) {
            System.out.format(
                "Error after execution: PC is: 0x%x, expected was 0x%x\n",
                pc, ra);
            if (pc == 0x10000) {
                System.out.println("  PC did not change during execution");
            }
        } else {
            System.out.println("Good, PC == RA");
        }

        // set return address register
        // C.RET instruction will return to address in RA
        // so after C.RET, PC == RA
        ra = 0x10006;
        uc.reg_write(UC_RISCV_REG_RA, ra);

        System.out.println("========");
        // execute c.ret instruction
        uc.emu_start(0x10004, -1, 0, 1);

        pc = uc.reg_read(UC_RISCV_REG_PC);
        if (pc != ra) {
            System.out.format(
                "Error after execution: PC is: 0x%x, expected was 0x%x\n",
                pc, ra);
            if (pc == 0x10004) {
                System.out.println("  PC did not change during execution");
            }
        } else {
            System.out.println("Good, PC == RA");
        }

        // now print out some registers
        System.out.println(">>> Emulation done.");
    }

    public static final void main(String[] args) {
        test_recover_from_illegal();

        System.out.println("------------------");
        test_riscv();

        System.out.println("------------------");
        test_riscv2();

        System.out.println("------------------");
        test_riscv3();

        System.out.println("------------------");
        test_riscv_step();

        // System.out.println("------------------");
        // test_riscv_timeout();

        System.out.println("------------------");
        test_riscv_sd64();

        System.out.println("------------------");
        test_riscv_func_return();
    }
}
