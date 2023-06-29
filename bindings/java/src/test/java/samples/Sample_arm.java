/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM code */

package samples;

import java.util.Arrays;

import unicorn.*;

public class Sample_arm implements UnicornConst, ArmConst {

    /** code to be emulated {@code mov r0, #0x37; sub r1, r2, r3} */
    // private static final byte[] ARM_CODE = Utils.hexToBytes("3700a0e3031042e0");
    /** code to be emulated {@code nop} */
    private static final byte[] ARM_CODE = Utils.hexToBytes("00f020e3");

    /** code to be emulated {@code sub sp, #0xc} */
    private static final byte[] THUMB_CODE = Utils.hexToBytes("83b0");

    /** code to be emulated
     * <pre>
     * cmp r2, r3
     * it ne
     * mov r2, #0x68
     * mov r2, #0x4d
     * </pre>
     */
    private static final byte[] ARM_THUMB_COND_CODE =
        Utils.hexToBytes("9a4214bf68224d22");

    /** code to be emulated {@code mov r0, #0x37; sub r1, r2, r3} */
    private static final byte[] ARM_CODE_EB =
        Utils.hexToBytes("e3a00037e0421003");
    /** code to be emulated {@code sub sp, #0xc} */
    private static final byte[] THUMB_CODE_EB = Utils.hexToBytes("b083");

    /** {@code 0xf3ef8014 - mrs r0, control} */
    private static final byte[] THUMB_CODE_MRS = Utils.hexToBytes("eff31480");

    /** memory address where emulation starts */
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

    public static void test_arm() {
        long r0 = 0x1234L; // R0 register
        long r2 = 0x6789L; // R1 register
        long r3 = 0x3333L; // R2 register

        System.out.println("Emulate ARM code");

        // Initialize emulator in ARM mode
        Unicorn u = new Unicorn(UC_ARCH_ARM, UC_MODE_ARM);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, ARM_CODE);

        // initialize machine registers
        u.reg_write(UC_ARM_REG_R0, r0);
        u.reg_write(UC_ARM_REG_R2, r2);
        u.reg_write(UC_ARM_REG_R3, r3);

        // tracing all basic blocks with customized callback
        u.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        u.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        u.emu_start(ADDRESS, ADDRESS + ARM_CODE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> R0 = 0x%x\n", u.reg_read(UC_ARM_REG_R0));
        System.out.format(">>> R1 = 0x%x\n", u.reg_read(UC_ARM_REG_R1));
    }

    public static void test_thumb() {
        long sp = 0x1234L; // R0 register

        System.out.println("Emulate THUMB code");

        // Initialize emulator in ARM mode
        Unicorn u = new Unicorn(UC_ARCH_ARM, UC_MODE_THUMB);

        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, THUMB_CODE);

        // initialize machine registers
        u.reg_write(UC_ARM_REG_SP, sp);

        // tracing all basic blocks with customized callback
        u.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        u.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        u.emu_start(ADDRESS | 1, ADDRESS + THUMB_CODE.length, 0, 0);

        // now print out some registers
        System.out.print(">>> Emulation done. Below is the CPU context\n");
        System.out.format(">>> SP = 0x%x\n", u.reg_read(UC_ARM_REG_SP));
    }

    public static void test_armeb() {
        long r0 = 0x1234L; // R0 register
        long r2 = 0x6789L; // R1 register
        long r3 = 0x3333L; // R2 register

        System.out.println("Emulate ARM Big-Endian code");

        // Initialize emulator in ARM mode
        Unicorn uc = new Unicorn(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, ARM_CODE_EB);

        // initialize machine registers
        uc.reg_write(UC_ARM_REG_R0, r0);
        uc.reg_write(UC_ARM_REG_R2, r2);
        uc.reg_write(UC_ARM_REG_R3, r3);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + ARM_CODE_EB.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> R0 = 0x%x\n", uc.reg_read(UC_ARM_REG_R0));
        System.out.format(">>> R1 = 0x%x\n", uc.reg_read(UC_ARM_REG_R1));
    }

    public static void test_thumbeb() {
        long sp = 0x1234L;

        System.out.println("Emulate THUMB Big-Endian code");

        // Initialize emulator in ARM mode
        Unicorn uc =
            new Unicorn(UC_ARCH_ARM, UC_MODE_THUMB + UC_MODE_BIG_ENDIAN);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, THUMB_CODE_EB);

        // initialize machine registers
        uc.reg_write(UC_ARM_REG_SP, sp);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        // Note we start at ADDRESS | 1 to indicate THUMB mode.
        uc.emu_start(ADDRESS | 1, ADDRESS + THUMB_CODE_EB.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> SP = 0x%x\n", uc.reg_read(UC_ARM_REG_SP));
    }

    public static void test_thumb_mrs() {
        System.out.println("Emulate THUMB MRS instruction");
        // 0xf3ef8014 - mrs r0, control

        // Initialize emulator in ARM mode
        Unicorn uc = new Unicorn(UC_ARCH_ARM, UC_MODE_THUMB);

        // Setup the cpu model.
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, THUMB_CODE_MRS);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing one instruction at ADDRESS with customized callback
        uc.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.

        // Note we start at ADDRESS | 1 to indicate THUMB mode.
        uc.emu_start(ADDRESS | 1, ADDRESS + THUMB_CODE_MRS.length, 0, 1);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        long pc = uc.reg_read(UC_ARM_REG_PC);
        System.out.format(">>> PC = 0x%x\n", pc);
        if (pc != ADDRESS + 4) {
            System.out.format("Error, PC was 0x%x, expected was 0x%x.\n", pc,
                ADDRESS + 4);
        }
    }

    private static void test_thumb_ite_internal(boolean step, long[] r2r3) {
        Unicorn uc = new Unicorn(UC_ARCH_ARM, UC_MODE_THUMB);

        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        uc.mem_write(ADDRESS, ARM_THUMB_COND_CODE);

        uc.reg_write(UC_ARM_REG_SP, 0x1234L);

        uc.reg_write(UC_ARM_REG_R2, 0);
        uc.reg_write(UC_ARM_REG_R3, 1);

        if (!step) {
            uc.emu_start(ADDRESS | 1, ADDRESS + ARM_THUMB_COND_CODE.length, 0,
                0);
        } else {
            long addr = ADDRESS;
            for (int i = 0; i < ARM_THUMB_COND_CODE.length / 2; i++) {
                uc.emu_start(addr | 1, ADDRESS + ARM_THUMB_COND_CODE.length, 0,
                    1);
                addr = uc.reg_read(UC_ARM_REG_PC);
            }
        }

        r2r3[0] = uc.reg_read(UC_ARM_REG_R2);
        r2r3[1] = uc.reg_read(UC_ARM_REG_R3);
    }

    public static void test_thumb_ite() {
        long[] r2r3 = new long[2];
        long[] step_r2r3 = new long[2];

        System.out.println(
            "Emulate a THUMB ITE block as a whole or per instruction.");

        // Run once.
        System.out.println("Running the entire binary.");
        test_thumb_ite_internal(false, r2r3);
        System.out.format(">>> R2: %d\n", r2r3[0]);
        System.out.format(">>> R3: %d\n\n", r2r3[1]);

        // Step each instruction.
        System.out.println("Running the binary one instruction at a time.");
        test_thumb_ite_internal(true, step_r2r3);
        System.out.format(">>> R2: %d\n", step_r2r3[0]);
        System.out.format(">>> R3: %d\n\n", step_r2r3[1]);

        if (!Arrays.equals(r2r3, step_r2r3)) {
            System.out.println("Failed with ARM ITE blocks stepping!");
        }
    }

    public static void test_read_sctlr() {
        System.out.println("Read the SCTLR register.");

        Unicorn uc = new Unicorn(UC_ARCH_ARM, UC_MODE_ARM);

        // SCTLR. See arm reference.
        Arm_CP reg = new Arm_CP(15, 0, 0, 1, 0, 0, 0);
        long val = (Long) uc.reg_read(UC_ARM_REG_CP_REG, reg);

        System.out.format(">>> SCTLR = 0x%x\n", val & 0xffffffffL);
        System.out.format(">>> SCTLR.IE = %d\n", (val >> 31) & 1);
        System.out.format(">>> SCTLR.B = %d\n", (val >> 7) & 1);
    }

    public static void main(String args[]) {
        test_arm();
        System.out.print("==========================\n");
        test_thumb();

        System.out.print("==========================\n");
        test_armeb();

        System.out.print("==========================\n");
        test_thumbeb();

        System.out.print("==========================\n");
        test_thumb_mrs();

        System.out.print("==========================\n");
        test_thumb_ite();

        System.out.print("==========================\n");
        test_read_sctlr();
    }

}
