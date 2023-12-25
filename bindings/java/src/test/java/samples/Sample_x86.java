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

/* Sample code to demonstrate how to emulate X86 code */

package samples;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import unicorn.*;

public class Sample_x86 implements UnicornConst, X86Const {

    /** code to be emulated
     * {@code INC ecx; DEC edx; PXOR xmm0, xmm1}
     */
    private static final byte[] X86_CODE32 = Utils.hexToBytes("414a660fefc1");
    /** code to be emulated
     * {@code jmp 4; nop; nop; nop; nop; nop; nop}
     */
    private static final byte[] X86_CODE32_JUMP =
        Utils.hexToBytes("eb02909090909090");
    // private static final byte[] X86_CODE32_SELF = Utils.hexToBytes("eb1c5a89d68b02663dca7d7506660503038902fec23d4141414175e9ffe6e8dfffffff31d26a0b589952682f2f7368682f62696e89e3525389e1ca7d41414141");

    /** code to be emulated
     * {@code PUSH ecx; PUSH ecx; PUSH ecx; PUSH ecx}
     */
    // private static final byte[] X86_CODE32 = Utils.hexToBytes("51515151");

    /** code to be emulated
     * {@code INC ecx; DEC edx; self_loop: JMP self_loop}
     */
    private static final byte[] X86_CODE32_LOOP = Utils.hexToBytes("414aebfe");

    /** code to be emulated
     * {@code mov [0xaaaaaaaa], ecx; INC ecx; DEC edx}
     */
    private static final byte[] X86_CODE32_MEM_WRITE =
        Utils.hexToBytes("890DAAAAAAAA414a");

    /** code to be emulated
     * {@code mov ecx, [0xaaaaaaaa]; INC ecx; DEC edx}
     */
    private static final byte[] X86_CODE32_MEM_READ =
        Utils.hexToBytes("8B0DAAAAAAAA414a");

    /** code to be emulated
     * {@code inc eax; mov ebx, [0x100000]; inc edx}
     */
    private static final byte[] X86_CODE32_MEM_READ_IN_TB =
        Utils.hexToBytes("408b1d0000100042");

    /** code to be emulated
     * {@code JMP outside; INC ecx; DEC edx}
     */
    private static final byte[] X86_CODE32_JMP_INVALID =
        Utils.hexToBytes("e9e9eeeeee414a");

    /** code to be emulated
     * {@code INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx}
     */
    private static final byte[] X86_CODE32_INOUT =
        Utils.hexToBytes("41E43F4aE64643");

    /** code to be emulated
     * {@code INC eax}
     */
    private static final byte[] X86_CODE32_INC = Utils.hexToBytes("40");

    //private static final byte[] X86_CODE64 = Utils.hexToBytes("41BC3BB0282A490FC9904D0FADCF4987FD904881D28ACE773548F7D9"); // <== still crash
    /** code to be emulated */
    private static final byte[] X86_CODE64 =
        Utils.hexToBytes("41BC3BB0282A490FC9904D0FADCF4987FD90" +
            "4881D28ACE773548F7D94D29F44981C9F68A" +
            "C6534D87ED480FADD249F7D448F7E14D19C5" +
            "4D89C548F7D641B84F8D6B594D87D0686A1E" +
            "093C59");
    /** code to be emulated
     * {@code add byte ptr [bx + si], al}
     */
    private static final byte[] X86_CODE16 = Utils.hexToBytes("0000");
    /** code to be emulated
     * {@code syscall}
     */
    private static final byte[] X86_CODE64_SYSCALL = Utils.hexToBytes("0f05");
    /** code to be emulated
     * {@code mov [0x20004], ecx; mov ecx, [0x20004]}
     */
    private static final byte[] X86_MMIO_CODE =
        Utils.hexToBytes("890d040002008b0d04000200");
    /** code to be emulated
     * <pre>
     * 0x1000 xor dword ptr [edi+0x3], eax ; edi=0x1000, eax=0xbc4177e6
     * 0x1003 dw 0x3ea98b13
     * </pre>
     */
    private static final byte[] X86_CODE32_SMC =
        Utils.hexToBytes("314703138ba93e");

    /** memory address where emulation starts */
    public static final int ADDRESS = 0x1000000;

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

            long eflags = uc.reg_read(UC_X86_REG_EFLAGS);
            System.out.format(">>> --- EFLAGS is 0x%x\n", eflags);

            // Uncomment below code to stop the emulation using uc_emu_stop()
            // if (address == 0x1000009)
            //    uc.emu_stop();
        };

    private static final CodeHook hook_code64 =
        (uc, address, size, user_data) -> {
            long rip = uc.reg_read(UC_X86_REG_RIP);
            System.out.format(
                ">>> Tracing instruction at 0x%x, instruction size = 0x%x\n",
                address, size);
            System.out.format(">>> RIP is 0x%x\n", rip);
        };

    private static final EventMemHook hook_mem_invalid =
        (uc, type, address, size, value, user) -> {
            switch (type) {
            default:
                // return false to indicate we want to stop emulation
                return false;
            case UC_MEM_WRITE_UNMAPPED:
                System.out.printf(
                    ">>> Missing memory is being WRITE at 0x%x, data size = %d, data value = 0x%x\n",
                    address, size, value);
                // map this memory in with 2MB in size
                uc.mem_map(0xaaaa0000L, 2 * 1024 * 1024, UC_PROT_ALL);
                // return true to indicate we want to continue
                return true;
            }
        };

    private static final MemHook hook_mem64 =
        (uc, type, address, size, value, user_data) -> {
            switch (type) {
            default:
                break;
            case UC_MEM_READ:
                System.out.format(
                    ">>> Memory is being READ at 0x%x, data size = %d\n",
                    address, size);
                break;
            case UC_MEM_WRITE:
                System.out.format(
                    ">>> Memory is being WRITE at 0x%x, data size = %d, data value = 0x%x\n",
                    address, size, value);
                break;
            }
        };

    // callback for IN instruction (X86).
    // this returns the data read from the port
    private static final InHook hook_in = (uc, port, size, user) -> {
        long r_eip = uc.reg_read(UC_X86_REG_EIP);

        System.out.printf(
            "--- reading from port 0x%x, size: %d, address: 0x%x\n", port,
            size, r_eip);

        switch (size) {
        case 1:
            // read 1 byte to AL
            return 0xf1;
        case 2:
            // read 2 byte to AX
            return 0xf2;
        case 4:
            // read 4 byte to EAX
            return 0xf4;
        }
        return 0;
    };

    // callback for OUT instruction (X86).
    private static final OutHook hook_out = (uc, port, size, value, user) -> {
        long eip = uc.reg_read(UC_X86_REG_EIP);
        long tmp = 0;
        System.out.printf(
            "--- writing to port 0x%x, size: %d, value: 0x%x, address: 0x%x\n",
            port, size, value, eip);

        // confirm that value is indeed the value of AL/AX/EAX
        switch (size) {
        default:
            return;   // should never reach this
        case 1:
            tmp = uc.reg_read(UC_X86_REG_AL);
            break;
        case 2:
            tmp = uc.reg_read(UC_X86_REG_AX);
            break;
        case 4:
            tmp = uc.reg_read(UC_X86_REG_EAX);
            break;
        }

        System.out.printf("--- register value = 0x%x\n", tmp);
    };

    // callback for SYSCALL instruction (X86).
    private static final SyscallHook hook_syscall = (uc, user_data) -> {
        long rax = uc.reg_read(UC_X86_REG_RAX);
        if (rax == 0x100) {
            rax = 0x200;
            uc.reg_write(UC_X86_REG_RAX, rax);
        } else {
            System.out.format("ERROR: was not expecting rax=0x%x in syscall\n",
                rax);
        }
    };

    private static final EventMemHook hook_memalloc =
        (uc, type, address, size, value, user_data) -> {
            long aligned_address = address & ~(0xFFFL);
            int aligned_size = ((int) (size / 0x1000) + 1) * 0x1000;

            System.out.format(
                ">>> Allocating block at 0x%x (0x%x), block size = 0x%x (0x%x)\n",
                address, aligned_address, size, aligned_size);

            uc.mem_map(aligned_address, aligned_size, UC_PROT_ALL);

            // write machine code to be emulated to memory
            uc.mem_write(aligned_address, X86_CODE32);

            // this recovers from missing memory, so we return true
            return true;
        };

    public static void test_miss_code() {
        int r_ecx = 0x1234; // ECX register
        int r_edx = 0x7890; // EDX register

        System.out.println("Emulate i386 code - missing code");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // tracing all instruction by having @begin > @end
        uc.hook_add(hook_code, 1, 0, null);

        // auto-allocate memory on access
        uc.hook_add(hook_memalloc, UC_HOOK_MEM_UNMAPPED, 1, 0, null);

        // emulate machine code, without having the code in yet
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
        System.out.format(">>> EDX = 0x%x\n", uc.reg_read(UC_X86_REG_EDX));
    }

    public static void test_i386() {
        int tmp;
        long r_ecx = 0x1234; // ECX register
        long r_edx = 0x7890; // EDX register
        // XMM0 and XMM1 registers, low qword then high qword
        BigInteger r_xmm0 =
            new BigInteger("000102030405060708090a0b0c0d0e0f", 16);
        BigInteger r_xmm1 =
            new BigInteger("00102030405060708090a0b0c0d0e0f0", 16);

        System.out.println("Emulate i386 code");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);
        uc.reg_write(UC_X86_REG_XMM0, r_xmm0);
        uc.reg_write(UC_X86_REG_XMM1, r_xmm1);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction by having @begin > @end
        uc.hook_add(hook_code, 1, 0, null);

        // emulate machine code in infinite time
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        r_ecx = uc.reg_read(UC_X86_REG_ECX);
        r_edx = uc.reg_read(UC_X86_REG_EDX);
        r_xmm0 = (BigInteger) uc.reg_read(UC_X86_REG_XMM0, null);
        System.out.format(">>> ECX = 0x%x\n", r_ecx);
        System.out.format(">>> EDX = 0x%x\n", r_edx);
        String xmm0_string =
            String.format("%32s", r_xmm0.toString(16)).replace(' ', '0');
        System.out.format(">>> XMM0 = 0x%s\n", xmm0_string);

        // read from memory
        tmp = Utils.toInt(uc.mem_read(ADDRESS, 4));
        System.out.format(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS,
            tmp);
    }

    public static void test_i386_map_ptr() {
        int tmp;
        int r_ecx = 0x1234; // ECX register
        int r_edx = 0x7890; // EDX register

        System.out.println("Emulate i386 code - use uc_mem_map_ptr()");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // malloc 2MB memory for this emulation
        ByteBuffer mem = ByteBuffer.allocateDirect(2 * 1024 * 1024);
        uc.mem_map_ptr(ADDRESS, mem, UC_PROT_ALL);
        mem.put(X86_CODE32);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction by having @begin > @end
        uc.hook_add(hook_code, 1, 0, null);

        // emulate machine code in infinite time
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
        System.out.format(">>> EDX = 0x%x\n", uc.reg_read(UC_X86_REG_EDX));

        // read from memory
        tmp = Utils.toInt(uc.mem_read(ADDRESS, 4));
        System.out.format(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS,
            tmp);
    }

    public static void test_i386_jump() {
        System.out.println("Emulate i386 code with jump");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_JUMP);

        // tracing 1 basic block with customized callback
        uc.hook_add(hook_block, ADDRESS, ADDRESS, null);

        // tracing 1 instruction at ADDRESS
        uc.hook_add(hook_code, ADDRESS, ADDRESS, null);

        // emulate machine code in infinite time
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_JUMP.length, 0, 0);

        System.out.println(">>> Emulation done. Below is the CPU context");
    }

    // emulate code that loop forever
    public static void test_i386_loop() {
        int r_ecx = 0x1234; // ECX register
        int r_edx = 0x7890; // EDX register

        System.out.println("Emulate i386 code that loop forever");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_LOOP);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // emulate machine code in 2 seconds, so we can quit even
        // if the code loops
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_LOOP.length,
            2 * UC_SECOND_SCALE, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
        System.out.format(">>> EDX = 0x%x\n", uc.reg_read(UC_X86_REG_EDX));
    }

    // emulate code that read invalid memory
    public static void test_i386_invalid_mem_read() {
        int r_ecx = 0x1234; // ECX register
        int r_edx = 0x7890; // EDX register

        System.out.println("Emulate i386 code that read from invalid memory");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_MEM_READ);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction by having @begin > @end
        uc.hook_add(hook_code, 1, 0, null);

        // emulate machine code in infinite time
        try {
            uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_READ.length, 0, 0);
            throw new RuntimeException("Expected a crash!");
        } catch (UnicornException e) {
            System.out.println("uc.emu_start failed as expected: " + e);
        }

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
        System.out.format(">>> EDX = 0x%x\n", uc.reg_read(UC_X86_REG_EDX));
    }

    // emulate code that write invalid memory
    public static void test_i386_invalid_mem_write() {
        int r_ecx = 0x1234; // ECX register
        int r_edx = 0x7890; // EDX register
        int tmp;

        System.out.println("Emulate i386 code that write to invalid memory");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_MEM_WRITE);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instruction by having @begin > @end
        uc.hook_add(hook_code, 1, 0, null);

        // intercept invalid memory events
        uc.hook_add(hook_mem_invalid,
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            1, 0, null);

        // emulate machine code in infinite time
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_WRITE.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
        System.out.format(">>> EDX = 0x%x\n", uc.reg_read(UC_X86_REG_EDX));

        // read from memory
        tmp = Utils.toInt(uc.mem_read(0xaaaaaaaaL, 4));
        System.out.format(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xaaaaaaaa,
            tmp);

        try {
            tmp = Utils.toInt(uc.mem_read(0xffffffaaL, 4));
            throw new RuntimeException("Expected mem_read to fail");
        } catch (UnicornException e) {
            System.out.format(">>> Failed to read 4 bytes from [0x%x]\n",
                0xffffffaa);
        }
    }

    // emulate code that jump to invalid memory
    public static void test_i386_jump_invalid() {
        int r_ecx = 0x1234; // ECX register
        int r_edx = 0x7890; // EDX register

        System.out.println("Emulate i386 code that jumps to invalid memory");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_JMP_INVALID);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_ECX, r_ecx);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instructions by having @begin > @end
        uc.hook_add(hook_code, 1, 0, null);

        // emulate machine code in infinite time
        try {
            uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_JMP_INVALID.length, 0,
                0);
            throw new RuntimeException("Expected a crash!");
        } catch (UnicornException e) {
            System.out.println("uc.emu_start failed as expected: " + e);
        }

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
        System.out.format(">>> EDX = 0x%x\n", uc.reg_read(UC_X86_REG_EDX));
    }

    public static void test_i386_inout() {
        int r_eax = 0x1234; // EAX register
        int r_ecx = 0x6789; // ECX register

        System.out.println("Emulate i386 code with IN/OUT instructions");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_INOUT);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_EAX, r_eax);
        uc.reg_write(UC_X86_REG_ECX, r_ecx);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instructions
        uc.hook_add(hook_code, 1, 0, null);

        // uc IN instruction
        uc.hook_add(hook_in, null);
        // uc OUT instruction
        uc.hook_add(hook_out, null);

        // emulate machine code in infinite time
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_INOUT.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> EAX = 0x%x\n", uc.reg_read(UC_X86_REG_EAX));
        System.out.format(">>> ECX = 0x%x\n", uc.reg_read(UC_X86_REG_ECX));
    }

    // emulate code and save/restore the CPU context
    public static void test_i386_context_save() {
        int r_eax = 0x1; // EAX register

        System.out.println("Save/restore CPU context in opaque blob");

        // initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 8KB memory for this emulation
        uc.mem_map(ADDRESS, 8 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_INC);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_EAX, r_eax);

        // emulate machine code in infinite time
        System.out.println(">>> Running emulation for the first time");
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_INC.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> EAX = 0x%x\n", uc.reg_read(UC_X86_REG_EAX));

        // allocate and save the CPU context
        System.out.println(">>> Saving CPU context");
        Unicorn.Context context = uc.context_save();

        // emulate machine code again
        System.out.println(">>> Running emulation for the second time");
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_INC.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> EAX = 0x%x\n", uc.reg_read(UC_X86_REG_EAX));

        // restore CPU context
        uc.context_restore(context);

        // now print out some registers
        System.out
                .println(">>> CPU context restored. Below is the CPU context");
        System.out.format(">>> EAX = 0x%x\n", uc.reg_read(UC_X86_REG_EAX));

        // modify some registers of the context
        context.reg_write(UC_X86_REG_EAX, 0xc8);

        // and restore CPU context again
        uc.context_restore(context);

        // now print out some registers
        System.out.format(
            ">>> CPU context restored with modification. Below is the CPU context\n");
        System.out.format(">>> EAX = 0x%x\n", uc.reg_read(UC_X86_REG_EAX));
    }

    public static void test_x86_64() {
        long rax = 0x71f3029efd49d41dL;
        long rbx = 0xd87b45277f133ddbL;
        long rcx = 0xab40d1ffd8afc461L;
        long rdx = 0x919317b4a733f01L;
        long rsi = 0x4c24e753a17ea358L;
        long rdi = 0xe509a57d2571ce96L;
        long r8 = 0xea5b108cc2b9ab1fL;
        long r9 = 0x19ec097c8eb618c1L;
        long r10 = 0xec45774f00c5f682L;
        long r11 = 0xe17e9dbec8c074aaL;
        long r12 = 0x80f86a8dc0f6d457L;
        long r13 = 0x48288ca5671c5492L;
        long r14 = 0x595f72f6e4017f6eL;
        long r15 = 0x1efd97aea331ccccL;

        long rsp = ADDRESS + 0x200000L;

        System.out.println("Emulate x86_64 code");

        // Initialize emulator in X86-64bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_64);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE64);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_RSP, rsp);

        uc.reg_write(UC_X86_REG_RAX, rax);
        uc.reg_write(UC_X86_REG_RBX, rbx);
        uc.reg_write(UC_X86_REG_RCX, rcx);
        uc.reg_write(UC_X86_REG_RDX, rdx);
        uc.reg_write(UC_X86_REG_RSI, rsi);
        uc.reg_write(UC_X86_REG_RDI, rdi);
        uc.reg_write(UC_X86_REG_R8, r8);
        uc.reg_write(UC_X86_REG_R9, r9);
        uc.reg_write(UC_X86_REG_R10, r10);
        uc.reg_write(UC_X86_REG_R11, r11);
        uc.reg_write(UC_X86_REG_R12, r12);
        uc.reg_write(UC_X86_REG_R13, r13);
        uc.reg_write(UC_X86_REG_R14, r14);
        uc.reg_write(UC_X86_REG_R15, r15);

        // tracing all basic blocks with customized callback
        uc.hook_add(hook_block, 1, 0, null);

        // tracing all instructions in the range [ADDRESS, ADDRESS+20]
        uc.hook_add(hook_code64, ADDRESS, ADDRESS + 20, null);

        // tracing all memory WRITE access (with @begin > @end)
        uc.hook_add(hook_mem64, UC_HOOK_MEM_WRITE, 1, 0, null);

        // tracing all memory READ access (with @begin > @end)
        uc.hook_add(hook_mem64, UC_HOOK_MEM_READ, 1, 0, null);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE64.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        System.out.format(">>> RAX = 0x%x\n", uc.reg_read(UC_X86_REG_RAX));
        System.out.format(">>> RBX = 0x%x\n", uc.reg_read(UC_X86_REG_RBX));
        System.out.format(">>> RCX = 0x%x\n", uc.reg_read(UC_X86_REG_RCX));
        System.out.format(">>> RDX = 0x%x\n", uc.reg_read(UC_X86_REG_RDX));
        System.out.format(">>> RSI = 0x%x\n", uc.reg_read(UC_X86_REG_RSI));
        System.out.format(">>> RDI = 0x%x\n", uc.reg_read(UC_X86_REG_RDI));
        System.out.format(">>> R8 = 0x%x\n", uc.reg_read(UC_X86_REG_R8));
        System.out.format(">>> R9 = 0x%x\n", uc.reg_read(UC_X86_REG_R9));
        System.out.format(">>> R10 = 0x%x\n", uc.reg_read(UC_X86_REG_R10));
        System.out.format(">>> R11 = 0x%x\n", uc.reg_read(UC_X86_REG_R11));
        System.out.format(">>> R12 = 0x%x\n", uc.reg_read(UC_X86_REG_R12));
        System.out.format(">>> R13 = 0x%x\n", uc.reg_read(UC_X86_REG_R13));
        System.out.format(">>> R14 = 0x%x\n", uc.reg_read(UC_X86_REG_R14));
        System.out.format(">>> R15 = 0x%x\n", uc.reg_read(UC_X86_REG_R15));
    }

    public static void test_x86_64_syscall() {
        long rax = 0x100;

        System.out.println("Emulate x86_64 code with 'syscall' instruction");

        // Initialize emulator in X86-64bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_64);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE64_SYSCALL);

        // hook interrupts for syscall
        uc.hook_add(hook_syscall, UC_X86_INS_SYSCALL, 1, 0, null);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_RAX, rax);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(ADDRESS, ADDRESS + X86_CODE64_SYSCALL.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");
        System.out.format(">>> RAX = 0x%x\n", uc.reg_read(UC_X86_REG_RAX));
    }

    public static void test_x86_16() {
        int eax = 7;
        int ebx = 5;
        int esi = 6;

        System.out.println("Emulate x86 16-bit code");

        // Initialize emulator in X86-16bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_16);

        // map 8KB memory for this emulation
        uc.mem_map(0, 8 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(0, X86_CODE16);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_EAX, eax);
        uc.reg_write(UC_X86_REG_EBX, ebx);
        uc.reg_write(UC_X86_REG_ESI, esi);

        // emulate machine code in infinite time (last param = 0), or when
        // finishing all the code.
        uc.emu_start(0, X86_CODE16.length, 0, 0);

        // now print out some registers
        System.out.println(">>> Emulation done. Below is the CPU context");

        // read from memory
        byte[] result = uc.mem_read(11, 1);
        System.out.format(">>> Read 1 bytes from [0x%x] = 0x%x\n", 11,
            result[0] & 0xff);
    }

    public static void test_i386_invalid_mem_read_in_tb() {
        int r_eax = 0x1234; // EAX register
        int r_edx = 0x7890; // EDX register

        System.out.format(
            "Emulate i386 code that read invalid memory in the middle of a TB\n");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 2MB memory for this emulation
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_MEM_READ_IN_TB);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_EAX, r_eax);
        uc.reg_write(UC_X86_REG_EDX, r_edx);

        // Add a dummy callback.
        // Note: if this callback is not added, the EIP will not be updated,
        // and EIP will read as ADDRESS after emu_start fails.
        uc.hook_add((MemHook) (u, type, address, size, value, user) -> {
        }, UC_HOOK_MEM_READ, 1, 0, null);

        // Let it crash by design.
        try {
            uc.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_READ_IN_TB.length, 0,
                0);
            throw new RuntimeException("Expected uc.emu_start to fail");
        } catch (UnicornException e) {
            System.out.println(
                "uc.emu_start() failed BY DESIGN with error returned: " + e);
        }

        System.out.println(">>> Emulation done. Below is the CPU context");

        long r_eip = uc.reg_read(UC_X86_REG_EIP);
        System.out.format(">>> EIP = 0x%x\n", r_eip);

        if (r_eip != ADDRESS + 1) {
            System.out.format(
                ">>> ERROR: Wrong PC 0x%x when reading unmapped memory in the middle of TB!\n",
                r_eip);
        } else {
            System.out.format(
                ">>> The PC is correct after reading unmapped memory in the middle of TB.\n");
        }
    }

    public static void test_i386_smc_xor() {
        long r_edi = ADDRESS;    // ECX register
        long r_eax = 0xbc4177e6L; // EDX register

        System.out.println("Emulate i386 code that modfies itself");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 1KB memory for this emulation
        uc.mem_map(ADDRESS, 0x1000, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_CODE32_SMC);

        // initialize machine registers
        uc.reg_write(UC_X86_REG_EDI, r_edi);
        uc.reg_write(UC_X86_REG_EAX, r_eax);

        // **Important Note**
        //
        // Since SMC code will cause TB regeneration, the XOR in fact would executed
        // twice (the first execution won't take effect.). Thus, if you would like
        // to use count to control the emulation, the count should be set to 2.
        //
        // uc.emu_start(ADDRESS, ADDRESS + 3, 0, 0);
        uc.emu_start(ADDRESS, 0, 0, 2);

        System.out.println(">>> Emulation done. Below is the result.");

        int result = Utils.toInt(uc.mem_read(ADDRESS + 3, 4));

        if (result == (0x3ea98b13 ^ 0xbc4177e6)) {
            System.out.format(
                ">>> SMC emulation is correct. 0x3ea98b13 ^ 0xbc4177e6 = 0x%x\n",
                result);
        } else {
            System.out.format(
                ">>> SMC emulation is wrong. 0x3ea98b13 ^ 0xbc4177e6 = 0x%x\n",
                result);
        }
    }

    private static final MmioReadHandler mmio_read_callback =
        (uc, offset, size, user_data) -> {
            System.out.format(
                ">>> Read IO memory at offset 0x%d with 0x%d bytes and return 0x19260817\n",
                offset, size);
            // The value returned here would be written to ecx.
            return 0x19260817;
        };

    private static final MmioWriteHandler mmio_write_callback =
        (uc, offset, size, value, user_data) -> {
            System.out.format(
                ">>> Write value 0x%d to IO memory at offset 0x%d with 0x%d bytes\n",
                value, offset, size);
        };

    public static void test_i386_mmio() {
        long r_ecx = 0xdeadbeefL;

        System.out.println("Emulate i386 code that uses MMIO");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 1KB memory for this emulation
        uc.mem_map(ADDRESS, 0x1000, UC_PROT_ALL);

        // write machine code to be emulated to memory
        uc.mem_write(ADDRESS, X86_MMIO_CODE);
        uc.mmio_map(0x20000, 0x4000, mmio_read_callback, null,
            mmio_write_callback, null);

        // prepare ecx
        uc.reg_write(UC_X86_REG_ECX, r_ecx);

        uc.emu_start(ADDRESS, ADDRESS + X86_MMIO_CODE.length, 0, 0);
        System.out.format(">>> Emulation done. ECX=0x%x\n",
            uc.reg_read(UC_X86_REG_ECX));
    }

    private static final EventMemHook test_i386_hook_mem_invalid_cb =
        (uc, type, address, size, value, user_data) -> {
            if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_WRITE_UNMAPPED) {
                System.out.format(
                    ">>> We have to add a map at 0x%x before continue execution!\n",
                    address);
                uc.mem_map(address, 0x1000, UC_PROT_ALL);
            }

            // If you really would like to continue the execution, make sure the memory
            // is already mapped properly!
            return true;
        };

    public static void test_i386_hook_mem_invalid() {
        // mov eax, 0xdeadbeef;
        // mov [0x8000], eax;
        // mov eax, [0x10000];
        byte[] code = Utils.hexToBytes("b8efbeaddea300800000a100000100");

        System.out.println(
            "Emulate i386 code that triggers invalid memory read/write.");

        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);
        uc.mem_map(ADDRESS, 0x1000, UC_PROT_ALL);
        uc.mem_write(ADDRESS, code);
        long hook = uc.hook_add(test_i386_hook_mem_invalid_cb,
            UC_HOOK_MEM_INVALID, 1, 0, null);
        uc.emu_start(ADDRESS, ADDRESS + code.length, 0, 0);

        uc.hook_del(hook);
    }

    public static void main(String args[]) {
        if (args.length == 1) {
            if (args[0].equals("-16")) {
                test_x86_16();
            } else if (args[0].equals("-32")) {
                test_miss_code();
                System.out.println("===================================");
                test_i386();
                System.out.println("===================================");
                test_i386_map_ptr();
                System.out.println("===================================");
                test_i386_inout();
                System.out.println("===================================");
                test_i386_context_save();
                System.out.println("===================================");
                test_i386_jump();
                System.out.println("===================================");
                test_i386_loop();
                System.out.println("===================================");
                test_i386_invalid_mem_read();
                System.out.println("===================================");
                test_i386_invalid_mem_write();
                System.out.println("===================================");
                test_i386_jump_invalid();
                // test_i386_invalid_c6c7();
            } else if (args[0].equals("-64")) {
                test_x86_64();
                System.out.println("===================================");
                test_x86_64_syscall();
            } else if (args[0].equals("-h")) {
                System.out.println(
                    "Syntax: java samples.Sample_x86 <-16|-32|-64>");
            }
        } else {
            test_x86_16();
            System.out.println("===================================");
            test_miss_code();
            System.out.println("===================================");
            test_i386();
            System.out.println("===================================");
            test_i386_map_ptr();
            System.out.println("===================================");
            test_i386_inout();
            System.out.println("===================================");
            test_i386_context_save();
            System.out.println("===================================");
            test_i386_jump();
            System.out.println("===================================");
            test_i386_loop();
            System.out.println("===================================");
            test_i386_invalid_mem_read();
            System.out.println("===================================");
            test_i386_invalid_mem_write();
            System.out.println("===================================");
            test_i386_jump_invalid();
            // test_i386_invalid_c6c7();
            System.out.println("===================================");
            test_x86_64();
            System.out.println("===================================");
            test_x86_64_syscall();
            System.out.println("===================================");
            test_i386_invalid_mem_read_in_tb();
            System.out.println("===================================");
            test_i386_smc_xor();
            System.out.println("===================================");
            test_i386_mmio();
            System.out.println("===================================");
            test_i386_hook_mem_invalid();
        }
    }
}
