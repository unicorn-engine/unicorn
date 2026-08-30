package tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.After;
import org.junit.Test;

import unicorn.Unicorn;
import unicorn.UnicornConst;

public class TestSamples implements UnicornConst {
    private final ByteArrayOutputStream outContent =
        new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @Before
    public void setUpStreams() {
        outContent.reset();
        System.setOut(new PrintStream(outContent));
    }

    @After
    public void restoreStreams() {
        System.setOut(originalOut);
    }

    @Test
    public void testArm() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_arm();
        assertEquals(
            "Emulate ARM code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> R0 = 0x1234\n" +
                ">>> R1 = 0x0\n",
            outContent.toString());
    }

    @Test
    public void testArmThumb() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_thumb();
        assertEquals(
            "Emulate THUMB code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x2\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x2\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> SP = 0x1228\n",
            outContent.toString());
    }

    @Test
    public void testArmEb() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_armeb();
        assertEquals(
            "Emulate ARM Big-Endian code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> R0 = 0x37\n" +
                ">>> R1 = 0x3456\n",
            outContent.toString());
    }

    @Test
    public void testArmThumbEb() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_thumbeb();
        assertEquals(
            "Emulate THUMB Big-Endian code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x2\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x2\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> SP = 0x1228\n",
            outContent.toString());
    }

    @Test
    public void testArmThumbMrs() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_thumb_mrs();
        assertEquals(
            "Emulate THUMB MRS instruction\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> PC = 0x10004\n",
            outContent.toString());
    }

    @Test
    public void testArmThumbIte() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_thumb_ite();
        assertEquals(
            "Emulate a THUMB ITE block as a whole or per instruction.\n" +
                "Running the entire binary.\n" +
                ">>> R2: 104\n" +
                ">>> R3: 1\n" +
                "\n" +
                "Running the binary one instruction at a time.\n" +
                ">>> R2: 104\n" +
                ">>> R3: 1\n" +
                "\n",
            outContent.toString());
    }

    @Test
    public void testArmReadSctlr() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM));
        samples.Sample_arm.test_read_sctlr();
        assertEquals(
            "Read the SCTLR register.\n" +
                ">>> SCTLR = 0xc50078\n" +
                ">>> SCTLR.IE = 0\n" +
                ">>> SCTLR.B = 0\n",
            outContent.toString());
    }

    @Test
    public void testArm64MemFetch() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM64));
        samples.Sample_arm64.test_arm64_mem_fetch();
        assertEquals(
            ">>> Emulate ARM64 fetching stack data from high address 10000000000000\n" +
                ">>> x0(Exception Level)=1\n" +
                ">>> X1 = 0xc8c8c8c8c8c8c8c8\n",
            outContent.toString());
    }

    @Test
    public void testArm64() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM64));
        samples.Sample_arm64.test_arm64();
        assertEquals(
            "Emulate ARM64 code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> As little endian, X15 should be 0x78:\n" +
                ">>> X15 = 0x78\n",
            outContent.toString());
    }

    @Test
    public void testArm64Eb() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM64));
        samples.Sample_arm64.test_arm64eb();
        assertEquals(
            "Emulate ARM64 Big-Endian code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> As big endian, X15 should be 0x78:\n" +
                ">>> X15 = 0x12\n",
            outContent.toString());
    }

    @Test
    public void testArm64Sctlr() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM64));
        samples.Sample_arm64.test_arm64_sctlr();
        assertEquals(
            "Read the SCTLR register.\n" +
                ">>> SCTLR_EL1 = 0xc50838\n" +
                ">>> SCTLR_EL2 = 0x0\n",
            outContent.toString());
    }

    @Test
    public void testArm64HookMrs() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM64));
        samples.Sample_arm64.test_arm64_hook_mrs();
        assertEquals(
            "Hook MRS instruction.\n" +
                ">>> Hook MSR instruction. Write 0x114514 to X2.\n" +
                ">>> X2 = 0x114514\n",
            outContent.toString());
    }

    @Test
    public void testArm64Pac() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_ARM64));
        samples.Sample_arm64.test_arm64_pac();
        assertEquals(
            "Try ARM64 PAC\n" +
                "X1 = 0x1401aaaabbbbcccc\n" +
                "SUCCESS: PAC tag found.\n",
            outContent.toString());
    }

    @Test
    public void testCtlRead() {
        samples.Sample_ctl.test_uc_ctl_read();
        assertEquals(
            "Reading some properties by uc_ctl.\n" +
                ">>> mode = 4, arch = 4, timeout=0, pagesize=4096\n",
            outContent.toString());
    }

    @Test
    public void testCtlExits() {
        samples.Sample_ctl.test_uc_ctl_exits();
        assertEquals(
            "Using multiple exits by uc_ctl.\n" +
                ">>> Getting a new edge from 0x10004 to 0x10005.\n" +
                ">>> eax = 1 and ebx = 0 after the first emulation\n" +
                ">>> Getting a new edge from 0x10004 to 0x10007.\n" +
                ">>> eax = 1 and ebx = 1 after the second emulation\n",
            outContent.toString());
    }

    @Test
    public void testM68k() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_M68K));
        samples.Sample_m68k.test_m68k();
        assertEquals(
            "Emulate M68K code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x2\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x2\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> A0 = 0x0		>>> D0 = 0x0\n" +
                ">>> A1 = 0x0		>>> D1 = 0x0\n" +
                ">>> A2 = 0x0		>>> D2 = 0x0\n" +
                ">>> A3 = 0x0		>>> D3 = 0xffffffed\n" +
                ">>> A4 = 0x0		>>> D4 = 0x0\n" +
                ">>> A5 = 0x0		>>> D5 = 0x0\n" +
                ">>> A6 = 0x0		>>> D6 = 0x0\n" +
                ">>> A7 = 0x0		>>> D7 = 0x0\n" +
                ">>> PC = 0x10002\n" +
                ">>> SR = 0x0\n",
            outContent.toString());
    }

    @Test
    public void testMipsEl() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_MIPS));
        samples.Sample_mips.test_mips_el();
        assertEquals(
            "Emulate MIPS code (little-endian)\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> R1 = 0x77df\n",
            outContent.toString());
    }

    @Test
    public void testMipsEb() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_MIPS));
        samples.Sample_mips.test_mips_eb();
        assertEquals(
            "Emulate MIPS code (big-endian)\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> R1 = 0x77df\n",
            outContent.toString());
    }

    @Test
    public void testMmuCpuTlb() {
        samples.Sample_mmu.cpu_tlb();
        assertEquals(
            "Emulate x86 amd64 code with mmu enabled and switch mappings\n" +
                "map code\n" +
                "map parent memory\n" +
                "map child memory\n" +
                "map tlb memory\n" +
                "set up the tlb\n" +
                "run the parent\n" +
                "save the context for the child\n" +
                "finish the parent\n" +
                "write at 0x1000: 0x3c\n" +
                "restore the context for the child\n" +
                "write at 0x2000: 0x2a\n" +
                "parent result == 60\n" +
                "child result == 42\n",
            outContent.toString());
    }

    @Test
    public void testMmuVirtualTlb() {
        samples.Sample_mmu.virtual_tlb();
        assertEquals(
            "Emulate x86 amd64 code with virtual mmu\n" +
                "map code\n" +
                "map parent memory\n" +
                "map child memory\n" +
                "run the parent\n" +
                "tlb lookup for address: 0x2000\n" +
                "save the context for the child\n" +
                "finish the parent\n" +
                "tlb lookup for address: 0x4000\n" +
                "write at 0x1000: 0x3c\n" +
                "restore the context for the child\n" +
                "tlb lookup for address: 0x2000\n" +
                "tlb lookup for address: 0x4000\n" +
                "write at 0x2000: 0x2a\n" +
                "parent result == 60\n" +
                "child result == 42\n",
            outContent.toString());
    }

    @Test
    public void testPpc() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_PPC));
        samples.Sample_ppc.test_ppc();
        assertEquals(
            "Emulate PPC code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> r26 = 0x79bd\n",
            outContent.toString());
    }

    @Test
    public void testRiscvRecoverFromIllegal() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_recover_from_illegal();
        assertEquals(
            "Emulate RISCV code: recover_from_illegal\n" +
                ">>> Allocating block at 0x1000 (0x1000), block size = 0x2 (0x1000)\n" +
                ">>> Tracing basic block at 0x1000, block size = 0x0\n" +
                "Expected Illegal Instruction error, got: " +
                "unicorn.UnicornException: Unhandled CPU exception (UC_ERR_EXCEPTION)\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> A0 = 0x1\n" +
                ">>> A1 = 0x7890\n",
            outContent.toString());
    }

    @Test
    public void testRiscv1() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv();
        assertEquals(
            "Emulate RISCV code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Tracing instruction at 0x10004, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> A0 = 0x1\n" +
                ">>> A1 = 0x78b0\n",
            outContent.toString());
    }

    @Test
    public void testRiscv2() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv2();
        assertEquals(
            "Emulate RISCV code: split emulation\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> A0 = 0x1\n" +
                ">>> A1 = 0x7890\n" +
                ">>> Tracing basic block at 0x10004, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10004, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> A0 = 0x1\n" +
                ">>> A1 = 0x78b0\n",
            outContent.toString());
    }

    @Test
    public void testRiscv3() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv3();
        assertEquals(
            "Emulate RISCV code: early stop\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                "stop emulation\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> A0 = 0x1234\n" +
                ">>> A1 = 0x7890\n",
            outContent.toString());
    }

    @Test
    public void testRiscvStep() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv_step();
        assertEquals(
            "Emulate RISCV code: step\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> A0 = 0x1\n" +
                ">>> A1 = 0x7890\n" +
                ">>> Tracing basic block at 0x10004, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10004, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> A0 = 0x1\n" +
                ">>> A1 = 0x78b0\n",
            outContent.toString());
    }

    @Ignore("timeout test is currently broken")
    @Test
    public void testRiscvTimeout() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv_timeout();
        assertEquals(
            "Emulate RISCV code: timeout\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x0\n" +
                "Failed on uc_emu_start() with error returned: 21\n" +
                "Error after step: PC is: 0x10004, expected was 0x10004\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x0\n" +
                "Failed on uc_emu_start() with error returned: 21\n" +
                "Error after step: PC is: 0x10004, expected was 0x10004\n" +
                ">>> Emulation done\n",
            outContent.toString());
    }

    @Test
    public void testRiscvSd64() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv_sd64();
        assertEquals(
            "Emulate RISCV code: sd64 instruction\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done.\n",
            outContent.toString());
    }

    @Test
    public void testRiscvFuncReturn() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_RISCV));
        samples.Sample_riscv.test_riscv_func_return();
        assertEquals(
            "Emulate RISCV code: return from func\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Tracing basic block at 0x10006, block size = 0x4\n" +
                "Good, PC == RA\n" +
                "========\n" +
                ">>> Tracing basic block at 0x10004, block size = 0x2\n" +
                ">>> Tracing instruction at 0x10004, instruction size = 0x2\n" +
                ">>> Tracing basic block at 0x10006, block size = 0x4\n" +
                "Good, PC == RA\n" +
                ">>> Emulation done.\n",
            outContent.toString());
    }

    @Test
    public void testS390x() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_S390X));
        samples.Sample_s390x.test_s390x();
        assertEquals(
            "Emulate S390X code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x2\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x2\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> R2 = 0x3		>>> R3 = 0x3\n",
            outContent.toString());
    }

    @Test
    public void testShellcode() {
        samples.Shellcode.test_i386();
        assertEquals(
            "Emulate i386 code\n" +
                "\n" +
                ">>> Start tracing this Linux code\n" +
                "Tracing instruction at 0x1000000, instruction size = 0x2\n" +
                "*** EIP = 1000000 ***: eb 1c \n" +
                "Tracing instruction at 0x100001e, instruction size = 0x5\n" +
                "*** EIP = 100001e ***: e8 df ff ff ff \n" +
                "Tracing instruction at 0x1000002, instruction size = 0x1\n" +
                "*** EIP = 1000002 ***: 5a \n" +
                "Tracing instruction at 0x1000003, instruction size = 0x2\n" +
                "*** EIP = 1000003 ***: 89 d6 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x100000d, instruction size = 0x4\n" +
                "*** EIP = 100000d ***: 66 5 3 3 \n" +
                "Tracing instruction at 0x1000011, instruction size = 0x2\n" +
                "*** EIP = 1000011 ***: 89 2 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x1000005, instruction size = 0x2\n" +
                "*** EIP = 1000005 ***: 8b 2 \n" +
                "Tracing instruction at 0x1000007, instruction size = 0x4\n" +
                "*** EIP = 1000007 ***: 66 3d ca 7d \n" +
                "Tracing instruction at 0x100000b, instruction size = 0x2\n" +
                "*** EIP = 100000b ***: 75 6 \n" +
                "Tracing instruction at 0x1000013, instruction size = 0x2\n" +
                "*** EIP = 1000013 ***: fe c2 \n" +
                "Tracing instruction at 0x1000015, instruction size = 0x5\n" +
                "*** EIP = 1000015 ***: 3d 41 41 41 41 \n" +
                "Tracing instruction at 0x100001a, instruction size = 0x2\n" +
                "*** EIP = 100001a ***: 75 e9 \n" +
                "Tracing instruction at 0x100001c, instruction size = 0x2\n" +
                "*** EIP = 100001c ***: ff e6 \n" +
                "Tracing instruction at 0x1000023, instruction size = 0x2\n" +
                "*** EIP = 1000023 ***: 31 d2 \n" +
                "Tracing instruction at 0x1000025, instruction size = 0x2\n" +
                "*** EIP = 1000025 ***: 6a b \n" +
                "Tracing instruction at 0x1000027, instruction size = 0x1\n" +
                "*** EIP = 1000027 ***: 58 \n" +
                "Tracing instruction at 0x1000028, instruction size = 0x1\n" +
                "*** EIP = 1000028 ***: 99 \n" +
                "Tracing instruction at 0x1000029, instruction size = 0x1\n" +
                "*** EIP = 1000029 ***: 52 \n" +
                "Tracing instruction at 0x100002a, instruction size = 0x5\n" +
                "*** EIP = 100002a ***: 68 2f 2f 73 68 \n" +
                "Tracing instruction at 0x100002f, instruction size = 0x5\n" +
                "*** EIP = 100002f ***: 68 2f 62 69 6e \n" +
                "Tracing instruction at 0x1000034, instruction size = 0x2\n" +
                "*** EIP = 1000034 ***: 89 e3 \n" +
                "Tracing instruction at 0x1000036, instruction size = 0x1\n" +
                "*** EIP = 1000036 ***: 52 \n" +
                "Tracing instruction at 0x1000037, instruction size = 0x1\n" +
                "*** EIP = 1000037 ***: 53 \n" +
                "Tracing instruction at 0x1000038, instruction size = 0x2\n" +
                "*** EIP = 1000038 ***: 89 e1 \n" +
                "Tracing instruction at 0x100003a, instruction size = 0x2\n" +
                "*** EIP = 100003a ***: cd 80 \n" +
                ">>> 0x100003c: interrupt 0x80, EAX = 0xb\n" +
                "Tracing instruction at 0x100003c, instruction size = 0x1\n" +
                "*** EIP = 100003c ***: 41 \n" +
                "Tracing instruction at 0x100003d, instruction size = 0x1\n" +
                "*** EIP = 100003d ***: 41 \n" +
                "Tracing instruction at 0x100003e, instruction size = 0x1\n" +
                "*** EIP = 100003e ***: 41 \n" +
                "Tracing instruction at 0x100003f, instruction size = 0x1\n" +
                "*** EIP = 100003f ***: 41 \n" +
                "Tracing instruction at 0x1000040, instruction size = 0x1\n" +
                "*** EIP = 1000040 ***: 41 \n" +
                "Tracing instruction at 0x1000041, instruction size = 0x1\n" +
                "*** EIP = 1000041 ***: 41 \n" +
                "Tracing instruction at 0x1000042, instruction size = 0x1\n" +
                "*** EIP = 1000042 ***: 41 \n" +
                "Tracing instruction at 0x1000043, instruction size = 0x1\n" +
                "*** EIP = 1000043 ***: 41 \n" +
                "\n" +
                ">>> Emulation done.\n",
            outContent.toString());
    }

    @Test
    public void testSparc() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_SPARC));
        samples.Sample_sparc.test_sparc();
        assertEquals(
            "Emulate SPARC code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x4\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> G3 = 0x79b9\n",
            outContent.toString());
    }

    @Test
    public void testTricore() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_TRICORE));
        samples.Sample_tricore.test_tricore();
        assertEquals(
            "Emulate TriCore code\n" +
                ">>> Tracing basic block at 0x10000, block size = 0x6\n" +
                ">>> Tracing instruction at 0x10000, instruction size = 0x2\n" +
                ">>> Tracing instruction at 0x10002, instruction size = 0x4\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> d0 = 0x8000\n" +
                ">>> d1 = 0x1\n",
            outContent.toString());
    }

    @Test
    public void testX86_16() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_x86_16();
        assertEquals(
            "Emulate x86 16-bit code\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> Read 1 bytes from [0xb] = 0x7\n",
            outContent.toString());
    }

    @Test
    public void testX86MissCode() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_miss_code();
        assertEquals(
            "Emulate i386 code - missing code\n" +
                ">>> Allocating block at 0x1000000 (0x1000000), block size = 0x1 (0x1000)\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Tracing instruction at 0x1000001, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x6\n" +
                ">>> Tracing instruction at 0x1000002, instruction size = 0x4\n" +
                ">>> --- EFLAGS is 0x12\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1235\n" +
                ">>> EDX = 0x788f\n",
            outContent.toString());
    }

    @Test
    public void testX86() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386();
        assertEquals(
            "Emulate i386 code\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x6\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Tracing instruction at 0x1000001, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x6\n" +
                ">>> Tracing instruction at 0x1000002, instruction size = 0x4\n" +
                ">>> --- EFLAGS is 0x12\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1235\n" +
                ">>> EDX = 0x788f\n" +
                ">>> XMM0 = 0x00112233445566778899aabbccddeeff\n" +
                ">>> Read 4 bytes from [0x1000000] = 0xf664a41\n",
            outContent.toString());
    }

    @Test
    public void testX86MapPtr() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_map_ptr();
        assertEquals(
            "Emulate i386 code - use uc_mem_map_ptr()\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x6\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Tracing instruction at 0x1000001, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x6\n" +
                ">>> Tracing instruction at 0x1000002, instruction size = 0x4\n" +
                ">>> --- EFLAGS is 0x12\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1235\n" +
                ">>> EDX = 0x788f\n" +
                ">>> Read 4 bytes from [0x1000000] = 0xf664a41\n",
            outContent.toString());
    }

    @Test
    public void testX86InOut() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_inout();
        assertEquals(
            "Emulate i386 code with IN/OUT instructions\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x7\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Tracing instruction at 0x1000001, instruction size = 0x2\n" +
                ">>> --- EFLAGS is 0x2\n" +
                "--- reading from port 0x3f, size: 1, address: 0x1000001\n" +
                ">>> Tracing instruction at 0x1000003, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Tracing instruction at 0x1000004, instruction size = 0x2\n" +
                ">>> --- EFLAGS is 0x96\n" +
                "--- writing to port 0x46, size: 1, value: 0xf1, address: 0x1000004\n" +
                "--- register value = 0xf1\n" +
                ">>> Tracing instruction at 0x1000006, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x96\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> EAX = 0x12f1\n" +
                ">>> ECX = 0x678a\n",
            outContent.toString());
    }

    @Test
    public void testX86ContextSave() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_context_save();
        assertEquals(
            "Save/restore CPU context in opaque blob\n" +
                ">>> Running emulation for the first time\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> EAX = 0x2\n" +
                ">>> Saving CPU context\n" +
                ">>> Running emulation for the second time\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> EAX = 0x3\n" +
                ">>> CPU context restored. Below is the CPU context\n" +
                ">>> EAX = 0x2\n" +
                ">>> CPU context restored with modification. Below is the CPU context\n" +
                ">>> EAX = 0xc8\n",
            outContent.toString());
    }

    @Test
    public void testX86Jump() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_jump();
        assertEquals(
            "Emulate i386 code with jump\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x2\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x2\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Emulation done. Below is the CPU context\n",
            outContent.toString());
    }

    @Test
    public void testX86Loop() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_loop();
        assertEquals(
            "Emulate i386 code that loop forever\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1235\n" +
                ">>> EDX = 0x788f\n",
            outContent.toString());
    }

    @Test
    public void testX86InvalidMemRead() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_invalid_mem_read();
        assertEquals(
            "Emulate i386 code that read from invalid memory\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x6\n" +
                ">>> --- EFLAGS is 0x2\n" +
                "uc.emu_start failed as expected: " +
                "unicorn.UnicornException: Invalid memory read (UC_ERR_READ_UNMAPPED)\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1234\n" +
                ">>> EDX = 0x7890\n",
            outContent.toString());
    }

    @Test
    public void testX86InvalidMemWrite() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_invalid_mem_write();
        assertEquals(
            "Emulate i386 code that write to invalid memory\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x8\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x6\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Missing memory is being WRITE at 0xaaaaaaaa, data size = 4, data value = 0x1234\n" +
                ">>> Tracing instruction at 0x1000006, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x2\n" +
                ">>> Tracing instruction at 0x1000007, instruction size = 0x1\n" +
                ">>> --- EFLAGS is 0x6\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1235\n" +
                ">>> EDX = 0x788f\n" +
                ">>> Read 4 bytes from [0xaaaaaaaa] = 0x1234\n" +
                ">>> Failed to read 4 bytes from [0xffffffaa]\n",
            outContent.toString());
    }

    @Test
    public void testX86JumpInvalid() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_jump_invalid();
        assertEquals(
            "Emulate i386 code that jumps to invalid memory\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x5\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x5\n" +
                ">>> --- EFLAGS is 0x2\n" +
                "uc.emu_start failed as expected: " +
                "unicorn.UnicornException: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> ECX = 0x1234\n" +
                ">>> EDX = 0x7890\n",
            outContent.toString());
    }

    @Test
    public void testX86_64() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_x86_64();
        assertEquals(
            "Emulate x86_64 code\n" +
                ">>> Tracing basic block at 0x1000000, block size = 0x4b\n" +
                ">>> Tracing instruction at 0x1000000, instruction size = 0x6\n" +
                ">>> RIP is 0x1000000\n" +
                ">>> Tracing instruction at 0x1000006, instruction size = 0x3\n" +
                ">>> RIP is 0x1000006\n" +
                ">>> Tracing instruction at 0x1000009, instruction size = 0x1\n" +
                ">>> RIP is 0x1000009\n" +
                ">>> Tracing instruction at 0x100000a, instruction size = 0x4\n" +
                ">>> RIP is 0x100000a\n" +
                ">>> Tracing instruction at 0x100000e, instruction size = 0x3\n" +
                ">>> RIP is 0x100000e\n" +
                ">>> Tracing instruction at 0x1000011, instruction size = 0x1\n" +
                ">>> RIP is 0x1000011\n" +
                ">>> Tracing instruction at 0x1000012, instruction size = 0x7\n" +
                ">>> RIP is 0x1000012\n" +
                ">>> Memory is being WRITE at 0x11ffff8, data size = 8, data value = 0x3c091e6a\n" +
                ">>> Memory is being READ at 0x11ffff8, data size = 8\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> RAX = 0xdb8ee18208cd6d03\n" +
                ">>> RBX = 0xd87b45277f133ddb\n" +
                ">>> RCX = 0x3c091e6a\n" +
                ">>> RDX = 0x25b8d5a4dbb38112\n" +
                ">>> RSI = 0xb3db18ac5e815ca7\n" +
                ">>> RDI = 0x48288ca5671c5492\n" +
                ">>> R8 = 0xec45774f00c5f682\n" +
                ">>> R9 = 0xc118b68e7fcfeeff\n" +
                ">>> R10 = 0x596b8d4f\n" +
                ">>> R11 = 0xe17e9dbec8c074aa\n" +
                ">>> R12 = 0x595f72f6b9d8cf32\n" +
                ">>> R13 = 0xea5b108cc2b9ab1f\n" +
                ">>> R14 = 0x595f72f6e4017f6e\n" +
                ">>> R15 = 0x3e04f60c8f7ecbd7\n",
            outContent.toString());
    }

    @Test
    public void testX86_64Syscall() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_x86_64_syscall();
        assertEquals(
            "Emulate x86_64 code with 'syscall' instruction\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> RAX = 0x200\n",
            outContent.toString());
    }

    @Test
    public void testX86InvalidMemReadInTb() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_invalid_mem_read_in_tb();
        assertEquals(
            "Emulate i386 code that read invalid memory in the middle of a TB\n" +
                "uc.emu_start() failed BY DESIGN with error returned: " +
                "unicorn.UnicornException: Invalid memory read (UC_ERR_READ_UNMAPPED)\n" +
                ">>> Emulation done. Below is the CPU context\n" +
                ">>> EIP = 0x1000001\n" +
                ">>> The PC is correct after reading unmapped memory in the middle of TB.\n",
            outContent.toString());
    }

    @Test
    public void testX86SmcXor() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_smc_xor();
        assertEquals(
            "Emulate i386 code that modfies itself\n" +
                ">>> Emulation done. Below is the result.\n" +
                ">>> SMC emulation is correct. 0x3ea98b13 ^ 0xbc4177e6 = 0x82e8fcf5\n",
            outContent.toString());
    }

    @Test
    public void testX86Mmio() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_mmio();
        assertEquals(
            "Emulate i386 code that uses MMIO\n" +
                ">>> Write value 0x3735928559 to IO memory at offset 0x4 with 0x4 bytes\n" +
                ">>> Read IO memory at offset 0x4 with 0x4 bytes and return 0x19260817\n" +
                ">>> Emulation done. ECX=0x19260817\n",
            outContent.toString());
    }

    @Test
    public void testX86HookMemInvalid() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86.test_i386_hook_mem_invalid();
        assertEquals(
            "Emulate i386 code that triggers invalid memory read/write.\n" +
                ">>> We have to add a map at 0x8000 before continue execution!\n" +
                ">>> We have to add a map at 0x10000 before continue execution!\n",
            outContent.toString());
    }

    @Test
    public void testX86Mmr() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86_mmr.test_x86_mmr();
        assertEquals(
            "Test x86 MMR read/write\n" +
                ">>> EAX = 0xdddddddd\n" +
                ">>> LDTR.base = 0x22222222\n" +
                ">>> LDTR.limit = 0x33333333\n" +
                ">>> LDTR.flags = 0x44444444\n" +
                ">>> LDTR.selector = 0x5555\n" +
                "\n" +
                ">>> GDTR.base = 0x77777777\n" +
                ">>> GDTR.limit = 0x8888\n",
            outContent.toString());
    }

    @Test
    public void testX86Gdt() {
        assumeTrue(Unicorn.arch_supported(UC_ARCH_X86));
        samples.Sample_x86_mmr.gdt_demo();
        assertEquals(
            "Demonstrate GDT usage\n" +
                "Executing at 0x1000000, ilen = 0x5\n" +
                "mem write at 0x120ffc, size = 4, value = 0x1234567\n" +
                "Executing at 0x1000005, ilen = 0x5\n" +
                "mem write at 0x120ff8, size = 4, value = 0x89abcdef\n" +
                "Executing at 0x100000a, ilen = 0xb\n" +
                "mem write at 0x7efdd000, size = 4, value = 0x1234567\n" +
                "Executing at 0x1000015, ilen = 0xb\n" +
                "mem write at 0x7efdd004, size = 4, value = 0x89abcdef\n" +
                "efcdab8967452301\n",
            outContent.toString());
    }

}
