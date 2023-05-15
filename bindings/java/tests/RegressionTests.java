package tests;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Ignore;
import org.junit.Test;

import unicorn.Unicorn;
import unicorn.UnicornException;
import unicorn.CodeHook;

public class RegressionTests {
    /** Test for GH #1539: Unable to read ARM64 v or q register using java binding */
    @Test
    public void testARM64VReg() {
        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0x1);
        uc.reg_write(Unicorn.UC_ARM64_REG_V0, BigInteger.valueOf(0x1234));
        uc.reg_read(Unicorn.UC_ARM64_REG_X0);
        assertEquals("V0 value", BigInteger.valueOf(0x1234),
            uc.reg_read(Unicorn.UC_ARM64_REG_V0, null)); // should not crash
        assertEquals("V0 low byte", 0x34,
            uc.reg_read(Unicorn.UC_ARM64_REG_B0));
        assertEquals("V0 low halfword", 0x1234,
            uc.reg_read(Unicorn.UC_ARM64_REG_H0));
    }

    /** Test for GH #1164: Java binding use CodeHook on Windows, will invoke callback before every instruction */
    @Test
    public void testCodeHookRunsOnce() {
        byte[] ARM_CODE =
            { 55, 0, (byte) 0xa0, (byte) 0xe3, 3, 16, 66, (byte) 0xe0 }; // mov r0, #0x37; sub r1, r2, r3
        int ADDRESS = 0x10000;
        final int[] hook_count = { 0 };

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_ARM);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, ARM_CODE);
        u.hook_add((CodeHook) (uc, address, size, user) -> hook_count[0] += 1,
            ADDRESS, ADDRESS, null);

        u.emu_start(ADDRESS, ADDRESS + ARM_CODE.length, 0, 0);
        assertEquals("Hook should only be called once", 1, hook_count[0]);

        u.close();
    }

    /** Test that close() can be called multiple times without crashing */
    @Test
    public void testCloseIdempotent() {
        Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_ARM);
        u.close();
        u.close();
    }

    /** Test that Unicorn instances are properly garbage-collected */
    @Ignore("This test is not deterministic")
    @Test
    public void testUnicornsWillGC() {
        final boolean[] close_called = { false };

        new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_ARM) {
            @Override
            public void close() throws UnicornException {
                close_called[0] = true;
                super.close();
            }
        };
        System.gc();
        System.runFinalization();
        assertEquals("close() was called", true, close_called[0]);
    }
}
