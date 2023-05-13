package tests;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import unicorn.Unicorn;
import unicorn.X86_Float80;

public class RegTests {
    @Test
    public void testX86ReadFloat80() {
        // fldl2e; fsin
        final byte[] X86_CODE = { -39, -22, -39, -2 };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, X86_CODE);
        u.emu_start(ADDRESS, ADDRESS + X86_CODE.length, 0, 0);
        X86_Float80 reg1 =
            (X86_Float80) u.reg_read(Unicorn.UC_X86_REG_ST0, null);
        X86_Float80 reg2 =
            (X86_Float80) u.reg_read(Unicorn.UC_X86_REG_FP7, null);
        assertEquals(null, ADDRESS, ADDRESS, ADDRESS);
        assertEquals(Math.sin(Math.log(Math.E) / Math.log(2)), reg1.toDouble(),
            1e-12);
        assertEquals(reg1.toDouble(), reg2.toDouble(), 1e-12);
        u.close();
    }

    @Test
    public void testX86WriteFloat80() {
        // fsin
        final byte[] X86_CODE = { -39, -2 };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, X86_CODE);
        X86_Float80 reg = X86_Float80.fromDouble(-1.1);
        u.reg_write(Unicorn.UC_X86_REG_ST0, reg);
        u.emu_start(ADDRESS, ADDRESS + X86_CODE.length, 0, 0);
        reg = (X86_Float80) u.reg_read(Unicorn.UC_X86_REG_ST0, null);
        assertEquals(Math.sin(-1.1), reg.toDouble(), 1e-12);
        u.close();
    }
}
