package tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.math.BigInteger;

import org.junit.Test;

import unicorn.Unicorn;
import unicorn.UnicornException;
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

    @Test
    public void testBigIntegerRegister() {
        Unicorn uc =
            new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        int reg = Unicorn.UC_ARM64_REG_V0;

        assertThrows(UnicornException.class, () -> uc.reg_read(reg));
        assertThrows(UnicornException.class, () -> uc.reg_write(reg, 1L));
        assertThrows(ClassCastException.class,
            () -> uc.reg_write(reg, (Long) 1L));

        BigInteger b127 = BigInteger.valueOf(2).pow(127);
        BigInteger bmax =
            BigInteger.valueOf(2).pow(128).subtract(BigInteger.ONE);

        uc.reg_write(reg, BigInteger.ZERO);
        assertEquals("write 0, get 0", BigInteger.ZERO, uc.reg_read(reg, null));

        uc.reg_write(reg, BigInteger.ONE);
        assertEquals("write 1, get 1", BigInteger.ONE, uc.reg_read(reg, null));
        assertEquals("get 1 from alias", BigInteger.ONE,
            uc.reg_read(Unicorn.UC_ARM64_REG_Q0, null));

        uc.reg_write(reg, BigInteger.ONE.negate());
        assertEquals("write -1, get 2^128 - 1", bmax, uc.reg_read(reg, null));

        uc.reg_write(reg, b127);
        assertEquals("write 2^127, get 2^127", b127, uc.reg_read(reg, null));

        uc.reg_write(reg, b127.negate());
        assertEquals("write -2^127, get 2^127", b127, uc.reg_read(reg, null));

        uc.reg_write(reg, bmax);
        assertEquals("write 2^128 - 1, get 2^128 - 1", bmax,
            uc.reg_read(reg, null));

        assertThrows("reject 2^128", IllegalArgumentException.class,
            () -> uc.reg_write(reg, bmax.add(BigInteger.ONE)));
        assertEquals("reg unchanged", bmax,
            uc.reg_read(reg, null));

        assertThrows("reject -2^127 - 1", IllegalArgumentException.class,
            () -> uc.reg_write(reg, b127.negate().subtract(BigInteger.ONE)));
        assertEquals("reg unchanged", bmax,
            uc.reg_read(reg, null));

        byte[] b = new byte[0x80];
        b[0x70] = -0x80;
        uc.reg_write(reg, new BigInteger(b));
        assertEquals("write untrimmed value", b127, uc.reg_read(reg, null));

        uc.close();
    }

    @Test
    public void testArm64Vector() {
        // add v0.8h, v1.8h, v2.8h
        final byte[] ARM64_CODE = { 0x20, (byte) 0x84, 0x62, 0x4e };

        long ADDRESS = 0x100000;

        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        uc.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        uc.mem_write(ADDRESS, ARM64_CODE);

        uc.reg_write(Unicorn.UC_ARM64_REG_V0,
            new BigInteger("0cc175b9c0f1b6a831c399e269772661", 16)); // MD5("a")
        uc.reg_write(Unicorn.UC_ARM64_REG_V1,
            new BigInteger("92eb5ffee6ae2fec3ad71c777531578f", 16)); // MD5("b")
        uc.reg_write(Unicorn.UC_ARM64_REG_V2,
            new BigInteger("-4a8a08f09d37b73795649038408b5f33", 16)); // -MD5("c")
        assertThrows("rejects overly large values",
            IllegalArgumentException.class,
            () -> uc.reg_write(Unicorn.UC_ARM64_REG_V2,
                new BigInteger("1111222233334444aaaabbbbccccdddde", 16)));

        assertEquals("v0 value",
            new BigInteger("0cc175b9c0f1b6a831c399e269772661", 16),
            uc.reg_read(Unicorn.UC_ARM64_REG_V0, null));
        assertEquals("v1 value",
            new BigInteger("92eb5ffee6ae2fec3ad71c777531578f", 16),
            uc.reg_read(Unicorn.UC_ARM64_REG_V1, null));
        assertEquals("v2 value",
            new BigInteger("b575f70f62c848c86a9b6fc7bf74a0cd", 16),
            uc.reg_read(Unicorn.UC_ARM64_REG_V2, null));

        uc.emu_start(ADDRESS, ADDRESS + ARM64_CODE.length, 0, 0);
        assertEquals("v0.8h = v1.8h + v2.8h",
            new BigInteger("4860570d497678b4a5728c3e34a5f85c", 16),
            uc.reg_read(Unicorn.UC_ARM64_REG_V0, null));

        uc.close();
    }
}
