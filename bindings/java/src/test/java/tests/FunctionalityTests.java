package tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import unicorn.Unicorn;
import unicorn.UnicornException;

/** Test miscellaneous features that don't fall into the register, memory
 * or hook API */
public class FunctionalityTests {

    @Test
    public void testStatics() {
        assertEquals(true, Unicorn.arch_supported(Unicorn.UC_ARCH_X86));
        assertEquals(false, Unicorn.arch_supported(Unicorn.UC_ARCH_MAX + 1));
        assertTrue("version check", Unicorn.version() >= 0x02000100);
        assertEquals("OK (UC_ERR_OK)", Unicorn.strerror(Unicorn.UC_ERR_OK));
        assertEquals("Invalid handle (UC_ERR_HANDLE)",
            Unicorn.strerror(Unicorn.UC_ERR_HANDLE));
    }

    @Test
    public void testCreation() {
        assertThrows(UnicornException.class,
            () -> new Unicorn(Unicorn.UC_ARCH_MAX + 1, 0));

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_X86)) {
            new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_16);
            new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
            new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_64);
            assertThrows(UnicornException.class,
                () -> new Unicorn(Unicorn.UC_ARCH_X86,
                    Unicorn.UC_MODE_BIG_ENDIAN));
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_M68K)) {
            new Unicorn(Unicorn.UC_ARCH_M68K, Unicorn.UC_MODE_BIG_ENDIAN);
            assertThrows(UnicornException.class,
                () -> new Unicorn(Unicorn.UC_ARCH_M68K,
                    Unicorn.UC_MODE_LITTLE_ENDIAN));
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_ARM)) {
            new Unicorn(Unicorn.UC_ARCH_ARM, 0);
            new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_BIG_ENDIAN);
            new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_THUMB);
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_ARM64)) {
            new Unicorn(Unicorn.UC_ARCH_ARM64, 0);
            new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_BIG_ENDIAN);
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_MIPS)) {
            new Unicorn(Unicorn.UC_ARCH_MIPS,
                Unicorn.UC_MODE_BIG_ENDIAN | Unicorn.UC_MODE_32);
            new Unicorn(Unicorn.UC_ARCH_MIPS,
                Unicorn.UC_MODE_LITTLE_ENDIAN | Unicorn.UC_MODE_32);
            new Unicorn(Unicorn.UC_ARCH_MIPS,
                Unicorn.UC_MODE_BIG_ENDIAN | Unicorn.UC_MODE_64);
            new Unicorn(Unicorn.UC_ARCH_MIPS,
                Unicorn.UC_MODE_LITTLE_ENDIAN | Unicorn.UC_MODE_64);
            assertThrows(UnicornException.class,
                () -> new Unicorn(Unicorn.UC_ARCH_MIPS, Unicorn.UC_MODE_16));
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_SPARC)) {
            new Unicorn(Unicorn.UC_ARCH_SPARC,
                Unicorn.UC_MODE_BIG_ENDIAN | Unicorn.UC_MODE_32);
            new Unicorn(Unicorn.UC_ARCH_SPARC,
                Unicorn.UC_MODE_BIG_ENDIAN | Unicorn.UC_MODE_64);
            assertThrows(UnicornException.class,
                () -> new Unicorn(Unicorn.UC_ARCH_SPARC,
                    Unicorn.UC_MODE_LITTLE_ENDIAN | Unicorn.UC_MODE_32));
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_PPC)) {
            new Unicorn(Unicorn.UC_ARCH_PPC,
                Unicorn.UC_MODE_BIG_ENDIAN | Unicorn.UC_MODE_32);
            new Unicorn(Unicorn.UC_ARCH_PPC,
                Unicorn.UC_MODE_BIG_ENDIAN | Unicorn.UC_MODE_64);
            assertThrows(UnicornException.class,
                () -> new Unicorn(Unicorn.UC_ARCH_PPC,
                    Unicorn.UC_MODE_LITTLE_ENDIAN | Unicorn.UC_MODE_32));
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_RISCV)) {
            new Unicorn(Unicorn.UC_ARCH_RISCV, Unicorn.UC_MODE_32);
            new Unicorn(Unicorn.UC_ARCH_RISCV, Unicorn.UC_MODE_64);
        }

        if (Unicorn.arch_supported(Unicorn.UC_ARCH_S390X)) {
            new Unicorn(Unicorn.UC_ARCH_S390X, Unicorn.UC_MODE_BIG_ENDIAN);
            assertThrows(UnicornException.class,
                () -> new Unicorn(Unicorn.UC_ARCH_S390X,
                    Unicorn.UC_MODE_LITTLE_ENDIAN));

            new Unicorn(Unicorn.UC_ARCH_TRICORE, 0);
        }
    }

    @Test
    public void testThreading() {
        // EB FE - label: jmp label
        final byte[] X86_CODE = { -21, -2 };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, X86_CODE);
        new Thread(() -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            u.emu_stop();
        }).start();
        u.emu_start(ADDRESS, ADDRESS + X86_CODE.length, 0, 0);
    }

    @Test
    public void testContext() {
        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xdeadbeefL);
        Unicorn.Context ctx = uc.context_save();
        assertEquals(0xdeadbeefL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xdeadbeefL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xfeedfaceL);
        assertEquals(0xfeedfaceL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xdeadbeefL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.context_restore(ctx);
        assertEquals(0xdeadbeefL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xdeadbeefL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xfee1deadL);
        assertEquals(0xfee1deadL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xdeadbeefL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.context_update(ctx);
        assertEquals(0xfee1deadL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xfee1deadL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xdeadbeefL);
        assertEquals(0xdeadbeefL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xfee1deadL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.context_restore(ctx);
        assertEquals(0xfee1deadL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        assertEquals(0xfee1deadL, ctx.reg_read(Unicorn.UC_ARM64_REG_X0));
    }

    @Test
    public void testOldContext() {
        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xdeadbeefL);
        long ctx = uc.context_alloc();
        uc.context_save(ctx);
        assertEquals(0xdeadbeefL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xfeedfaceL);
        assertEquals(0xfeedfaceL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.context_restore(ctx);
        assertEquals(0xdeadbeefL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xfee1deadL);
        assertEquals(0xfee1deadL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.context_save(ctx);
        assertEquals(0xfee1deadL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xdeadbeefL);
        assertEquals(0xdeadbeefL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.context_restore(ctx);
        assertEquals(0xfee1deadL, uc.reg_read(Unicorn.UC_ARM64_REG_X0));

        uc.free(ctx);
    }
}
