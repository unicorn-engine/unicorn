package tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import unicorn.CodeHook;
import unicorn.MemRegion;
import unicorn.TlbFillHook;
import unicorn.Unicorn;
import unicorn.UnicornException;
import unicorn.X86_Float80;

public class FunctionalityTests {
    @Test
    public void testMemRegions() {
        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        long ADDR1 = 0x10000;
        long ADDR2 = 0xdeadbeeffeed1000L;
        uc.mem_map(ADDR1, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        uc.mem_map(ADDR2, 4096, Unicorn.UC_PROT_READ);
        MemRegion[] arr = uc.mem_regions();
        assertEquals("two memory regions", 2, arr.length);
        assertEquals("begin", ADDR1, arr[0].begin);
        assertEquals("end", ADDR1 + 2 * 1024 * 1024 - 1, arr[0].end);
        assertEquals("perms", Unicorn.UC_PROT_ALL, arr[0].perms);
        assertEquals("begin", ADDR2, arr[1].begin);
        assertEquals("end", ADDR2 + 4096 - 1, arr[1].end);
        assertEquals("perms", Unicorn.UC_PROT_READ, arr[1].perms);
        uc.close();
    }

    @Test
    public void testContext() {
        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xdeadbeef);
        Unicorn.Context ctx = uc.context_save();
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xfeedface);
        assertEquals("X0 changed", 0xfeedface,
            uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        uc.context_restore(ctx);
        assertEquals("X0 restored", 0xdeadbeef,
            uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xfee1dead);
        uc.context_update(ctx);
        assertEquals("X0 changed", 0xfee1dead,
            uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        uc.reg_write(Unicorn.UC_ARM64_REG_X0, 0xdeadbeef);
        assertEquals("X0 changed", 0xdeadbeef,
            uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        uc.context_restore(ctx);
        assertEquals("X0 restored", 0xfee1dead,
            uc.reg_read(Unicorn.UC_ARM64_REG_X0));
        uc.close();
    }

    @Test
    public void testMmio() {
        // mov ecx, [0xaaaaaaa8]; inc ecx; dec edx; mov [0xaaaaaaa8], ecx; inc ecx; dec edx
        final byte[] X86_CODE32_MEM_READ_WRITE =
            { -117, 13, -88, -86, -86, -86, 65, 74, -119, 13, -88, -86, -86,
                -86, 65, 74 };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        // map 2MB memory for this emulation
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);

        // write machine code to be emulated to memory
        u.mem_write(ADDRESS, X86_CODE32_MEM_READ_WRITE);

        // initialize machine registers
        u.reg_write(Unicorn.UC_X86_REG_ECX, 0x12345678);
        u.reg_write(Unicorn.UC_X86_REG_EDX, 0x22334455);

        u.mmio_map(0xaaaaa000L, 0x1000, (uc, offset, size, user_data) -> {
            assertEquals("read offset", 0xaa8, offset);
            assertEquals("read size", 4, size);
            assertEquals("read user_data", "read_data", user_data);
            return 0x44556677;
        }, "read_data", (uc, offset, size, value, user_data) -> {
            assertEquals("write offset", 0xaa8, offset);
            assertEquals("write size", 4, size);
            assertEquals("write value", 0x44556678, value);
            assertEquals("write user_data", "write_data", user_data);
        }, "write_data");

        u.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_READ_WRITE.length, 0, 0);

        assertEquals("ecx", 0x44556679, u.reg_read(Unicorn.UC_X86_REG_ECX));
        assertEquals("edx", 0x22334453, u.reg_read(Unicorn.UC_X86_REG_EDX));

        u.close();
    }

    @Test
    public void testMemMapPtr() {
        ByteBuffer buffer =
            ByteBuffer.allocateDirect(0x1000).order(ByteOrder.LITTLE_ENDIAN);
        final byte[] X86_CODE32_MEM_WRITE =
            { -119, 13, -86, -86, -86, -86, 65, 74 };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_map_ptr(0xaaaaa000L, buffer, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, X86_CODE32_MEM_WRITE);
        u.reg_write(Unicorn.UC_X86_REG_ECX, 0x12345678);
        u.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_WRITE.length, 0, 0);

        assertEquals("buffer contents", 0x12345678, buffer.getInt(0xaaa));

        u.close();
    }

    @Test
    public void testTlbHook() {
        // mov ecx, [0xaaaaaaa8]
        final byte[] X86_CODE32_MEM_READ = { -117, 13, -88, -86, -86, -86 };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_map(0xbbbbb000L, 0x1000, Unicorn.UC_PROT_READ);
        u.hook_add((TlbFillHook) (uc, address, type, user_data) -> {
            assertEquals("fill hook address", 0xaaaaa000L, address);
            assertEquals("fill hook type", Unicorn.UC_MEM_READ, type);
            assertEquals("fill hook user", "fill_hook", user_data);
            return 0xbbbbb000L | Unicorn.UC_PROT_READ;
        }, 0xaaaaa000L, 0xaaaab000L, "fill_hook");
        u.mem_write(ADDRESS, X86_CODE32_MEM_READ);
        u.mem_write(0xbbbbbaa8L, new byte[] { 1, 2, 3, 4 });
        u.reg_write(Unicorn.UC_X86_REG_ECX, 0x12345678);
        u.ctl_tlb_mode(Unicorn.UC_TLB_VIRTUAL);
        u.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_READ.length, 0, 0);
        assertEquals("ecx", u.reg_read(Unicorn.UC_X86_REG_ECX), 0x04030201);

        u.close();
    }

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
    public void testRemoveHook() {
        byte[] X86_CODE = { 0x40, 0x40, 0x40, 0x40 }; // (inc eax) x 4
        int ADDRESS = 0x10000;
        final int[] hook_accum = { 0 };

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, X86_CODE);

        CodeHook hook =
            (uc, address, size, user) -> hook_accum[0] += (int) user;
        long h1 = u.hook_add(hook, ADDRESS, ADDRESS, 1);
        long h2 = u.hook_add(hook, ADDRESS + 1, ADDRESS + 1, 2);
        long h3 = u.hook_add(hook, ADDRESS + 2, ADDRESS + 2, 4);
        long h4 = u.hook_add(hook, ADDRESS + 3, ADDRESS + 3, 8);

        hook_accum[0] = 0;
        u.emu_start(ADDRESS, ADDRESS + X86_CODE.length, 0, 0);
        assertEquals(15, hook_accum[0]);

        u.hook_del(h2);

        hook_accum[0] = 0;
        u.emu_start(ADDRESS, ADDRESS + X86_CODE.length, 0, 0);
        assertEquals(13, hook_accum[0]);

        u.hook_del(hook);

        hook_accum[0] = 0;
        u.emu_start(ADDRESS, ADDRESS + X86_CODE.length, 0, 0);
        assertEquals(0, hook_accum[0]);

        assertThrows(UnicornException.class, () -> u.hook_del(h1));
        assertThrows(UnicornException.class, () -> u.hook_del(h3));
        assertThrows(UnicornException.class, () -> u.hook_del(h4));

        u.close();
    }
}
