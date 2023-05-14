package tests;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import unicorn.MemRegion;
import unicorn.Unicorn;

public class MemTests {
    private static void assertMemRegion(long address, long size,
            int perms, MemRegion actual) {
        assertEquals(address, actual.begin);
        assertEquals(address + size - 1, actual.end);
        assertEquals(perms, actual.perms);
    }

    @Test
    public void testMemRegions() {
        Unicorn uc = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
        long ADDR1 = 0x10000;
        long ADDR2 = 0xdeadbeeffeed1000L;
        uc.mem_map(ADDR1, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        uc.mem_map(ADDR2, 4096, Unicorn.UC_PROT_READ);
        MemRegion[] arr = uc.mem_regions();
        assertEquals("two memory regions", 2, arr.length);
        assertMemRegion(ADDR1, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL, arr[0]);
        assertMemRegion(ADDR2, 4096, Unicorn.UC_PROT_READ, arr[1]);
    }

    @Test
    public void testMemRegions2() {
        Unicorn u = new Unicorn(Unicorn.UC_ARCH_TRICORE, 0);
        u.mem_map(0x10000, 0x10000, Unicorn.UC_PROT_ALL);
        u.mem_map(0x30000, 0x10000, Unicorn.UC_PROT_READ);
        u.mem_map(0x50000, 0x10000,
            Unicorn.UC_PROT_READ | Unicorn.UC_PROT_WRITE);
        u.mem_map(0x70000, 0x20000, 0);
        u.mem_protect(0x80000, 0x10000, Unicorn.UC_PROT_EXEC);

        ByteBuffer buf = ByteBuffer.allocateDirect(0x10000);
        u.mem_map_ptr(0x110000, buf, Unicorn.UC_PROT_ALL);

        u.mmio_map(0x210000, 0x10000,
            (uc, offset, size, user_data) -> 0x41414141,
            null, (uc, offset, size, value, user_data) -> {
            }, null);
        u.mmio_map(0x230000, 0x10000,
            (uc, offset, size, user_data) -> 0x41414141,
            null, null, null);
        u.mmio_map(0x250000, 0x10000, null, null,
            (uc, offset, size, value, user_data) -> {
            }, null);
        u.mmio_map(0x270000, 0x10000, null, null, null, null);

        MemRegion[] mrs = u.mem_regions();
        assertEquals(10, mrs.length);
        assertMemRegion(0x10000, 0x10000, Unicorn.UC_PROT_ALL, mrs[0]);
        assertMemRegion(0x30000, 0x10000, Unicorn.UC_PROT_READ, mrs[1]);
        assertMemRegion(0x50000, 0x10000,
            Unicorn.UC_PROT_READ | Unicorn.UC_PROT_WRITE, mrs[2]);
        assertMemRegion(0x70000, 0x10000, Unicorn.UC_PROT_NONE, mrs[3]);
        assertMemRegion(0x80000, 0x10000, Unicorn.UC_PROT_EXEC, mrs[4]);
        assertMemRegion(0x110000, 0x10000, Unicorn.UC_PROT_ALL, mrs[5]);
        assertMemRegion(0x210000, 0x10000,
            Unicorn.UC_PROT_READ | Unicorn.UC_PROT_WRITE, mrs[6]);
        assertMemRegion(0x230000, 0x10000, Unicorn.UC_PROT_READ, mrs[7]);
        assertMemRegion(0x250000, 0x10000, Unicorn.UC_PROT_WRITE, mrs[8]);
        assertMemRegion(0x270000, 0x10000, Unicorn.UC_PROT_NONE, mrs[9]);
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
    }
}
