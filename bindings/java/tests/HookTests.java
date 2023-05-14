package tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

import unicorn.CodeHook;
import unicorn.EdgeGeneratedHook;
import unicorn.TlbFillHook;
import unicorn.TranslationBlock;
import unicorn.Unicorn;
import unicorn.UnicornException;

public class HookTests {
    private static void assertTranslationBlock(TranslationBlock expected,
            TranslationBlock actual) {
        assertEquals(expected.pc, actual.pc);
        assertEquals(expected.icount, actual.icount);
        assertEquals(expected.size, actual.size);
    }

    @Test
    public void testEdgeHook() {
        /*
        00000000  83FB01            cmp ebx,byte +0x1
        00000003  7405              jz 0xa
        00000005  B802000000        mov eax,0x2
        0000000A  40                inc eax
        0000000B  EBFE              jmp short 0xb
        */
        final byte[] X86_CODE =
            { -125, -5, 1, 116, 5, -72, 2, 0, 0, 0, 64, -21, -2 };
        final TranslationBlock[] expectedTb = { null, null };

        long ADDRESS = 0x100000;

        Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
        u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
        u.mem_write(ADDRESS, X86_CODE);
        expectedTb[1] = new TranslationBlock(ADDRESS, 2, 5);
        u.hook_add((EdgeGeneratedHook) (uc, cur_tb, prev_tb, user) -> {
            assertTranslationBlock(expectedTb[0], cur_tb);
            assertTranslationBlock(expectedTb[1], prev_tb);
            assertEquals("user data", user);
        }, ADDRESS, ADDRESS + 10, "user data");

        // TODO(nneonneo): why is icount 2/3 in the subsequent blocks?
        expectedTb[0] = new TranslationBlock(ADDRESS + 10, 2, 1);
        u.reg_write(Unicorn.UC_X86_REG_EBX, 1);
        u.emu_start(ADDRESS, ADDRESS + 11, 0, 0);

        expectedTb[0] = new TranslationBlock(ADDRESS + 5, 3, 6);
        u.reg_write(Unicorn.UC_X86_REG_EBX, 0);
        u.emu_start(ADDRESS, ADDRESS + 11, 0, 0);

        assertTranslationBlock(new TranslationBlock(ADDRESS, 2, 5),
            u.ctl_request_cache(ADDRESS));
        // TODO(nneonneo): I don't totally understand this output! Why 8 bytes at address 5?
        assertTranslationBlock(new TranslationBlock(ADDRESS + 5, 3, 8),
            u.ctl_request_cache(ADDRESS + 5));
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
    }
}
