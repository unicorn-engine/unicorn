package samples;

import java.util.Arrays;

import unicorn.*;

public class Sample_ctl implements UnicornConst, X86Const {
    /** Code to be emulated
     * <pre>
     *   cmp eax, 0;
     *   jg lb;
     *   inc eax;
     *   nop;
     * lb:
     *   inc ebx;
     *   nop;
     * </pre>
     */
    private static final byte[] X86_JUMP_CODE =
        Utils.hexToBytes("83f8007f0240904390");

    /** memory address where emulation starts */
    private static final long ADDRESS = 0x10000;

    public static void test_uc_ctl_read() {
        System.out.println("Reading some properties by uc_ctl.");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // Let's query some properties by uc_ctl.
        int mode = uc.ctl_get_mode();
        int arch = uc.ctl_get_arch();
        long timeout = uc.ctl_get_timeout();
        int pagesize = uc.ctl_get_page_size();

        System.out.format(">>> mode = %d, arch = %d, timeout=%d, pagesize=%d\n",
            mode, arch, timeout, pagesize);
    }

    private static final EdgeGeneratedHook trace_new_edge =
        (uc, cur, prev, data) -> {
            System.out.format(">>> Getting a new edge from 0x%x to 0x%x.\n",
                prev.pc + prev.size - 1, cur.pc);
        };

    public static void test_uc_ctl_exits() {
        long r_eax, r_ebx;
        long exits[] = { ADDRESS + 6, ADDRESS + 8 };

        System.out.println("Using multiple exits by uc_ctl.");

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        uc.mem_map(ADDRESS, 0x1000, UC_PROT_ALL);

        // Write our code to the memory.
        uc.mem_write(ADDRESS, X86_JUMP_CODE);

        // We trace if any new edge is generated.
        uc.hook_add(trace_new_edge, 1, 0, null);

        // Enable multiple exits.
        uc.ctl_exits_enabled(true);
        uc.ctl_set_exits(exits);

        // This should stop at ADDRESS + 6 and increase eax, even thouhg we don't
        // provide an exit.
        uc.emu_start(ADDRESS, 0, 0, 0);

        r_eax = uc.reg_read(UC_X86_REG_EAX);
        r_ebx = uc.reg_read(UC_X86_REG_EBX);
        System.out.format(
            ">>> eax = %d and ebx = %d after the first emulation\n",
            r_eax, r_ebx);

        // This should stop at ADDRESS + 8, even though we don't provide an exit.
        uc.emu_start(ADDRESS, 0, 0, 0);

        r_eax = uc.reg_read(UC_X86_REG_EAX);
        r_ebx = uc.reg_read(UC_X86_REG_EBX);
        System.out.format(
            ">>> eax = %d and ebx = %d after the second emulation\n",
            r_eax, r_ebx);
    }

    private static final int TB_COUNT = 8;
    private static final int TCG_MAX_INSNS = 512; // from tcg.h
    private static final int CODE_LEN = TB_COUNT * TCG_MAX_INSNS;

    private static double time_emulation(Unicorn uc, long start, long end) {
        long t1 = System.nanoTime();
        uc.emu_start(start, end, 0, 0);
        long t2 = System.nanoTime();
        return (t2 - t1) / 1000000.0;
    }

    public static void test_uc_ctl_tb_cache() {
        byte[] code = new byte[CODE_LEN];
        double standard, cached, evicted;

        System.out.println(
            "Controlling the TB cache in a finer granularity by uc_ctl.");

        // Fill the code buffer with NOP.
        Arrays.fill(code, (byte) 0x90);

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        uc.mem_map(ADDRESS, 0x10000, UC_PROT_ALL);

        // Write our code to the memory.
        uc.mem_write(ADDRESS, code);

        // We trace if any new edge is generated.
        // Note: In this sample, there is only **one** basic block while muliple
        // translation blocks is generated due to QEMU tcg buffer limit. In this
        // case, we don't consider it as a new edge.
        uc.hook_add(trace_new_edge, 1, 0, null);

        // Do emulation without any cache.
        standard = time_emulation(uc, ADDRESS, ADDRESS + CODE_LEN);

        // Now we request cache for all TBs.
        for (int i = 0; i < TB_COUNT; i++) {
            TranslationBlock tb =
                uc.ctl_request_cache(ADDRESS + i * TCG_MAX_INSNS);
            System.out.format(
                ">>> TB is cached at 0x%x which has %d instructions with %d bytes.\n",
                tb.pc, tb.icount, tb.size);
        }

        // Do emulation with all TB cached.
        cached = time_emulation(uc, ADDRESS, ADDRESS + CODE_LEN);

        // Now we clear cache for all TBs.
        for (int i = 0; i < TB_COUNT; i++) {
            uc.ctl_remove_cache(ADDRESS + i * TCG_MAX_INSNS,
                ADDRESS + i * TCG_MAX_INSNS + 1);
        }

        // Do emulation with all TB cache evicted.
        evicted = time_emulation(uc, ADDRESS, ADDRESS + CODE_LEN);

        System.out.format(
            ">>> Run time: First time: %fms, Cached: %fms, Cache evicted: %fms\n",
            standard, cached, evicted);
    }

    public static final void main(String[] args) {
        test_uc_ctl_read();
        System.out.println("====================");
        test_uc_ctl_exits();
        System.out.println("====================");
        test_uc_ctl_tb_cache();
    }
}
