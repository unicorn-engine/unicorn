package samples;

import unicorn.*;

public class Sample_mmu implements UnicornConst, X86Const {
    /** Code:
     * <pre>
     * mov rax, 57
     * syscall
     * test rax, rax
     * jz child
     * xor rax, rax
     * mov rax, 60
     * mov [0x4000], rax
     * syscall
     *
     * child:
     * xor rcx, rcx
     * mov rcx, 42
     * mov [0x4000], rcx
     * mov rax, 60
     * syscall
     * </pre>
     */
    private static final byte[] CODE = Utils.hexToBytes(
        "B8390000000F054885C0740FB83C00000048890425004000000F05B92A00000048890C2500400000B83C0000000F05");

    private static final MemHook mmu_write_callback =
        (uc, type, address, size, value, user_data) -> {
            System.out.format("write at 0x%x: 0x%x\n", address, value);
        };

    private static void x86_mmu_prepare_tlb(Unicorn uc, long vaddr,
            long tlb_base) {
        long cr0;
        long cr4;
        X86_MSR msr = new X86_MSR(0xC0000080);
        long pml4o = ((vaddr & 0x00ff8000000000L) >> 39) * 8;
        long pdpo = ((vaddr & 0x00007fc0000000L) >> 30) * 8;
        long pdo = ((vaddr & 0x0000003fe00000L) >> 21) * 8;
        long pml4e = (tlb_base + 0x1000L) | 1 | (1 << 2);
        long pdpe = (tlb_base + 0x2000L) | 1 | (1 << 2);
        long pde = (tlb_base + 0x3000L) | 1 | (1 << 2);
        uc.mem_write(tlb_base + pml4o, Utils.toBytes(pml4e));
        uc.mem_write(tlb_base + 0x1000 + pdpo, Utils.toBytes(pdpe));
        uc.mem_write(tlb_base + 0x2000 + pdo, Utils.toBytes(pde));
        uc.reg_write(UC_X86_REG_CR3, tlb_base);
        cr0 = uc.reg_read(UC_X86_REG_CR0);
        cr4 = uc.reg_read(UC_X86_REG_CR4);
        msr.value = (Long) uc.reg_read(UC_X86_REG_MSR, msr);

        cr0 |= 1;                   //enable protected mode
        cr0 |= 1l << 31;            //enable paging
        cr4 |= 1l << 5;             //enable physical address extension
        msr.value |= 1l << 8;       //enable long mode

        uc.reg_write(UC_X86_REG_CR0, cr0);
        uc.reg_write(UC_X86_REG_CR4, cr4);
        uc.reg_write(UC_X86_REG_MSR, msr);
    }

    private static void x86_mmu_pt_set(Unicorn uc, long vaddr, long paddr,
            long tlb_base) {
        long pto = ((vaddr & 0x000000001ff000L) >> 12) * 8;
        long pte = (paddr) | 1 | (1 << 2);
        uc.mem_write(tlb_base + 0x3000 + pto, Utils.toBytes((int) pte));
    }

    private static SyscallHook x86_mmu_syscall_callback = (uc, userdata) -> {
        boolean[] parent_done = (boolean[]) userdata;
        long rax = uc.reg_read(UC_X86_REG_RAX);
        switch ((int) rax) {
        case 57:
            /* fork */
            break;
        case 60:
            /* exit */
            parent_done[0] = true;
            uc.emu_stop();
            return;
        default:
            System.out.println("unknown syscall");
            System.exit(1);
        }

        if (!parent_done[0]) {
            rax = 27;
            uc.reg_write(UC_X86_REG_RAX, rax);
            uc.emu_stop();
        }
    };

    public static void cpu_tlb() {
        long tlb_base = 0x3000;
        long rip;
        boolean[] parent_done = { false };

        System.out.println(
            "Emulate x86 amd64 code with mmu enabled and switch mappings");

        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_64);
        uc.ctl_tlb_mode(UC_TLB_CPU);
        Unicorn.Context context = uc.context_save();

        uc.hook_add(x86_mmu_syscall_callback, UC_X86_INS_SYSCALL, 1, 0,
            parent_done);

        // Memory hooks are called after the mmu translation, so hook the physicall addresses
        uc.hook_add(mmu_write_callback, UC_HOOK_MEM_WRITE, 0x1000, 0x3000,
            null);

        System.out.println("map code");
        uc.mem_map(0x0, 0x1000, UC_PROT_ALL); // Code
        uc.mem_write(0x0, CODE);
        System.out.println("map parent memory");
        uc.mem_map(0x1000, 0x1000, UC_PROT_ALL); // Parrent
        System.out.println("map child memory");
        uc.mem_map(0x2000, 0x1000, UC_PROT_ALL); // Child
        System.out.println("map tlb memory");
        uc.mem_map(tlb_base, 0x4000, UC_PROT_ALL); // TLB

        System.out.println("set up the tlb");
        x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
        x86_mmu_pt_set(uc, 0x2000, 0x0, tlb_base);
        x86_mmu_pt_set(uc, 0x4000, 0x1000, tlb_base);

        uc.ctl_flush_tlb();
        System.out.println("run the parent");
        uc.emu_start(0x2000, 0x0, 0, 0);

        System.out.println("save the context for the child");
        uc.context_update(context);
        System.out.println("finish the parent");
        rip = uc.reg_read(UC_X86_REG_RIP);

        uc.emu_start(rip, 0x0, 0, 0);

        System.out.println("restore the context for the child");
        uc.context_restore(context);
        x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
        x86_mmu_pt_set(uc, 0x4000, 0x2000, tlb_base);
        uc.reg_write(UC_X86_REG_RAX, 0L);
        uc.ctl_flush_tlb();

        uc.emu_start(rip, 0x0, 0, 0);
        long parent = Utils.toLong(uc.mem_read(0x1000, Long.BYTES));
        long child = Utils.toLong(uc.mem_read(0x2000, Long.BYTES));
        System.out.format("parent result == %d\n", parent);
        System.out.format("child result == %d\n", child);
    }

    private static final TlbFillHook virtual_tlb_callback =
        (uc, addr, type, user_data) -> {
            boolean[] parent_done = (boolean[]) user_data;
            System.out.format("tlb lookup for address: 0x%X\n", addr);
            switch ((int) (addr & ~(0xfffL))) {
            case 0x2000:
                return 0x0L | UC_PROT_EXEC;
            case 0x4000:
                if (parent_done[0]) {
                    return (0x2000L) | UC_PROT_READ | UC_PROT_WRITE;
                } else {
                    return (0x1000L) | UC_PROT_READ | UC_PROT_WRITE;
                }
            default:
                return -1L;
            }
        };

    public static void virtual_tlb() {
        long rip;
        boolean[] parent_done = { false };

        System.out.println("Emulate x86 amd64 code with virtual mmu");
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_64);
        uc.ctl_tlb_mode(UC_TLB_VIRTUAL);
        Unicorn.Context context = uc.context_save();

        uc.hook_add(x86_mmu_syscall_callback, UC_X86_INS_SYSCALL, 1, 0,
            parent_done);

        // Memory hooks are called after the mmu translation, so hook the physicall addresses
        uc.hook_add(mmu_write_callback, UC_HOOK_MEM_WRITE, 0x1000, 0x3000,
            null);

        System.out.println("map code");
        uc.mem_map(0x0, 0x1000, UC_PROT_ALL); // Code
        uc.mem_write(0x0, CODE);
        System.out.println("map parent memory");
        uc.mem_map(0x1000, 0x1000, UC_PROT_ALL); // Parrent
        System.out.println("map child memory");
        uc.mem_map(0x2000, 0x1000, UC_PROT_ALL); // Child

        uc.hook_add(virtual_tlb_callback, 1, 0, parent_done);

        System.out.println("run the parent");
        uc.emu_start(0x2000, 0x0, 0, 0);

        System.out.println("save the context for the child");
        uc.context_update(context);
        System.out.println("finish the parent");
        rip = uc.reg_read(UC_X86_REG_RIP);

        uc.emu_start(rip, 0x0, 0, 0);

        System.out.println("restore the context for the child");
        uc.context_restore(context);
        parent_done[0] = true;
        uc.reg_write(UC_X86_REG_RAX, 0);
        uc.ctl_flush_tlb();

        uc.emu_start(rip, 0x0, 0, 0);
        long parent = Utils.toLong(uc.mem_read(0x1000, Long.BYTES));
        long child = Utils.toLong(uc.mem_read(0x2000, Long.BYTES));
        System.out.format("parent result == %d\n", parent);
        System.out.format("child result == %d\n", child);
    }

    public static final void main(String[] args) {
        cpu_tlb();
        System.out.println("------------------");
        virtual_tlb();
    }
}
