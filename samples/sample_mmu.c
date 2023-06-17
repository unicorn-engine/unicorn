#include <unicorn/unicorn.h>
#include <stdio.h>

/*
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
 */
char code[] = "\xB8\x39\x00\x00\x00\x0F\x05\x48\x85\xC0\x74\x0F\xB8\x3C\x00\x00"
              "\x00\x48\x89\x04\x25\x00\x40\x00\x00\x0F\x05\xB9\x2A\x00\x00\x00"
              "\x48\x89\x0C\x25\x00\x40\x00\x00\xB8\x3C\x00\x00\x00\x0F\x05";

static void mmu_write_callback(uc_engine *uc, uc_mem_type type,
                               uint64_t address, int size, int64_t value,
                               void *user_data)
{
    printf("write at 0x%lx: 0x%lx\n", address, value);
}

static void x86_mmu_prepare_tlb(uc_engine *uc, uint64_t vaddr,
                                uint64_t tlb_base)
{
    uc_err err;
    uint64_t cr0;
    uint64_t cr4;
    uc_x86_msr msr = {.rid = 0xC0000080, .value = 0};
    uint64_t pml4o = ((vaddr & 0x00ff8000000000) >> 39) * 8;
    uint64_t pdpo = ((vaddr & 0x00007fc0000000) >> 30) * 8;
    uint64_t pdo = ((vaddr & 0x0000003fe00000) >> 21) * 8;
    uint64_t pml4e = (tlb_base + 0x1000) | 1 | (1 << 2);
    uint64_t pdpe = (tlb_base + 0x2000) | 1 | (1 << 2);
    uint64_t pde = (tlb_base + 0x3000) | 1 | (1 << 2);
    err = uc_mem_write(uc, tlb_base + pml4o, &pml4e, sizeof(pml4o));
    if (err) {
        printf("failed to write pml4e\n");
        exit(1);
    }
    err = uc_mem_write(uc, tlb_base + 0x1000 + pdpo, &pdpe, sizeof(pdpe));
    if (err) {
        printf("failed to write pml4e\n");
        exit(1);
    }
    err = uc_mem_write(uc, tlb_base + 0x2000 + pdo, &pde, sizeof(pde));
    if (err) {
        printf("failed to write pde\n");
        exit(1);
    }
    err = uc_reg_write(uc, UC_X86_REG_CR3, &tlb_base);
    if (err) {
        printf("failed to write CR3\n");
        exit(1);
    }
    err = uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    if (err) {
        printf("failed to read CR0\n");
        exit(1);
    }
    err = uc_reg_read(uc, UC_X86_REG_CR4, &cr4);
    if (err) {
        printf("failed to read CR4\n");
        exit(1);
    }
    err = uc_reg_read(uc, UC_X86_REG_MSR, &msr);
    if (err) {
        printf("failed to read MSR\n");
        exit(1);
    }

    cr0 |= 1;             // enable protected mode
    cr0 |= 1l << 31;      // enable paging
    cr4 |= 1l << 5;       // enable physical address extension
    msr.value |= 1l << 8; // enable long mode

    err = uc_reg_write(uc, UC_X86_REG_CR0, &cr0);
    if (err) {
        printf("failed to write CR0\n");
        exit(1);
    }
    err = uc_reg_write(uc, UC_X86_REG_CR4, &cr4);
    if (err) {
        printf("failed to write CR4\n");
        exit(1);
    }
    err = uc_reg_write(uc, UC_X86_REG_MSR, &msr);
    if (err) {
        printf("failed to write MSR\n");
        exit(1);
    }
}

static void x86_mmu_pt_set(uc_engine *uc, uint64_t vaddr, uint64_t paddr,
                           uint64_t tlb_base)
{
    uint64_t pto = ((vaddr & 0x000000001ff000) >> 12) * 8;
    uint32_t pte = (paddr) | 1 | (1 << 2);
    uc_mem_write(uc, tlb_base + 0x3000 + pto, &pte, sizeof(pte));
}

static void x86_mmu_syscall_callback(uc_engine *uc, void *userdata)
{
    uc_err err;
    bool *parrent_done = userdata;
    uint64_t rax;
    err = uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    if (err) {
        printf("failed to read rax\n");
        exit(1);
    }
    switch (rax) {
    case 57:
        /* fork */
        break;
    case 60:
        /* exit */
        *parrent_done = true;
        uc_emu_stop(uc);
        return;
    default:
        printf("unknown syscall");
        exit(1);
    }

    if (!(*parrent_done)) {
        rax = 27;
        err = uc_reg_write(uc, UC_X86_REG_RAX, &rax);
        if (err) {
            printf("failed to write rax\n");
            exit(1);
        }
        uc_emu_stop(uc);
    }
}

void cpu_tlb(void)
{
    uint64_t tlb_base = 0x3000;
    uint64_t rax, rip;
    bool parrent_done = false;
    uint64_t parrent, child;
    uc_context *context;
    uc_engine *uc;
    uc_err err;
    uc_hook h1, h2;

    printf("Emulate x86 amd64 code with mmu enabled and switch mappings\n");

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        exit(1);
    }
    uc_ctl_tlb_mode(uc, UC_TLB_CPU);
    err = uc_context_alloc(uc, &context);
    if (err) {
        printf("Failed on uc_context_alloc() with error returned: %u\n", err);
        exit(1);
    }

    err = uc_hook_add(uc, &h1, UC_HOOK_INSN, &x86_mmu_syscall_callback,
                      &parrent_done, 1, 0, UC_X86_INS_SYSCALL);
    if (err) {
        printf("Failed on uc_hook_add() with error returned: %u\n", err);
        exit(1);
    }

    // Memory hooks are called after the mmu translation, so hook the physicall
    // addresses
    err = uc_hook_add(uc, &h2, UC_HOOK_MEM_WRITE, &mmu_write_callback, NULL,
                      0x1000, 0x3000);
    if (err) {
        printf("Faled on uc_hook_add() with error returned: %u\n", err);
    }

    printf("map code\n");
    err = uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL); // Code
    if (err) {
        printf("Failed on uc_mem_map() with error return: %u\n", err);
        exit(1);
    }
    err = uc_mem_write(uc, 0x0, code, sizeof(code) - 1);
    if (err) {
        printf("Failed on uc_mem_wirte() with error return: %u\n", err);
        exit(1);
    }
    printf("map parrent memory\n");
    err = uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL); // Parrent
    if (err) {
        printf("Failed on uc_mem_map() with error return: %u\n", err);
        exit(1);
    }
    printf("map child memory\n");
    err = uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL); // Child
    if (err) {
        printf("failed to map child memory\n");
        exit(1);
    }
    printf("map tlb memory\n");
    err = uc_mem_map(uc, tlb_base, 0x4000, UC_PROT_ALL); // TLB
    if (err) {
        printf("failed to map memory for tlb\n");
        exit(1);
    }

    printf("set up the tlb\n");
    x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    x86_mmu_pt_set(uc, 0x2000, 0x0, tlb_base);
    x86_mmu_pt_set(uc, 0x4000, 0x1000, tlb_base);

    err = uc_ctl_flush_tlb(uc);
    if (err) {
        printf("failed to flush tlb\n");
        exit(1);
    }
    printf("run the parrent\n");
    err = uc_emu_start(uc, 0x2000, 0x0, 0, 0);
    if (err) {
        printf("failed to run parrent\n");
        exit(1);
    }

    printf("save the context for the child\n");
    err = uc_context_save(uc, context);
    printf("finish the parrent\n");
    err = uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    if (err) {
        printf("failed to read rip\n");
        exit(1);
    }

    err = uc_emu_start(uc, rip, 0x0, 0, 0);
    if (err) {
        printf("failed to flush tlb\n");
        exit(1);
    }

    printf("restore the context for the child\n");
    err = uc_context_restore(uc, context);
    if (err) {
        printf("failed to restore context\n");
        exit(1);
    }
    x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    x86_mmu_pt_set(uc, 0x4000, 0x2000, tlb_base);
    rax = 0;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    if (err) {
        printf("failed to write rax\n");
        exit(1);
    }
    err = uc_ctl_flush_tlb(uc);
    if (err) {
        printf("failed to flush tlb\n");
        exit(1);
    }

    err = uc_emu_start(uc, rip, 0x0, 0, 0);
    if (err) {
        printf("failed to run child\n");
        exit(1);
    }
    err = uc_mem_read(uc, 0x1000, &parrent, sizeof(parrent));
    if (err) {
        printf("failed to read from parrent memory\n");
        exit(1);
    }
    err = uc_mem_read(uc, 0x2000, &child, sizeof(child));
    if (err) {
        printf("failed to read from child memory\n");
        exit(1);
    }
    printf("parrent result == %lu\n", parrent);
    printf("child result == %lu\n", child);
    uc_close(uc);
}

static bool virtual_tlb_callback(uc_engine *uc, uint64_t addr, uc_mem_type type,
                                 uc_tlb_entry *result, void *user_data)
{
    bool *parrent_done = user_data;
    printf("tlb lookup for address: 0x%lX\n", addr);
    switch (addr & ~(0xfff)) {
    case 0x2000:
        result->paddr = 0x0;
        result->perms = UC_PROT_EXEC;
        return true;
    case 0x4000:
        if (*parrent_done) {
            result->paddr = 0x2000;
        } else {
            result->paddr = 0x1000;
        }
        result->perms = UC_PROT_READ | UC_PROT_WRITE;
        return true;
    default:
        break;
    }
    return false;
}

void virtual_tlb(void)
{
    uint64_t rax, rip;
    bool parrent_done = false;
    uint64_t parrent, child;
    uc_context *context;
    uc_engine *uc;
    uc_err err;
    uc_hook h1, h2, h3;

    printf("Emulate x86 amd64 code with virtual mmu\n");

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        exit(1);
    }
    uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL);
    err = uc_context_alloc(uc, &context);
    if (err) {
        printf("Failed on uc_context_alloc() with error returned: %u\n", err);
        exit(1);
    }

    err = uc_hook_add(uc, &h1, UC_HOOK_INSN, &x86_mmu_syscall_callback,
                      &parrent_done, 1, 0, UC_X86_INS_SYSCALL);
    if (err) {
        printf("Failed on uc_hook_add() with error returned: %u\n", err);
        exit(1);
    }

    // Memory hooks are called after the mmu translation, so hook the physicall
    // addresses
    err = uc_hook_add(uc, &h2, UC_HOOK_MEM_WRITE, &mmu_write_callback, NULL,
                      0x1000, 0x3000);
    if (err) {
        printf("Faled on uc_hook_add() with error returned: %u\n", err);
    }

    printf("map code\n");
    err = uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL); // Code
    if (err) {
        printf("Failed on uc_mem_map() with error return: %u\n", err);
        exit(1);
    }
    err = uc_mem_write(uc, 0x0, code, sizeof(code) - 1);
    if (err) {
        printf("Failed on uc_mem_wirte() with error return: %u\n", err);
        exit(1);
    }
    printf("map parrent memory\n");
    err = uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL); // Parrent
    if (err) {
        printf("Failed on uc_mem_map() with error return: %u\n", err);
        exit(1);
    }
    printf("map child memory\n");
    err = uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL); // Child
    if (err) {
        printf("failed to map child memory\n");
        exit(1);
    }

    err = uc_hook_add(uc, &h3, UC_HOOK_TLB_FILL, virtual_tlb_callback,
                      &parrent_done, 1, 0);

    printf("run the parrent\n");
    err = uc_emu_start(uc, 0x2000, 0x0, 0, 0);
    if (err) {
        printf("failed to run parrent\n");
        exit(1);
    }

    printf("save the context for the child\n");
    err = uc_context_save(uc, context);
    printf("finish the parrent\n");
    err = uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    if (err) {
        printf("failed to read rip\n");
        exit(1);
    }

    err = uc_emu_start(uc, rip, 0x0, 0, 0);
    if (err) {
        printf("failed to flush tlb\n");
        exit(1);
    }

    printf("restore the context for the child\n");
    err = uc_context_restore(uc, context);
    if (err) {
        printf("failed to restore context\n");
        exit(1);
    }
    rax = 0;
    parrent_done = true;
    err = uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    if (err) {
        printf("failed to write rax\n");
        exit(1);
    }
    err = uc_ctl_flush_tlb(uc);
    if (err) {
        printf("failed to flush tlb\n");
        exit(1);
    }

    err = uc_emu_start(uc, rip, 0x0, 0, 0);
    if (err) {
        printf("failed to run child\n");
        exit(1);
    }
    err = uc_mem_read(uc, 0x1000, &parrent, sizeof(parrent));
    if (err) {
        printf("failed to read from parrent memory\n");
        exit(1);
    }
    err = uc_mem_read(uc, 0x2000, &child, sizeof(child));
    if (err) {
        printf("failed to read from child memory\n");
        exit(1);
    }
    printf("parrent result == %lu\n", parrent);
    printf("child result == %lu\n", child);
    uc_close(uc);
}

int main(void)
{
    cpu_tlb();
    virtual_tlb();
}
