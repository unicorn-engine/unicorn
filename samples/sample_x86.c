#include <unicorn/unicorn.h>
#include <string.h>

bool hook_mem_unmapped(
    uc_engine * uc,
    uc_mem_type type,
    uint64_t    address,
    int         size,
    int64_t     value,
    void *      user_data
) {
    return false;
}

struct SegmentSelector {
    union {
        struct {
            uint16_t rpl  : 2;
            uint16_t table: 1;
            uint16_t index: 13;
        };

        uint64_t desc;
    };
};

struct SegmentDescriptor {
    union {
        struct {
            uint16_t limit0;
            uint16_t base0;
            uint8_t  base1;
            uint8_t  type       : 4;
            uint8_t  system     : 1;
            uint8_t  dpl        : 2;
            uint8_t  present    : 1;
            uint8_t  limit1     : 4;
            uint8_t  avail      : 1;
            uint8_t  is_64_code : 1;
            uint8_t  db         : 1;
            uint8_t  granularity: 1;
            uint8_t  base2;
        };

        uint64_t desc;
    };
};

int main() {
    uc_engine *uc_ = NULL;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc_);
    uc_hook passUnMapped;

    uc_err       err = uc_hook_add(uc_, &passUnMapped, UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped, NULL, 1, 0);
    uc_x86_mmr gdtr;

    const uint64_t     m_gdt_address = 0xc000000000000000;
    struct SegmentDescriptor *gdt           = (struct SegmentDescriptor *) malloc(31 * sizeof(struct SegmentDescriptor));

    struct SegmentSelector r_gs;
    memset(&r_gs, 0, sizeof(struct SegmentSelector));
    r_gs.desc            = 0x2B;

    gdtr.base  = m_gdt_address;
    gdtr.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

    err = uc_reg_write(uc_, UC_X86_REG_GDTR, &gdtr);

    // call the UC_HOOK_MEM_UNMAPPED hook, and return false
    err = uc_reg_write(uc_, UC_X86_REG_GS, &r_gs);
    free(gdt);

    // both UC_ERR_NOMEM, but sometimes crash the program
    err = uc_mem_map(uc_, 0x00007ffe0e250000, 0x0000000000001000, 1);
    err = uc_mem_map(uc_, 0x00007ffe0e251000, 0x000000000011b000, 5);
    err = uc_mem_map(uc_, 0x000000927fcfc000, 0x0000000000004000, 3);
    err = uc_mem_map(uc_, 0x00007ffe0e250000, 0x0000000000001000, 1);
}