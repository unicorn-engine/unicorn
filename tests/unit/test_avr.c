#include "unicorn_test.h"

#include <assert.h>

const uint64_t code_start = 0;
const uint64_t code_len = 0x4000;

const uint64_t MAIN_ADDR = 0x58;
const uint64_t STOP_ADDR = 0x6e;
const uint64_t DATA_ADDR = 0x70;

const uint64_t MEM_ADDR = 0x800200;

uint8_t code[] = {
    // 00000000 <__ctors_end>:
    0x12, 0xe0, // ldi r17, 0x02
    0xa0, 0xe0, // ldi r26, 0x00
    0xb2, 0xe0, // ldi r27, 0x02
    0xe0, 0xe7, // ldi r30, 0x70
    0xf0, 0xe0, // ldi r31, 0x00
    0x00, 0xe0, // ldi r16, 0x00
    0x0b, 0xbf, // out 0x3b, r16
    0x02, 0xc0, // rjmp .+4
    0x07, 0x90, // elpm r0, Z+
    0x0d, 0x92, // st X+, r0
    0xa2, 0x30, // cpi r26, 0x02
    0xb1, 0x07, // cpc r27, r17
    0xd9, 0xf7, // brne .-10

    // 0000001a <test_func>:
    0x20, 0x91, 0x00, 0x02, // lds r18, 0x0200
    0x30, 0x91, 0x01, 0x02, // lds r19, 0x0201
    0x86, 0x0f,             // add r24, r22
    0x97, 0x1f,             // adc r25, r23
    0x88, 0x0f,             // add r24, r24
    0x99, 0x1f,             // adc r25, r25
    0x82, 0x0f,             // add r24, r18
    0x93, 0x1f,             // adc r25, r19
    0x08, 0x95,             // ret

    // 00000030 <test_1>:
    0x62, 0xe0,             // ldi r22, 0x02
    0x70, 0xe0,             // ldi r23, 0x00
    0x81, 0xe0,             // ldi r24, 0x01
    0x90, 0xe0,             // ldi r25, 0x00
    0x0e, 0x94, 0x0d, 0x00, // call 0x1a
    0x07, 0x97,             // sbiw r24, 0x07
    0x11, 0xf0,             // breq .+4
    0x0e, 0x94, 0x31, 0x00, // call 0x62
    0x60, 0xe8,             // ldi r22, 0x80
    0x70, 0xe0,             // ldi r23, 0x00
    0x80, 0xe4,             // ldi r24, 0x40
    0x90, 0xe0,             // ldi r25, 0x00
    0x0e, 0x94, 0x0d, 0x00, // call 0x1a
    0x81, 0x38,             // cpi r24, 0x81
    0x91, 0x40,             // sbci r25, 0x01
    0xa9, 0xf7,             // brne .-22
    0x08, 0x95,             // ret

    // 00000058 <main>:
    0x0e, 0x94, 0x18, 0x00, // call 0x30
    0x80, 0xe0,             // ldi r24, 0x00
    0x90, 0xe0,             // ldi r25, 0x00
    0x08, 0x95,             // ret

    // 00000062 <abort>:
    0x81, 0xe0,             // ldi r24, 0x01
    0x90, 0xe0,             // ldi r25, 0x00
    0xf8, 0x94,             // cli
    0x0c, 0x94, 0x36, 0x00, // jmp 0x6c

    // 0000006c <_exit>:
    0xf8, 0x94, // cli

    // 0000006e <__stop_program>:
    0xff, 0xcf, // rjmp .-2

    // 0x000070 .data
    0x01, 0x00,

    //
};

static void uc_common_setup(uc_engine **uc, const uint8_t *code, uint64_t size)
{
    OK(uc_open(UC_ARCH_AVR, UC_MODE_LITTLE_ENDIAN, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
    OK(uc_mem_map(*uc, 0x800000, 0x1000, UC_PROT_ALL)); // SRAM
}

static void test_avr_basic_alu(void)
{
    uc_engine *uc;

    uint8_t code[] = {
        0x86, 0x0f, // add r24, r22
        0x97, 0x1f, // adc r25, r23
    };

    uint32_t pc;
    uint16_t arg0 = 1;
    uint16_t arg1 = 2;
    uint16_t retval;

    uint8_t r22 = 2;
    uint8_t r24 = 1;

    uint8_t r23;
    uint8_t r25;

    uc_common_setup(&uc, code, sizeof(code));

    OK(uc_reg_write(uc, UC_AVR_REG_R24W, &arg0));
    OK(uc_reg_write(uc, UC_AVR_REG_R22W, &arg1));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_AVR_REG_PC, &pc));
    OK(uc_reg_read(uc, UC_AVR_REG_R25, &r25));
    OK(uc_reg_read(uc, UC_AVR_REG_R24, &r24));
    OK(uc_reg_read(uc, UC_AVR_REG_R23, &r23));
    OK(uc_reg_read(uc, UC_AVR_REG_R22, &r22));

    TEST_CHECK(pc == code_start + 4);
    TEST_CHECK(r25 == 0 && r24 == 3);
    TEST_CHECK(r23 == 0 && r22 == 2);

    OK(uc_reg_read(uc, UC_AVR_REG_R24W, &retval));
    OK(uc_reg_read(uc, UC_AVR_REG_R22W, &arg1));

    TEST_CHECK(retval == r24);
    TEST_CHECK(arg1 == r22);

    OK(uc_close(uc));
}

typedef struct MemHookResult {
    uc_mem_type type;
    uint64_t address;
    int size;
    uint64_t value;
} MemHookResult;

typedef struct MemHookResults {
    uint64_t count;
    MemHookResult results[16];
} MemHookResults;

static bool test_avr_basic_mem_cb_eventmem(uc_engine *uc, uc_mem_type type,
                                           uint64_t address, int size,
                                           int64_t value, void *user_data)
{
    MemHookResults *const r = user_data;

    uint64_t count = r->count;
    if (count >= 16) {
        TEST_ASSERT(false);
    }

    r->results[count].type = type;
    r->results[count].address = address;
    r->results[count].size = size;
    r->results[count].value = value;
    r->count++;
    return true;
}

static void test_avr_basic_mem(void)
{
    uc_engine *uc = NULL;
    uc_hook eventmem_hook;
    MemHookResults eventmem_trace = {0};

    uint8_t data[] = {0x01, 0x00};
    uint8_t mem[2];

    uint32_t pc;
    int i;

    uc_common_setup(&uc, code, sizeof(code));
    OK(uc_hook_add(uc, &eventmem_hook, UC_HOOK_MEM_VALID,
                   test_avr_basic_mem_cb_eventmem, &eventmem_trace, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + 26, 0, 0));

    OK(uc_reg_read(uc, UC_AVR_REG_PC, &pc));
    TEST_CHECK(pc == code_start + 26);

    // Check SRAM was correctly initialized with data from Flash program
    OK(uc_mem_read(uc, MEM_ADDR, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, data, 2) == 0);

    TEST_CHECK(eventmem_trace.count == 2 * 2);
    for (i = 0; i < 2; i++) {
        MemHookResult *mr = &eventmem_trace.results[2 * i];
        TEST_CHECK(mr->type == UC_MEM_READ);
        TEST_CHECK(mr->address == DATA_ADDR + i);
        TEST_CHECK(mr->size == 1);
        TEST_CHECK(mr->value == 0);

        MemHookResult *mw = &eventmem_trace.results[(2 * i) + 1];
        TEST_CHECK(mw->type == UC_MEM_WRITE);
        TEST_CHECK(mw->address == MEM_ADDR + i);
        TEST_CHECK(mw->size == 1);
        TEST_CHECK(mw->value == data[i]);
    }

    OK(uc_close(uc));
}

static void test_avr_full_exec(void)
{
    uc_engine *uc = NULL;

    uint32_t pc;
    uint32_t sp;
    uint8_t r24, r25;

    uc_common_setup(&uc, code, sizeof(code));

    OK(uc_emu_start(uc, code_start, code_start + 26, 0, 0));

    OK(uc_reg_read(uc, UC_AVR_REG_PC, &pc));
    TEST_CHECK(pc == code_start + 26);

    sp = 0x2ff;
    OK(uc_reg_write(uc, UC_AVR_REG_SP, &sp));

    const uint64_t exits[] = {MAIN_ADDR, STOP_ADDR};
    OK(uc_ctl_exits_enable(uc));
    OK(uc_ctl_set_exits(uc, exits, 2));

    OK(uc_emu_start(uc, MAIN_ADDR, STOP_ADDR, 0, 0));

    OK(uc_reg_read(uc, UC_AVR_REG_R25, &r25));
    OK(uc_reg_read(uc, UC_AVR_REG_R24, &r24));
    TEST_CHECK(r25 == 0 && r24 == 0);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_avr_basic_alu", test_avr_basic_alu},
             {"test_avr_basic_mem", test_avr_basic_mem},
             {"test_avr_full_exec", test_avr_full_exec},
             {NULL, NULL}};
