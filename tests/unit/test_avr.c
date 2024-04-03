#include <assert.h>
#include "unicorn_test.h"

#define ARRAY_ELEMS(a)  (sizeof(a) / sizeof((a)[0]))

#define PAGE_SIZE       256
#define PAGE_ALIGN(x)   (((x) + PAGE_SIZE - 1) & -PAGE_SIZE)

#define UC_AVR_REG_SREG_H_BIT 5

enum {
    ADDR__init__,
    ADDR_test_func,
    ADDR_test_1,
    ADDR_main,
    ADDR_abort,
    ADDR_exit,
    ADDR__stop_program,
    ADDR__data__,
};

static const uint16_t ADDR[] = {
    0x0000, // __init__
    0x001a, // test_func()
    0x0030, // test_1()
    0x0058, // main()
    0x0062, // abort()
    0x006c, // _exit()
    0x006e, // __stop_program()
    0x0070, // __data__
    0x0072, // __size__
};

static const uint8_t FLASH[] =
    // 00000000 <__ctors_end>:
    "\x12\xe0"          // ldi	r17, 0x02
    "\xa0\xe0"          // ldi	r26, 0x00
    "\xb2\xe0"          // ldi	r27, 0x02
    "\xe0\xe7"          // ldi	r30, 0x70
    "\xf0\xe0"          // ldi	r31, 0x00
    "\x00\xe0"          // ldi	r16, 0x00
    "\x0b\xbf"          // out	0x3b, r16
    "\x02\xc0"          // rjmp	.+4
    "\x07\x90"          // elpm	r0, Z+
    "\x0d\x92"          // st	X+, r0
    "\xa2\x30"          // cpi	r26, 0x02
    "\xb1\x07"          // cpc	r27, r17
    "\xd9\xf7"          // brne	.-10

    // 0000001a <test_func>:
    "\x20\x91\x00\x02"  // lds	r18, 0x0200
    "\x30\x91\x01\x02"  // lds	r19, 0x0201
    "\x86\x0f"          // add	r24, r22
    "\x97\x1f"          // adc	r25, r23
    "\x88\x0f"          // add	r24, r24
    "\x99\x1f"          // adc	r25, r25
    "\x82\x0f"          // add	r24, r18
    "\x93\x1f"          // adc	r25, r19
    "\x08\x95"          // ret

    // 00000030 <test_1>:
    "\x62\xe0"          // ldi	r22, 0x02
    "\x70\xe0"          // ldi	r23, 0x00
    "\x81\xe0"          // ldi	r24, 0x01
    "\x90\xe0"          // ldi	r25, 0x00
    "\x0e\x94\x0d\x00"  // call	0x1a
    "\x07\x97"          // sbiw	r24, 0x07
    "\x11\xf0"          // breq	.+4
    "\x0e\x94\x31\x00"  // call	0x62
    "\x60\xe8"          // ldi	r22, 0x80
    "\x70\xe0"          // ldi	r23, 0x00
    "\x80\xe4"          // ldi	r24, 0x40
    "\x90\xe0"          // ldi	r25, 0x00
    "\x0e\x94\x0d\x00"  // call	0x1a
    "\x81\x38"          // cpi	r24, 0x81
    "\x91\x40"          // sbci	r25, 0x01
    "\xa9\xf7"          // brne	.-22
    "\x08\x95"          // ret

    // 00000058 <main>:
    "\x0e\x94\x18\x00"  // call	0x30
    "\x80\xe0"          // ldi	r24, 0x00
    "\x90\xe0"          // ldi	r25, 0x00
    "\x08\x95"          // ret

    // 00000062 <abort>:
    "\x81\xe0"          // ldi	r24, 0x01
    "\x90\xe0"          // ldi	r25, 0x00
    "\xf8\x94"          // cli
    "\x0c\x94\x36\x00"  // jmp	0x6c

    // 0000006c <_exit>:
    "\xf8\x94"          // cli

    // 0000006e <__stop_program>:
    "\xff\xcf"          // rjmp	.-2

    // 0x000070 .data
    "\x01\x00"
    ;
const uint64_t FLASH_SIZE = sizeof(FLASH);

const uint64_t MEM_BASE = 0x0200;
const uint64_t MEM_SIZE = 0x0100;

static void uc_common_setup(uc_engine **uc, uc_cpu_avr cpu_model,
    const uint8_t *code, uint64_t code_size)
{
    OK(uc_open(UC_ARCH_AVR, UC_MODE_LITTLE_ENDIAN, uc));
    if (cpu_model != 0)
        OK(uc_ctl_set_cpu_model(*uc, cpu_model));

    OK(uc_mem_map(*uc, UC_AVR_MEM_FLASH, PAGE_ALIGN(code_size),
           UC_PROT_READ|UC_PROT_EXEC));
    OK(uc_mem_write(*uc, UC_AVR_MEM_FLASH, code, code_size));
    OK(uc_mem_map(*uc, MEM_BASE, MEM_SIZE, UC_PROT_READ|UC_PROT_WRITE));
}

static void test_avr_basic_alu(void)
{
    uc_engine *uc = NULL;
    uint8_t r[32] = {0,};
    uint16_t r_func_arg0 = 1, r_func_arg1 = 2, r_func_ret;
    r[24] = 1;
    r[22] = 2;

    uc_common_setup(&uc, 0, FLASH, FLASH_SIZE);
    OK(uc_reg_write(uc, UC_AVR_REG_R24W, &r_func_arg0));
    OK(uc_reg_write(uc, UC_AVR_REG_R22W, &r_func_arg1));

    const uint64_t code_start = ADDR[ADDR_test_func] + 8;
    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    uint32_t r_pc;
    OK(uc_reg_read(uc, UC_AVR_REG_PC, &r_pc));
    OK(uc_reg_read(uc, UC_AVR_REG_R25, &r[25]));
    OK(uc_reg_read(uc, UC_AVR_REG_R24, &r[24]));
    OK(uc_reg_read(uc, UC_AVR_REG_R23, &r[23]));
    OK(uc_reg_read(uc, UC_AVR_REG_R22, &r[22]));

    TEST_CHECK(r_pc == code_start + 4);
    TEST_CHECK(r[25] == 0 && r[24] == 3);
    TEST_CHECK(r[23] == 0 && r[22] == 2);

    OK(uc_reg_read(uc, UC_AVR_REG_R24W, &r_func_ret));
    OK(uc_reg_read(uc, UC_AVR_REG_R22W, &r_func_arg1));

    TEST_CHECK(r_func_ret == r[24]);
    TEST_CHECK(r_func_arg1 == r[22]);

    OK(uc_close(uc));
}

typedef struct MEM_HOOK_RESULT_s {
    uc_mem_type type;
    uint64_t address;
    int size;
    uint64_t value;
} MEM_HOOK_RESULT;

typedef struct MEM_HOOK_RESULTS_s {
    uint64_t count;
    MEM_HOOK_RESULT results[16];
} MEM_HOOK_RESULTS;

static bool test_avr_basic_mem_cb_eventmem(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data)
{
    MEM_HOOK_RESULTS *const r = user_data;

    uint64_t count = r->count;
    if (count >= ARRAY_ELEMS(r->results)) {
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
    MEM_HOOK_RESULTS eventmem_trace = {0};

    uc_common_setup(&uc, 0, FLASH, FLASH_SIZE);
    OK(uc_hook_add(uc, &eventmem_hook, UC_HOOK_MEM_VALID,
           test_avr_basic_mem_cb_eventmem, &eventmem_trace, 1, 0));

    const uint64_t code_start = ADDR[ADDR__init__];
    OK(uc_emu_start(uc, code_start, ADDR[ADDR__init__+1], 0, 0));

    uint32_t r_pc;
    OK(uc_reg_read(uc, UC_AVR_REG_PC, &r_pc));
    TEST_CHECK(r_pc == ADDR[ADDR__init__+1]);

    const uint16_t DATA_BASE = ADDR[ADDR__data__];
    const uint16_t DATA_SIZE = ADDR[ADDR__data__+1] - DATA_BASE;
    const uint8_t *const DATA = &FLASH[ADDR[ADDR__data__]];

    // Check SRAM was correctly initialized with data from Flash program memory
    uint8_t mem[DATA_SIZE];
    OK(uc_mem_read(uc, MEM_BASE, mem, sizeof(mem)));
    TEST_CHECK(memcmp(mem, DATA, DATA_SIZE) == 0);

    TEST_CHECK(eventmem_trace.count == 2*DATA_SIZE);
    for (unsigned i = 0; i < DATA_SIZE; i++) {
        const MEM_HOOK_RESULT *const mr = &eventmem_trace.results[2*i];
        TEST_CHECK(mr->type == UC_MEM_READ);
        TEST_CHECK(mr->address == (UC_AVR_MEM_FLASH|(DATA_BASE+i)));
        TEST_CHECK(mr->size == 1);
        TEST_CHECK(mr->value == 0);

        const MEM_HOOK_RESULT *const mw = &eventmem_trace.results[2*i+1];
        TEST_CHECK(mw->type == UC_MEM_WRITE);
        TEST_CHECK(mw->address == MEM_BASE+i);
        TEST_CHECK(mw->size == 1);
        TEST_CHECK(mw->value == DATA[i]);
    }

    OK(uc_close(uc));
}

static void test_avr_full_exec(void)
{
    uc_engine *uc = NULL;

    uc_common_setup(&uc, 0, FLASH, FLASH_SIZE);

    const uint64_t code_start = ADDR[ADDR__init__];
    OK(uc_emu_start(uc, code_start, ADDR[ADDR__init__+1], 0, 0));

    uint32_t r_pc;
    OK(uc_reg_read(uc, UC_AVR_REG_PC, &r_pc));
    TEST_CHECK(r_pc == ADDR[ADDR__init__+1]);

    uint32_t r_sp = MEM_BASE + MEM_SIZE - 1;
    OK(uc_reg_write(uc, UC_AVR_REG_SP, &r_sp));

    const uint64_t exits[] = {
        ADDR[ADDR_main],
        ADDR[ADDR__stop_program]
    };
    OK(uc_ctl_exits_enable(uc));
    OK(uc_ctl_set_exits(uc, exits, ARRAY_ELEMS(exits)));

    const uint64_t code_main = ADDR[ADDR_main];
    OK(uc_emu_start(uc, code_main, 0, 0, 0));

    uint8_t r[32] = {0,};
    OK(uc_reg_read(uc, UC_AVR_REG_R25, &r[25]));
    OK(uc_reg_read(uc, UC_AVR_REG_R24, &r[24]));
    TEST_CHECK(r[25] == 0 && r[24] == 0);

    OK(uc_close(uc));
}

static void cpu_set_des_encrypt_mode(uc_engine *uc, int encrypt_mode)
{
    uint8_t sreg;
    OK(uc_reg_read(uc, UC_AVR_REG_SREG, &sreg));
    sreg &= ~(1U << UC_AVR_REG_SREG_H_BIT);
    sreg |= (!encrypt_mode) << UC_AVR_REG_SREG_H_BIT;
    OK(uc_reg_write(uc, UC_AVR_REG_SREG, &sreg));
}

static void cpu_set_des_key(uc_engine *uc, const uint8_t key[8])
{
    for (int i = 0; i < 8; i++) {
        OK(uc_reg_write(uc, UC_AVR_REG_R15-i, &key[i]));
    }
}

static void cpu_set_des_data(uc_engine *uc, const uint8_t data[8])
{
    for (int i = 0; i < 8; i++) {
        OK(uc_reg_write(uc, UC_AVR_REG_R7-i, &data[i]));
    }
}

static void cpu_get_des_data(uc_engine *uc, uint8_t data[8])
{
    for (int i = 0; i < 8; i++) {
        OK(uc_reg_read(uc, UC_AVR_REG_R7-i, &data[i]));
    }
}

static void test_avr_xmega_des(void)
{
    uint8_t code[16*2 + 2], *code_ptr = code;
    for (unsigned i = 0; i < 16; i++) {
        *code_ptr++ = 0x0b | (i << 4);  // des i
        *code_ptr++ = 0x94;
    }
    *code_ptr++ = 0x08;                 // ret
    *code_ptr++ = 0x95;

    uc_engine *uc = NULL;
    uc_common_setup(&uc, UC_CPU_AVR_ATXMEGA16A4, code, sizeof(code));

    uint8_t des_output[8];
    static const uint8_t des_key[8] =
        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    static const uint8_t plaintext[8] =
        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe7 };
    static const uint8_t ciphertext[8] =
        { 0xc9, 0x57, 0x44, 0x25, 0x6a, 0x5e, 0xd3, 0x1d };

    // Encrypt
    cpu_set_des_encrypt_mode(uc, 1);
    cpu_set_des_key(uc, des_key);
    cpu_set_des_data(uc, plaintext);
    OK(uc_emu_start(uc, 0, sizeof(code) - 2, 0, 0));
    cpu_get_des_data(uc, des_output);
    TEST_CHECK(memcmp(des_output, ciphertext, sizeof(des_output)) == 0);

    // Decrypt
    cpu_set_des_encrypt_mode(uc, 0);
    cpu_set_des_key(uc, des_key);
    cpu_set_des_data(uc, ciphertext);
    OK(uc_emu_start(uc, 0, sizeof(code) - 2, 0, 0));
    cpu_get_des_data(uc, des_output);
    TEST_CHECK(memcmp(des_output, plaintext, sizeof(des_output)) == 0);

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_avr_basic_alu", test_avr_basic_alu},
    {"test_avr_basic_mem", test_avr_basic_mem},
    {"test_avr_full_exec", test_avr_full_exec},
    {"test_avr_xmega_des", test_avr_xmega_des},
    {NULL, NULL}
};
