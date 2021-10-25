#include "unicorn_test.h"
#include "unicorn/unicorn.h"

#define MEM_BASE 0x40000000
#define MEM_SIZE 1024*1024
#define MEM_STACK MEM_BASE + (MEM_SIZE / 2)
#define MEM_TEXT MEM_STACK + 4096

#define CODE_X86_NOP_OFFSET 4
// note: fxsave was introduced in Pentium II
static uint8_t code_x86[] = {
	// help testing through NOP offset      [disassembly in at&t syntax]
	0x90, 0x90, 0x90, 0x90, 		// nop nop nop nop
	// run a floating point instruction
	0xdb, 0xc9,				// fcmovne %st(1), %st
	// fxsave needs 512 bytes of storage space
	0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 	// subl $512, %esp
	// fxsave needs a 16-byte aligned address for storage
	0x83, 0xe4, 0xf0,			// andl $0xfffffff0, %esp
	// store fxsave data on the stack
	0x0f, 0xae, 0x04, 0x24,			// fxsave (%esp)
	// fxsave stores FPIP at an 8-byte offset, move FPIP to eax register
	0x8b, 0x44, 0x24, 0x08			// movl 0x8(%esp), %eax
};

#define CODE_X64_NOP_OFFSET 8
static uint8_t code_x64[] = {
	// help testing through NOP offset     [disassembly in at&t]
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops
	// run a floating point instruction
	0xdb, 0xc9,			       // fcmovne %st(1), %st
	// fxsave64 needs 512 bytes of storage space
	0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // subq $512, %rsp
	// fxsave needs a 16-byte aligned address for storage
	0x48, 0x83, 0xe4, 0xf0,	               // andq 0xfffffffffffffff0, %rsp
	// store fxsave64 data on the stack
	0x48, 0x0f, 0xae, 0x04, 0x24,          // fxsave64 (%rsp)
	// fxsave64 stores FPIP at an 8-byte offset, move FPIP to rax register
	0x48, 0x8b, 0x44, 0x24, 0x08,	       // movq 0x8(%rsp), %rax
};

static void test_x86(void **state) {
	uc_err err;
	uint32_t stack_top = (uint32_t) MEM_STACK;
	uint32_t value;
	uc_engine *uc;

	// initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    	uc_assert_success(err);
	
	// map 1MB of memory for this emulation
	err = uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL);
	uc_assert_success(err);

	err = uc_mem_write(uc, MEM_TEXT, code_x86, sizeof(code_x86));
	uc_assert_success(err);
	
	err = uc_reg_write(uc, UC_X86_REG_ESP, &stack_top);
	uc_assert_success(err);

	err = uc_emu_start(uc, MEM_TEXT, MEM_TEXT + sizeof(code_x86), 0, 0);
	uc_assert_success(err);

	err = uc_reg_read(uc, UC_X86_REG_EAX, &value);
	uc_assert_success(err);

	assert_true(value == ((uint32_t) MEM_TEXT + CODE_X86_NOP_OFFSET));

	err = uc_mem_unmap(uc, MEM_BASE, MEM_SIZE);
	uc_assert_success(err);

	err = uc_close(uc);
	uc_assert_success(err);
}

static void test_x64(void **state) {
	uc_err err;
	uint64_t stack_top = (uint64_t) MEM_STACK;
	uint64_t value;
	uc_engine *uc;

	// initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    	uc_assert_success(err);
	
	// map 1MB of memory for this emulation
	err = uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL);
	uc_assert_success(err);

	err = uc_mem_write(uc, MEM_TEXT, code_x64, sizeof(code_x64));
	uc_assert_success(err);
	
	err = uc_reg_write(uc, UC_X86_REG_RSP, &stack_top);
	uc_assert_success(err);

	err = uc_emu_start(uc, MEM_TEXT, MEM_TEXT + sizeof(code_x64), 0, 0);
	uc_assert_success(err);

	err = uc_reg_read(uc, UC_X86_REG_RAX, &value);
	uc_assert_success(err);

	assert_true(value == ((uint64_t) MEM_TEXT + CODE_X64_NOP_OFFSET));

	err = uc_mem_unmap(uc, MEM_BASE, MEM_SIZE);
	uc_assert_success(err);

	err = uc_close(uc);
	uc_assert_success(err);
}

int main(void) {
    const struct CMUnitTest tests[] = {
	cmocka_unit_test(test_x86),
	cmocka_unit_test(test_x64),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
