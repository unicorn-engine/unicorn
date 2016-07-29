#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>


void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t eax = 0, eflags = 0;
	uc_reg_read(uc, UC_X86_REG_EAX, &eax);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
	printf("eip=%08x - eax=%08x -  eflags=%08X\n", (uint32_t)address, eax, eflags);
}

const char code32_prob[] = { 
	0xB8, 0x3C, 0x00, 0x00, 0x00,	//0x100000: mov     eax, 3Ch
	0xB1, 0x02,						//0x100005: mov     cl, 2
	0xD3, 0xE0,						//0x100007: shl     eax, cl  <- do not set PF
	0x33, 0xC0						//0x100009: xor     eax, eax
};

const char code32_ok[] = {
	0xB8, 0x3C, 0x00, 0x00, 0x00,	//0x100000: mov     eax, 3Ch
	0xC1, 0xE0, 0x02,				//0x100005: shl     eax, 2  <- set PF correctly
	0x33, 0xC0						//0x100007: xor     eax, eax
};

const char code16_prob[] = {
	0x66, 0xB8, 0x3C, 0x00,			//0x100000: mov     ax, 3Ch
	0xB1, 0x02,						//0x100004: mov     cl, 2
	0x66, 0xD3, 0xE0,				//0x100006: shl     ax, cl
	0x33, 0xC0						//0x100009: xor     eax, eax
};

const char code16_ok[] = {
	0x66, 0xB8, 0x3C, 0x00,			//0x100000: mov     ax, 3Ch
	0x66, 0xC1, 0xE0, 0x02,			//0x100004: shl     ax, 2
	0x33, 0xC0						//0x100008: xor     eax, eax
};

const char code8_prob[] = {
	0xB0, 0x3C,						//0x100000: mov     al, 3Ch
	0xB1, 0x02,						//0x100002: mov     cl, 2
	0xD2, 0xE0,						//0x100004: shl     al, 2
	0x33, 0xC0						//0x100006: xor     eax, eax
};

const char code8_ok[] = {
	0xB0, 0x3C,						//0x100000: mov     al, 3Ch
	0xC0, 0xE0, 0x02,				//0x100002: shl     al, 2
	0x33, 0xC0						//0x100005: xor     eax, eax
};

#define ADDR_START 0x100000

#define TEST(X)		if((X) != UC_ERR_OK) { \
											printf("error: '" #X "' failed\n"); \
											return 1; \
										 }

int main()
{
	uc_engine *	uc = NULL;

	TEST(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

	uc_hook trace_hook_code;
	TEST(uc_hook_add(uc, &trace_hook_code, UC_HOOK_CODE, hook_code, NULL, 1, 0));
	TEST(uc_mem_map(uc, ADDR_START, 0x1000, UC_PROT_READ | UC_PROT_EXEC));

	//32 bits
	TEST(uc_mem_write(uc, ADDR_START, code32_prob, sizeof(code32_prob)));
	printf("running code_prob\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code32_prob) - 1, 0, 4));

	uint32_t eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code32_ok, sizeof(code32_ok)));
	printf("running code_ok\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code32_ok) - 1, 0, 3));

	//16 bits
	eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code16_prob, sizeof(code16_prob)));
	printf("running code16_prob\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code16_prob) - 1, 0, 4));
	
	eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code16_ok, sizeof(code16_ok)));
	printf("running code16_ok\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code16_ok) - 1, 0, 3));

	//8 bits
	eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code8_prob, sizeof(code8_prob)));
	printf("running code8_prob\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code8_prob) - 1, 0, 4));

	eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code8_ok, sizeof(code8_ok)));
	printf("running code8_ok\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code8_ok) - 1, 0, 3));

	TEST(uc_close(uc));

	return 0;
}
