#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unicorn/unicorn.h>

#ifdef _WIN32
#	include <Windows.h>
#	define printf	OutputDebugStringA
#endif

char buffer[256];

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t eax = 0, ebx = 0, eflags = 0;
	uc_reg_read(uc, UC_X86_REG_EAX, &eax);
	uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
	sprintf(buffer, "eip=%08x - eax=%08x - ebx=%08x -  eflags=%08X\n", (uint32_t)address, eax, ebx, eflags);
	printf(buffer);
}

const char code32_prob[] = { 
	0xBB, 0x3C, 0x00, 0x00, 0x00,	//0x100000: mov     ebx, 3Ch
	0xB1, 0x02,						//0x100005: mov     cl, 2
	0xD3, 0xE3,						//0x100007: shl     ebx, cl
	0x9F,							//0x100009: lahf
	0xCC							//0x10000A: int3
};

const char code32_ok[] = {
	0xBB, 0x3C, 0x00, 0x00, 0x00,	//0x100000: mov     ebx, 3Ch
	0xC1, 0xE3, 0x02,				//0x100005: shl     ebx, 2
	0x9F,							//0x100008: lahf
	0xCC							//0x100009: int3
};

const char code16_prob[] = {
	0x66, 0xBB, 0x3C, 0x00,			//0x100000: mov     bx, 3Ch
	0xB1, 0x02,						//0x100004: mov     cl, 2
	0x66, 0xD3, 0xE3,				//0x100006: shl     bx, cl
	0x9F,							//0x100009: lahf
	0xCC							//0x10000A: int3
};

const char code16_ok[] = {
	0x66, 0xBB, 0x3C, 0x00,			//0x100000: mov     bx, 3Ch
	0x66, 0xC1, 0xE3, 0x02,			//0x100004: shl     bx, 2
	0x9F,							//0x100008: lahf
	0xCC							//0x10000A: int3
};

const char code8_prob[] = {
	0xB3, 0x3C,						//0x100000: mov     bl, 3Ch
	0xB1, 0x02,						//0x100002: mov     cl, 2
	0xD2, 0xE3,						//0x100004: shl     bl, 2
	0x9F,							//0x100006: lahf
	0xCC							//0x100007: int3
};

const char code8_ok[] = {
	0xB3, 0x3C,						//0x100000: mov     bl, 3Ch
	0xC0, 0xE3, 0x02,				//0x100002: shl     bl, 2
	0x9F,							//0x100005: lahf
	0xCC							//0x100006: int3
};

const char code_SHL_JP_CL[] = {
	0xB4, 0x00,						//0x100000: mov     ah, 0
	0x9E,							//0x100002: sahf
	0xB8, 0x3C, 0x00, 0x00, 0x00,	//0x100003: mov     eax, 3Ch
	0xB1, 0x02,						//0x100008: mov     cl, 2
	0xD3, 0xE0,						//0x10000A: shl     eax, cl
	0x7A, 0x07,						//0x10000C: jp +7
	0xB8, 0x00, 0x00, 0x00, 0x00,	//0x10000E: mov     eax, 0
	0xEB, 0x05,						//0x100014: jmp +5
	0xB8, 0x01, 0x00, 0x00, 0x00,	//0x100016: mov     eax, 1
	0xCC							//0x10001B: int3
};

const char code_SHL_JP_NOCL[] = {
	0xB4, 0x00,						//0x100000: mov     ah, 0
	0x9E,							//0x100002: sahf
	0xB8, 0x3C, 0x00, 0x00, 0x00,	//0x100003: mov     eax, 3Ch
	0xC1, 0xE0, 0x02,				//0x100008: shl     eax, 2
	0x7A, 0x07,						//0x10000B: jp +7
	0xB8, 0x00, 0x00, 0x00, 0x00,	//0x10000D: mov     eax, 0
	0xEB, 0x05,						//0x100014: 
	0xB8, 0x01, 0x00, 0x00, 0x00,	//0x100016: mov     eax, 1
	0xCC							//0x100017: int3
};


#define ADDR_START 0x100000

#define TEST(X)		if((X) != UC_ERR_OK) { \
											printf("error: '" #X "' failed\n"); \
											return 1; \
										 }

int main()
{
	uint32_t eflags = 0, eax = 0;
	uc_engine *	uc = NULL;

	TEST(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

	uc_hook trace_hook_code;
	TEST(uc_hook_add(uc, &trace_hook_code, UC_HOOK_CODE, hook_code, NULL, 1, 0));
	TEST(uc_mem_map(uc, ADDR_START, 0x1000, UC_PROT_READ | UC_PROT_EXEC));

#define RUN_CODE(CODE)	{ \
	TEST(uc_mem_write(uc, ADDR_START, CODE, sizeof(CODE))); \
	printf("running " #CODE "...\n"); \
	eflags = 0; \
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags); \
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(CODE) - 1, 0, 0)); \
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags); \
	uc_reg_read(uc, UC_X86_REG_EAX, &eax); \
	sprintf(buffer, "after uc_emu_start: eflags=%08X - ah=%08X - %s\n", eflags, (eax>>8) & 0xFF, eflags & 4 ? "success" : "failed"); \
	printf(buffer); \
}

	//32 bits
	RUN_CODE(code32_prob);
	RUN_CODE(code32_ok);

	//16 bits
	RUN_CODE(code16_prob);
	RUN_CODE(code16_ok);

	//8 bits
	RUN_CODE(code8_prob);
	RUN_CODE(code8_ok);

	//test with JP-CL
	eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code_SHL_JP_CL, sizeof(code_SHL_JP_CL)));
	printf("running code_SHL_JP_CL ...\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code_SHL_JP_CL) - 1, 0, 0));

	eax = 0;
	uc_reg_read(uc, UC_X86_REG_EAX, &eax);
	if (eax == 1)	printf("success\n");
	else			printf("failed\n");

	//test with JP-NOCL
	eflags = 0;
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

	TEST(uc_mem_write(uc, ADDR_START, code_SHL_JP_NOCL, sizeof(code_SHL_JP_NOCL)));
	printf("running code_SHL_JP_NOCL ...\n");
	TEST(uc_emu_start(uc, ADDR_START, ADDR_START + sizeof(code_SHL_JP_NOCL) - 1, 0, 0));

	eax = 0;
	uc_reg_read(uc, UC_X86_REG_EAX, &eax);
	if (eax == 1)	printf("success\n");
	else			printf("failed\n");

	TEST(uc_close(uc));

	return 0;
}
