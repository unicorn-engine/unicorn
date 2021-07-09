#include <unicorn/unicorn.h>
#include <assert.h>

#define CODE "\x0F\xC7\x0D\xE0\xBE\xAD\xDE" // cmpxchg8b [0xdeadbee0]
#define CODE_ADDR 0
#define DATA_ADDR 0xdeadb000

int read_happened = 0;
int write_happened = 0;

static void hook_mem(uc_engine *uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void *user_data)
{
	switch (type) {
	default: break;
	case UC_MEM_READ:
		read_happened = 1;
		break;
	case UC_MEM_WRITE:
		write_happened = 1;
		break;
	}
}

int main(int argc, char **argv, char **envp)
{
	uc_engine *uc;
	uc_hook trace1;
	uint64_t buffer;

	uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	uc_mem_map(uc, CODE_ADDR, 0x1000, UC_PROT_ALL);
	uc_mem_map(uc, DATA_ADDR, 0x1000, UC_PROT_ALL);
	uc_mem_write(uc, CODE_ADDR, CODE, sizeof(CODE) - 1);
	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem, NULL, 1, 0);

	// memory is initially zero
	uc_mem_read(uc, 0xdeadbee0, &buffer, sizeof(buffer));
	assert(buffer == 0x0000000000000000);

	// mov edx:eax, 0x0000000000000000
	// mov ecx:ebx, 0x4141414141414141
	int zero = 0x00000000;
	int AAAA = 0x41414141;
	uc_reg_write(uc, UC_X86_REG_EDX, &zero);
	uc_reg_write(uc, UC_X86_REG_EAX, &zero);
	uc_reg_write(uc, UC_X86_REG_ECX, &AAAA);
	uc_reg_write(uc, UC_X86_REG_EBX, &AAAA);
	uc_emu_start(uc, CODE_ADDR, CODE_ADDR + sizeof(CODE) - 1, 0, 0);

	// memory was written to at 0xdeadbee0, but no write hook fired!
	uc_mem_read(uc, 0xdeadbee0, &buffer, sizeof(buffer));
	assert(buffer == 0x4141414141414141);
	assert(read_happened);
	assert(write_happened);
	printf("Test passed!\n");
	return 0;
}
