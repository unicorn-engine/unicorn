#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <unicorn/unicorn.h>

/* **** */

#define uc_assert_success(_check) \
	do { \
		uc_err __err = _check; \
		if(__err) \
		{ \
			fprintf(stderr, "%s", uc_strerror(__err)); \
			assert(false); \
		} \
	}while(0);

typedef struct test_t* test_p;
typedef struct test_t {
	uc_engine*  uc;

	uc_hook     trace1,
				trace2;

	uint32_t    pc;
	uint8_t     code[256];

	uint64_t	check;
}test_t;

/* **** */

static inline void _cxx(test_p t, uint32_t address, uint32_t value)
{
	uint8_t size = sizeof(uint32_t);

	for(int i = 0; i < size; i++)
		t->code[t->pc++] = (value >> ((i) << 3)) & 0xff;
}

#define _dxx _cxx

/* **** */
static void hook_mem(uc_engine *uc, uc_mem_type type,
		uint64_t address, int size, int64_t value, void *user_data)
{
	test_p t = (test_p)user_data;

	assert(size <= t->check);
	
	switch(type) {
		default: break;
		case UC_MEM_READ:
			uc_mem_read(uc, address, &t->check, size);
			if(1) printf(">>>  READ: 0x%"PRIx64 ", size = %u, value = 0x%"PRIx64 "\n",
				address, size, value);
			break;
		case UC_MEM_WRITE:
			if(1) printf(">>> WRITE: 0x%"PRIx64 ", value = 0x%"PRIx64 ", check = 0x%"PRIx64 "\n",
				address, value, t->check);
			assert(value == t->check);
			break;
	}
}

/* **** */

int main(void)
{
	test_t test, *t = &test;
	
	t->pc = 0;

	uc_assert_success(uc_open(UC_ARCH_ARM, UC_MODE_ARM926, &t->uc));
	uc_assert_success(uc_mem_map(t->uc, t->pc, 2 * 1024 * 1024, UC_PROT_ALL));

	uc_assert_success(uc_hook_add(t->uc, &t->trace1,
		UC_HOOK_MEM_READ, hook_mem, t, 1, 0));
		
	uc_assert_success(uc_hook_add(t->uc, &t->trace2,
		UC_HOOK_MEM_WRITE, hook_mem, t, 1, 0));

	t->pc = 0;

	_cxx(t, 0x0000, 0xe59f1010);		/*	ldr		r1, [pc, #0x10]   */
	_cxx(t, 0x0004, 0xe58f1028);		/*	str		r1, [pc, #0x28]   */
	_cxx(t, 0x0008, 0xeb000005);		/*	bl		#0x24             */
	_cxx(t, 0x000c, 0xe59f300c);		/*	ldr		r3, [pc, #0xc]    */
	_cxx(t, 0x0010, 0xe58f3024);		/*	str		r3, [pc, #0x24]   */
	_cxx(t, 0x0014, 0xea000005);		/*	b		#0x30             */
	_dxx(t, 0x0018, 0xcafebabe);
	_dxx(t, 0x001c, 0xdeadbeef);
	_dxx(t, 0x0020, 0xfeedface);
	_cxx(t, 0x0024, 0xe51f2010);		/*	ldr		r2, [pc, #-0x10]  */
	_cxx(t, 0x0028, 0xe58f2008);		/*	str		r2, [pc, #8]      */
	_cxx(t, 0x002c, 0xe12fff1e);		/*	bx		lr                */
	_cxx(t, 0x0030, 0xea000002);		/*	b		#0x40             */
	_dxx(t, 0x0034, 0x00000000);
	_dxx(t, 0x0038, 0x00000000);
	_dxx(t, 0x003c, 0x00000000);

	uint32_t end_pc = t->pc;
	t->pc = 0;
	
	uc_assert_success(uc_mem_write(t->uc, t->pc, &t->code, sizeof(t->code) - 1));

	// emulate machine code in infinite time (last param = 0), or when
	// finishing all the code.
	uc_assert_success(uc_emu_start(t->uc, t->pc, end_pc, 0, 32));

	uc_assert_success(uc_close(t->uc));

	return(0);
}
