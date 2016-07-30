#include <stdint.h>

#include "unicorn_test.h"


#define OK(x)   uc_assert_success(x)

#define CF_MASK		(1<<0)
#define PF_MASK		(1<<2)
#define ZF_MASK		(1<<6)
#define SF_MASK		(1<<7)
#define OF_MASK		(1<<11)
#define ALL_MASK	(OF_MASK|SF_MASK|ZF_MASK|PF_MASK|CF_MASK)
#define NO_MASK		0xFFFFFFFF

typedef struct _reg_value
{
	uint32_t regId, regValue, mask;
} reg_value;

typedef struct _instruction
{
	const char*			asmStr;
	const uint8_t*		code;
	uint32_t			codeSize;
	const reg_value*	values;
	uint32_t			nbValues;
} instruction;

typedef struct _block
{
	instruction*	insts[255];
	uint32_t		nbInsts;
	uint32_t		size;
} block;

typedef struct _exec_state
{
	uint32_t		curr;
	block*			block;
} exec_state;

/******************************************************************************/

#define CAT2(X, Y)		X ## Y
#define CAT(X, Y)		CAT2(X, Y)

#define ADD_INSTRUCTION(BLOCK, CODE_ASM, CODE, REGVALUES)	\
				const uint8_t CAT(code, __LINE__)[] = CODE; \
				const reg_value CAT(regValues, __LINE__)[] = REGVALUES; \
				inst = newInstruction(CAT(code, __LINE__), sizeof(CAT(code, __LINE__)), CODE_ASM, CAT(regValues, __LINE__), sizeof(CAT(regValues, __LINE__)) / sizeof(reg_value)); \
				addInstructionToBlock(BLOCK, inst);

#define V(...)	{ __VA_ARGS__ }

/******************************************************************************/

instruction*	newInstruction(const uint8_t * _code, uint32_t _codeSize, const char* _asmStr, const reg_value* _values, uint32_t _nbValues);
void			addInstructionToBlock(block* _b, instruction* _i);
uint32_t		loadBlock(uc_engine *_uc, block* _block, uint32_t _at);
void			freeBlock(block* _block);
const char*		getRegisterName(uint32_t _regid);
uint32_t		getRegisterValue(uc_engine *uc, uint32_t _regid);

/******************************************************************************/

void hook_code_test_i386_shl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t i;
	exec_state* es = (exec_state*)user_data;
	instruction* currInst = es->block->insts[es->curr];

	print_message("|\teip=%08x - %s\n", (uint32_t)address, es->block->insts[es->curr]->asmStr);

	for (i = 0; i < currInst->nbValues; i++)
	{
		if (currInst->values[i].regId == UC_X86_REG_INVALID) continue;
		uint32_t regValue = getRegisterValue(uc, currInst->values[i].regId);
		print_message("|\t\ttesting %s : ", getRegisterName(currInst->values[i].regId));
		assert_int_equal(regValue & currInst->values[i].mask, currInst->values[i].regValue);
		print_message("ok\n");
	}

	es->curr++;
	if (es->curr >= es->block->nbInsts)
	{
		print_message("stopping emulation\n");
		uc_emu_stop(uc);
	}
}

#define ADDR_START 0x100000

static void test_i386_shl_prob(void **state)
{
	uc_engine *uc;
	uc_hook trace1;

	// Initialize emulator in X86-32bit mode
	OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
	OK(uc_mem_map(uc, ADDR_START, 0x1000, UC_PROT_ALL));

	{
		exec_state es;
		block block_shl_prob;
		instruction* inst;

		es.curr = 0;
		es.block = &block_shl_prob;

		block_shl_prob.nbInsts = 0;

		ADD_INSTRUCTION(&block_shl_prob, "mov ebx, 3Ch", V(0xBB, 0x3C, 0x00, 0x00, 0x00), V(V(UC_X86_REG_INVALID, 0x0, NO_MASK)));
		ADD_INSTRUCTION(&block_shl_prob, "mov cl, 2", V(0xB1, 0x02), V(V(UC_X86_REG_EBX, 0x3C, NO_MASK)));
		ADD_INSTRUCTION(&block_shl_prob, "shl ebx, cl", V(0xD3, 0xE3), V(V(UC_X86_REG_EBX, 0x3C, NO_MASK), V(UC_X86_REG_CL, 0x2, NO_MASK)));
		ADD_INSTRUCTION(&block_shl_prob, "lahf", V(0x9F), V(V(UC_X86_REG_EBX, 0xF0, NO_MASK), V(UC_X86_REG_CL, 0x2, NO_MASK), V(UC_X86_REG_EFLAGS, 0x4, ALL_MASK)));
		ADD_INSTRUCTION(&block_shl_prob, "int3", V(0xCC), V(V(UC_X86_REG_AH, 0x4, PF_MASK), V(UC_X86_REG_EBX, 0xF0, NO_MASK), V(UC_X86_REG_CL, 0x2, NO_MASK), V(UC_X86_REG_EFLAGS, 0x4, ALL_MASK)));

		loadBlock(uc, &block_shl_prob, ADDR_START);

		// initialize machine registers
		uint32_t zero = 0;
		OK(uc_reg_write(uc, UC_X86_REG_EAX, &zero));
		OK(uc_reg_write(uc, UC_X86_REG_EBX, &zero));
		OK(uc_reg_write(uc, UC_X86_REG_ECX, &zero));
		OK(uc_reg_write(uc, UC_X86_REG_EDX, &zero));

		OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &es, 1, 0));

		// emulate machine code in infinite time
		OK(uc_emu_start(uc, ADDR_START, ADDR_START + block_shl_prob.size - 1, 0, 0));

		freeBlock(&block_shl_prob);
	}

	uc_close(uc);
}

static void test_i386_shl_ok(void **state)
{
	uc_engine *uc;
	uc_hook trace1;

	// Initialize emulator in X86-32bit mode
	OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
	OK(uc_mem_map(uc, ADDR_START, 0x1000, UC_PROT_ALL));

	{
		exec_state es;
		block block_shl_ok;
		instruction* inst;

		es.curr = 0;
		es.block = &block_shl_ok;

		block_shl_ok.nbInsts = 0;

		ADD_INSTRUCTION(&block_shl_ok, "mov ebx, 3Ch", V(0xBB, 0x3C, 0x00, 0x00, 0x00), V(V(UC_X86_REG_INVALID, 0x0, NO_MASK)));
		ADD_INSTRUCTION(&block_shl_ok, "shl ebx, 2", V(0xC1, 0xE3, 0x02), V(V(UC_X86_REG_EBX, 0x3C, NO_MASK)));
		ADD_INSTRUCTION(&block_shl_ok, "lahf", V(0x9F), V(V(UC_X86_REG_EBX, 0xF0, NO_MASK), V(UC_X86_REG_EFLAGS, 0x4, ALL_MASK)));
		ADD_INSTRUCTION(&block_shl_ok, "int3", V(0xCC), V(V(UC_X86_REG_AH, 0x4, PF_MASK), V(UC_X86_REG_EBX, 0xF0, NO_MASK), V(UC_X86_REG_EFLAGS, 0x4, ALL_MASK)));

		loadBlock(uc, &block_shl_ok, ADDR_START);

		// initialize machine registers
		uint32_t zero = 0;
		OK(uc_reg_write(uc, UC_X86_REG_EAX, &zero));
		OK(uc_reg_write(uc, UC_X86_REG_EBX, &zero));
		OK(uc_reg_write(uc, UC_X86_REG_ECX, &zero));
		OK(uc_reg_write(uc, UC_X86_REG_EDX, &zero));

		OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &es, 1, 0));

		// emulate machine code in infinite time
		OK(uc_emu_start(uc, ADDR_START, ADDR_START + block_shl_ok.size - 1, 0, 0));

		freeBlock(&block_shl_ok);
	}

	uc_close(uc);
}

/******************************************************************************/

int main(void) {
	const struct CMUnitTest tests[] = {

		cmocka_unit_test(test_i386_shl_prob),
		cmocka_unit_test(test_i386_shl_ok),

	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

/******************************************************************************/

instruction* newInstruction(const uint8_t * _code, uint32_t _codeSize, const char* _asmStr, const reg_value* _values, uint32_t _nbValues)
{
	instruction* inst = (instruction*)malloc(sizeof(instruction));

	inst->asmStr = _asmStr;
	inst->code = _code;
	inst->codeSize = _codeSize;
	inst->values = _values;
	inst->nbValues = _nbValues;

	return inst;
}

void addInstructionToBlock(block* _b, instruction* _i)
{
	_b->insts[_b->nbInsts++] = _i;
}

uint32_t loadBlock(uc_engine *_uc, block* _block, uint32_t _at)
{
	uint32_t i, offset;

	for (i = 0, offset = 0; i < _block->nbInsts; i++)
	{
		OK(uc_mem_write(_uc, _at + offset, _block->insts[i]->code, _block->insts[i]->codeSize));
		offset += _block->insts[i]->codeSize;
	}
	_block->size = offset;
	return offset;
}

void freeBlock(block* _block)
{
	uint32_t i;

	for (i = 0; i < _block->nbInsts; i++)
		free(_block->insts[i]);
}

const char* getRegisterName(uint32_t _regid)
{
	switch (_regid)
	{
		//8
	case UC_X86_REG_AH:		return "AH";
	case UC_X86_REG_AL:		return "AL";
	case UC_X86_REG_BH:		return "BH";
	case UC_X86_REG_BL:		return "BL";
	case UC_X86_REG_CL:		return "CL";
	case UC_X86_REG_CH:		return "CH";
	case UC_X86_REG_DH:		return "DH";
	case UC_X86_REG_DL:		return "DL";
		//16
	case UC_X86_REG_AX:		return "AX";
	case UC_X86_REG_BX:		return "BX";
	case UC_X86_REG_CX:		return "CX";
	case UC_X86_REG_DX:		return "DX";
		//32
	case UC_X86_REG_EAX:	return "EAX";
	case UC_X86_REG_EBX:	return "EBX";
	case UC_X86_REG_ECX:	return "ECX";
	case UC_X86_REG_EDX:	return "EDX";
	case UC_X86_REG_EDI:	return "EDI";
	case UC_X86_REG_ESI:	return "ESI";
	case UC_X86_REG_EBP:	return "EBP";
	case UC_X86_REG_ESP:	return "ESP";
	case UC_X86_REG_EIP:	return "EIP";
	case UC_X86_REG_EFLAGS: return "EFLAGS";

	default: fail();
	}
	return "UNKNOWN";
}

uint32_t getRegisterValue(uc_engine *uc, uint32_t _regid)
{
	switch (_regid)
	{
		//8
	case UC_X86_REG_AH:		case UC_X86_REG_AL:
	case UC_X86_REG_BH:		case UC_X86_REG_BL:
	case UC_X86_REG_CL:		case UC_X86_REG_CH:
	case UC_X86_REG_DH:		case UC_X86_REG_DL:
	{
		uint8_t val = 0;
		uc_reg_read(uc, _regid, &val);
		return val;
	}
	//16
	case UC_X86_REG_AX:		case UC_X86_REG_BX:
	case UC_X86_REG_CX:		case UC_X86_REG_DX:
	{
		uint16_t val = 0;
		uc_reg_read(uc, _regid, &val);
		return val;
	}
	//32
	case UC_X86_REG_EAX:	case UC_X86_REG_EBX:
	case UC_X86_REG_ECX:	case UC_X86_REG_EDX:
	case UC_X86_REG_EDI:	case UC_X86_REG_ESI:
	case UC_X86_REG_EBP:	case UC_X86_REG_ESP:
	case UC_X86_REG_EIP:	case UC_X86_REG_EFLAGS:
	{
		uint32_t val = 0;
		uc_reg_read(uc, _regid, &val);
		return val;
	}

	default: fail();
	}
	return 0;
}
