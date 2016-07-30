#include <stdint.h>
#include <vector>

extern "C"
{
#include "unicorn_test.h"
}


#define OK(x)   uc_assert_success(x)

#define CF_MASK		(1<<0)
#define PF_MASK		(1<<2)
#define ZF_MASK		(1<<6)
#define SF_MASK		(1<<7)
#define OF_MASK		(1<<11)
#define ALL_MASK	(OF_MASK|SF_MASK|ZF_MASK|PF_MASK|CF_MASK)


struct instruction
{
	std::vector<uint8_t> code;
	const char* asmStr;
	struct reg_value {
		uint32_t regId, regValue, mask;
		reg_value(uint32_t _rid, uint32_t _rval, uint32_t _msk = 0xFFFFFFFF) : regId(_rid), regValue(_rval), mask(_msk)
		{}
	};
	std::vector<reg_value> values;
};

struct exec_state
{
	uint32_t					curr;
	std::vector<instruction>	insts;
};

const char* getRegisterName(uint32_t _regid)
{
	switch (_regid)
	{
        //8
        case UC_X86_REG_AH:	return "AH";
        case UC_X86_REG_AL:	return "AL";
        case UC_X86_REG_BH:	return "BH";	
        case UC_X86_REG_BL:	return "BL";
        case UC_X86_REG_CL:	return "CL";
        case UC_X86_REG_CH:	return "CH";
        case UC_X86_REG_DH:	return "DH";
        case UC_X86_REG_DL:	return "DL";
        //16
        case UC_X86_REG_AX:	return "AX";
        case UC_X86_REG_BX:	return "BX";
        case UC_X86_REG_CX:	return "CX";
        case UC_X86_REG_DX:	return "DX";
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
}

void hook_code_test_i386_shl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	exec_state* es = (exec_state*)user_data;

	print_message("\teip=%08x - %s\n", (uint32_t)address, es->insts[es->curr].asmStr);

	std::vector<instruction::reg_value>& rval = es->insts[es->curr].values;
	for (auto& v : rval)
	{
		uint32_t regValue = getRegisterValue(uc, v.regId);
		print_message("\t\ttesting %s : ", getRegisterName(v.regId));
		assert_int_equal(regValue & v.mask, v.regValue);
		print_message("ok\n");
	}

	es->curr++;
}

std::vector<instruction> codeSHL_prob = {
	{ { 0xBB, 0x3C, 0x00, 0x00, 0x00 }, "mov ebx, 3Ch", {} },
	{ { 0xB1, 0x02 }, "mov cl, 2", { { UC_X86_REG_EBX, 0x3C } } },
	{ { 0xD3, 0xE3 }, "shl ebx, cl", { { UC_X86_REG_EBX, 0x3C }, { UC_X86_REG_CL, 0x2 } } },
	{ { 0x9F }, "lahf", { { UC_X86_REG_EBX, 0xF0 }, { UC_X86_REG_CL, 0x2 }, { UC_X86_REG_EFLAGS, 0x4, ALL_MASK } } },
	{ { 0xCC }, "int3", { { UC_X86_REG_AH, 0x4, PF_MASK }, { UC_X86_REG_EBX, 0xF0 }, { UC_X86_REG_CL, 0x2 }, { UC_X86_REG_EFLAGS, 0x4, ALL_MASK } } }
};

std::vector<instruction> codeSHL_ok = {
	{ { 0xBB, 0x3C, 0x00, 0x00, 0x00 }, "mov ebx, 3Ch", {} },
	{ { 0xC1, 0xE3, 0x02 }, "shl ebx, 2", { { UC_X86_REG_EBX, 0x3C } } },
	{ { 0x9F }, "lahf", { { UC_X86_REG_EBX, 0xF0 }, { UC_X86_REG_EFLAGS, 0x4, ALL_MASK } } },
	{ { 0xCC }, "int3", { { UC_X86_REG_AH, 0x4, PF_MASK }, { UC_X86_REG_EBX, 0xF0 }, { UC_X86_REG_EFLAGS, 0x4, ALL_MASK } } }
};

uint32_t loadCode(uc_engine *_uc, const std::vector<instruction>& _insts, uint32_t _at)
{
	std::vector<uint8_t> code;
	for (auto& inst : _insts)
		code.insert(code.end(), inst.code.begin(), inst.code.end());

	OK(uc_mem_write(_uc, _at, code.data(), code.size()));

	return code.size();
}

#define ADDR_START 0x100000

static void test_i386_shl_prob(void **state)
{
	uc_engine *uc;
	uc_err err;
	uc_hook trace1;

	// Initialize emulator in X86-32bit mode
	OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
	OK(uc_mem_map(uc, ADDR_START, 0x1000, UC_PROT_ALL));

	uint32_t codeSize = loadCode(uc, codeSHL_prob, ADDR_START);

	exec_state es;
	es.curr = 0;
	es.insts = codeSHL_prob;

	// initialize machine registers
	uint32_t zero = 0;
	OK(uc_reg_write(uc, UC_X86_REG_EAX, &zero));
	OK(uc_reg_write(uc, UC_X86_REG_EBX, &zero));
	OK(uc_reg_write(uc, UC_X86_REG_ECX, &zero));
	OK(uc_reg_write(uc, UC_X86_REG_EDX, &zero));

	OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &es, 1, 0));

	// emulate machine code in infinite time
	OK(uc_emu_start(uc, ADDR_START, ADDR_START + codeSize - 1, 0, 0));

	uc_close(uc);
}

static void test_i386_shl_ok(void **state)
{
	uc_engine *uc;
	uc_err err;
	uc_hook trace1;

	// Initialize emulator in X86-32bit mode
	OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
	OK(uc_mem_map(uc, ADDR_START, 0x1000, UC_PROT_ALL));

	uint32_t codeSize = loadCode(uc, codeSHL_ok, ADDR_START);

	exec_state es;
	es.curr = 0;
	es.insts = codeSHL_ok;

	// initialize machine registers
	uint32_t zero = 0;
	OK(uc_reg_write(uc, UC_X86_REG_EAX, &zero));
	OK(uc_reg_write(uc, UC_X86_REG_EBX, &zero));
	OK(uc_reg_write(uc, UC_X86_REG_ECX, &zero));
	OK(uc_reg_write(uc, UC_X86_REG_EDX, &zero));

	OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &es, 1, 0));

	// emulate machine code in infinite time
	OK(uc_emu_start(uc, ADDR_START, ADDR_START + codeSize - 1, 0, 0));

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
