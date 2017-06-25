#include "unicorn/unicorn.h"
#include <string.h>

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
    const char*		asmStr;
    uint8_t			code[16]; //x86 inst == 15 bytes max
    uint32_t		codeSize;
    reg_value*		values;
    uint32_t		nbValues;
    uint32_t		addr;
} instruction;

typedef struct _block
{
    instruction*	insts[255];
    uint32_t		nbInsts;
    uint32_t		size;
} block;

/******************************************************************************/

#define CAT2(X, Y)		X ## Y
#define CAT(X, Y)		CAT2(X, Y)

#define BLOCK_START(BLOCK) \
    { \
        block* blockPtr = &BLOCK; \
        blockPtr->nbInsts = 0; \
        instruction* instPtr = NULL;

#define BLOCK_END() }

#define BLOCK_ADD(CODE_ASM, CODE)	\
                const uint8_t CAT(code, __LINE__)[] = CODE; \
                instPtr = newInstruction(CAT(code, __LINE__), sizeof(CAT(code, __LINE__)), CODE_ASM, NULL, 0); \
                addInstructionToBlock(blockPtr, instPtr);

#define BLOCK_ADD_CHECK(CODE_ASM, CODE, REGVALUES)	\
                const uint8_t CAT(code, __LINE__)[] = CODE; \
                const reg_value CAT(regValues, __LINE__)[] = REGVALUES; \
                instPtr = newInstruction(CAT(code, __LINE__), sizeof(CAT(code, __LINE__)), CODE_ASM, CAT(regValues, __LINE__), sizeof(CAT(regValues, __LINE__)) / sizeof(reg_value)); \
                addInstructionToBlock(blockPtr, instPtr);

#define V(...)	{ __VA_ARGS__ }

/******************************************************************************/

instruction*	newInstruction(const uint8_t * _code, uint32_t _codeSize, const char* _asmStr, const reg_value* _values, uint32_t _nbValues);
void			addInstructionToBlock(block* _b, instruction* _i);
uint32_t		loadBlock(uc_engine *_uc, block* _block, uint32_t _at);
void			freeBlock(block* _block);
const char*		getRegisterName(uint32_t _regid);
uint32_t		getRegisterValue(uc_engine *uc, uint32_t _regid);
instruction*	getInstruction(block * _block, uint32_t _addr);
void			initRegisters(uc_engine *uc);

/******************************************************************************/

void hook_code_test_i386_shl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint32_t i;
    block* b = (block*)user_data;
    instruction* currInst = getInstruction(b, (uint32_t)address);
    assert_true(currInst != NULL);

    printf("|\teip=%08x - %s\n", (uint32_t)address, currInst->asmStr);

    for (i = 0; i < currInst->nbValues; i++)
    {
        uint32_t regValue = getRegisterValue(uc, currInst->values[i].regId);
        printf("|\t\ttesting %s : ", getRegisterName(currInst->values[i].regId));
        assert_int_equal(regValue & currInst->values[i].mask, currInst->values[i].regValue);
        printf("ok\n");
    }

    if (currInst->code[0] == 0xCC)
        OK(uc_emu_stop(uc));
}

bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data)
{
    switch (type)
    {
    default:
        printf("hook_mem_invalid: UC_HOOK_MEM_INVALID type: %d at 0x%" PRIx64 "\n", type, addr); break;
    case UC_MEM_READ_UNMAPPED:
        printf("hook_mem_invalid: Read from invalid memory at 0x%" PRIx64 ", data size = %u\n", addr, size); break;
    case UC_MEM_WRITE_UNMAPPED:
        printf("hook_mem_invalid: Write to invalid memory at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", addr, size, value); break;
    case UC_MEM_FETCH_PROT:
        printf("hook_mem_invalid: Fetch from non-executable memory at 0x%" PRIx64 "\n", addr); break;
    case UC_MEM_WRITE_PROT:
        printf("hook_mem_invalid: Write to non-writeable memory at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", addr, size, value); break;
    case UC_MEM_READ_PROT:
        printf("hook_mem_invalid: Read from non-readable memory at 0x%" PRIx64 ", data size = %u\n", addr, size); break;
    }
    return false;
}

#define ADDR_CODE	0x100000
#define	ADDR_STACK	0x200000



static void test_i386_shl_cl(void **state)
{
    uc_engine *uc;
    uc_hook trace1;
    block b;

    // Initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, ADDR_CODE, 0x1000, UC_PROT_ALL));
    
    initRegisters(uc);

    BLOCK_START(b);
    BLOCK_ADD(		"mov ebx, 3Ch", V(0xBB, 0x3C, 0x00, 0x00, 0x00));
    BLOCK_ADD_CHECK("mov cl, 2",	V(0xB1, 0x02),					V(V(UC_X86_REG_EBX, 0x3C, NO_MASK)));
    BLOCK_ADD_CHECK("shl ebx, cl",	V(0xD3, 0xE3),					V(V(UC_X86_REG_CL, 0x2, NO_MASK)));
    BLOCK_ADD_CHECK("lahf",			V(0x9F),						V(V(UC_X86_REG_EBX, 0xF0, NO_MASK), V(UC_X86_REG_EFLAGS, 0x4, ALL_MASK)));
    BLOCK_ADD_CHECK("int3",			V(0xCC),						V(V(UC_X86_REG_AH, 0x4, PF_MASK)));
    BLOCK_END();

    loadBlock(uc, &b, ADDR_CODE);

    OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &b, 1, 0));
    OK(uc_hook_add(uc, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0));

    // emulate machine code in infinite time
    OK(uc_emu_start(uc, ADDR_CODE, ADDR_CODE + b.size, 0, 0));

    freeBlock(&b);

    uc_close(uc);
}

static void test_i386_shl_imm(void **state)
{
    uc_engine *uc;
    uc_hook trace1;
    block b;

    // Initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, ADDR_CODE, 0x1000, UC_PROT_ALL));

    initRegisters(uc);

    BLOCK_START(b);
    BLOCK_ADD(		"mov ebx, 3Ch",	V(0xBB, 0x3C, 0x00, 0x00, 0x00));
    BLOCK_ADD(		"shl ebx, 2",	V(0xC1, 0xE3, 0x02));
    BLOCK_ADD_CHECK("lahf",			V(0x9F),						V(V(UC_X86_REG_EBX, 0xF0, NO_MASK), V(UC_X86_REG_EFLAGS, 0x4, ALL_MASK)));
    BLOCK_ADD_CHECK("int3",			V(0xCC),						V(V(UC_X86_REG_AH, 0x4, PF_MASK)));
    BLOCK_END();

    loadBlock(uc, &b, ADDR_CODE);
    
    OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &b, 1, 0));
    OK(uc_hook_add(uc, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0));
    
    // emulate machine code in infinite time
    OK(uc_emu_start(uc, ADDR_CODE, ADDR_CODE + b.size, 0, 0));
    
    freeBlock(&b);

    uc_close(uc);
}

static void test_i386_enter_leave(void **state)
{
    uc_engine *uc;
    uc_hook trace1;
    block b;

    // Initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, ADDR_CODE, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, ADDR_STACK - 0x1000, 0x1000, UC_PROT_ALL));

    initRegisters(uc);

    BLOCK_START(b);
    BLOCK_ADD(		"mov esp, 0x200000",	V(0xBC, 0x00, 0x00, 0x20, 0x00));
    BLOCK_ADD_CHECK("mov eax, 1", 			V(0xB8, 0x01, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_ESP, 0x200000, NO_MASK)));
    BLOCK_ADD_CHECK("call 0x100015",		V(0xE8, 0x06, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_EAX, 0x1, NO_MASK)));
    BLOCK_ADD_CHECK("mov eax, 3",			V(0xB8, 0x03, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_EAX, 0x2, NO_MASK)));
    BLOCK_ADD_CHECK("int3",					V(0xCC), 							V(V(UC_X86_REG_EAX, 0x3, NO_MASK)));
    BLOCK_ADD_CHECK("enter 0x10,0",			V(0xC8, 0x10, 0x00, 0x00),			V(V(UC_X86_REG_ESP, 0x200000 - 4, NO_MASK)));
    BLOCK_ADD_CHECK("mov eax, 2",			V(0xB8, 0x02, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_ESP, 0x200000 - 4 - 4 - 0x10, NO_MASK), V(UC_X86_REG_EBP, 0x200000 - 4 - 4, NO_MASK)));
    BLOCK_ADD_CHECK("leave",				V(0xC9),							V(V(UC_X86_REG_EAX, 0x2, NO_MASK)));
    BLOCK_ADD_CHECK("ret",					V(0xC3),							V(V(UC_X86_REG_ESP, 0x200000 - 4, NO_MASK)));
    BLOCK_END();

    loadBlock(uc, &b, ADDR_CODE);

    OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &b, 1, 0));
    OK(uc_hook_add(uc, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0));

    // emulate machine code in infinite time
    OK(uc_emu_start(uc, ADDR_CODE, ADDR_CODE + b.size, 0, 0));

    freeBlock(&b);

    uc_close(uc);
}

static void test_i386_enter_nested_leave(void **state)
{
    uc_engine *uc;
    uc_hook trace1;
    block b;

    // Initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, ADDR_CODE, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, ADDR_STACK - 0x1000, 0x1000, UC_PROT_ALL));

    initRegisters(uc);

    BLOCK_START(b);
    BLOCK_ADD(		"mov esp, 0x200000",	V(0xBC, 0x00, 0x00, 0x20, 0x00));
    BLOCK_ADD_CHECK("mov eax, 1",			V(0xB8, 0x01, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_ESP, 0x200000, NO_MASK)));
    BLOCK_ADD_CHECK("call 0x100015", 		V(0xE8, 0x06, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_EAX, 0x1, NO_MASK)));
    BLOCK_ADD_CHECK("mov eax, 3",			V(0xB8, 0x03, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_EAX, 0x2, NO_MASK)));
    BLOCK_ADD_CHECK("int3",					V(0xCC),							V(V(UC_X86_REG_EAX, 0x3, NO_MASK)));
    BLOCK_ADD_CHECK("mov ebp, esp",			V(0x89, 0xE5),						V(V(UC_X86_REG_ESP, 0x200000 - 4, NO_MASK)));
    BLOCK_ADD_CHECK("enter 0x10,1",			V(0xC8, 0x10, 0x00, 0x01),			V(V(UC_X86_REG_EBP, 0x200000 - 4, NO_MASK)));
    BLOCK_ADD_CHECK("mov eax, 2",			V(0xB8, 0x02, 0x00, 0x00, 0x00),	V(V(UC_X86_REG_ESP, 0x200000 - 4 - 2*4 - 0x10, NO_MASK), V(UC_X86_REG_EBP, 0x200000 - 4 - 4, NO_MASK)));
    BLOCK_ADD_CHECK("leave",				V(0xC9),							V(V(UC_X86_REG_EAX, 0x2, NO_MASK)));
    BLOCK_ADD_CHECK("ret",					V(0xC3),							V(V(UC_X86_REG_ESP, 0x200000 - 4, NO_MASK)));
    BLOCK_END();

    loadBlock(uc, &b, ADDR_CODE);

    OK(uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code_test_i386_shl, &b, 1, 0));
    OK(uc_hook_add(uc, &trace1, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0));

    // emulate machine code in infinite time
    OK(uc_emu_start(uc, ADDR_CODE, ADDR_CODE + b.size, 0, 0));

    freeBlock(&b);
    
    uc_close(uc);
}

/******************************************************************************/

int main(void) {
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_i386_shl_cl),
        cmocka_unit_test(test_i386_shl_imm),
        cmocka_unit_test(test_i386_enter_leave), 
        cmocka_unit_test(test_i386_enter_nested_leave),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/******************************************************************************/

instruction* newInstruction(const uint8_t * _code, uint32_t _codeSize, const char* _asmStr, const reg_value* _values, uint32_t _nbValues)
{
    instruction* inst = (instruction*)malloc(sizeof(instruction));

    inst->asmStr = _asmStr;
    memcpy(inst->code, _code, _codeSize);
    inst->codeSize = _codeSize;
    inst->nbValues = 0;
    if (_values)
    {
        inst->values = (reg_value*)malloc(_nbValues*sizeof(reg_value));
        memcpy(inst->values, _values, _nbValues*sizeof(reg_value));
        inst->nbValues = _nbValues;
    }

    return inst;
}

void addInstructionToBlock(block* _b, instruction* _i)
{
    _b->insts[_b->nbInsts++] = _i;
}

uint32_t loadBlock(uc_engine *_uc, block* _block, uint32_t _at)
{
    uint32_t i, j, offset;

    for (i = 0, offset = 0; i < _block->nbInsts; i++)
    {
        const uint32_t codeSize = _block->insts[i]->codeSize;
        const uint8_t* code = _block->insts[i]->code;
        _block->insts[i]->addr = _at + offset;
        printf("load: %08X: ", _block->insts[i]->addr);
        for (j = 0; j < codeSize; j++)			printf("%02X ", code[j]);
        for (j = 0; j < 15 - codeSize; j++)		printf("   ");
        printf("%s\n", _block->insts[i]->asmStr);
        OK(uc_mem_write(_uc, _at + offset, code, codeSize));
        offset += codeSize;
    }
    _block->size = offset;
    return offset;
}

void freeBlock(block* _block)
{
    uint32_t i;
    for (i = 0; i < _block->nbInsts; i++)
    {
        if (_block->insts[i]->nbValues > 0)
            free(_block->insts[i]->values);
        free(_block->insts[i]);
    }
}

void initRegisters(uc_engine *uc)
{
    // initialize machine registers
    uint32_t zero = 0;
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_EBP, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_ESP, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_EDI, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_ESI, &zero));
    OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &zero));
}

instruction* getInstruction(block* _block, uint32_t _addr)
{
    uint32_t i;
    for (i = 0; i < _block->nbInsts; i++)
    {
        if (_block->insts[i]->addr == _addr)
            return _block->insts[i];
    }
    return NULL;
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
        OK(uc_reg_read(uc, _regid, &val));
        return val;
    }
    //16
    case UC_X86_REG_AX:		case UC_X86_REG_BX:
    case UC_X86_REG_CX:		case UC_X86_REG_DX:
    {
        uint16_t val = 0;
        OK(uc_reg_read(uc, _regid, &val));
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
        OK(uc_reg_read(uc, _regid, &val));
        return val;
    }

    default: fail();
    }
    return 0;
}
