
/* 
	stdcall unicorn engine shim layer for use with VB6 or C#
	code ripped from unicorn_dynload.c 
	
	Contributed by: FireEye FLARE team
	Author:         David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
	License:        Apache

	Disassembler support can be optionally compiled in using:
	   libdasm (c) 2004 - 2006  jt / nologin.org

    this project has been built with vs2008

    precompiled binaries with disasm support available here:
       https://github.com/dzzie/libs/tree/master/unicorn_emu

*/

#include <io.h>
#include <windows.h>

#ifdef _WIN64
#error vb6 is 32bit only
#endif

#include <unicorn/unicorn.h>
#pragma comment(lib, "unicorn.lib")

//if you compile with VS2008 you will need to add stdint.h and inttypes.h to your compiler include directory
//you can find examples here: https://github.com/dzzie/VS_LIBEMU/tree/master/libemu/include

//if you want to include disassembler support:
//  1) install libdasm in your compilers include directory 
//  2) add libdasm.h/.c to the project (drag and drop into VS project explorer),
//  3) remove the comment from the define below. 
//The vb code detects the changes at runtime.
//#define INCLUDE_DISASM

#ifdef INCLUDE_DISASM
#include <libdasm/libdasm.h>
#endif


#include "msvbvm60.tlh" //so we can use the vb6 collection object

#define EXPORT comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)


enum hookCatagory{hc_code = 0, hc_block = 1, hc_inst = 2, hc_int = 3, hc_mem = 4, hc_memInvalid = 5};

//tracing UC_HOOK_CODE & UC_HOOK_BLOCK 
typedef void (__stdcall *vb_cb_hookcode_t)   (uc_engine *uc,  uint64_t address,  uint32_t size,    void *user_data); 
vb_cb_hookcode_t vbHookcode = 0;
vb_cb_hookcode_t vbHookBlock = 0;

//hooking memory UC_MEM_READ/WRITE/FETCH 
typedef void (__stdcall *vb_cb_hookmem_t)    (uc_engine *uc,  uc_mem_type type,  uint64_t address, int size,int64_t value, void *user_data);
vb_cb_hookmem_t vbHookMem = 0;

//invalid memory access  UC_MEM_*_UNMAPPED and UC_MEM_*PROT events 
typedef bool (__stdcall *vb_cb_eventmem_t)   (uc_engine *uc,  uc_mem_type type,  uint64_t address, int size, int64_t value, void *user_data);   
vb_cb_eventmem_t vbInvalidMem = 0;

//tracing interrupts for uc_hook_intr() 
typedef void (__stdcall *vb_cb_hookintr_t)   (uc_engine *uc,  uint32_t intno,    void *user_data); 
vb_cb_hookintr_t vbHookInt = 0;

/*
typedef uint32_t (__stdcall *uc_cb_insn_in_t)(uc_engine *uc,  uint32_t port,     int size,         void *user_data);                                      tracing IN instruction of X86
typedef void (__stdcall *uc_cb_insn_out_t)   (uc_engine *uc,  uint32_t port,     int size,         uint32_t value,  void *user_data);                     tracing OUT instruction of X86
*/

//------------------ [ call back proxies ] -------------------------
static void c_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	if(vbHookcode==0) return;
	vbHookcode(uc,address,size,user_data);
}

static void c_hook_mem(uc_engine *uc, uc_mem_type type,uint64_t address, int size, int64_t value, void *user_data)
{
	if(vbHookMem==0) return;
	vbHookMem(uc,type,address,size,value,user_data);
}

static bool c_hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if(vbInvalidMem==0) return false;
	return vbInvalidMem(uc,type,address,size,value,user_data);
}


static void c_hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	if(vbHookBlock==0) return;
	vbHookBlock(uc,address,size,user_data);
}

static void c_hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
	if(vbHookInt==0) return;
	vbHookInt(uc,intno,user_data);
}


/*
static uint32_t hook_in(uc_engine *uc, uint32_t port, int size, void *user_data)
{
}

static void hook_out(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
}
*/

//-------------------------------------------------------------

//uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback, void *user_data, uint64_t begin, uint64_t end, ...);
//we need to use a C stub cdecl callback then proxy to the stdcall vb one..
//we could get cute with an asm thunk in vb but not worth complexity there are only a couple of them to support..
//cdecl callback to vb stdcall callback for tracing
uc_err __stdcall ucs_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback, void *user_data, uint64_t begin, uint64_t end, int catagory, int instr_id){
#pragma EXPORT

	if(catagory == hc_code){
		if(vbHookcode == 0){
			if((int)callback==0) return UC_ERR_FETCH_UNMAPPED;
			vbHookcode = (vb_cb_hookcode_t)callback;
		}
		return uc_hook_add(uc,hh,type,c_hook_code,user_data,begin,end);
	}

	if(catagory == hc_block){
		if(vbHookBlock == 0){
			if((int)callback==0) return UC_ERR_FETCH_UNMAPPED;
			vbHookBlock = (vb_cb_hookcode_t)callback;
		}
		return uc_hook_add(uc,hh,type,c_hook_block,user_data,begin,end);
	}

	if(catagory == hc_mem){ //then it is some combination of memory access hook flags..
		if(vbHookMem == 0){
			if((int)callback==0) return UC_ERR_FETCH_UNMAPPED;
			vbHookMem = (vb_cb_hookmem_t)callback;
		}
		return uc_hook_add(uc,hh,type,c_hook_mem,user_data,begin,end);
	}

	if(catagory == hc_memInvalid){ //then it is some combination of invalid memory access hook flags..
		if(vbInvalidMem == 0){
			if((int)callback==0) return UC_ERR_FETCH_UNMAPPED;
			vbInvalidMem = (vb_cb_eventmem_t)callback;
		}
		return uc_hook_add(uc,hh,type,c_hook_mem_invalid,user_data,begin,end);
	}

	if(catagory == hc_int){
		if(vbHookInt == 0){
			if((int)callback==0) return UC_ERR_FETCH_UNMAPPED;
			vbHookInt = (vb_cb_hookintr_t)callback;
		}
		return uc_hook_add(uc,hh,UC_HOOK_INTR,c_hook_intr,user_data,begin,end);
	}

	return UC_ERR_ARG;
}

unsigned int __stdcall ucs_dynload(char *path){
#pragma EXPORT
    /*#ifdef DYNLOAD
		return uc_dyn_load(path, 0);
	#else*/
		return 1;
	//#endif	
}

unsigned int __stdcall ucs_version(unsigned int *major, unsigned int *minor){
#pragma EXPORT
    return uc_version(major, minor);
}

bool __stdcall ucs_arch_supported(uc_arch arch){
#pragma EXPORT
    return uc_arch_supported(arch);
}

uc_err __stdcall ucs_open(uc_arch arch, uc_mode mode, uc_engine **uc){
#pragma EXPORT
    return uc_open(arch, mode, uc);
}

uc_err __stdcall ucs_close(uc_engine *uc){
#pragma EXPORT
    return uc_close(uc);
}

uc_err __stdcall ucs_query(uc_engine *uc, uc_query_type type, size_t *result){
#pragma EXPORT
    return uc_query(uc, type, result);
}

uc_err __stdcall ucs_errno(uc_engine *uc){
#pragma EXPORT
    return uc_errno(uc);
}

const char *__stdcall ucs_strerror(uc_err code){
#pragma EXPORT
    return uc_strerror(code);
}

uc_err __stdcall ucs_reg_write(uc_engine *uc, int regid, const void *value){
#pragma EXPORT
    return uc_reg_write(uc, regid, value);
}

uc_err __stdcall ucs_reg_read(uc_engine *uc, int regid, void *value){
#pragma EXPORT
    return uc_reg_read(uc, regid, value);
}

uc_err __stdcall ucs_reg_write_batch(uc_engine *uc, int *regs, void *const *vals, int count){
#pragma EXPORT
    return uc_reg_write_batch(uc, regs, vals, count);
}

uc_err __stdcall ucs_reg_read_batch(uc_engine *uc, int *regs, void **vals, int count){
#pragma EXPORT
    return uc_reg_read_batch(uc, regs, vals, count);
}

uc_err __stdcall ucs_mem_write(uc_engine *uc, uint64_t address, const void *bytes, size_t size){
#pragma EXPORT
    return uc_mem_write(uc, address, bytes, size);
}

uc_err __stdcall ucs_mem_read(uc_engine *uc, uint64_t address, void *bytes, size_t size){
#pragma EXPORT
    return uc_mem_read(uc, address, bytes, size);
}

uc_err __stdcall ucs_emu_start(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count){
#pragma EXPORT
    return uc_emu_start(uc, begin, until, timeout, count);
}

uc_err __stdcall ucs_emu_stop(uc_engine *uc){
#pragma EXPORT
    return uc_emu_stop(uc);
}

uc_err __stdcall ucs_hook_del(uc_engine *uc, uc_hook hh){
#pragma EXPORT
    return uc_hook_del(uc, hh);
}

uc_err __stdcall ucs_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms){
#pragma EXPORT
    return uc_mem_map(uc, address, size, perms);
}

//requires link against v1.0
uc_err __stdcall ucs_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr){
#pragma EXPORT
    return uc_mem_map_ptr(uc, address, size, perms, ptr);
}


uc_err __stdcall ucs_mem_unmap(uc_engine *uc, uint64_t address, size_t size){
#pragma EXPORT
    return uc_mem_unmap(uc, address, size);
}

uc_err __stdcall ucs_mem_protect(uc_engine *uc, uint64_t address, size_t size, uint32_t perms){
#pragma EXPORT
    return uc_mem_protect(uc, address, size, perms);
}

uc_err __stdcall ucs_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count){
#pragma EXPORT
    return uc_mem_regions(uc, regions, count);
}

uc_err __stdcall ucs_context_alloc(uc_engine *uc, uc_context **context){
#pragma EXPORT
    return uc_context_alloc(uc, context);
}

uc_err __stdcall ucs_free(void *mem){
#pragma EXPORT
    return uc_free(mem);
}

uc_err __stdcall ucs_context_save(uc_engine *uc, uc_context *context){
#pragma EXPORT
    return uc_context_save(uc, context);
}

uc_err __stdcall ucs_context_restore(uc_engine *uc, uc_context *context){
#pragma EXPORT
    return uc_context_restore(uc, context);
}

/*
char* asprintf(char* format, ...){
	
	char *ret = 0;
	
	if(!format) return 0;

	va_list args; 
	va_start(args,format); 
	int size = _vscprintf(format, args); 
	
	if(size > 0){
		size++; //for null
		ret = (char*)malloc(size+2);
		if(ret) _vsnprintf(ret, size, format, args);
	}

	va_end(args);
	return ret;
}*/

#ifdef INCLUDE_DISASM
int __stdcall disasm_addr(uc_engine *uc, uint32_t va, char *str, int bufLen){
#pragma EXPORT
	uint32_t instr_len = 0;
	int readLen = 15;
    uint8_t data[32];
	INSTRUCTION inst;

	if(bufLen < 100) return -1;

	//longest x86 instruction is 15 bytes, what if at the tail end of an allocation? try to read as much as we can..
	while(uc_mem_read(uc,va,data,readLen) != 0){
		readLen--;
		if(readLen == 0) return -2;
	}
  
	instr_len = get_instruction(&inst, data, MODE_32);
	if( instr_len == 0 ) return -3;

	get_instruction_string(&inst, FORMAT_INTEL, va, str, bufLen);

	/* 
	if(inst.type == INSTRUCTION_TYPE_JMP || inst.type == INSTRUCTION_TYPE_JMPC){
		if(inst.op1.type == OPERAND_TYPE_IMMEDIATE){
			if(strlen(str) + 6 < bufLen){
				if(getJmpTarget(str) < va){
					strcat(str,"   ^^");  
				}else{
					strcat(str,"  vv");
				}
			}
		}
	}*/

	return instr_len;
}
#endif


//maps and write in one shot, auto handles alignment..
uc_err __stdcall mem_write_block(uc_engine *uc, uint64_t address, void* data, uint32_t size, uint32_t perm){
#pragma EXPORT

	uc_err x;
	uint64_t base = address;
    uint32_t sz = size;

	while(base % 0x1000 !=0){
		base--;
		if(base==0) break;
	}
	
	sz += address-base; //if data starts mid block, we need to alloc more than just size..
	while(sz % 0x1000 !=0){
		sz++;
	}

	x = uc_mem_map(uc, base, sz, perm);
	if(x) return x;

	x = uc_mem_write(uc, address, (void*)data, size);
	if(x) return x;
	return UC_ERR_OK;
}

void addStr(_CollectionPtr p , char* str){
	_variant_t vv;
	vv.SetString(str);
	p->Add( &vv.GetVARIANT() );
}

uc_err __stdcall get_memMap(uc_engine *uc, _CollectionPtr *pColl){
#pragma EXPORT

   uc_mem_region *regions;
   uint32_t count;
   char tmp[200]; //max 46 chars used

   uc_err err = uc_mem_regions(uc, &regions, &count);
   
   if (err != UC_ERR_OK) return err;

   for (uint32_t i = 0; i < count; i++) {
     sprintf(tmp,"&h%llx,&h%llx,&h%x", regions[i].begin, regions[i].end, regions[i].perms);
	 addStr(*pColl,tmp);
   }

   //free(regions); //https://github.com/unicorn-engine/unicorn/pull/373#issuecomment-271187118
   
   uc_free((void*)regions);
   return err;

}

enum op{
	op_add = 0,
	op_sub = 1,
	op_div = 2,
	op_mul = 3,
	op_mod = 4,
	op_xor = 5,
	op_and = 6,
	op_or  = 7,
	op_rsh = 8,
	op_lsh = 9,
	op_gt  = 10,
	op_lt  = 11,
	op_gteq = 12,
	op_lteq = 13
};

unsigned int __stdcall ULong(unsigned int v1, unsigned int v2, int operation){
#pragma EXPORT

	switch(operation){
		case op_add: return v1 + v2;
		case op_sub: return v1 - v2;
		case op_div: return v1 / v2;
		case op_mul: return v1 * v2;
		case op_mod: return v1 % v2;
		case op_xor: return v1 ^ v2;
		case op_and: return v1 & v2;
		case op_or:  return v1 | v2;
		case op_rsh: return v1 >> v2;
		case op_lsh: return v1 << v2;
		case op_gt: return (v1 > v2 ? 1 : 0);
		case op_lt: return (v1 < v2 ? 1 : 0);
		case op_gteq: return (v1 >= v2 ? 1 : 0);
		case op_lteq: return (v1 <= v2 ? 1 : 0);
	}

	return -1;

}