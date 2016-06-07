package unicorn

import (
	"errors"
	"unsafe"
)

/*
#include <unicorn/unicorn.h>
#include "hook.h"
*/
import "C"

type HookData struct {
	Uc       Unicorn
	Callback interface{}
}

type Hook uint64

var hookDataMap = make(map[uintptr]*HookData)

//export hookCode
func hookCode(handle unsafe.Pointer, addr uint64, size uint32, user unsafe.Pointer) {
	hook := hookDataMap[uintptr(user)]
	hook.Callback.(func(Unicorn, uint64, uint32))(hook.Uc, uint64(addr), uint32(size))
}

//export hookMemInvalid
func hookMemInvalid(handle unsafe.Pointer, typ C.uc_mem_type, addr uint64, size int, value int64, user unsafe.Pointer) bool {
	hook := hookDataMap[uintptr(user)]
	return hook.Callback.(func(Unicorn, int, uint64, int, int64) bool)(hook.Uc, int(typ), addr, size, value)
}

//export hookMemAccess
func hookMemAccess(handle unsafe.Pointer, typ C.uc_mem_type, addr uint64, size int, value int64, user unsafe.Pointer) {
	hook := hookDataMap[uintptr(user)]
	hook.Callback.(func(Unicorn, int, uint64, int, int64))(hook.Uc, int(typ), addr, size, value)
}

//export hookInterrupt
func hookInterrupt(handle unsafe.Pointer, intno uint32, user unsafe.Pointer) {
	hook := hookDataMap[uintptr(user)]
	hook.Callback.(func(Unicorn, uint32))(hook.Uc, intno)
}

//export hookX86In
func hookX86In(handle unsafe.Pointer, port, size uint32, user unsafe.Pointer) uint32 {
	hook := hookDataMap[uintptr(user)]
	return hook.Callback.(func(Unicorn, uint32, uint32) uint32)(hook.Uc, port, size)
}

//export hookX86Out
func hookX86Out(handle unsafe.Pointer, port, size, value uint32, user unsafe.Pointer) {
	hook := hookDataMap[uintptr(user)]
	hook.Callback.(func(Unicorn, uint32, uint32, uint32))(hook.Uc, port, size, value)
}

//export hookX86Syscall
func hookX86Syscall(handle unsafe.Pointer, user unsafe.Pointer) {
	hook := hookDataMap[uintptr(user)]
	hook.Callback.(func(Unicorn))(hook.Uc)
}

func (u *uc) HookAdd(htype int, cb interface{}, begin, end uint64, extra ...int) (Hook, error) {
	var callback unsafe.Pointer
	var insn C.int
	var insnMode bool
	switch htype {
	case HOOK_BLOCK, HOOK_CODE:
		callback = C.hookCode_cgo
	case HOOK_MEM_READ, HOOK_MEM_WRITE, HOOK_MEM_READ | HOOK_MEM_WRITE:
		callback = C.hookMemAccess_cgo
	case HOOK_INTR:
		callback = C.hookInterrupt_cgo
	case HOOK_INSN:
		insn = C.int(extra[0])
		insnMode = true
		switch insn {
		case X86_INS_IN:
			callback = C.hookX86In_cgo
		case X86_INS_OUT:
			callback = C.hookX86Out_cgo
		case X86_INS_SYSCALL, X86_INS_SYSENTER:
			callback = C.hookX86Syscall_cgo
		default:
			return 0, errors.New("Unknown instruction type.")
		}
	default:
		// special case for mask
		if htype&(HOOK_MEM_READ_UNMAPPED|HOOK_MEM_WRITE_UNMAPPED|HOOK_MEM_FETCH_UNMAPPED|
			HOOK_MEM_READ_PROT|HOOK_MEM_WRITE_PROT|HOOK_MEM_FETCH_PROT) != 0 {
			callback = C.hookMemInvalid_cgo
		} else {
			return 0, errors.New("Unknown hook type.")
		}
	}
	var h2 C.uc_hook
	data := &HookData{u, cb}
	uptr := uintptr(unsafe.Pointer(data))
	if insnMode {
		C.uc_hook_add_insn(u.handle, &h2, C.uc_hook_type(htype), callback, C.uintptr_t(uptr), C.uint64_t(begin), C.uint64_t(end), insn)
	} else {
		C.uc_hook_add_wrap(u.handle, &h2, C.uc_hook_type(htype), callback, C.uintptr_t(uptr), C.uint64_t(begin), C.uint64_t(end))
	}
	hookDataMap[uptr] = data
	u.hooks[Hook(h2)] = uptr
	return Hook(h2), nil
}

func (u *uc) HookDel(hook Hook) error {
	if uptr, ok := u.hooks[hook]; ok {
		delete(u.hooks, hook)
		delete(hookDataMap, uptr)
	}
	return errReturn(C.uc_hook_del(u.handle, C.uc_hook(hook)))
}
