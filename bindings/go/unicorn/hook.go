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
	Uc       *Uc
	Callback interface{}
}

//export hookCode
func hookCode(handle C.uch, addr uint64, size uint32, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, uint64, uint32))(hook.Uc, uint64(addr), uint32(size))
}

//export hookMemInvalid
func hookMemInvalid(handle C.uch, typ C.uc_mem_type, addr uint64, size int, value int64, user unsafe.Pointer) bool {
	hook := (*HookData)(user)
	return hook.Callback.(func(*Uc, int, uint64, int, int64) bool)(hook.Uc, int(typ), addr, size, value)
}

//export hookMemAccess
func hookMemAccess(handle C.uch, typ C.uc_mem_type, addr uint64, size int, value int64, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, int, uint64, int, int64))(hook.Uc, int(typ), addr, size, value)
}

//export hookInterrupt
func hookInterrupt(handle C.uch, intno uint32, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, uint32))(hook.Uc, intno)
}

//export hookX86In
func hookX86In(handle C.uch, port, size uint32, user unsafe.Pointer) uint32 {
	hook := (*HookData)(user)
	return hook.Callback.(func(*Uc, uint32, uint32) uint32)(hook.Uc, port, size)
}

//export hookX86Out
func hookX86Out(handle C.uch, port, size, value uint32, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, uint32, uint32, uint32))(hook.Uc, port, size, value)
}

//export hookX86Syscall
func hookX86Syscall(handle C.uch, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc))(hook.Uc)
}

var hookRetain = make(map[C.uch]*HookData)

func (u *Uc) HookAdd(htype int, cb interface{}, extra ...uint64) (C.uch, error) {
	var callback unsafe.Pointer
	var iarg1 C.int
	var uarg1, uarg2 C.uint64_t
	rangeMode := false
	switch htype {
	case UC_HOOK_BLOCK, UC_HOOK_CODE:
		rangeMode = true
		callback = C.hookCode_cgo
	case UC_HOOK_MEM_INVALID:
		rangeMode = true
		callback = C.hookMemInvalid_cgo
	case UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ_WRITE:
		rangeMode = true
		callback = C.hookMemAccess_cgo
	case UC_HOOK_INTR:
		callback = C.hookInterrupt_cgo
	case UC_HOOK_INSN:
		iarg1 = C.int(extra[0])
		switch iarg1 {
		case UC_X86_INS_IN:
			callback = C.hookX86In_cgo
		case UC_X86_INS_OUT:
			callback = C.hookX86Out_cgo
		case UC_X86_INS_SYSCALL, UC_X86_INS_SYSENTER:
			callback = C.hookX86Syscall_cgo
		default:
			return 0, errors.New("Unknown instruction type.")
		}
	default:
		return 0, errors.New("Unknown hook type.")
	}
	var h2 C.uch
	data := &HookData{u, cb}
	if rangeMode {
		if len(extra) == 2 {
			uarg1 = C.uint64_t(extra[0])
			uarg2 = C.uint64_t(extra[1])
		} else {
			uarg1, uarg2 = 1, 0
		}
		C.uc_hook_add_u2(u.Handle, &h2, C.uc_hook_type(htype), callback, unsafe.Pointer(data), uarg1, uarg2)
	} else {
		C.uc_hook_add_i1(u.Handle, &h2, C.uc_hook_type(htype), callback, unsafe.Pointer(data), iarg1)
	}
	hookRetain[h2] = data
	return h2, nil
}

func (u *Uc) HookDel(hook *C.uch) error {
	delete(hookRetain, *hook)
	return errReturn(C.uc_hook_del(u.Handle, hook))
}
