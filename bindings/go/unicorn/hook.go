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
func hookCode(handle C.uch, addr C.uint64_t, size C.uint32_t, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, uint64, uint32))(hook.Uc, uint64(addr), uint32(size))
}

//export hookMemInvalid
func hookMemInvalid(handle C.uch, typ C.uc_mem_type, addr C.uint64_t, value C.int64_t, user unsafe.Pointer) C.bool {
	hook := (*HookData)(user)
	return C.bool(hook.Callback.(func(*Uc, int, uint64, int64) bool)(hook.Uc, int(typ), uint64(addr), int64(value)))
}

//export hookMemAccess
func hookMemAccess(handle C.uch, typ C.uc_mem_type, addr C.uint64_t, size int, value C.int64_t, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, int, uint64, uint32, int64))(hook.Uc, int(typ), uint64(addr), uint32(size), int64(value))
}

//export hookX86In
func hookX86In(handle C.uch, port, size uint32, user unsafe.Pointer) C.uint32_t {
	hook := (*HookData)(user)
	return C.uint32_t(hook.Callback.(func(*Uc, uint32, uint32) uint32)(hook.Uc, port, size))
}

//export hookX86Out
func hookX86Out(handle C.uch, port, size, value uint32, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc, uint32, uint32, uint32))(hook.Uc, uint32(port), uint32(size), uint32(value))
}

//export hookX86Syscall
func hookX86Syscall(handle C.uch, user unsafe.Pointer) {
	hook := (*HookData)(user)
	hook.Callback.(func(*Uc))(hook.Uc)
}

func (u *Uc) HookAdd(htype int, cb interface{}, insn ...int) (C.uch, error) {
	var callback unsafe.Pointer
	var extra C.int
	switch htype {
	case UC_HOOK_BLOCK, UC_HOOK_CODE:
		callback = C.hookCode_cgo
	case UC_HOOK_MEM_INVALID:
		callback = C.hookMemInvalid_cgo
	case UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ_WRITE:
		callback = C.hookMemAccess_cgo
	case UC_HOOK_INSN:
		extra = C.int(insn[0])
		switch extra {
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
	C.uc_hook_add2(u.Handle, &h2, C.uc_hook_t(htype), callback, unsafe.Pointer(&HookData{u, cb}), extra)
	return h2, nil
}

func (u *Uc) HookDel(hook *C.uch) error {
	return errReturn(C.uc_hook_del(u.Handle, hook))
}
