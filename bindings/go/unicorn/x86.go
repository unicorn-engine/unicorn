package unicorn

import (
	"unsafe"
)

// #include <unicorn/unicorn.h>
// #include <unicorn/x86.h>
import "C"

type X86Mmr struct {
	Selector uint16
	Base     uint64
	Limit    uint32
	Flags    uint32
}

func (u *uc) RegWriteMmr(reg int, value *X86Mmr) error {
	var val C.uc_x86_mmr
	val.selector = C.uint16_t(value.Selector)
	val.base = C.uint64_t(value.Base)
	val.limit = C.uint32_t(value.Limit)
	val.flags = C.uint32_t(value.Flags)
	ucerr := C.uc_reg_write(u.handle, C.int(reg), unsafe.Pointer(&val))
	return errReturn(ucerr)
}
