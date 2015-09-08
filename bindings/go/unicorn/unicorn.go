package unicorn

import (
	"unsafe"
)

/*
#cgo LDFLAGS: -lunicorn
#include <unicorn/unicorn.h>
*/
import "C"

type UcError C.uc_err

func (u UcError) Error() string {
	return C.GoString(C.uc_strerror(C.uc_err(u)))
}

func errReturn(err C.uc_err) error {
	if err != UC_ERR_OK {
		return UcError(err)
	}
	return nil
}

type Uc struct {
	Handle     *C.uc_engine
	Arch, Mode int
}

type UcOptions struct {
	Timeout, Count uint64
}

func NewUc(arch, mode int) (*Uc, error) {
	var major, minor C.uint
	C.uc_version(&major, &minor)
	if major != C.UC_API_MAJOR || minor != C.UC_API_MINOR {
		return nil, UcError(UC_ERR_VERSION)
	}
	var handle *C.uc_engine
	if ucerr := C.uc_open(C.uc_arch(arch), C.uc_mode(mode), &handle); ucerr != UC_ERR_OK {
		return nil, UcError(ucerr)
	}
	uc := &Uc{handle, arch, mode}
	return uc, nil
}

func (u *Uc) StartWithOptions(begin, until uint64, options *UcOptions) error {
	ucerr := C.uc_emu_start(u.Handle, C.uint64_t(begin), C.uint64_t(until), C.uint64_t(options.Timeout), C.size_t(options.Count))
	return errReturn(ucerr)
}

func (u *Uc) Start(begin, until uint64) error {
	return u.StartWithOptions(begin, until, &UcOptions{})
}

func (u *Uc) Stop() error {
	return errReturn(C.uc_emu_stop(u.Handle))
}

func (u *Uc) RegWrite(reg int, value uint64) error {
	var val C.uint64_t = C.uint64_t(value)
	ucerr := C.uc_reg_write(u.Handle, C.int(reg), unsafe.Pointer(&val))
	return errReturn(ucerr)
}

func (u *Uc) RegRead(reg int) (uint64, error) {
	var val C.uint64_t
	ucerr := C.uc_reg_read(u.Handle, C.int(reg), unsafe.Pointer(&val))
	return uint64(val), errReturn(ucerr)
}

func (u *Uc) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return errReturn(C.uc_mem_write(u.Handle, C.uint64_t(addr), unsafe.Pointer(&data[0]), C.size_t(len(data))))
}

func (u *Uc) MemReadInto(dst []byte, addr uint64) error {
	if len(dst) == 0 {
		return nil
	}
	return errReturn(C.uc_mem_read(u.Handle, C.uint64_t(addr), unsafe.Pointer(&dst[0]), C.size_t(len(dst))))
}

func (u *Uc) MemRead(addr, size uint64) ([]byte, error) {
	dst := make([]byte, size)
	return dst, u.MemReadInto(dst, addr)
}

func (u *Uc) MemMapProt(addr, size uint64, prot int) error {
	return errReturn(C.uc_mem_map(u.Handle, C.uint64_t(addr), C.size_t(size), C.uint32_t(prot)))
}

func (u *Uc) MemMap(addr, size uint64) error {
	return u.MemMapProt(addr, size, UC_PROT_ALL)
}
