package unicorn

import (
	"runtime"
	"sync"
	"unsafe"
)

/*
#include <unicorn/unicorn.h>
#include "uc.h"
*/
import "C"

type UcError C.uc_err

func (u UcError) Error() string {
	return C.GoString(C.uc_strerror(C.uc_err(u)))
}

func errReturn(err C.uc_err) error {
	if err != ERR_OK {
		return UcError(err)
	}
	return nil
}

type MemRegion struct {
	Begin, End uint64
	Prot       int
}

type Unicorn interface {
	MemMap(addr, size uint64) error
	MemMapProt(addr, size uint64, prot int) error
	MemMapPtr(addr, size uint64, prot int, ptr unsafe.Pointer) error
	MemProtect(addr, size uint64, prot int) error
	MemUnmap(addr, size uint64) error
	MemRegions() ([]*MemRegion, error)
	MemRead(addr, size uint64) ([]byte, error)
	MemReadInto(dst []byte, addr uint64) error
	MemWrite(addr uint64, data []byte) error
	RegRead(reg int) (uint64, error)
	RegReadBatch(regs []int) ([]uint64, error)
	RegWrite(reg int, value uint64) error
	RegWriteBatch(regs []int, vals []uint64) error
	RegReadMmr(reg int) (*X86Mmr, error)
	RegWriteMmr(reg int, value *X86Mmr) error
	Start(begin, until uint64) error
	StartWithOptions(begin, until uint64, options *UcOptions) error
	Stop() error
	HookAdd(htype int, cb interface{}, begin, end uint64, extra ...int) (Hook, error)
	HookDel(hook Hook) error
	Query(queryType int) (uint64, error)
	Close() error

	ContextSave(reuse Context) (Context, error)
	ContextRestore(Context) error
	Handle() *C.uc_engine
	RegWriteX86Msr(reg uint64, val uint64) error
	RegReadX86Msr(reg uint64) (uint64, error)

	GetMode() (int, error)
	GetPageSize() (uint32, error)
	SetPageSize(pageSize uint32) error
	GetArch() (int, error)
	GetTimeout() (uint64, error)
	ExitsEnable() error
	ExitsDisable() error
	GetExitsCnt() (uint32, error)
	GetExits() ([]uint64, error)
	SetExits(exits []uint64) error
	GetCPUModel() (int, error)
	SetCPUModel(model int) error
	RemoveCache(address, end uint64) error
	RequestCache(address uint64) (UcTb, error)
	FlushTB() error
	FlushTLB() error
	TLBMode(mode int) error
	GetTCGBufferSize() (uint32, error)
	SetTCGBufferSize(size uint32) error
	ContextMode(mode int) error
}

type uc struct {
	handle *C.uc_engine
	final  sync.Once
	hooks  map[Hook]uintptr
}

type UcOptions struct {
	Timeout, Count uint64
}

type UcTb struct {
	Pc     uint64
	Icount uint16
	Size   uint16
}

func Version() (int, int) {
	var major, minor C.uint
	C.uc_version(&major, &minor)
	return int(major), int(minor)
}

func NewUnicorn(arch, mode int) (Unicorn, error) {
	major, minor := Version()
	if major != C.UC_API_MAJOR || minor != C.UC_API_MINOR {
		return nil, UcError(ERR_VERSION)
	}
	var handle *C.uc_engine
	if ucerr := C.uc_open(C.uc_arch(arch), C.uc_mode(mode), &handle); ucerr != ERR_OK {
		return nil, UcError(ucerr)
	}
	u := &uc{handle: handle, hooks: make(map[Hook]uintptr)}
	runtime.SetFinalizer(u, func(u *uc) { u.Close() })
	return u, nil
}

func (u *uc) Close() (err error) {
	u.final.Do(func() {
		if u.handle != nil {
			for _, uptr := range u.hooks {
				hookMap.remove(uptr)
			}
			u.hooks = nil
			err = errReturn(C.uc_close(u.handle))
			u.handle = nil
		}
	})
	return err
}

func (u *uc) StartWithOptions(begin, until uint64, options *UcOptions) error {
	ucerr := C.uc_emu_start(
		u.handle,
		C.uint64_t(begin),
		C.uint64_t(until),
		C.uint64_t(options.Timeout),
		C.size_t(options.Count),
	)
	return errReturn(ucerr)
}

func (u *uc) Start(begin, until uint64) error {
	return u.StartWithOptions(begin, until, &UcOptions{})
}

func (u *uc) Stop() error {
	return errReturn(C.uc_emu_stop(u.handle))
}

func (u *uc) RegWrite(reg int, value uint64) error {
	var val C.uint64_t = C.uint64_t(value)
	ucerr := C.uc_reg_write(u.handle, C.int(reg), unsafe.Pointer(&val))
	return errReturn(ucerr)
}

func (u *uc) RegRead(reg int) (uint64, error) {
	var val C.uint64_t
	ucerr := C.uc_reg_read(u.handle, C.int(reg), unsafe.Pointer(&val))
	return uint64(val), errReturn(ucerr)
}

func (u *uc) RegWriteBatch(regs []int, vals []uint64) error {
	if len(regs) == 0 {
		return nil
	}
	if len(vals) < len(regs) {
		regs = regs[:len(vals)]
	}
	cregs := make([]C.int, len(regs))
	for i, v := range regs {
		cregs[i] = C.int(v)
	}
	cregs2 := (*C.int)(unsafe.Pointer(&cregs[0]))
	cvals := (*C.uint64_t)(unsafe.Pointer(&vals[0]))
	ucerr := C.uc_reg_write_batch_helper(u.handle, cregs2, cvals, C.int(len(regs)))
	return errReturn(ucerr)
}

func (u *uc) RegReadBatch(regs []int) ([]uint64, error) {
	if len(regs) == 0 {
		return nil, nil
	}
	cregs := make([]C.int, len(regs))
	for i, v := range regs {
		cregs[i] = C.int(v)
	}
	cregs2 := (*C.int)(unsafe.Pointer(&cregs[0]))
	vals := make([]uint64, len(regs))
	cvals := (*C.uint64_t)(unsafe.Pointer(&vals[0]))
	ucerr := C.uc_reg_read_batch_helper(u.handle, cregs2, cvals, C.int(len(regs)))
	return vals, errReturn(ucerr)
}

func (u *uc) MemRegions() ([]*MemRegion, error) {
	var regions *C.uc_mem_region
	var count C.uint32_t
	ucerr := C.uc_mem_regions(u.handle, &regions, &count)
	if ucerr != C.UC_ERR_OK {
		return nil, errReturn(ucerr)
	}
	ret := make([]*MemRegion, count)
	tmp := (*[1 << 24]C.struct_uc_mem_region)(unsafe.Pointer(regions))[:count]
	for i, v := range tmp {
		ret[i] = &MemRegion{
			Begin: uint64(v.begin),
			End:   uint64(v.end),
			Prot:  int(v.perms),
		}
	}
	C.uc_free(unsafe.Pointer(regions))
	return ret, nil
}

func (u *uc) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return errReturn(
		C.uc_mem_write(u.handle, C.uint64_t(addr), unsafe.Pointer(&data[0]), C.uint64_t(len(data))),
	)
}

func (u *uc) MemReadInto(dst []byte, addr uint64) error {
	if len(dst) == 0 {
		return nil
	}
	return errReturn(
		C.uc_mem_read(u.handle, C.uint64_t(addr), unsafe.Pointer(&dst[0]), C.uint64_t(len(dst))),
	)
}

func (u *uc) MemRead(addr, size uint64) ([]byte, error) {
	dst := make([]byte, size)
	return dst, u.MemReadInto(dst, addr)
}

func (u *uc) MemMapProt(addr, size uint64, prot int) error {
	return errReturn(C.uc_mem_map(u.handle, C.uint64_t(addr), C.uint64_t(size), C.uint32_t(prot)))
}

func (u *uc) MemMap(addr, size uint64) error {
	return u.MemMapProt(addr, size, PROT_ALL)
}

func (u *uc) MemMapPtr(addr, size uint64, prot int, ptr unsafe.Pointer) error {
	return errReturn(
		C.uc_mem_map_ptr(u.handle, C.uint64_t(addr), C.uint64_t(size), C.uint32_t(prot), ptr),
	)
}

func (u *uc) MemProtect(addr, size uint64, prot int) error {
	return errReturn(
		C.uc_mem_protect(u.handle, C.uint64_t(addr), C.uint64_t(size), C.uint32_t(prot)),
	)
}

func (u *uc) MemUnmap(addr, size uint64) error {
	return errReturn(C.uc_mem_unmap(u.handle, C.uint64_t(addr), C.uint64_t(size)))
}

func (u *uc) Query(queryType int) (uint64, error) {
	var ret C.size_t
	ucerr := C.uc_query(u.handle, C.uc_query_type(queryType), &ret)
	return uint64(ret), errReturn(ucerr)
}

func (u *uc) Handle() *C.uc_engine {
	return u.handle
}

func (u *uc) GetMode() (int, error) {
	var mode C.int
	ucerr := C.uc_ctl_get_mode_helper(u.handle, &mode)
	return int(mode), errReturn(ucerr)
}

func (u *uc) GetPageSize() (uint32, error) {
	var ptr C.uint32_t
	ucerr := C.uc_ctl_get_page_size_helper(u.handle, &ptr)
	return uint32(ptr), errReturn(ucerr)
}

func (u *uc) SetPageSize(pageSize uint32) error {
	ucerr := C.uc_ctl_set_page_size_helper(u.handle, C.uint32_t(pageSize))
	return errReturn(ucerr)
}

func (u *uc) GetArch() (int, error) {
	var arch C.int
	ucerr := C.uc_ctl_get_arch_helper(u.handle, &arch)
	return int(arch), errReturn(ucerr)
}

func (u *uc) GetTimeout() (uint64, error) {
	var timeout C.uint64_t
	ucerr := C.uc_ctl_get_timeout_helper(u.handle, &timeout)
	return uint64(timeout), errReturn(ucerr)
}

func (u *uc) ExitsEnable() error {
	return errReturn(C.uc_ctl_exits_enable_helper(u.handle))
}

func (u *uc) ExitsDisable() error {
	return errReturn(C.uc_ctl_exits_disable_helper(u.handle))
}

func (u *uc) GetExitsCnt() (uint32, error) {
	var count C.size_t
	ucerr := C.uc_ctl_get_timeout_helper(u.handle, &count)
	return uint32(count), errReturn(ucerr)
}

func (u *uc) GetExits() ([]uint64, error) {
	count, err := u.GetExitsCnt()
	if err != nil {
		return nil, err
	}
	exits := make([]C.uint64_t, count)
	ucerr := C.uc_ctl_get_exits_helper(u.handle, &exits[0], C.size_t(count))

	res := make([]uint64, count)
	for i := 0; i < int(count); i++ {
		res[i] = uint64(exits[i])
	}
	return res, errReturn(ucerr)
}

func (u *uc) SetExits(exits []uint64) error {
	cExits := make([]C.uint64_t, len(exits))
	for i := 0; i < len(exits); i++ {
		cExits[i] = C.uint64_t(exits[i])
	}
	ucerr := C.uc_ctl_set_exits_helper(u.handle, &cExits[0], C.size_t(len(exits)))
	return errReturn(ucerr)
}

func (u *uc) GetCPUModel() (int, error) {
	var model C.int
	ucerr := C.uc_ctl_get_cpu_model_helper(u.handle, &model)
	return int(model), errReturn(ucerr)
}

func (u *uc) SetCPUModel(model int) error {
	ucerr := C.uc_ctl_set_cpu_model_helper(u.handle, C.int(model))
	return errReturn(ucerr)
}

func (u *uc) RemoveCache(address, end uint64) error {
	ucerr := C.uc_ctl_remove_cache_helper(u.handle, C.uint64_t(address), C.uint64_t(end))
	return errReturn(ucerr)
}

func (u *uc) RequestCache(address uint64) (UcTb, error) {
	var tb C.uc_tb
	ucerr := C.uc_ctl_request_cache_helper(u.handle, C.uint64_t(address), &tb)
	err := errReturn(ucerr)
	if err != nil {
		return UcTb{}, err
	}
	return UcTb{
		Pc:     uint64(tb.pc),
		Icount: uint16(tb.icount),
		Size:   uint16(tb.size),
	}, nil
}

func (u *uc) FlushTB() error {
	ucerr := C.uc_ctl_flush_tb_helper(u.handle)
	return errReturn(ucerr)
}

func (u *uc) FlushTLB() error {
	ucerr := C.uc_ctl_flush_tlb_helper(u.handle)
	return errReturn(ucerr)
}

func (u *uc) TLBMode(mode int) error {
	ucerr := C.uc_ctl_tlb_mode_helper(u.handle, C.int(mode))
	return errReturn(ucerr)
}

func (u *uc) GetTCGBufferSize() (uint32, error) {
	var size C.uint32_t
	ucerr := C.uc_ctl_get_tcg_buffer_size_helper(u.handle, &size)
	return uint32(size), errReturn(ucerr)
}

func (u *uc) SetTCGBufferSize(size uint32) error {
	ucerr := C.uc_ctl_set_tcg_buffer_size_helper(u.handle, C.uint32_t(size))
	return errReturn(ucerr)
}

func (u *uc) ContextMode(mode int) error {
	ucerr := C.uc_ctl_context_mode_helper(u.handle, C.int(mode))
	return errReturn(ucerr)
}
