package unicorn

import (
	"errors"
	"runtime"
	"unsafe"
)

/*
#include <unicorn/unicorn.h>

void *reg_batch_setup(int *regs, int count, uint64_t **vals, int **enums, void ***refs) {
	size_t uvsz = sizeof(uint64_t) * count;
	size_t ensz = sizeof(int) * count;
	size_t ursz = sizeof(uintptr_t) * count;
	int i;

	uintptr_t buf = (uintptr_t)calloc(1, uvsz+ensz+ursz);
	if (buf == 0) return NULL;

	*vals = (uint64_t *)buf;
	*enums = (int *)(buf + uvsz);
	*refs = (void **)(buf + uvsz + ensz);
	for (i = 0; i < count; i++) {
		(*enums)[i] = regs[i];
		(*refs)[i] = &(*vals)[i];
	}
	return (void *)buf;
}
*/
import "C"

type RegBatch struct {
	// cast to local type
	vals []uint64

	// pass these to C
	cenums *C.int
	crefs  *unsafe.Pointer
	ccount C.int
}

func regBatchSetup(regs []int) (buf unsafe.Pointer, vals []uint64, cenums *C.int, crefs *unsafe.Pointer) {
	enums := make([]C.int, len(regs))
	for i := 0; i < len(regs); i++ {
		enums[i] = C.int(regs[i])
	}
	var cvals *C.uint64_t
	var inEnums *C.int
	if len(regs) > 0 {
		inEnums = (*C.int)(unsafe.Pointer(&enums[0]))
	}
	buf = C.reg_batch_setup(inEnums, C.int(len(regs)), &cvals, &cenums, &crefs)
	vals = (*[1 << 24]uint64)(unsafe.Pointer(cvals))[:len(regs)]
	return
}

func NewRegBatch(regs []int) (*RegBatch, error) {
	r := &RegBatch{}
	var buf unsafe.Pointer
	buf, r.vals, r.cenums, r.crefs = regBatchSetup(regs)
	if buf == nil {
		return nil, errors.New("failed to allocate RegBatch memory")
	}
	r.ccount = C.int(len(regs))
	// when RegBatch is collected, free C-owned data
	runtime.SetFinalizer(r, func(r *RegBatch) {
		C.free(buf)
	})
	return r, nil
}

// ReadFast skips copying and returns the internal vals array
func (r *RegBatch) ReadFast(u Unicorn) ([]uint64, error) {
	ucerr := C.uc_reg_read_batch(u.Handle(), r.cenums, r.crefs, r.ccount)
	if ucerr != ERR_OK {
		return nil, errReturn(ucerr)
	}
	return r.vals, nil
}

func (r *RegBatch) Read(u Unicorn, vals []uint64) error {
	tmp, err := r.ReadFast(u)
	if err != nil {
		return err
	}
	copy(vals, tmp[:len(vals)])
	return nil
}

func (r *RegBatch) Write(u Unicorn, vals []uint64) error {
	copy(r.vals[:len(vals)], vals)
	ucerr := C.uc_reg_write_batch(u.Handle(), r.cenums, r.crefs, r.ccount)
	return errReturn(ucerr)
}
