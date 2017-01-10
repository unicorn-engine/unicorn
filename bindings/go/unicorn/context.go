package unicorn

import (
	"runtime"
	"unsafe"
)

// #include <unicorn/unicorn.h>
import "C"

type Context **C.uc_context

func (u *uc) ContextSave(reuse Context) (Context, error) {
	ctx := reuse
	if ctx == nil {
		ctx = new(*C.uc_context)
	}
	if err := errReturn(C.uc_context_alloc(u.handle, ctx)); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(ctx, func(p Context) { C.uc_free(unsafe.Pointer(*p)) })
	if err := errReturn(C.uc_context_save(u.handle, *ctx)); err != nil {
	}
	return ctx, nil
}

func (u *uc) ContextRestore(ctx Context) error {
	return errReturn(C.uc_context_restore(u.handle, *ctx))
}
