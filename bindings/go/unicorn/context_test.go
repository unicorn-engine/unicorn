package unicorn

import (
	"testing"
)

func TestContext(t *testing.T) {
	u, err := NewUnicorn(ARCH_X86, MODE_32)
	if err != nil {
		t.Fatal(err)
	}
	u.RegWrite(X86_REG_EBP, 100)
	ctx, err := u.ContextSave(nil)
	if err != nil {
		t.Fatal(err)
	}
	u.RegWrite(X86_REG_EBP, 200)
	err = u.ContextRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	val, _ := u.RegRead(X86_REG_EBP)
	if val != 100 {
		t.Fatal("context restore failed")
	}
}
