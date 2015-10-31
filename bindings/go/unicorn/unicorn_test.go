package unicorn

import (
	"fmt"
	"testing"
)

func TestMemUnmap(t *testing.T) {
	mu, err := NewUnicorn(ARCH_X86, MODE_32)
	if err != nil {
		t.Fatal(err)
	}
	if err := mu.MemMap(0x1000, 0x1000); err != nil {
		t.Fatal(err)
	}
	tmp := make([]byte, 1024)
	if err := mu.MemWrite(0x1000, tmp); err != nil {
		t.Fatal(err)
	}
	if err := mu.MemUnmap(0x1000, 0x1000); err != nil {
		t.Fatal(err)
	}
	if err := mu.MemWrite(0x1000, tmp); err.(UcError) != ERR_WRITE_UNMAPPED {
		t.Fatal(fmt.Errorf("Expected ERR_WRITE_UNMAPPED, got: %v", err))
	}
}

func TestDoubleClose(t *testing.T) {
	mu, err := NewUnicorn(ARCH_X86, MODE_32)
	if err != nil {
		t.Fatal(err)
	}
	if err := mu.Close(); err != nil {
		t.Fatal(err)
	}
	if err := mu.Close(); err != nil {
		t.Fatal(err)
	}
}
