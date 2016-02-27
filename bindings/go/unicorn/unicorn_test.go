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

func TestMemRegions(t *testing.T) {
	mu, err := NewUnicorn(ARCH_X86, MODE_32)
	if err != nil {
		t.Fatal(err)
	}
	err = mu.MemMap(0x1000, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	regions, err := mu.MemRegions()
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 1 {
		t.Fatalf("returned wrong number of regions: %d != 1", len(regions))
	}
	r := regions[0]
	if r.Begin != 0x1000 || r.End != 0x1fff || r.Prot != 7 {
		t.Fatalf("incorrect region: %#v", r)
	}
}

func TestQuery(t *testing.T) {
	mu, err := NewUnicorn(ARCH_ARM, MODE_THUMB)
	if err != nil {
		t.Fatal(err)
	}
	mode, err := mu.Query(QUERY_MODE)
	if err != nil {
		t.Fatal(err)
	}
	if mode != MODE_THUMB {
		t.Fatal("query returned invalid mode: %d != %d", mode, MODE_THUMB)
	}
}
