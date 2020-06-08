package unicorn;

import (
	"testing"
)

// var ADDRESS uint64 = 0x100000;
var DATA_ADDR uint64 = 0;

func MakePowerPCUc(code string) (Unicorn,error) {
	mu, err := NewUnicorn(ARCH_PPC,MODE_32 + MODE_BIG_ENDIAN)

	mu.MemMap(ADDRESS, 2*1024*1024);
	mu.MemMap(DATA_ADDR,4096);

	mu.MemWrite(ADDRESS,[]byte(code));

	return mu, err
}

func TestSimple(t *testing.T) {
	code:= "\x39\x20\x00\x04" + // li        r9, 4
           "\x91\x3F\x00\x08" + // stw       r9, 8(r31)
           "\x39\x20\x00\x05" + // li        r9, 5
           "\x91\x3F\x00\x0C" + // stw       r9, 0xC(r31)
           "\x81\x5F\x00\x08" + // lwz       r10, 8(r31)
           "\x81\x3F\x00\x0C" + // lwz       r9, 0xC(r31)
           "\x7D\x2A\x4A\x14";  // add       r9, r10, r9

	mu, err := MakePowerPCUc(code);
	if err != nil {
		t.Fatal(err)
	}

	mu.RegWrite(PPC_REG_GPR_31, DATA_ADDR)
	mu.Start(ADDRESS, ADDRESS+uint64(len(code)));
	r9, _ := mu.RegRead(PPC_REG_GPR_9)
	if r9 != 9 {
		t.Fatal("invalid value for r9")
	}
}