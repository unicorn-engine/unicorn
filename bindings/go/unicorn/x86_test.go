package unicorn

import (
	"testing"
)

var ADDRESS uint64 = 0x1000000

func MakeUc(mode int, code string) (Unicorn, error) {
	mu, err := NewUnicorn(ARCH_X86, mode)
	if err != nil {
		return nil, err
	}
	if err := mu.MemMap(ADDRESS, 2*1024*1024); err != nil {
		return nil, err
	}
	if err := mu.MemWrite(ADDRESS, []byte(code)); err != nil {
		return nil, err
	}
	if err := mu.RegWrite(X86_REG_ECX, 0x1234); err != nil {
		return nil, err
	}
	if err := mu.RegWrite(X86_REG_EDX, 0x7890); err != nil {
		return nil, err
	}
	return mu, nil
}

func TestX86(t *testing.T) {
	code := "\x41\x4a"
	mu, err := MakeUc(MODE_32, code)
	if err != nil {
		t.Fatal(err)
	}
	if err := mu.Start(ADDRESS, ADDRESS+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	ecx, _ := mu.RegRead(X86_REG_ECX)
	edx, _ := mu.RegRead(X86_REG_EDX)
	if ecx != 0x1235 || edx != 0x788f {
		t.Fatal("Bad register values.")
	}
}

func TestX86InvalidRead(t *testing.T) {
	code := "\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a"
	mu, err := MakeUc(MODE_32, code)
	if err != nil {
		t.Fatal(err)
	}
	err = mu.Start(ADDRESS, ADDRESS+uint64(len(code)))
	if err.(UcError) != ERR_READ_UNMAPPED {
		t.Fatal("Expected ERR_READ_INVALID")
	}
	ecx, _ := mu.RegRead(X86_REG_ECX)
	edx, _ := mu.RegRead(X86_REG_EDX)
	if ecx != 0x1234 || edx != 0x7890 {
		t.Fatal("Bad register values.")
	}
}

func TestX86InvalidWrite(t *testing.T) {
	code := "\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a"
	mu, err := MakeUc(MODE_32, code)
	if err != nil {
		t.Fatal(err)
	}
	err = mu.Start(ADDRESS, ADDRESS+uint64(len(code)))
	if err.(UcError) != ERR_WRITE_UNMAPPED {
		t.Fatal("Expected ERR_WRITE_INVALID")
	}
	ecx, _ := mu.RegRead(X86_REG_ECX)
	edx, _ := mu.RegRead(X86_REG_EDX)
	if ecx != 0x1234 || edx != 0x7890 {
		t.Fatal("Bad register values.")
	}
}

func TestX86InOut(t *testing.T) {
	code := "\x41\xE4\x3F\x4a\xE6\x46\x43"
	mu, err := MakeUc(MODE_32, code)
	if err != nil {
		t.Fatal(err)
	}
	var outVal uint64
	var inCalled, outCalled bool
	mu.HookAdd(HOOK_INSN, func(_ Unicorn, port, size uint32) uint32 {
		inCalled = true
		switch size {
		case 1:
			return 0xf1
		case 2:
			return 0xf2
		case 4:
			return 0xf4
		default:
			return 0
		}
	}, 1, 0, X86_INS_IN)
	mu.HookAdd(HOOK_INSN, func(_ Unicorn, port, size, value uint32) {
		outCalled = true
		var err error
		switch size {
		case 1:
			outVal, err = mu.RegRead(X86_REG_AL)
		case 2:
			outVal, err = mu.RegRead(X86_REG_AX)
		case 4:
			outVal, err = mu.RegRead(X86_REG_EAX)
		}
		if err != nil {
			t.Fatal(err)
		}
	}, 1, 0, X86_INS_OUT)
	if err := mu.Start(ADDRESS, ADDRESS+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	if !inCalled || !outCalled {
		t.Fatal("Ports not accessed.")
	}
	if outVal != 0xf1 {
		t.Fatal("Incorrect OUT value.")
	}
}

func TestX86Syscall(t *testing.T) {
	code := "\x0f\x05"
	mu, err := MakeUc(MODE_64, code)
	if err != nil {
		t.Fatal(err)
	}
	mu.HookAdd(HOOK_INSN, func(_ Unicorn) {
		rax, _ := mu.RegRead(X86_REG_RAX)
		mu.RegWrite(X86_REG_RAX, rax+1)
	}, 1, 0, X86_INS_SYSCALL)
	mu.RegWrite(X86_REG_RAX, 0x100)
	err = mu.Start(ADDRESS, ADDRESS+uint64(len(code)))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := mu.RegRead(X86_REG_RAX)
	if v != 0x101 {
		t.Fatal("Incorrect syscall return value.")
	}
}

func TestX86Mmr(t *testing.T) {
	mu, err := MakeUc(MODE_64, "")
	if err != nil {
		t.Fatal(err)
	}
	err = mu.RegWriteMmr(X86_REG_GDTR, &X86Mmr{Selector: 0, Base: 0x1000, Limit: 0x1fff, Flags: 0})
	if err != nil {
		t.Fatal(err)
	}
	mmr, err := mu.RegReadMmr(X86_REG_GDTR)
	if mmr.Selector != 0 || mmr.Base != 0x1000 || mmr.Limit != 0x1fff || mmr.Flags != 0 {
		t.Fatalf("mmr read failed: %#v", mmr)
	}
}
