package main

import (
	"encoding/hex"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"strings"
)

var asm = strings.Join([]string{
	"48c7c003000000", // mov rax, 3
	"0f05",           // syscall
	"48c7c700400000", // mov rdi, 0x4000
	"488907",         // mov [rdi], rdx
	"488b07",         // mov rdx, [rdi]
	"4883c201",       // add rdx, 1
}, "")

func addHooks(mu uc.Unicorn) {
	mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		fmt.Printf("Block: 0x%x, 0x%x\n", addr, size)
	}, 1, 0)
	mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		fmt.Printf("Code: 0x%x, 0x%x\n", addr, size)
	}, 1, 0)
	mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
			fmt.Printf("Mem write")
		} else {
			fmt.Printf("Mem read")
		}
		fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
	}, 1, 0)
	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		switch access {
		case uc.MEM_WRITE_UNMAPPED | uc.MEM_WRITE_PROT:
			fmt.Printf("invalid write")
		case uc.MEM_READ_UNMAPPED | uc.MEM_READ_PROT:
			fmt.Printf("invalid read")
		case uc.MEM_FETCH_UNMAPPED | uc.MEM_FETCH_PROT:
			fmt.Printf("invalid fetch")
		default:
			fmt.Printf("unknown memory error")
		}
		fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
		return false
	}, 1, 0)
	mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
		fmt.Printf("Syscall: %d\n", rax)
	}, 1, 0, uc.X86_INS_SYSCALL)
}

func run() error {
	code, err := hex.DecodeString(asm)
	if err != nil {
		return err
	}
	// set up unicorn instance and add hooks
	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
	if err != nil {
		return err
	}
	addHooks(mu)
	// map and write code to memory
	if err := mu.MemMap(0x1000, 0x1000); err != nil {
		return err
	}
	if err := mu.MemWrite(0x1000, code); err != nil {
		return err
	}
	// map scratch space
	if err := mu.MemMap(0x4000, 0x1000); err != nil {
		return err
	}
	// set example register
	if err := mu.RegWrite(uc.X86_REG_RDX, 1); err != nil {
		return err
	}
	rdx, err := mu.RegRead(uc.X86_REG_RDX)
	if err != nil {
		return err
	}
	fmt.Printf("RDX is: %d\n", rdx)

	// start emulation
	if err := mu.Start(0x1000, 0x1000+uint64(len(code))); err != nil {
		return err
	}

	// read back example register
	rdx, err = mu.RegRead(uc.X86_REG_RDX)
	if err != nil {
		return err
	}
	fmt.Printf("RDX is now: %d\n", rdx)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}
