import unicorn

uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

# 0:   48 c7 c0 00 20 00 00    mov    rax,0x2000
# 7:   48 c7 00 34 12 00 00    mov    QWORD PTR [rax],0x1234
# e:   48 8b 00                mov    rax,QWORD PTR [rax]
code = '48c7c00020000048c70034120000488b00'.decode('hex')
code_addr = 0x1000
data_addr = 0x2000

uc.mem_map(code_addr, 0x1000)
uc.mem_map(data_addr, 0x1000)
uc.mem_write(code_addr, code)

# first run
uc.emu_start(code_addr, code_addr + len(code))
assert uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX) == 0x1234

# tlb of data page should be invalid
uc.mem_unmap(data_addr, 0x1000)

try:
    uc.emu_start(code_addr, code_addr + len(code))
except unicorn.unicorn.UcError as e:
    assert e.errno == unicorn.UC_ERR_WRITE_UNMAPPED

assert uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX) == 0x2000
