{
  FreePascal/Delphi bindings for the UnicornEngine Emulator Engine .

  Copyright(c) 2018 Coldzer0 .

  License : GPLv2 .
}

program x86;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$ifdef MSWINDOWS}
  {$apptype CONSOLE}
{$endif}

uses
  SysUtils,
  Unicorn_dyn,
  UnicornConst,
  X86Const;

const
  // code to be emulated .
  X86_CODE32: array[0..6] of Byte = ($41, $4a,$66,$0f,$ef,$c1, $00); // INC ecx; DEC edx ; PXOR xmm0, xmm1 ;
  X86_CODE32_JUMP: array[0..8] of Byte = ($eb, $02, $90, $90, $90, $90, $90, $90, $00); // jmp 4; nop; nop; nop; nop; nop; nop ;
  X86_CODE32_LOOP: array[0..4] of Byte = ($41, $4a, $eb, $fe, $00); // INC ecx; DEC edx; JMP self-loop
  X86_CODE32_MEM_WRITE: array[0..8] of Byte = ($89, $0d, $aa, $aa, $aa, $aa, $41, $4a, $00); // mov [0xaaaaaaaa], ecx; INC ecx; DEC edx ;
  X86_CODE32_MEM_READ: array[0..8] of Byte = ($8b, $0d, $aa, $aa, $aa, $aa, $41, $4a, $00); // mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx ;

  X86_CODE32_JMP_INVALID: array[0..6] of Byte = ($e9, $e9, $ee, $ee, $41, $4a, $00); //  JMP outside; INC ecx; DEC edx ;
  X86_CODE32_INOUT: array[0..7] of Byte = ($41, $E4, $3F, $4a, $E6, $46, $43, $00); // INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx ;
  X86_CODE32_INC : array[0..1] of byte = ($40,$00); // INC eax .

  X86_CODE64: array[0..75] of Byte = (
    $41, $BC, $3B, $B0, $28, $2A, $49, $0F, $C9, $90, $4D, $0F, $AD, $CF, $49, $87, $FD, $90, $48, $81,
    $D2, $8A, $CE, $77, $35, $48, $F7, $D9, $4D, $29, $F4, $49, $81, $C9, $F6, $8A, $C6, $53, $4D, $87,
    $ED, $48, $0F, $AD, $D2, $49, $F7, $D4, $48, $F7, $E1, $4D, $19, $C5, $4D, $89, $C5, $48, $F7, $D6,
    $41, $B8, $4F, $8D, $6B, $59, $4D, $87, $D0, $68, $6A, $1E, $09, $3C, $59, $00);
  X86_CODE16: array[0..2] of Byte = ($00, $00, $00);   // add   byte ptr [bx + si], al
  X86_CODE64_SYSCALL: array[0..2] of Byte = ($0f, $05, $00); // SYSCALL

  // memory address where emulation starts
  ADDRESS = $1000000;

// callback for tracing basic blocks
procedure HookBlock(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
begin
  WriteLn(Format('>>> Tracing basic block at 0x%x, block size = 0x%x', [address, size]));
end;

// callback for tracing instruction
procedure HookCode(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
var
  eflags: integer;
begin
  WriteLn(Format('>>> Tracing instruction at 0x%x, instruction size = 0x%x', [address, size]));
  uc_reg_read(uc, UC_X86_REG_EFLAGS, @eflags);
  WriteLn(Format('>>> --- EFLAGS is 0x%x', [eflags]));
end;

// callback for tracing instruction
procedure HookCode64(uc: uc_engine; address: UInt64; size: Cardinal; user_data: Pointer); cdecl;
var
  rip: UInt64;
begin
  WriteLn(Format('>>> Tracing instruction at 0x%x, instruction size = 0x%x', [address, size]));
  uc_reg_read(uc, UC_X86_REG_RIP, @rip);
  WriteLn(Format('>>> --- RIP is 0x%x', [rip]));
end;

function HookMemInvalid(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: Cardinal; value: Int64; user_data: Pointer): LongBool; cdecl;
begin
  case _type of
    UC_MEM_WRITE_UNMAPPED:
      begin
        WriteLn(Format('>>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x', [address, size, value]));
        // map this memory in with 2MB in size
        uc_mem_map(uc, $aaaa0000, 2 * 1024*1024, UC_PROT_ALL);
        // return true to indicate we want to continue
        Result := true;
      end
    else
      begin
        // return false to indicate we want to stop emulation
        Result := false;
      end;
  end;
end;

procedure HookMem64(uc: uc_engine; _type: uc_mem_type; address: UInt64; size: Cardinal; value: Int64; user_data: Pointer); cdecl;
begin
  case _type of
    UC_MEM_READ:
      begin
        WriteLn(Format('>>> Memory is being READ at 0x%x, data size = %u', [address, size]));
      end;
    UC_MEM_WRITE:
      begin
        WriteLn(Format('>>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x', [address, size, value]));
      end;
  end;
end;

// callback for IN instruction (X86).
// this returns the data read from the port
function HookIn(uc: uc_engine; port: UInt32; size: integer; user_data: Pointer): Uint32; cdecl;
var
  eip: UInt32;
begin
  uc_reg_read(uc, UC_X86_REG_EIP, @eip);
  WriteLn(Format('--- reading from port 0x%x, size: %u, address: 0x%x', [port, size, eip]));
  case size of
    1:
      begin
        // read 1 byte to AL
        Result := $f1;
      end;
    2:
      begin
        // read 2 byte to AX
        Result := $f2;
      end;
    4:
      begin
        // read 4 byte to EAX
        Result := $f4;
      end;
    else
      begin
        // should never reach this
        Result := 0;
      end;
  end;
end;

// callback for OUT instruction (X86).
procedure HookOut(uc: uc_engine; port: UInt32; size: integer; value: UInt32; user_data: Pointer); cdecl;
var
  tmp, eip: UInt32;
begin
  uc_reg_read(uc, UC_X86_REG_EIP, @eip);
  WriteLn(Format('--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x', [port, size, value, eip]));

  // confirm that value is indeed the value of AL/AX/EAX
  case size of
    1:
      begin
        uc_reg_read(uc, UC_X86_REG_AL, @tmp);
      end;
    2:
      begin
        uc_reg_read(uc, UC_X86_REG_AX, @tmp);
      end;
    4:
      begin
        uc_reg_read(uc, UC_X86_REG_EAX, @tmp);
      end;
    else
      begin
        // should never reach this
        Exit;
      end;
  end;
  WriteLn(Format('--- register value = 0x%x', [tmp]));
end;

// callback for SYSCALL instruction (X86).
procedure HookSyscall(uc: uc_engine; user_data: Pointer); cdecl;
var
  rax: UInt64;
begin
  uc_reg_read(uc, UC_X86_REG_RAX, @rax);
  if (rax = $100) then begin
    rax := $200;
    uc_reg_write(uc, UC_X86_REG_RAX, @rax);
  end else
    WriteLn(Format('ERROR: was not expecting rax=0x%x in syscall', [rax]));
end;

procedure TestI386;
var
  uc: uc_engine;
  err: uc_err;
  tmp: UInt32;
  trace1, trace2: uc_hook;
  r_ecx, r_edx: integer;
  r_xmm0,r_xmm1 : array [0..1] of UInt64;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  r_xmm0[0] := $08090a0b0c0d0e0f; r_xmm0[1] := $0001020304050607;
  r_xmm1[0] := {%H-}$8090a0b0c0d0e0f0; r_xmm1[1] := $0010203040506070;


  WriteLn('Emulate i386 code');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32, SizeOf(X86_CODE32) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);
  uc_reg_write(uc, UC_X86_REG_XMM0, @r_xmm0);
  uc_reg_write(uc, UC_X86_REG_XMM1, @r_xmm1);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0,[]);

  // emulate machine code in infinite time
  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  uc_reg_read(uc, UC_X86_REG_XMM0, @r_xmm0);

  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));
  WriteLn(Format('>>> XMM0 = 0x%s%s', [IntToHex(r_xmm0[1],16),IntToHex(r_xmm0[0],16)]));

  // read from memory
  err := uc_mem_read_(uc, ADDRESS, @tmp, SizeOf(tmp));
  if (err = UC_ERR_OK) then begin
    WriteLn(Format('>>> Read 4 bytes from [0x%x] = 0x%x', [ADDRESS, tmp]));
  end else begin
    WriteLn(Format('>>> Failed to read 4 bytes from [0x%x], err = %u: %s', [ADDRESS, err, uc_strerror(err)]));
  end;

  uc_close(uc);
end;

procedure test_i386_map_ptr();
var
  uc: uc_engine;
  err: uc_err;
  tmp: UInt32;
  trace1, trace2: uc_hook;
  mem : Pointer;
  r_ecx, r_edx: integer;
  r_xmm0,r_xmm1 : array [0..1] of UInt64;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  r_xmm0[0] := $08090a0b0c0d0e0f; r_xmm0[1] := $0001020304050607;
  r_xmm1[0] := {%H-}$8090a0b0c0d0e0f0; r_xmm1[1] := $0010203040506070;


  WriteLn('===================================');
  WriteLn('Emulate i386 code - use uc_mem_map_ptr()');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  mem := AllocMem(2 * 1024 * 1024);
  if mem = nil then
  begin
    Writeln('Failed to Allocmem');
    uc_close(uc);
    exit;
  end;

  err := uc_mem_map_ptr(uc,ADDRESS,2 * 1024 * 1024,UC_PROT_ALL,mem);
  if err <> UC_ERR_OK then
  begin
    WriteLn(Format('Failed on uc_mem_map_ptr() with error returned: %u - %s', [err,uc_strerror(err)]));
    FreeMem(mem,2 * 1024 * 1024);
    uc_close(uc);
    Exit;
  end;

  Move(X86_CODE32,mem^,SizeOf(X86_CODE32)-1);
  if CompareMem(mem,@X86_CODE32,SizeOf(X86_CODE32)-1) <> true then
  begin
    Writeln('Failed to write emulation code to memory, quit!');
    Freemem(mem,2 * 1024 * 1024);
    uc_close(uc);
    exit;
  end;
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);
  uc_reg_write(uc, UC_X86_REG_XMM0, @r_xmm0);
  uc_reg_write(uc, UC_X86_REG_XMM1, @r_xmm1);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end .
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0,[]);

  // emulate machine code in infinite time
  err := uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
  if err <> UC_ERR_OK then
     WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));

  Writeln('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  uc_reg_read(uc, UC_X86_REG_XMM0, @r_xmm0);

  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));
  WriteLn(Format('>>> XMM0 = 0x%s%s', [IntToHex(r_xmm0[1],16),IntToHex(r_xmm0[0],16)]));

  // read from memory
  err := uc_mem_read_(uc, ADDRESS, @tmp, SizeOf(tmp));
  if (err = UC_ERR_OK) then begin
    WriteLn(Format('>>> Read 4 bytes from [0x%x] = 0x%x', [ADDRESS, tmp]));
  end else begin
    WriteLn(Format('>>> Failed to read 4 bytes from [0x%x], err = %u: %s', [ADDRESS, err, uc_strerror(err)]));
  end;

  Freemem(mem,2 * 1024 * 1024);
  uc_close(uc);
end;

procedure TestI386Jump;
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
begin
  WriteLn('===================================');
  WriteLn('Emulate i386 code with jump');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_JUMP, SizeOf(X86_CODE32_JUMP) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // tracing 1 basic block with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, ADDRESS, ADDRESS,[]);

  // tracing 1 instruction at ADDRESS
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, ADDRESS, ADDRESS,[]);

  // emulate machine code in infinite time
  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_JUMP) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  WriteLn('>>> Emulation done.');
  uc_close(uc);
end;

procedure TestI386Loop;
var
  uc: uc_engine;
  err: uc_err;
  r_ecx, r_edx: integer;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  WriteLn('===================================');
  WriteLn('Emulate i386 code that loop forever');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_LOOP, SizeOf(X86_CODE32_LOOP) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);

  // emulate machine code in 2 seconds, so we can quit even
  // if the code loops
  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_LOOP) - 1, 2 * UC_SECOND_SCALE, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));

  uc_close(uc);
end;

procedure TestI386InvalidMemRead;
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  r_ecx, r_edx: integer;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  WriteLn('===================================');
  WriteLn('Emulate i386 code that read from invalid memory');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_MEM_READ, SizeOf(X86_CODE32_MEM_READ) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    uc_close(uc);
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0,[]);

  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_MEM_READ) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));

  uc_close(uc);
end;

procedure TestI386InvalidMemWrite;
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2, trace3: uc_hook;
  r_ecx, r_edx: integer;
  tmp: UInt32;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  WriteLn('===================================');
  WriteLn('Emulate i386 code that write to invalid memory');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_MEM_WRITE, SizeOf(X86_CODE32_MEM_WRITE) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0,[]);

  // intercept invalid memory events
  uc_hook_add(uc, trace3, UC_HOOK_MEM_READ_UNMAPPED or UC_HOOK_MEM_WRITE_UNMAPPED, @HookMemInvalid, nil,1,0,[]);

  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_MEM_WRITE) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));

  // read from memory
  err := uc_mem_read_(uc, $aaaaaaaa, @tmp, SizeOf(tmp));
  if (err = UC_ERR_OK) then
    WriteLn(Format('>>> Read 4 bytes from [0x%x] = 0x%x', [$aaaaaaaa, tmp]))
  else
    WriteLn(Format('>>> Failed to read 4 bytes from [0x%x]', [$aaaaaaaa]));

  err := uc_mem_read_(uc, $ffffffaa, @tmp, SizeOf(tmp));
  if (err = UC_ERR_OK) then
    WriteLn(Format('>>> Read 4 bytes from [0x%x] = 0x%x', [$ffffffaa, tmp]))
  else
    WriteLn(Format('>>> Failed to read 4 bytes from [0x%x]', [$ffffffaa]));

  uc_close(uc);
end;

procedure TestI386JumpInvalid;
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2: uc_hook;
  r_ecx, r_edx: integer;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  WriteLn('===================================');
  WriteLn('Emulate i386 code that jumps to invalid memory');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_JMP_INVALID, SizeOf(X86_CODE32_JMP_INVALID) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    uc_close(uc);
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0,[]);

  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_JMP_INVALID) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));

  uc_close(uc);
end;

procedure TestI386Inout;
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2, trace3, trace4: uc_hook;
  r_ecx, r_edx: integer;
begin
  r_ecx := $1234;     // ECX register
  r_edx := $7890;     // EDX register
  WriteLn('===================================');
  WriteLn('Emulate i386 code with IN/OUT instructions');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_INOUT, SizeOf(X86_CODE32_INOUT) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, @r_edx);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode, nil, 1, 0,[]);

  // uc IN instruction
  uc_hook_add(uc, trace3, UC_HOOK_INSN, @HookIn, nil, 1,0,[UC_X86_INS_IN]);
  // uc OUT instruction
  uc_hook_add(uc, trace4, UC_HOOK_INSN, @HookOut, nil, 1,0,[UC_X86_INS_OUT]);

  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE32_INOUT) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_ECX, @r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, @r_edx);
  WriteLn(Format('>>> ECX = 0x%x', [r_ecx]));
  WriteLn(Format('>>> EDX = 0x%x', [r_edx]));

  uc_close(uc);
end;

procedure test_i386_context_save();
var
  uc: uc_engine;
  context : uc_context;
  err: uc_err;
  r_eax : integer;
begin
  r_eax := 1;     // EAX register
  WriteLn('===================================');
  WriteLn('Emulate i386 code - Save/restore CPU context in opaque blob');

  // Initialize emulator in X86-32bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_32, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  uc_mem_map(uc,ADDRESS,8 * 1024 , UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE32_INC, SizeOf(X86_CODE32_INC) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    uc_close(uc);
    Exit;
  end;
  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_EAX, @r_eax);

  // emulate machine code in infinite time
  writeln('>>> Running emulation for the first time');
  err := uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INC) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  Writeln('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_EAX, @r_eax);
  WriteLn(Format('>>> EAX = 0x%x', [r_eax]));

  Writeln('>>> Saving CPU context');

  err := uc_context_alloc(uc,context);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_context_alloc() with error returned %u : %s', [err, uc_strerror(err)]));
    exit;
  end;

  err := uc_context_save(uc, context);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_context_save() with error returned %u : %s', [err, uc_strerror(err)]));
    exit;
  end;

  Writeln('>>> Running emulation for the second time');

  err := uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32_INC) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  Writeln('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_EAX, @r_eax);
  WriteLn(Format('>>> EAX = 0x%x', [r_eax]));

  err := uc_context_restore(uc, context);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_context_restore() with error returned %u: %s', [err, uc_strerror(err)]));
    exit;
  end;

  Writeln('>>> CPU context restored. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_EAX, @r_eax);
  WriteLn(Format('>>> EAX = 0x%x', [r_eax]));

  err := uc_free(context);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_free() with error returned %u: %s', [err, uc_strerror(err)]));
    exit;
  end;

  uc_close(uc);
end;

procedure TestX86_64;
var
  uc: uc_engine;
  err: uc_err;
  trace1, trace2, trace3, trace4: uc_hook;
  rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, rsp: UInt64;
begin
  rax := $71f3029efd49d41d;
  rbx := $d87b45277f133ddb;
  rcx := $ab40d1ffd8afc461;
  rdx := $919317b4a733f01;
  rsi := $4c24e753a17ea358;
  rdi := $e509a57d2571ce96;
  r8  := $ea5b108cc2b9ab1f;
  r9  := $19ec097c8eb618c1;
  r10 := $ec45774f00c5f682;
  r11 := $e17e9dbec8c074aa;
  r12 := $80f86a8dc0f6d457;
  r13 := $48288ca5671c5492;
  r14 := $595f72f6e4017f6e;
  r15 := $1efd97aea331cccc;

  rsp := ADDRESS + $200000;

  WriteLn('Emulate x86_64 code');

  // Initialize emulator in X86-64bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_64, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE64, SizeOf(X86_CODE64) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_RSP, @rsp);

  uc_reg_write(uc, UC_X86_REG_RAX, @rax);
  uc_reg_write(uc, UC_X86_REG_RBX, @rbx);
  uc_reg_write(uc, UC_X86_REG_RCX, @rcx);
  uc_reg_write(uc, UC_X86_REG_RDX, @rdx);
  uc_reg_write(uc, UC_X86_REG_RSI, @rsi);
  uc_reg_write(uc, UC_X86_REG_RDI, @rdi);
  uc_reg_write(uc, UC_X86_REG_R8,  @r8);
  uc_reg_write(uc, UC_X86_REG_R9,  @r9);
  uc_reg_write(uc, UC_X86_REG_R10, @r10);
  uc_reg_write(uc, UC_X86_REG_R11, @r11);
  uc_reg_write(uc, UC_X86_REG_R12, @r12);
  uc_reg_write(uc, UC_X86_REG_R13, @r13);
  uc_reg_write(uc, UC_X86_REG_R14, @r14);
  uc_reg_write(uc, UC_X86_REG_R15, @r15);

  // tracing all basic blocks with customized callback
  uc_hook_add(uc, trace1, UC_HOOK_BLOCK, @HookBlock, nil, 1, 0,[]);

  // tracing all instruction by having @begin > @end
  uc_hook_add(uc, trace2, UC_HOOK_CODE, @HookCode64, nil, ADDRESS, ADDRESS + 20,[]);

  // tracing all memory WRITE access (with @begin > @end)
  uc_hook_add(uc, trace3, UC_HOOK_MEM_WRITE, @HookMem64, nil, 1, 0,[]);
  // tracing all memory READ access (with @begin > @end)
  uc_hook_add(uc, trace4, UC_HOOK_MEM_READ, @HookMem64, nil, 1, 0,[]);

  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE64) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_RAX, @rax);
  uc_reg_read(uc, UC_X86_REG_RBX, @rbx);
  uc_reg_read(uc, UC_X86_REG_RCX, @rcx);
  uc_reg_read(uc, UC_X86_REG_RDX, @rdx);
  uc_reg_read(uc, UC_X86_REG_RSI, @rsi);
  uc_reg_read(uc, UC_X86_REG_RDI, @rdi);
  uc_reg_read(uc, UC_X86_REG_R8,  @r8);
  uc_reg_read(uc, UC_X86_REG_R9,  @r9);
  uc_reg_read(uc, UC_X86_REG_R10, @r10);
  uc_reg_read(uc, UC_X86_REG_R11, @r11);
  uc_reg_read(uc, UC_X86_REG_R12, @r12);
  uc_reg_read(uc, UC_X86_REG_R13, @r13);
  uc_reg_read(uc, UC_X86_REG_R14, @r14);
  uc_reg_read(uc, UC_X86_REG_R15, @r15);

  WriteLn(Format('>>> RAX = 0x%.16x', [rax]));
  WriteLn(Format('>>> RBX = 0x%.16x', [rbx]));
  WriteLn(Format('>>> RCX = 0x%.16x', [rcx]));
  WriteLn(Format('>>> RDX = 0x%.16x', [rdx]));
  WriteLn(Format('>>> RSI = 0x%.16x', [rsi]));
  WriteLn(Format('>>> RDI = 0x%.16x', [rdi]));
  WriteLn(Format('>>> R8  = 0x%.16x', [r8]));
  WriteLn(Format('>>> R9  = 0x%.16x', [r9]));
  WriteLn(Format('>>> R10 = 0x%.16x', [r10]));
  WriteLn(Format('>>> R11 = 0x%.16x', [r11]));
  WriteLn(Format('>>> R12 = 0x%.16x', [r12]));
  WriteLn(Format('>>> R13 = 0x%.16x', [r13]));
  WriteLn(Format('>>> R14 = 0x%.16x', [r14]));
  WriteLn(Format('>>> R15 = 0x%.16x', [r15]));

  uc_close(uc);
end;

procedure TestX86_64Syscall;
var
  uc: uc_engine;
  err: uc_err;
  trace1: uc_hook;
  rax: UInt64;
begin
  rax := $100;
  WriteLn('===================================');
  WriteLn('Emulate x86_64 code with "syscall" instruction');

  // Initialize emulator in X86-64bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_64, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, ADDRESS, @X86_CODE64_SYSCALL, SizeOf(X86_CODE64_SYSCALL) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // hook interrupts for syscall
  uc_hook_add(uc, trace1, UC_HOOK_INSN, @HookSyscall, nil, 1 , 0 , [UC_X86_INS_SYSCALL]);

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_RAX, @rax);

  // emulate machine code in infinite time (last param = 0), or when
  // finishing all the code.
  err := uc_emu_start(uc, ADDRESS, ADDRESS + SizeOf(X86_CODE64_SYSCALL) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  uc_reg_read(uc, UC_X86_REG_RAX, @rax);
  WriteLn(Format('>>> RAX = 0x%x', [rax]));

  uc_close(uc);
end;

procedure TestX86_16;
var
  uc: uc_engine;
  err: uc_err;
  tmp: Word;
  eax, ebx, esi: UInt32;
begin
  eax := 7;
  ebx := 5;
  esi := 6;

  WriteLn('Emulate x86 16-bit code');

  // Initialize emulator in X86-16bit mode
  err := uc_open(UC_ARCH_X86, UC_MODE_16, uc);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_open() with error returned: %u', [err]));
    Exit;
  end;

  // map 8KB memory for this emulation
  uc_mem_map(uc, 0, 8 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write_(uc, 0, @X86_CODE16, SizeOf(X86_CODE16) - 1) <> UC_ERR_OK) then begin
    WriteLn('Failed to write emulation code to memory, quit!');
    Exit;
  end;

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_EAX, @eax);
  uc_reg_write(uc, UC_X86_REG_EBX, @ebx);
  uc_reg_write(uc, UC_X86_REG_ESI, @esi);

  // emulate machine code in infinite time (last param = 0), or when
  // finishing all the code.
  err := uc_emu_start(uc, 0, SizeOf(X86_CODE16) - 1, 0, 0);
  if (err <> UC_ERR_OK) then begin
    WriteLn(Format('Failed on uc_emu_start() with error returned %u: %s', [err, uc_strerror(err)]));
  end;

  // now print out some registers
  WriteLn('>>> Emulation done. Below is the CPU context');

  err := uc_mem_read_(uc, 11, @tmp, 1);
  if (err = UC_ERR_OK) then
    WriteLn(Format('>>> Read 1 bytes from [0x%x] = 0x%x', [11, tmp]))
  else
    WriteLn(Format('>>> Failed to read 1 bytes from [0x%x]', [11]));

  uc_close(uc);
end;

begin
  if ParamCount > 0 then begin
    if (ParamStr(1) = '-32') then begin
      TestI386;
      test_i386_map_ptr;
      test_i386_context_save;
      TestI386Inout;
      TestI386Jump;
      TestI386Loop;
      TestI386InvalidMemRead;
      TestI386InvalidMemWrite;
      TestI386JumpInvalid;
    end;

    if (ParamStr(1) = '-64') then begin
      TestX86_64;
      TestX86_64Syscall;
    end;

    if (ParamStr(1) = '-16') then begin
      TestX86_16;
    end;

  end else
    WriteLn(#10'Syntax: SampleX86 <-16|-32|-64>'#10);
end.
