VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "ucIntel32"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Option Explicit

'Unicorn Engine x86 32bit wrapper class for vb6

'Contributed by: FireEye FLARE team
'Author:         David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License:        Apache

'we hide the extra labor of x64 conversion from the user. I could simplify
'this at the C shim layer but I might write an x64 class later
'
'since the vb long type only natively supports signed math, I have also handed off a couple
'calculations in this class to a C stub just to be safe.
'
'you can find a full unsigned and x64 safe library for vb6 here:
'    https://github.com/dzzie/libs/tree/master/vb6_utypes

Public hLib As Long
Public uc As Long
Public errMsg As String
Public Version As String
Public major As Long
Public minor As Long

Private r32 As Variant
Private r16 As Variant
Private r8 As Variant
Private rs_ As Variant
Private rs_Name As Variant
Private r32_Name As Variant
Private r16_Name As Variant
Private r8_Name As Variant
Private hooks As New Collection
Private m_DisasmOk As Boolean

Event CodeHook(ByVal address As Long, ByVal size As Long)
Event BlockHook(ByVal address As Long, ByVal size As Long)
Event MemAccess(ByVal t As uc_mem_type, ByVal address As Long, ByVal size As Long, ByVal value As Long)
Event InvalidMem(ByVal t As uc_mem_type, ByVal address As Long, ByVal size As Long, ByVal value As Long, ByRef continue As Boolean)
Event Interrupt(ByVal intno As Long)

'our vb enum is 0 based then mapped to the real C values so we can loop them to dump with name lookup
'these sub enums also keep the intellisense lists short and focused when reading/writing vals
'they are accessed through reg32, reg16, reg8, rs properties, or use raw full enum through reg property
'the names of each can be looked up through the reg32n etc properties
Public Enum reg_32
    eax_r = 0
    ecx_r = 1
    edx_r = 2
    ebx_r = 3
    esp_r = 4
    ebp_r = 5
    esi_r = 6
    edi_r = 7
End Enum

Public Enum reg_16
    ax_r = 0
    cx_r = 1
    dx_r = 2
    bx_r = 3
    sp_r = 4
    bp_r = 5
    si_r = 6
    di_r = 7
End Enum

Public Enum reg_8
    ah_r = 0
    ch_r = 1
    dh_r = 2
    bh_r = 3
    al_r = 4
    cl_r = 5
    dl_r = 6
    bl_r = 7
End Enum

Public Enum reg_Special
    CS_r = 0
    DS_r = 1
    ES_r = 2
    FS_r = 3
    GS_r = 4
    SS_r = 5
    IDTR_r = 6
    GDTR_r = 7
    LDTR_r = 8
End Enum

Property Get DisasmAvail() As Boolean
    DisasmAvail = m_DisasmOk
End Property

Property Get lastError() As Long
    lastError = ucs_errno(uc)
End Property

Property Get hadErr() As Boolean
    If Len(errMsg) > 0 Then hadErr = True
End Property

Property Get eip() As Long
    Dim e As uc_err, value As Long
    e = ucs_reg_read(uc, UC_X86_REG_EIP, value)
    eip = value
End Property

Property Let eip(v As Long)
    Dim e As uc_err
    e = ucs_reg_write(uc, UC_X86_REG_EIP, v)
End Property

Property Get eflags() As Long
    Dim e As uc_err, value As Long
    e = ucs_reg_read(uc, UC_X86_REG_EFLAGS, value)
    eflags = value
End Property

Property Let eflags(v As Long)
    Dim e As uc_err
    e = ucs_reg_write(uc, UC_X86_REG_EFLAGS, v)
End Property


'full access to all registers if you need it..
Property Get reg(r As uc_x86_reg) As Long
    Dim e As uc_err, value As Long
    e = ucs_reg_read(uc, r, value)
    reg = value
End Property

Property Let reg(r As uc_x86_reg, value As Long)
    Dim e As uc_err
    e = ucs_reg_write(uc, r, value)
End Property

'32 bit registers
Property Get reg32(r As reg_32) As Long
    Dim e As uc_err, value As Long
    If r < 0 Or r > UBound(r32) Then Exit Property
    e = ucs_reg_read(uc, r32(r), value)
    reg32 = value
End Property

Property Let reg32(r As reg_32, value As Long)
    Dim e As uc_err
    If r < 0 Or r > UBound(r32) Then Exit Property
    e = ucs_reg_write(uc, r32(r), value)
End Property

'16 bit registers
Property Get reg16(r As reg_16) As Long
    Dim e As uc_err, value As Long
    If r < 0 Or r > UBound(r16) Then Exit Property
    e = ucs_reg_read(uc, r16(r), value)
    reg16 = CInt(value)
End Property

Property Let reg16(r As reg_16, ByVal value As Long)
    Dim e As uc_err
    value = value And &HFFFF
    If r < 0 Or r > UBound(r16) Then Exit Property
    e = ucs_reg_write(uc, r16(r), value)
End Property

'8 bit registers
Property Get reg8(r As reg_8) As Long
    Dim e As uc_err, value As Long
    If r < 0 Or r > UBound(r8) Then Exit Property
    e = ucs_reg_read(uc, r8(r), value)
    reg8 = value
End Property

Property Let reg8(r As reg_8, ByVal value As Long)
    Dim e As uc_err
    value = value And &HFF
    If r < 0 Or r > UBound(r8) Then Exit Property
    e = ucs_reg_write(uc, r8(r), value)
End Property

'special registers
Property Get rs(r As reg_Special) As Long
    Dim e As uc_err, value As Long
    If r < 0 Or r > UBound(rs_) Then Exit Property
    e = ucs_reg_read(uc, rs_(r), value)
    rs = value
End Property

Property Let rs(r As reg_Special, ByVal value As Long)
    Dim e As uc_err
    If r < 0 Or r > UBound(rs_) Then Exit Property
    e = ucs_reg_write(uc, rs_(r), value)
End Property


'reg index to name translation for looping
Property Get reg32n(r As reg_32) As String
    If r < 0 Or r > UBound(r32_Name) Then Exit Property
    reg32n = r32_Name(r)
End Property

Property Get reg16n(r As reg_16) As String
    If r < 0 Or r > UBound(r16_Name) Then Exit Property
    reg16n = r16_Name(r)
End Property

Property Get reg8n(r As reg_8) As String
    If r < 0 Or r > UBound(r8_Name) Then Exit Property
    reg8n = r8_Name(r)
End Property

Property Get rsn(r As reg_Special) As String
    If r < 0 Or r > UBound(rs_Name) Then Exit Property
    rsn = rs_Name(r)
End Property

Function regDump(Optional includeState As Boolean = True) As String
    Dim i As Long
    Dim tmp As String
    
    For i = 0 To UBound(r32)
        tmp = tmp & reg32n(i) & "=" & Hex(reg32(i)) & "  "
        'if i mod 3 = 0 and i <> 0 then tmp = tmp & vbcrlf
    Next
    
    regDump = tmp
    
    If includeState Then
        regDump = regDump & "eip=" & Hex(Me.eip) & "  " & dumpFlags()
    End If
    
End Function

Function dumpFlags() As String
    
    Dim ret() As String
    Dim n As Variant
    Dim i As Long
    Dim flags As Long
    
    'http://www.c-jump.com/CIS77/ASM/Instructions/I77_0050_eflags.htm
    n = Array("C ", 0, "P ", 0, "A ", 0, "Z ", "S ", _
              "T ", "I ", "D ", "O ", "IOPL ", "IOPL ", "NT ", 0, _
              "RF ", "VM ", "AC ", "VIF ", "VIP ", "ID ", 0)

    flags = Me.eflags
    push ret, "EFL " & Hex(flags)

    For i = 0 To 21
        If flags And ULong(1, i, op_lsh) Then
            If n(i) <> 0 Then push ret, n(i)
        End If
    Next
    
    dumpFlags = Join(ret, "  ")
    
        
End Function

Private Sub Class_Initialize()
    
    Dim e As uc_err
    
    'mapping our simplified to real values..
    r32 = Array(UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI)
    r32_Name = Array("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")

    r16 = Array(UC_X86_REG_AX, UC_X86_REG_CX, UC_X86_REG_DX, UC_X86_REG_BX, UC_X86_REG_SP, UC_X86_REG_BP, UC_X86_REG_SI, UC_X86_REG_DI)
    r16_Name = Array("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")

    r8 = Array(UC_X86_REG_AH, UC_X86_REG_CH, UC_X86_REG_DH, UC_X86_REG_BH, UC_X86_REG_AL, UC_X86_REG_CL, UC_X86_REG_DL, UC_X86_REG_Bl)
    r8_Name = Array("ah", "ch", "dh", "bh", "al", "cl", "dl", "bl")
  
    rs_ = Array(UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_SS, UC_X86_REG_IDTR, UC_X86_REG_GDTR, UC_X86_REG_LDTR)
    rs_Name = Array("cs", "ds", "es", "fs", "gs", "ss", "idtr", "gdtr", "ldtr")
    
    'just to ensure IDE finds the dll before we try to use it...
    Const dllName As String = "ucvbshim.dll"
    
    If Len(UNICORN_PATH) = 0 Then
        UNICORN_PATH = vbNullString
    ElseIf FolderExists(UNICORN_PATH) Then
        UNICORN_PATH = UNICORN_PATH & IIf(Right(UNICORN_PATH, 1) = "\", "", "\") & "unicorn.dll"
    End If
    
    If hLib = 0 Then
        hLib = GetModuleHandle(dllName)
        If hLib = 0 Then
            hLib = LoadLibrary(GetParentFolder(UNICORN_PATH) & "\" & dllName)
            If hLib = 0 Then
                hLib = LoadLibrary(dllName)
                If hLib = 0 Then
                    errMsg = "Could not load " & dllName
                    Exit Sub
                End If
            End If
        End If
    End If
    
    If DYNLOAD = 0 Then
        DYNLOAD = ucs_dynload(UNICORN_PATH)
        If DYNLOAD = 0 Then
            errMsg = "Dynamic Loading of unicorn.dll failed " & IIf(Len(UNICORN_PATH) > 0, "path: " & UNICORN_PATH, "")
            Exit Sub
        End If
    End If
    
    ucs_version major, minor
    Version = major & "." & minor
    
    If ucs_arch_supported(UC_ARCH_X86) <> 1 Then
        errMsg = "UC_ARCH_X86 not supported"
        Exit Sub
    End If
    
    e = ucs_open(UC_ARCH_X86, UC_MODE_32, uc)
    If e <> uc_err_ok Then
        errMsg = "Failed to create new x86 32bit engine instance " & err2str(e)
        Exit Sub
    End If
    
    If GetProcAddress(hLib, "disasm_addr") <> 0 Then m_DisasmOk = True
     
    instances.Add Me, "objptr:" & ObjPtr(Me)
    
End Sub

Private Sub Class_Terminate()
    If uc = 0 Then Exit Sub
    stopEmu
    ucs_close uc
    On Error Resume Next
    instances.Remove "objptr:" & ObjPtr(Me)
End Sub

Function mapMem(address As Long, size As Long, Optional protection As uc_prot = UC_PROT_ALL) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    
    errMsg = Empty
    addr = lng2Cur(address)
   
    e = ucs_mem_map(uc, addr, size, protection)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    mapMem = True
    
End Function

'address and size must be 4kb aligned, real buffer must be at least of size, and not go out of scope!
Function mapMemPtr(ByRef b() As Byte, address As Long, size As Long, Optional protection As uc_prot = UC_PROT_ALL) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    
    errMsg = Empty
    addr = lng2Cur(address)
   
    If UBound(b) < size Then
        errMsg = "Buffer is < size"
        Exit Function
    End If
    
    If size Mod &H1000 <> 0 Then
        errMsg = "Size must be 4kb aligned"
        Exit Function
    End If
    
    If address Mod &H1000 <> 0 Then
        errMsg = "address must be 4kb aligned"
        Exit Function
    End If
   
    e = ucs_mem_map_ptr(uc, addr, size, protection, VarPtr(b(0)))
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    mapMemPtr = True
    
End Function

Function findAlloc(address As Long, Optional inRange As Boolean = False) As CMemRegion
    Dim m As CMemRegion
    Dim found As Boolean
    
    For Each m In getMemMap()
        If inRange Then
            If ULong(address, m.address, op_gteq) = 1 And ULong(address, m.address, op_lteq) = 1 Then found = True
        Else
            If m.address = address Then found = True
        End If
        If found Then
            Set findAlloc = m
            Exit Function
        End If
    Next
End Function

'we could accept a variant here instead of CMemRegion
'if typename(v) = "Long" then enum regions and find cmem, else expect CMemRegion..
'would be convient.. or a findAlloc(base as long) as CMemRegion
Function changePermissions(m As CMemRegion, newProt As uc_prot)
    Dim e As uc_err
    Dim addr64 As Currency

    errMsg = Empty

    If m Is Nothing Then Exit Function

    If newProt = m.perm Then
        changePermissions = True
        Exit Function
    End If

    addr64 = lng2Cur(m.address)

    e = ucs_mem_protect(uc, addr64, m.size, newProt)

    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If

    m.perm = newProt
    changePermissions = True

End Function


Function unMapMem(base As Long) As Boolean

    Dim m As CMemRegion
    Dim e As uc_err
    Dim addr64 As Currency

    errMsg = Empty
    addr64 = lng2Cur(base)

    For Each m In getMemMap()
        If m.address = base Then
            e = ucs_mem_unmap(uc, addr64, m.size)
            unMapMem = (e = uc_err_ok)
            If Not unMapMem Then errMsg = err2str(e)
            Exit Function
        End If
    Next

End Function

'this function maps and writes (note 32bit only right now)
Function writeBlock(address As Long, buf() As Byte, Optional perm As uc_prot = UC_PROT_ALL) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    
    addr = lng2Cur(address)
    
    errMsg = Empty
    e = mem_write_block(uc, addr, buf(0), UBound(buf) + 1, perm)
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    writeBlock = True
    
End Function

'this function requires the memory already be mapped in, use writeBlock for easier access...
Function writeMem(address As Long, buf() As Byte) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    
    errMsg = Empty
    addr = lng2Cur(address)
    
    e = ucs_mem_write(uc, addr, buf(0), UBound(buf) + 1)
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    writeMem = True
    
End Function

Function writeByte(address As Long, b As Byte) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    Dim buf(0) As Byte
    
    errMsg = Empty
    addr = lng2Cur(address)
    buf(0) = b
    
    e = ucs_mem_write(uc, addr, buf(0), 1)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    writeByte = True
    
End Function

Function writeLong(address As Long, value As Long) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    Dim buf(0 To 3) As Byte
    
    errMsg = Empty
    addr = lng2Cur(address)
    CopyMemory buf(0), ByVal VarPtr(value), 4
    
    e = ucs_mem_write(uc, addr, buf(0), 4)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    writeLong = True
    
End Function

Function writeInt(address As Long, value As Integer) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    Dim buf(0 To 1) As Byte
    
    errMsg = Empty
    addr = lng2Cur(address)
    CopyMemory buf(0), ByVal VarPtr(value), 2
    
    e = ucs_mem_write(uc, addr, buf(0), 2)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    writeInt = True
    
End Function

Function readMem(address As Long, ByRef buf() As Byte, ByVal size As Long) As Boolean
    
    Dim addr As Currency
    Dim e As uc_err
    
    errMsg = Empty
    addr = lng2Cur(address)
    ReDim buf(size - 1) '0 based..
    
    e = ucs_mem_read(uc, addr, buf(0), UBound(buf) + 1)
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    readMem = True
    
End Function

Function readByte(address As Long, ByRef b As Byte) As Boolean
    
    Dim buf() As Byte
    
    readMem address, buf, 1
    If hadErr Then Exit Function

    b = buf(0)
    readByte = True

End Function

Function readLong(address As Long, ByRef retVal As Long) As Boolean
    
    Dim buf() As Byte
    
    readMem address, buf, 4
    If hadErr Then Exit Function

    CopyMemory ByVal VarPtr(retVal), buf(0), 4
    readLong = True
    
End Function

Function readInt(address As Long, ByRef retVal As Integer) As Boolean
    
    Dim buf() As Byte
    
    readMem address, buf, 2
    If hadErr Then Exit Function
    
    CopyMemory ByVal VarPtr(retVal), buf(0), 2
    readInt = True
    
End Function


Function saveContext() As Long
    
    Dim hContext As Long
    Dim e As uc_err
    
    errMsg = Empty
    e = ucs_context_alloc(uc, hContext)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    e = ucs_context_save(uc, hContext)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        e = ucs_free(hContext)
        If e <> uc_err_ok Then errMsg = errMsg & " error freeing context: " & err2str(e)
        Exit Function
    End If
    
    saveContext = hContext
    
End Function

Function restoreContext(hContext As Long) As Boolean
    
    Dim e As uc_err
    
    errMsg = Empty
    e = ucs_context_restore(uc, hContext)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    restoreContext = True
    
End Function

Function freeContext(hContext As Long) As Boolean
    Dim e As uc_err
    e = ucs_free(hContext)
    If e <> uc_err_ok Then
        errMsg = err2str(e)
    Else
        freeContext = True
    End If
End Function


Function disasm(va As Long, Optional ByRef instrLen As Long) As String

    Dim buf As String, i As Long, b() As Byte
    Dim dump As String
    On Error Resume Next
    
    If Not m_DisasmOk Then
        disasm = Right("00000000" & Hex(va), 8)
        Exit Function
    End If
    
    buf = String(300, Chr(0))
    
    instrLen = disasm_addr(uc, va, buf, Len(buf))
    If instrLen < 1 Then
        Select Case instrLen
            Case -1: buf = "Buffer to small"
            Case -2: buf = "Failed to read memory"
            Case -3: buf = "Failed to disassemble"
            Case Default: buf = "Unknown error " & instrLen
        End Select
        dump = "?? ?? ??"
        GoTo end_of_func
    End If
    
    i = InStr(buf, Chr(0))
    If i > 2 Then buf = VBA.Left(buf, i - 1) Else buf = Empty
    
    readMem va, b(), instrLen
    
    For i = 0 To UBound(b)
        dump = dump & hhex(b(i)) & " "
    Next
    
end_of_func:
    disasm = Right("00000000" & Hex(va), 8) & "  " & rpad(dump, 25) & buf
    
End Function

Function startEmu(beginAt As Long, endAt As Long, Optional timeout As Long = 0, Optional count As Long = 0) As Boolean
    
    Dim e As uc_err
    Dim a As Currency, b As Currency, t As Currency
    
    a = lng2Cur(beginAt)
    b = lng2Cur(endAt)
    t = lng2Cur(timeout)
    
    errMsg = Empty
    e = ucs_emu_start(uc, a, b, t, count)
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If

    startEmu = True
    
End Function

Function stopEmu() As Boolean
    Dim e As uc_err
    errMsg = Empty
    e = ucs_emu_stop(uc)
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    stopEmu = True
End Function


 Function addHook(catagory As hookCatagory, flags As uc_hook_type, Optional beginAt As Long = 1, Optional endAt As Long = 0) As Boolean

    Dim e As uc_err
    Dim hHook As Long 'handle to remove hook
    Dim a As Currency, b As Currency
    
    e = -1
    a = lng2Cur(beginAt)
    b = lng2Cur(endAt)
    errMsg = Empty
       
    If KeyExistsInCollection(hooks, "flags:" & flags) Then
        addHook = True
        Exit Function
    End If
    
    If catagory = hc_code Then e = ucs_hook_add(uc, hHook, flags, AddressOf code_hook, ObjPtr(Me), a, b, catagory)
    If catagory = hc_mem Then e = ucs_hook_add(uc, hHook, flags, AddressOf mem_hook, ObjPtr(Me), a, b, catagory)
    If catagory = hc_memInvalid Then e = ucs_hook_add(uc, hHook, flags, AddressOf invalid_mem_hook, ObjPtr(Me), a, b, catagory)
    If catagory = hc_block Then e = ucs_hook_add(uc, hHook, flags, AddressOf block_hook, ObjPtr(Me), a, b, catagory)
    If catagory = hc_int Then e = ucs_hook_add(uc, hHook, flags, AddressOf interrupt_hook, ObjPtr(Me), a, b, catagory)
    
    If e = -1 Then
        errMsg = "Unimplemented hook catagory"
        Exit Function
    End If
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    hooks.Add hHook, "flags:" & flags
    addHook = True
    
 End Function

'actually these appear to use different prototypes for each instruction? (only in/out examples seen...)
'what about all the others? not implemented yet in c or vb callback
'Function hookInstruction(i As uc_x86_insn, Optional beginAt As Long = 1, Optional endAt As Long = 0) As Boolean
'
'    Dim e As uc_err
'    Dim hHook As Long 'handle to remove hook
'    Dim a As Currency, b As Currency
'
'    If i = UC_X86_INS_INVALID Then Exit Function
'
'    e = -1
'    a = lng2Cur(beginAt)
'    b = lng2Cur(endAt)
'    errMsg = Empty
'
'    If KeyExistsInCollection(hooks, "instr:" & i) Then
'        hookInstruction = True
'        Exit Function
'    End If
'
'    e = ucs_hook_add(uc, hHook, UC_HOOK_INSN, AddressOf instruction_hook, ObjPtr(Me), a, b, hc_inst, i)
'
'    If e <> UC_ERR_OK Then
'        errMsg = err2str(e)
'        Exit Function
'    End If
'
'    hooks.Add hHook, "instr:" & i
'    hookInstruction = True
'
' End Function


Function removeHook(ByVal flags As uc_hook_type) As Boolean
    
    On Error Resume Next
    
    Dim hHook As Long, e As uc_err, wasInstr As Boolean
    
    errMsg = Empty
    hHook = hooks("flags:" & flags)
    
    If hHook = 0 Then
        hHook = hooks("instr:" & flags) 'maybe it was an instruction hook?
        If hHook = 0 Then
            errMsg = "Hook handle not found for supplied flags."
            Exit Function
        Else
           wasInstr = True
        End If
    End If
    
    e = ucs_hook_del(uc, hHook)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    If wasInstr Then
        hooks.Remove "instr:" & flags
    Else
        hooks.Remove "flags:" & flags
    End If
    
    removeHook = True
    
End Function

Function getMemMap() As Collection 'of 32bit CMemRegion
    Dim c As New Collection
    Dim ret As New Collection
    Dim mem As CMemRegion
    Dim e As uc_err
    Dim s, tmp, v
    
    errMsg = Empty
    Set getMemMap = ret
    
    e = get_memMap(uc, c)
    
    If e <> uc_err_ok Then
        errMsg = err2str(e)
        Exit Function
    End If
    
    For Each s In c               '&h1000000,&h11fffff,&h7 these should always be 32bit safe values created in this class..
        If Len(s) > 0 Then
            tmp = Split(s, ",")
            If UBound(tmp) = 2 Then
                Set mem = New CMemRegion
                mem.address = CLng(tmp(0))
                mem.endsAt = CLng(tmp(1))
                mem.size = ULong(mem.endsAt, mem.address, op_sub) + 1 'vb native math is signed only..we play it safe..
                mem.perm = CLng(tmp(2))
                ret.Add mem
            End If
        End If
    Next
    
End Function


'these are internal functions used from the callback in the module to route the message to the event interface
'little confusing but in the end easier for the end user...also lays foundation for multiple live instances
'(although only one can run at a time since vb is single threaded)

Friend Function internal_invalid_mem_hook(ByVal t As uc_mem_type, ByVal address As Currency, ByVal size As Long, ByVal value As Currency) As Long
    Dim addr As Long, v As Long, continue As Boolean
    addr = cur2lng(address)
    v = cur2lng(value)
    RaiseEvent InvalidMem(t, addr, size, v, continue)
    internal_invalid_mem_hook = IIf(continue, 1, 0)
End Function

Friend Sub internal_mem_hook(ByVal t As uc_mem_type, ByVal address As Currency, ByVal size As Long, ByVal value As Currency)
    Dim addr As Long, v As Long
    addr = cur2lng(address)
    v = cur2lng(value)
    RaiseEvent MemAccess(t, addr, size, v)
End Sub

Friend Sub internal_code_hook(ByVal address As Currency, ByVal size As Long)
    Dim addr As Long
    addr = cur2lng(address)
    RaiseEvent CodeHook(addr, size)
End Sub

Friend Sub internal_block_hook(ByVal address As Currency, ByVal size As Long)
    Dim addr As Long
    addr = cur2lng(address)
    RaiseEvent BlockHook(addr, size)
End Sub

Friend Sub internal_interrupt_hook(ByVal intno As Long)
    RaiseEvent Interrupt(intno)
End Sub

