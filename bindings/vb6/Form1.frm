VERSION 5.00
Begin VB.Form Form1 
   Caption         =   "Form1"
   ClientHeight    =   6720
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   14220
   LinkTopic       =   "Form1"
   ScaleHeight     =   6720
   ScaleWidth      =   14220
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton Command1 
      Caption         =   "Copy"
      Height          =   465
      Left            =   6180
      TabIndex        =   1
      Top             =   6150
      Width           =   1995
   End
   Begin VB.ListBox List1 
      BeginProperty Font 
         Name            =   "Courier New"
         Size            =   11.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   5925
      Left            =   150
      TabIndex        =   0
      Top             =   120
      Width           =   13965
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

'Contributed by: FireEye FLARE team
'Author:         David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
'License:        Apache

Public WithEvents uc As ucIntel32
Attribute uc.VB_VarHelpID = -1
Dim hContext As Long


'test sample ported from: (requires unicorn 1.0 for success)
'   https://github.com/unicorn-engine/unicorn/blob/master/tests/unit/test_pc_change.c
'   https://github.com/unicorn-engine/unicorn/issues/210

Private Sub Form_Load()
    
    Dim ecx As Long, edx As Long
    Dim address As Long, size As Long, endAt As Long
    Dim b() As Byte, c As Collection, mem As CMemRegion
    
    Me.Visible = True
    
    'you can set UNICORN_PATH global variable to load a specific dll, do this before initilizing the class
    Set uc = New ucIntel32
    
    If uc.hadErr Then
        List1.AddItem uc.errMsg
        Exit Sub
    End If

    List1.AddItem "ucvbshim.dll loaded @" & Hex(uc.hLib)
    List1.AddItem "Unicorn version: " & uc.Version
    List1.AddItem "Disassembler available: " & uc.DisasmAvail
    If uc.major < 1 Then List1.AddItem "Change Eip in hook test requires >= v1.x for success"
    
    List1.AddItem "Unicorn x86 32bit engine handle: " & Hex(uc.uc)
        
'    ReDim b(8) 'for clarity in what we are testing..
'    b(0) = &H41 ' inc ECX @0x1000000
'    b(1) = &H41 ' inc ECX
'    b(2) = &H41 ' inc ECX
'    b(3) = &H41 ' inc ECX @0x1000003
'    b(4) = &H41 ' inc ECX
'    b(5) = &H41 ' inc ECX
'
'    b(6) = &H42 ' inc EDX @0x1000006
'    b(7) = &H42 ' inc EDX

'    #define X86_CODE32_MEM_WRITE "\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" // mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
    
    'we mash up two different test cases, first the change eip in hook test, then an invalid memory access
    'note the format accepted by tobytes() is somewhat forgiving (always use 2char hex vals though)
    b() = toBytes("4141414141414242cc\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a")
     
    ecx = 3
    edx = 15
    address = &H1000000
    size = &H200000
    endAt = address + UBound(b) + 1
    
    If Not uc.mapMem(address, size) Then
        List1.AddItem "Failed to map in 2mb memory " & uc.errMsg
        Exit Sub
    End If
    
    ' write machine code to be emulated to memory
    If Not uc.writeMem(address, b()) Then
        List1.AddItem "Failed to write code to memory " & uc.errMsg
        Exit Sub
    End If

    List1.AddItem "starts at: " & uc.disasm(address)
    
    Dim b2() As Byte
    If uc.readMem(address, b2, UBound(b) + 1) Then '+1 because ubound is 0 based..
        List1.AddItem "readMem: " & HexDump(b2, 1)
    End If
    
    uc.reg32(ecx_r) = ecx
    uc.reg32(edx_r) = edx
    List1.AddItem "start values ECX = " & ecx & " EDX = " & edx

    ' trace all instructions
    uc.addHook hc_code, UC_HOOK_CODE
    uc.addHook hc_memInvalid, UC_HOOK_MEM_READ_UNMAPPED Or UC_HOOK_MEM_WRITE_UNMAPPED
    'uc.removeHook UC_HOOK_MEM_READ_UNMAPPED Or UC_HOOK_MEM_WRITE_UNMAPPED
    uc.addHook hc_int, UC_HOOK_INTR
    
    List1.AddItem "beginning emulation.."
    If Not uc.startEmu(address, endAt) Then List1.AddItem uc.errMsg
    
    ecx = uc.reg32(ecx_r)
    edx = uc.reg8(dl_r)

    List1.AddItem "ECX:  6 =? " & ecx
    List1.AddItem "EDX: 17 =? " & edx
    List1.AddItem uc.dumpFlags
    If ecx <> 6 Then List1.AddItem "failed to change eip in hook!"
    
    ReDim b(100) 'this will handle mapping and alignment automatically..
    uc.writeBlock &H2001, b(), UC_PROT_READ Or UC_PROT_WRITE
    
    List1.AddItem "Initilizing sharedMemory with: aabbccddeeff0011223344556677889900"
    sharedMemory() = toBytes("aabbccddeeff0011223344556677889900")
    ReDim Preserve sharedMemory(&H1000) 'must be 4k bytes aligned...
    
    If Not uc.mapMemPtr(sharedMemory, &H4000, UBound(sharedMemory)) Then
        List1.AddItem "Failed to map in host memory " & uc.errMsg
    Else
        
        Dim bb As Byte, ii As Integer, ll As Long
        
        If Not uc.writeByte(&H4001, &H41) Then
             List1.AddItem "Failed to write byte to shared mem"
        Else
            List1.AddItem "Wrote 0x41 to sharedMemory + 1"
            If uc.readByte(&H4001, bb) Then List1.AddItem "readByte = " & Hex(bb)
        End If
        
        'uc.writeInt &H4001, &H4142
        'If uc.readInt(&H4001, ii) Then List1.AddItem Hex(ii)
        
        'uc.writeLong &H4001, &H11223344
        'If uc.readLong(&H4001, ll) Then List1.AddItem Hex(ll)
        
        Erase b2
        If uc.readMem(&H4000, b2, 20) Then
            List1.AddItem "emu read of sharedMemory: " & HexDump(b2, 1)
        Else
            List1.AddItem "Failed to readMem on sharedMemory " & uc.errMsg
        End If
        
        List1.AddItem "sanity checking host mem: " & HexDump(sharedMemory, 1, , 20)
        
    End If
    
    List1.AddItem "Enumerating memory regions..."
    
    Set c = uc.getMemMap()
    
    For Each mem In c
        List1.AddItem mem.toString()
    Next
    
    If hContext <> 0 Then
        List1.AddItem "trying to restore context.."
        If Not uc.restoreContext(hContext) Then List1.AddItem uc.errMsg
        List1.AddItem uc.regDump()
        List1.AddItem "beginning emulation.."
        If Not uc.startEmu(uc.eip, endAt) Then List1.AddItem uc.errMsg
        List1.AddItem uc.regDump()
        List1.AddItem "releasing saved context.."
        If Not uc.freeContext(hContext) Then List1.AddItem uc.errMsg
    End If
    
    Set mem = c(2)
    If Not uc.changePermissions(mem, UC_PROT_ALL) Then
        List1.AddItem "Failed to change permissions on second alloc " & uc.errMsg
    Else
        List1.AddItem "Changed permissions on second alloc to ALL"
        List1.AddItem "redumping memory regions to check..."
        Set c = uc.getMemMap()
        For Each mem In c
            List1.AddItem mem.toString()
        Next
    End If

    If uc.unMapMem(&H2000) Then
        List1.AddItem "Successfully unmapped new alloc"
    Else
        List1.AddItem "Failed to unmap alloc " & uc.errMsg
    End If

    List1.AddItem "Mem allocs count now: " & uc.getMemMap().count
     
End Sub

Private Sub Command1_Click()
    Clipboard.Clear
    Clipboard.SetText lbCopy(List1)
End Sub

Private Sub Form_Unload(Cancel As Integer)
    'so IDE doesnt hang onto dll and we can recompile in development testing.. if you hit stop this benefit is lost..
    'do not use this in your real code, only for c dll development..
    If uc.hLib <> 0 Then FreeLibrary uc.hLib
End Sub

Private Sub uc_CodeHook(ByVal address As Long, ByVal size As Long)
    
    List1.AddItem "> " & uc.disasm(address)
    
    If hContext = 0 And address = &H1000003 Then   'change the PC to "inc EDX"
        List1.AddItem "changing eip to skip last inc ecx's and saving context..."
        hContext = uc.saveContext()
        If hContext = 0 Then List1.AddItem "Failed to save context " & uc.errMsg
        uc.eip = &H1000006
    End If
    
End Sub

Private Sub uc_Interrupt(ByVal intno As Long)
    List1.AddItem "Interrupt: " & intno
End Sub

Private Sub uc_InvalidMem(ByVal t As uc_mem_type, ByVal address As Long, ByVal size As Long, ByVal value As Long, continue As Boolean)
    'continue defaults to false so we can ignore it unless we want to continue..
    List1.AddItem "Invalid mem access address: " & Hex(address) & " size: " & Hex(size) & " type: " & memType2str(t)
End Sub

Private Sub uc_MemAccess(ByVal t As uc_mem_type, ByVal address As Long, ByVal size As Long, ByVal value As Long)
    List1.AddItem "mem access: address: " & Hex(address) & " size: " & Hex(size) & " type: " & memType2str(t)
End Sub

