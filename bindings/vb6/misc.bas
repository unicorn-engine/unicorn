Attribute VB_Name = "misc"
Option Explicit

Public sharedMemory() As Byte 'in a module so it never goes out of scope and becomes unallocated..

Public Declare Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As Long
Public Declare Function FreeLibrary Lib "kernel32" (ByVal hLibModule As Long) As Long
Public Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As Long)
Public Declare Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long
Public Declare Function GetModuleHandle Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As Long

Enum op
    op_add = 0
    op_sub = 1
    op_div = 2
    op_mul = 3
    op_mod = 4
    op_xor = 5
    op_and = 6
    op_or = 7
    op_rsh = 8
    op_lsh = 9
    op_gt = 10
    op_lt = 11
    op_gteq = 12
    op_lteq = 13
End Enum

'unsigned math operations
Public Declare Function ULong Lib "ucvbshim.dll" (ByVal v1 As Long, ByVal v2 As Long, ByVal operation As op) As Long

'this is just a quick way to support x64 numbers in vb6 its lite but can be bulky to work with
'if we wanted to really work with x64 values we would compile a library such as the following into the shim layer:
'  https://github.com/dzzie/libs/tree/master/vb6_utypes

Private Type Bit64Currency
  value As Currency
End Type

Private Type Bit64Integer
  LowValue As Long
  HighValue As Long
End Type

Global Const LANG_US = &H409

Function lng2Cur(v As Long) As Currency
  Dim c As Bit64Currency
  Dim dl As Bit64Integer
  dl.LowValue = v
  dl.HighValue = 0
  LSet c = dl
  lng2Cur = c.value
End Function

Function cur2lng(v As Currency) As Long
  Dim c As Bit64Currency
  Dim dl As Bit64Integer
  c.value = v
  LSet dl = c
  cur2lng = dl.LowValue
End Function

Function KeyExistsInCollection(c As Collection, val As String) As Boolean
    On Error GoTo nope
    Dim t
    t = c(val)
    KeyExistsInCollection = True
 Exit Function
nope: KeyExistsInCollection = False
End Function

Function FileExists(path As String) As Boolean
  On Error GoTo nope
    
  If Len(path) = 0 Then Exit Function
  If Right(path, 1) = "\" Then Exit Function
  If Dir(path, vbHidden Or vbNormal Or vbReadOnly Or vbSystem) <> "" Then FileExists = True
  
  Exit Function
nope: FileExists = False
End Function

Function FileNameFromPath(fullpath) As String
    Dim tmp
    If InStr(fullpath, "\") > 0 Then
        tmp = Split(fullpath, "\")
        FileNameFromPath = CStr(tmp(UBound(tmp)))
    End If
End Function

Function GetParentFolder(path) As String
    Dim tmp, a As Long
    
    If Right(path, 1) = "\" Then
        GetParentFolder = path
    Else
        a = InStrRev(path, "\")
        If a > 0 Then
           GetParentFolder = Mid(path, 1, a)
        End If
    End If
        
End Function

Function FolderExists(ByVal path As String) As Boolean
  On Error GoTo nope
  If Len(path) = 0 Then Exit Function
  If Right(path, 1) <> "\" Then path = path & "\"
  If Dir(path, vbDirectory) <> "" Then FolderExists = True
  Exit Function
nope: FolderExists = False
End Function

Function HexDump(bAryOrStrData, Optional hexOnly = 0, Optional ByVal startAt As Long = 1, Optional ByVal Length As Long = -1) As String
    Dim s() As String, chars As String, tmp As String
    On Error Resume Next
    Dim ary() As Byte
    Dim offset As Long
    Const LANG_US = &H409
    Dim i As Long, tt, h, x

    offset = 0
    
    If TypeName(bAryOrStrData) = "Byte()" Then
        ary() = bAryOrStrData
    Else
        ary = StrConv(CStr(bAryOrStrData), vbFromUnicode, LANG_US)
    End If
    
    If startAt < 1 Then startAt = 1
    If Length < 1 Then Length = -1
    
    While startAt Mod 16 <> 0
        startAt = startAt - 1
    Wend
    
    startAt = startAt + 1
    
    chars = "   "
    For i = startAt To UBound(ary) + 1
        tt = Hex(ary(i - 1))
        If Len(tt) = 1 Then tt = "0" & tt
        tmp = tmp & tt & " "
        x = ary(i - 1)
        'chars = chars & IIf((x > 32 And x < 127) Or x > 191, Chr(x), ".") 'x > 191 causes \x0 problems on non us systems... asc(chr(x)) = 0
        chars = chars & IIf((x > 32 And x < 127), Chr(x), ".")
        If i > 1 And i Mod 16 = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            If hexOnly = 0 Then
                push s, h & "   " & tmp & chars
            Else
                push s, tmp
            End If
            offset = offset + 16
            tmp = Empty
            chars = "   "
        End If
        If Length <> -1 Then
            Length = Length - 1
            If Length = 0 Then Exit For
        End If
    Next
    
    'if read length was not mod 16=0 then
    'we have part of line to account for
    If tmp <> Empty Then
        If hexOnly = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            h = h & "   " & tmp
            While Len(h) <= 56: h = h & " ": Wend
            push s, h & chars
        Else
            push s, tmp
        End If
    End If
    
    HexDump = Join(s, vbCrLf)
    
    If hexOnly <> 0 Then
        HexDump = Replace(HexDump, " ", "")
        HexDump = Replace(HexDump, vbCrLf, "")
    End If
    
End Function


Public Function toBytes(ByVal hexstr, Optional strRet As Boolean = False)

'supports:
'11 22 33 44   spaced hex chars
'11223344      run together hex strings
'11,22,33,44   csv hex
'\x11,0x22     misc C source rips
'
'ignores common C source prefixes, operators, delimiters, and whitespace
'
'not supported
'1,2,3,4        all hex chars are must have two chars even if delimited
'
'a version which supports more formats is here:
'  https://github.com/dzzie/libs/blob/master/dzrt/globals.cls

    Dim ret As String, x As String, str As String
    Dim r() As Byte, b As Byte, b1 As Byte
    Dim foundDecimal As Boolean, tmp, i, a, a2
    Dim pos As Long, marker As String
    
    On Error GoTo nope
    
    str = Replace(hexstr, vbCr, Empty)
    str = Replace(str, vbLf, Empty)
    str = Replace(str, vbTab, Empty)
    str = Replace(str, Chr(0), Empty)
    str = Replace(str, "{", Empty)
    str = Replace(str, "}", Empty)
    str = Replace(str, ";", Empty)
    str = Replace(str, "+", Empty)
    str = Replace(str, """""", Empty)
    str = Replace(str, "'", Empty)
    str = Replace(str, " ", Empty)
    str = Replace(str, "0x", Empty)
    str = Replace(str, "\x", Empty)
    str = Replace(str, ",", Empty)
    
    For i = 1 To Len(str) Step 2
        x = Mid(str, i, 2)
        If Not isHexChar(x, b) Then Exit Function
        bpush r(), b
    Next
    
    If strRet Then
        toBytes = StrConv(r, vbUnicode, LANG_US)
    Else
        toBytes = r
    End If
    
nope:
End Function

Private Sub bpush(bAry() As Byte, b As Byte) 'this modifies parent ary object
    On Error GoTo init
    Dim x As Long
    
    x = UBound(bAry) '<-throws Error If Not initalized
    ReDim Preserve bAry(UBound(bAry) + 1)
    bAry(UBound(bAry)) = b
    
    Exit Sub

init:
    ReDim bAry(0)
    bAry(0) = b
    
End Sub

Sub push(ary, value) 'this modifies parent ary object
    On Error GoTo init
    Dim x
       
    x = UBound(ary)
    ReDim Preserve ary(x + 1)
    
    If IsObject(value) Then
        Set ary(x + 1) = value
    Else
        ary(x + 1) = value
    End If
    
    Exit Sub
init:
    ReDim ary(0)
    If IsObject(value) Then
        Set ary(0) = value
    Else
        ary(0) = value
    End If
End Sub


Public Function isHexChar(hexValue As String, Optional b As Byte) As Boolean
    On Error Resume Next
    Dim v As Long
    
    If Len(hexValue) = 0 Then GoTo nope
    If Len(hexValue) > 2 Then GoTo nope 'expecting hex char code like FF or 90
    
    v = CLng("&h" & hexValue)
    If Err.Number <> 0 Then GoTo nope 'invalid hex code
    
    b = CByte(v)
    If Err.Number <> 0 Then GoTo nope  'shouldnt happen.. > 255 cant be with len() <=2 ?

    isHexChar = True
    
    Exit Function
nope:
    Err.Clear
    isHexChar = False
End Function

Function hhex(b As Byte) As String
    hhex = Hex(b)
    If Len(hhex) = 1 Then hhex = "0" & hhex
End Function

Function rpad(x, i, Optional c = " ")
    rpad = Left(x & String(i, c), i)
End Function

Function lbCopy(lstBox As Object) As String
    
    Dim i As Long
    Dim tmp() As String
    
    For i = 0 To lstBox.ListCount
        push tmp, lstBox.List(i)
    Next
    
    lbCopy = Join(tmp, vbCrLf)
    
End Function

