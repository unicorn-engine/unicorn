VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CMemRegion"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
'this is for 32bit address space..
Public address As Long
Public size As Long
Public endsAt As Long
Public perm As Long

Function toString() As String
    toString = "Addr: " & Hex(address) & " Size: " & Hex(size) & " Perm: " & permToString() & " (" & Hex(perm) & ")"
End Function

'Public Enum uc_prot
'    UC_PROT_NONE = 0
'    UC_PROT_READ = 1
'    UC_PROT_WRITE = 2
'    UC_PROT_EXEC = 4
'    UC_PROT_ALL = 7
'End Enum

Function permToString() As String
    
    If perm = 7 Then
        permToString = "All"
        Exit Function
    End If
    
    If perm = 0 Then
        permToString = "None"
        Exit Function
    End If
    
    If (perm And 1) = 1 Then permToString = "Read "
    If (perm And 2) = 2 Then permToString = permToString & "Write "
    If (perm And 4) = 4 Then permToString = permToString & "Exec"
    
    permToString = Trim(permToString)
    
End Function
