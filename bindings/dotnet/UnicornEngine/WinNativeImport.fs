namespace UnicornEngine

open System
open System.Runtime.InteropServices

module private WinNativeImport =
    module private Imports =
        [<DllImport("kernel32.dll")>] extern bool GetProcessMitigationPolicy(IntPtr hProcess, uint32 MitigationPolicy, uint32& Buffer, UIntPtr Length)

     let public CheckCFG() =
        let CurrentProcess = IntPtr(-1)
        let CFGFlag = 7u
        let mutable Flags = 0u
        let BufferSize = UIntPtr(uint32 sizeof<uint32>)
        if Imports.GetProcessMitigationPolicy(CurrentProcess, CFGFlag, &Flags, BufferSize) then
            if (Flags &&& 0x1u) <> 0u then
                raise <| ApplicationException("Control Flow Guard (CFG) is enabled. Unicorn cannot run with CFG enabled.")