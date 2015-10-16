(*

.NET bindings for the UnicornEngine Emulator Engine

Copyright(c) 2015 Antonio Parata

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*)

namespace UnicornEngine

open System
open System.Threading
open System.Collections.Generic
open System.Runtime.InteropServices
open UnicornEngine.Const

// exported hooks
type CodeHook = delegate of Unicorn * UInt64 * Int32 * Object -> unit
and BlockHook = delegate of Unicorn * UInt64 * Int32 * Object -> unit
and InterruptHook = delegate of Unicorn * Int32 * Object -> unit
and MemReadHook = delegate of Unicorn * UInt64 * Int32 * Object -> unit
and MemWriteHook = delegate of Unicorn * UInt64 * Int32 * UInt64 * Object -> unit
and EventMemHook = delegate of Unicorn * UInt64 * Int32 * UInt64 * Object -> unit
and InHook = delegate of Unicorn * Int32 * Int32 * Object -> unit
and OutHook = delegate of Unicorn * Int32 * Int32 * Int32 * Object -> unit
and SyscallHook = delegate of Unicorn * Object -> unit

// the managed unicorn engine
and Unicorn(arch: Int32, mode: Int32) = 

    // hook callback list
    let _codeHooks = new Dictionary<IntPtr, (CodeHook * Object)>()
    let _blockHooks = new Dictionary<IntPtr, (BlockHook * Object)>()
    let _interruptHooks = new Dictionary<IntPtr, (InterruptHook * Object)>()
    let _memReadHooks = new Dictionary<IntPtr, (MemReadHook * Object)>()
    let _memWriteHooks = new Dictionary<IntPtr, (MemWriteHook * Object)>()
    let _memEventHooks = new Dictionary<IntPtr, (EventMemHook * Object)>()
    let _inHooks = new Dictionary<IntPtr, (InHook * Object)>()
    let _outHooks = new Dictionary<IntPtr, (OutHook * Object)>()
    let _syscallHooks = new Dictionary<IntPtr, (SyscallHook * Object)>()

    let mutable _eng = [|UIntPtr.Zero|]

    let checkResult(errCode: Int32, errMsg: String) =
        if errCode <> Common.UC_ERR_OK then raise(ApplicationException(String.Format("{0}. Error: {1}", errMsg, errCode)))
    
    let getId =
        let counter = ref 0
        fun () -> new IntPtr(Interlocked.Increment(counter))

    let hookDel(callbacks: Dictionary<IntPtr, 'a * Object>) (callback: 'a)=
        // TODO: invoke the native function in order to not call the trampoline anymore
        callbacks.Keys
        |> Seq.tryFind(fun k -> match callbacks.[k] with | (c, _) -> c = callback)
        |> (fun k -> if k.IsSome then callbacks.Remove(k.Value) |> ignore)
            
    do
        let mem = Marshal.AllocHGlobal(IntPtr.Size)
        _eng <- [|new UIntPtr(mem.ToPointer())|]
        let err = NativeUnicornEngine.uc_open(uint32 arch, uint32 mode, _eng)
        checkResult(err, "Unable to open the Unicorn Engine")

    member private this.CheckResult(errorCode: Int32) =
        // return the exception instead of raising it in order to have a more meaningful stack trace
        if errorCode <> Common.UC_ERR_OK then
            let errorMessage = this.StrError(errorCode)
            Some <| UnicornEngineException(errorCode, errorMessage)
        else None

    member this.MemMap(address: UInt64, size: UIntPtr, perm: Int32) =
        match NativeUnicornEngine.mem_map(_eng.[0], address, size, uint32 perm) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.MemWrite(address: UInt64, value: Byte array) =
        match NativeUnicornEngine.mem_write(_eng.[0], address, value, new UIntPtr(uint32 value.Length)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.MemRead(address: UInt64, memValue: Byte array) =
        match NativeUnicornEngine.mem_read(_eng.[0], address, memValue, new UIntPtr(uint32 memValue.Length)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.RegWrite(regId: Int32, value: Byte array) =
        match NativeUnicornEngine.reg_write(_eng.[0], regId, value) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.RegRead(regId: Int32, regValue: Byte array) =
        match NativeUnicornEngine.reg_read(_eng.[0], regId, regValue) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.EmuStart(beginAddr: UInt64, untilAddr: UInt64, timeout: UInt64, count: UIntPtr) =
        match NativeUnicornEngine.emu_start(_eng.[0], beginAddr, untilAddr, timeout, count) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.EmuStop() =
        match NativeUnicornEngine.emu_stop(_eng.[0]) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.Close() =
        match NativeUnicornEngine.close(_eng.[0]) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.ArchSupported(arch: Int32) =
        NativeUnicornEngine.arch_supported(arch)

    member this.ErrNo() =
        NativeUnicornEngine.errno(_eng.[0])

    member this.StrError(errorNo: Int32) =
        let errorStringPointer = NativeUnicornEngine.strerror(errorNo)
        Marshal.PtrToStringAnsi(errorStringPointer)

    member this.AddCodeHook(callback: CodeHook, userData: Object, beginAdd: UInt64, endAddr: UInt64) =   
        let trampoline(u: IntPtr) (addr: UInt64) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _codeHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, userData)
        
        let id = getId()
        _codeHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new CodeHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0_arg1(_eng.[0], hh, Common.UC_HOOK_CODE, new UIntPtr(funcPointer.ToPointer()), id, beginAdd, endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: CodeHook) =
        hookDel _codeHooks callback

    member this.AddBlockHook(callback: BlockHook, userData: Object, beginAdd: UInt64, endAddr: UInt64) =   
        let trampoline(u: IntPtr) (addr: UInt64) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _blockHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, userData)

        let id = getId()
        _blockHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new BlockHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0_arg1(_eng.[0], hh, Common.UC_HOOK_BLOCK, new UIntPtr(funcPointer.ToPointer()), id, beginAdd, endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: BlockHook) =
        hookDel _blockHooks callback

    member this.AddInterruptHook(callback: InterruptHook, userData: Object) =   
        let trampoline(u: IntPtr) (intNumber: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _interruptHooks.TryGetValue(user)
            if exist then callback.Invoke(this, intNumber, userData)

        let id = getId()
        _interruptHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new InterruptHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_noarg(_eng.[0], hh, Common.UC_HOOK_INTR, new UIntPtr(funcPointer.ToPointer()), id) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: InterruptHook) =
        hookDel _interruptHooks callback

    member this.AddMemReadHook(callback: MemReadHook, userData: Object, beginAdd: UInt64, endAddr: UInt64) =   
        let trampoline(u: IntPtr) (addr: UInt64) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _memReadHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, userData)

        let id = getId()
        _memReadHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new MemReadHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0_arg1(_eng.[0], hh, Common.UC_HOOK_MEM_READ, new UIntPtr(funcPointer.ToPointer()), id, beginAdd, endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: MemReadHook) =
        hookDel _memReadHooks callback

    member this.AddMemWriteHook(callback: MemWriteHook, userData: Object, beginAdd: UInt64, endAddr: UInt64) =   
        let trampoline(u: IntPtr) (addr: UInt64) (size: Int32) (value: UInt64) (user: IntPtr) =
            let (exist, (callback, userData)) = _memWriteHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, value, userData)

        let id = getId()
        _memWriteHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new MemWriteHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0_arg1(_eng.[0], hh, Common.UC_HOOK_MEM_WRITE, new UIntPtr(funcPointer.ToPointer()), id, beginAdd, endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: MemWriteHook) =
        hookDel _memWriteHooks callback

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32, userData: Object) =
        let trampoline(u: IntPtr) (addr: UInt64) (size: Int32) (value: UInt64) (user: IntPtr) =
            let (exist, (callback, userData)) = _memEventHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, value, userData)

        let registEventMemHook(check: Int32) =            
            let id = getId()
            _memEventHooks.Add(id, (callback, userData))

            let funcPointer = Marshal.GetFunctionPointerForDelegate(new EventMemHookInternal(trampoline))
            let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
            match NativeUnicornEngine.hook_add_noarg(_eng.[0], hh, check, new UIntPtr(funcPointer.ToPointer()), id) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        // test all the events types agains the input eventType
        [
            Common.UC_HOOK_MEM_READ_UNMAPPED
            Common.UC_HOOK_MEM_WRITE_UNMAPPED
            Common.UC_HOOK_MEM_FETCH_UNMAPPED
            Common.UC_HOOK_MEM_READ_PROT
            Common.UC_HOOK_MEM_WRITE_PROT
            Common.UC_HOOK_MEM_FETCH_PROT
        ] 
        |> List.filter(fun eventFlag -> eventType &&& eventFlag <> 0)
        |> List.map registEventMemHook
        |> List.rev |> List.head

    member this.HookDel(callback: EventMemHook) =
        hookDel _memEventHooks callback

    member this.AddInHook(callback: InHook, userData: Object) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _inHooks.TryGetValue(user)
            if exist then callback.Invoke(this, port, size, userData)

        let id = getId()
        _inHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new InHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), id, new IntPtr(X86.UC_X86_INS_IN)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddOutHook(callback: OutHook, userData: Object) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (value: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _outHooks.TryGetValue(user)
            if exist then callback.Invoke(this, port, size, value, userData)

        let id = getId()
        _outHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new OutHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), id, new IntPtr(X86.UC_X86_INS_OUT)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddSyscallHook(callback: SyscallHook, userData: Object) =
        let trampoline(u: IntPtr) (user: IntPtr) =
            let (exist, (callback, userData)) = _syscallHooks.TryGetValue(user)
            if exist then callback.Invoke(this, userData)

        let id = getId()
        _syscallHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new SyscallHookInternal(trampoline))
        let hh = new UIntPtr(Marshal.AllocHGlobal(IntPtr.Size).ToPointer())
        match NativeUnicornEngine.hook_add_arg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), id, new IntPtr(X86.UC_X86_INS_SYSCALL)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()
    
    member this.Version() =
        let (major, minor) = (new UIntPtr(), new UIntPtr())
        let combined = NativeUnicornEngine.version(major, minor)
        (major.ToUInt32(), minor.ToUInt32(), combined)
