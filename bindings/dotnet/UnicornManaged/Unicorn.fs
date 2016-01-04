namespace UnicornManaged
    
open System
open System.Threading
open System.Collections.Generic
open System.Runtime.InteropServices
open UnicornManaged.Const
open UnicornManaged.Binding

// exported hooks
type CodeHook = delegate of Unicorn * Int64 * Int32 * Object -> unit
and BlockHook = delegate of Unicorn * Int64 * Int32 * Object -> unit
and InterruptHook = delegate of Unicorn * Int32 * Object -> unit
and MemReadHook = delegate of Unicorn * Int64 * Int32 * Object -> unit
and MemWriteHook = delegate of Unicorn * Int64 * Int32 * Int64 * Object -> unit
and EventMemHook = delegate of Unicorn * Int64 * Int32 * Int64 * Object -> unit
and InHook = delegate of Unicorn * Int32 * Int32 * Object -> unit
and OutHook = delegate of Unicorn * Int32 * Int32 * Int32 * Object -> unit
and SyscallHook = delegate of Unicorn * Object -> unit

// the managed unicorn engine
and Unicorn(arch: Int32, mode: Int32, binding: IBinding) = 

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
    let _disposablePointers = new List<nativeint>()

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
       
    let allocate(size: Int32) =
        let mem = Marshal.AllocHGlobal(size)
        _disposablePointers.Add(mem)
        mem.ToPointer()

    do  
        _eng <- [|new UIntPtr(allocate(IntPtr.Size))|]
        let err = binding.UcOpen(uint32 arch, uint32 mode, _eng)
        checkResult(err, "Unable to open the Unicorn Engine")

    new(arch, mode) = new Unicorn(arch, mode, BindingFactory.getDefault())
    
    member private this.CheckResult(errorCode: Int32) =
        // return the exception instead of raising it in order to have a more meaningful stack trace
        if errorCode <> Common.UC_ERR_OK then
            let errorMessage = this.StrError(errorCode)
            Some <| UnicornEngineException(errorCode, errorMessage)
        else None

    member this.MemMap(address: Int64, size: Int64, perm: Int32) =
        let size = new UIntPtr(uint64 size)
        match binding.MemMap(_eng.[0], uint64 address, size, uint32 perm) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.MemMapPtr(address: Int64, size: Int64, perm: Int32, ptr: IntPtr) =
        let size = new UIntPtr(uint64 size)
        let ptr = new UIntPtr(ptr.ToPointer())
        match binding.MemMapPtr(_eng.[0], uint64 address, size, uint32 perm, ptr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()   
        
    member this.MemUnmap(address: Int64, size: Int64) =
        let size = new UIntPtr(uint64 size)
        match binding.MemUnmap(_eng.[0], uint64 address, size) |> this.CheckResult with 
        | Some e -> raise e | None -> ()   

    member this.MemProtect(address: Int64, size: Int64, ?perm: Int32) =
        let size = new UIntPtr(uint64 size)
        let perm = defaultArg perm Common.UC_PROT_ALL
        match binding.MemProtect(_eng.[0], uint64 address, size, uint32 perm) |> this.CheckResult with 
        | Some e -> raise e | None -> ()   
        
    member this.MemWrite(address: Int64, value: Byte array) =
        match binding.MemWrite(_eng.[0], uint64 address, value, new UIntPtr(uint32 value.Length)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.MemRead(address: Int64, memValue: Byte array) =
        match binding.MemRead(_eng.[0], uint64 address, memValue, new UIntPtr(uint32 memValue.Length)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.RegWrite(regId: Int32, value: Byte array) =
        match binding.RegWrite(_eng.[0], regId, value) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.RegRead(regId: Int32, regValue: Byte array) =
        match binding.RegRead(_eng.[0], regId, regValue) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.EmuStart(beginAddr: Int64, untilAddr: Int64, timeout: Int64, count: Int64) =
        match binding.EmuStart(_eng.[0], uint64 beginAddr, uint64 untilAddr, uint64 timeout, uint64 count) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.EmuStop() =
        match binding.EmuStop(_eng.[0]) |> this.CheckResult with 
        | Some e -> raise e | None -> ()
        
    member this.Close() =
        match binding.Close(_eng.[0]) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.ArchSupported(arch: Int32) =
        binding.ArchSupported(arch)

    member this.ErrNo() =
        binding.Errono(_eng.[0])

    member this.StrError(errorNo: Int32) =
        let errorStringPointer = binding.Strerror(errorNo)
        Marshal.PtrToStringAnsi(errorStringPointer)

    member this.AddCodeHook(callback: CodeHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _codeHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, userData)
        
        let id = getId()
        _codeHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new CodeHookInternal(trampoline))        
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_CODE, new UIntPtr(funcPointer.ToPointer()), id, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddCodeHook(callback: CodeHook, beginAddr: Int64, endAddr: Int64) =   
        this.AddCodeHook(callback, null, beginAddr, endAddr)

    member this.HookDel(callback: CodeHook) =
        hookDel _codeHooks callback

    member this.AddBlockHook(callback: BlockHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _blockHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, userData)

        let id = getId()
        _blockHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new BlockHookInternal(trampoline))
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_BLOCK, new UIntPtr(funcPointer.ToPointer()), id, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
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
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_INTR, new UIntPtr(funcPointer.ToPointer()), id) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddInterruptHook(callback: InterruptHook) =
        this.AddInterruptHook(callback, null)

    member this.HookDel(callback: InterruptHook) =
        hookDel _interruptHooks callback

    member this.AddMemReadHook(callback: MemReadHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _memReadHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, userData)

        let id = getId()
        _memReadHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new MemReadHookInternal(trampoline))
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_MEM_READ, new UIntPtr(funcPointer.ToPointer()), id, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: MemReadHook) =
        hookDel _memReadHooks callback

    member this.AddMemWriteHook(callback: MemWriteHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (value: Int64) (user: IntPtr) =
            let (exist, (callback, userData)) = _memWriteHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, value, userData)

        let id = getId()
        _memWriteHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new MemWriteHookInternal(trampoline))
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_MEM_WRITE, new UIntPtr(funcPointer.ToPointer()), id, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.HookDel(callback: MemWriteHook) =
        hookDel _memWriteHooks callback

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32, userData: Object) =
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (value: Int64) (user: IntPtr) =
            let (exist, (callback, userData)) = _memEventHooks.TryGetValue(user)
            if exist then callback.Invoke(this, addr, size, value, userData)

        let registEventMemHook(check: Int32) =            
            let id = getId()
            _memEventHooks.Add(id, (callback, userData))

            let funcPointer = Marshal.GetFunctionPointerForDelegate(new EventMemHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddNoarg(_eng.[0], hh, check, new UIntPtr(funcPointer.ToPointer()), id) |> this.CheckResult with 
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
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), id, new IntPtr(X86.UC_X86_INS_IN)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddOutHook(callback: OutHook, userData: Object) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (value: Int32) (user: IntPtr) =
            let (exist, (callback, userData)) = _outHooks.TryGetValue(user)
            if exist then callback.Invoke(this, port, size, value, userData)

        let id = getId()
        _outHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new OutHookInternal(trampoline))
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), id, new IntPtr(X86.UC_X86_INS_OUT)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddSyscallHook(callback: SyscallHook, userData: Object) =
        let trampoline(u: IntPtr) (user: IntPtr) =
            let (exist, (callback, userData)) = _syscallHooks.TryGetValue(user)
            if exist then callback.Invoke(this, userData)

        let id = getId()
        _syscallHooks.Add(id, (callback, userData))

        let funcPointer = Marshal.GetFunctionPointerForDelegate(new SyscallHookInternal(trampoline))
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), id, new IntPtr(X86.UC_X86_INS_SYSCALL)) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.AddSyscallHook(callback: SyscallHook) =
        this.AddSyscallHook(callback, null)
    
    member this.Version() =
        let (major, minor) = (new UIntPtr(), new UIntPtr())
        let combined = binding.Version(major, minor)
        (major.ToUInt32(), minor.ToUInt32(), combined)

    abstract Dispose : Boolean -> unit
    default this.Dispose(disposing: Boolean) =
        if (disposing) then
            // free managed resources, this is the default dispose implementation pattern
            ()

        _disposablePointers
        |> Seq.filter(fun pointer -> pointer <> IntPtr.Zero)
        |> Seq.iter Marshal.FreeHGlobal
        _disposablePointers.Clear()

    member this.Dispose() =
        this.Dispose(true)
        GC.SuppressFinalize(this)

    override this.Finalize() =
        this.Dispose(false)

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()