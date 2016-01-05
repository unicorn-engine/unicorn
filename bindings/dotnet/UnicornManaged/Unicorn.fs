namespace UnicornManaged
    
open System
open System.Threading
open System.Collections.Generic
open System.Runtime.InteropServices
open System.Linq
open UnicornManaged.Const
open UnicornManaged.Binding

// exported hooks
type CodeHook = delegate of Unicorn * Int64 * Int32 * Object -> unit
and BlockHook = delegate of Unicorn * Int64 * Int32 * Object -> unit
and InterruptHook = delegate of Unicorn * Int32 * Object -> unit
and MemReadHook = delegate of Unicorn * Int64 * Int32 * Object -> unit
and MemWriteHook = delegate of Unicorn * Int64 * Int32 * Int64 * Object -> unit
and EventMemHook = delegate of Unicorn * Int32 * Int64 * Int32 * Int64 * Object -> Boolean
and InHook = delegate of Unicorn * Int32 * Int32 * Object -> Int32
and OutHook = delegate of Unicorn * Int32 * Int32 * Int32 * Object -> unit
and SyscallHook = delegate of Unicorn * Object -> unit

// the managed unicorn engine
and Unicorn(arch: Int32, mode: Int32, binding: IBinding) = 

    // hook callback list
    let _codeHooks = new List<(CodeHook * Object)>()
    let _blockHooks = new List<(BlockHook * Object)>()
    let _interruptHooks = new List<(InterruptHook * Object)>()
    let _memReadHooks = new List<(MemReadHook * Object)>()
    let _memWriteHooks = new List<(MemWriteHook * Object)>()
    let _memEventHooks = new Dictionary<Int32, List<(EventMemHook * Object)>>()
    let _inHooks = new List<(InHook * Object)>()
    let _outHooks = new List<(OutHook * Object)>()
    let _syscallHooks = new List<(SyscallHook * Object)>()
    let _disposablePointers = new List<nativeint>()

    let _eventMemMap =
        [
            (UC_HOOK_MEM_READ_UNMAPPED, UC_MEM_READ_UNMAPPED)
            (UC_HOOK_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_UNMAPPED)
            (UC_HOOK_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_UNMAPPED)
            (UC_HOOK_MEM_READ_PROT, UC_MEM_READ_PROT)
            (UC_HOOK_MEM_WRITE_PROT, UC_MEM_WRITE_PROT)
            (UC_HOOK_MEM_FETCH_PROT, UC_MEM_FETCH_PROT)
        ] |> dict
        
    let mutable _eng = [|UIntPtr.Zero|]
    
    let checkResult(errCode: Int32, errMsg: String) =
        if errCode <> Common.UC_ERR_OK then raise(ApplicationException(String.Format("{0}. Error: {1}", errMsg, errCode)))
    
    let hookDel(callbacks: List<'a * Object>) (callback: 'a)=
        // TODO: invoke the native function in order to not call the trampoline anymore
        callbacks
        |> Seq.tryFind(fun item -> match item with | (c, _) -> c = callback)
        |> (fun k -> if k.IsSome then callbacks.Remove(k.Value) |> ignore)
       
    let allocate(size: Int32) =
        let mem = Marshal.AllocHGlobal(size)
        _disposablePointers.Add(mem)
        mem.ToPointer()

    do  
        // initialize event list
        _eventMemMap
        |> Seq.map(fun kv -> kv.Key)
        |> Seq.iter (fun eventType -> _memEventHooks.Add(eventType, new List<EventMemHook * Object>()))

        // init engine
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

    member this.RegWrite(regId: Int32, value: Int64) =
        this.RegWrite(regId, int64ToBytes value)

    member this.RegRead(regId: Int32, regValue: Byte array) =
        match binding.RegRead(_eng.[0], regId, regValue) |> this.CheckResult with 
        | Some e -> raise e | None -> ()

    member this.RegRead(regId: Int32) =
        let buffer = Array.zeroCreate<Byte> 8
        this.RegRead(regId, buffer)
        bytesToInt64 buffer

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
            _codeHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, addr, size, userData))
        
        if _codeHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new CodeHookInternal(trampoline))        
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_CODE, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _codeHooks.Add(callback, userData)

    member this.AddCodeHook(callback: CodeHook, beginAddr: Int64, endAddr: Int64) =
        this.AddCodeHook(callback, null, beginAddr, endAddr)

    member this.HookDel(callback: CodeHook) =
        hookDel _codeHooks callback

    member this.AddBlockHook(callback: BlockHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            _blockHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, addr, size, userData))

        if _blockHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new BlockHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_BLOCK, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _blockHooks.Add(callback, userData)

    member this.HookDel(callback: BlockHook) =
        hookDel _blockHooks callback

    member this.AddInterruptHook(callback: InterruptHook, userData: Object) =   
        let trampoline(u: IntPtr) (intNumber: Int32) (user: IntPtr) =
            _interruptHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, intNumber, userData))
        
        if _interruptHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new InterruptHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_INTR, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _interruptHooks.Add(callback, userData)

    member this.AddInterruptHook(callback: InterruptHook) =
        this.AddInterruptHook(callback, null)

    member this.HookDel(callback: InterruptHook) =
        hookDel _interruptHooks callback

    member this.AddMemReadHook(callback: MemReadHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            _memReadHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, addr, size, userData))

        if _memReadHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new MemReadHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_MEM_READ, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _memReadHooks.Add(callback, userData)

    member this.HookDel(callback: MemReadHook) =
        hookDel _memReadHooks callback

    member this.AddMemWriteHook(callback: MemWriteHook, userData: Object, beginAddr: Int64, endAddr: Int64) =   
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (value: Int64) (user: IntPtr) =
            _memWriteHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, addr, size, value, userData))
        
        if _memWriteHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new MemWriteHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0Arg1(_eng.[0], hh, Common.UC_HOOK_MEM_WRITE, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _memWriteHooks.Add(callback, userData)

    member this.HookDel(callback: MemWriteHook) =
        hookDel _memWriteHooks callback

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32, userData: Object) =
        let trampoline(u: IntPtr) (eventType: Int32) (addr: Int64) (size: Int32) (value: Int64) (user: IntPtr) =            
            _memEventHooks.Keys
            |> Seq.filter(fun eventFlag -> (eventType &&& eventFlag) <> 0)
            |> Seq.map(fun eventflag -> _memEventHooks.[eventflag])
            |> Seq.concat
            |> Seq.map(fun (callback, userData) -> callback.Invoke(this, eventType, addr, size, value, userData))
            |> Seq.forall id

        // register the event if not already done
        _memEventHooks.Keys
        |> Seq.filter(fun eventFlag -> (eventType &&& eventFlag) <> 0)
        |> Seq.filter(fun eventFlag -> _memEventHooks.[eventFlag] |> Seq.isEmpty)
        |> Seq.iter(fun eventFlag ->
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new EventMemHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))      
            match binding.HookAddNoarg(_eng.[0], hh, eventFlag, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero) |> this.CheckResult with 
            | Some e -> raise e | None -> ()
        )

        // register the callbacks      
        _memEventHooks.Keys
        |> Seq.filter(fun eventFlag -> (eventType &&& eventFlag) <> 0)
        |> Seq.iter(fun eventFlag -> _memEventHooks.[eventFlag].Add((callback, userData)))

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32) =
        this.AddEventMemHook(callback, eventType, null)

    member this.HookDel(callback: EventMemHook) =
        let callbacks = (_memEventHooks.Values |> Seq.concat).ToList()
        hookDel callbacks callback

    member this.AddInHook(callback: InHook, userData: Object) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (user: IntPtr) =
            _inHooks
            |> Seq.map(fun (callback, userData) -> callback.Invoke(this, port, size, userData))
            |> Seq.last
        
        if _inHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new InHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, X86.UC_X86_INS_IN) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _inHooks.Add(callback, userData)

    member this.AddInHook(callback: InHook) =
        this.AddInHook(callback, null)

    member this.AddOutHook(callback: OutHook, userData: Object) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (value: Int32) (user: IntPtr) =
            _outHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, port, size, value, userData))
            
        if _outHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new OutHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, X86.UC_X86_INS_OUT) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _outHooks.Add(callback, userData)

    member this.AddOutHook(callback: OutHook) =
        this.AddOutHook(callback, null)

    member this.AddSyscallHook(callback: SyscallHook, userData: Object) =
        let trampoline(u: IntPtr) (user: IntPtr) =
            _syscallHooks
            |> Seq.iter(fun (callback, userData) -> callback.Invoke(this, userData))
                    
        if _syscallHooks |> Seq.isEmpty then
            let funcPointer = Marshal.GetFunctionPointerForDelegate(new SyscallHookInternal(trampoline))
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, X86.UC_X86_INS_SYSCALL) |> this.CheckResult with 
            | Some e -> raise e | None -> ()

        _syscallHooks.Add(callback, userData)

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