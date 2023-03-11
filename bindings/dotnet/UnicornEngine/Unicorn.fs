namespace UnicornEngine

open System
open System.Collections.Generic
open System.Runtime.InteropServices
open System.Linq
open UnicornEngine.Const
open UnicornEngine.Binding

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
    let _codeHooks = new List<(CodeHook * (UIntPtr * Object * Object))>()
    let _blockHooks = new List<(BlockHook * (UIntPtr * Object * Object))>()
    let _interruptHooks = new List<(InterruptHook * (UIntPtr * Object * Object))>()
    let _memReadHooks = new List<(MemReadHook * (UIntPtr * Object * Object))>()
    let _memWriteHooks = new List<(MemWriteHook * (UIntPtr * Object * Object))>()
    let _memEventHooks = new Dictionary<Int32, List<(EventMemHook * (UIntPtr * Object * Object))>>()
    let _inHooks = new List<(InHook * (UIntPtr * Object * Object))>()
    let _outHooks = new List<(OutHook * (UIntPtr * Object * Object))>()
    let _syscallHooks = new List<(SyscallHook * (UIntPtr * Object * Object))>()
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

    let strError(errorNo: Int32) =
        let errorStringPointer = binding.Strerror(errorNo)
        Marshal.PtrToStringAnsi(errorStringPointer)

    let checkResult(errorCode: Int32) =
        // return the exception instead of raising it in order to have a more meaningful stack trace
        if errorCode <> Common.UC_ERR_OK then
            let errorMessage = strError(errorCode)
            Some <| UnicornEngineException(errorCode, errorMessage)
        else None

    let hookDel(callbacks: List<'a * (UIntPtr * Object * Object)>) (callback: 'a)=
        match callbacks |> Seq.tryFind(fun item -> match item with | (c, _) -> c = callback) with
        | Some(item) ->
            let (hh, _, _) = snd item
            match binding.HookDel(_eng.[0], hh) |> checkResult with
            | Some e -> raise e
            | None -> callbacks.Remove(item) |> ignore
        | None -> ()

    let allocate(size: Int32) =
        let mem = Marshal.AllocHGlobal(size)
        _disposablePointers.Add(mem)
        mem.ToPointer()

    do
        // initialize event list
        _eventMemMap
        |> Seq.map(fun kv -> kv.Key)
        |> Seq.iter (fun eventType -> _memEventHooks.Add(eventType, new List<EventMemHook * (UIntPtr * Object * Object)>()))

        // init engine
        _eng <- [|new UIntPtr(allocate(IntPtr.Size))|]
        let err = binding.UcOpen(uint32 arch, uint32 mode, _eng)
        if err <> Common.UC_ERR_OK then
            raise(ApplicationException(String.Format("Unable to open the Unicorn Engine. Error: {0}", err)))

    new(arch, mode) = new Unicorn(arch, mode, BindingFactory.getDefault())

    member this.MemMap(address: Int64, size: Int64, perm: Int32) =
        let size = new UIntPtr(uint64 size)
        match binding.MemMap(_eng.[0], uint64 address, size, uint32 perm) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.MemMapPtr(address: Int64, size: Int64, perm: Int32, ptr: IntPtr) =
        let size = new UIntPtr(uint64 size)
        let ptr = new UIntPtr(ptr.ToPointer())
        match binding.MemMapPtr(_eng.[0], uint64 address, size, uint32 perm, ptr) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.MemUnmap(address: Int64, size: Int64) =
        let size = new UIntPtr(uint64 size)
        match binding.MemUnmap(_eng.[0], uint64 address, size) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.MemProtect(address: Int64, size: Int64, ?perm: Int32) =
        let size = new UIntPtr(uint64 size)
        let perm = defaultArg perm Common.UC_PROT_ALL
        match binding.MemProtect(_eng.[0], uint64 address, size, uint32 perm) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.MemWrite(address: Int64, value: Byte array) =
        match binding.MemWrite(_eng.[0], uint64 address, value, new UIntPtr(uint32 value.Length)) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.MemRead(address: Int64, memValue: Byte array) =
        match binding.MemRead(_eng.[0], uint64 address, memValue, new UIntPtr(uint32 memValue.Length)) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.RegWrite(regId: Int32, value: Byte array) =
        match binding.RegWrite(_eng.[0], regId, value) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.RegWrite(regId: Int32, value: Int64) =
        this.RegWrite(regId, int64ToBytes value)

    member this.RegRead(regId: Int32, regValue: Byte array) =
        match binding.RegRead(_eng.[0], regId, regValue) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.RegRead(regId: Int32) =
        let buffer = Array.zeroCreate<Byte> 8
        this.RegRead(regId, buffer)
        bytesToInt64 buffer

    member this.EmuStart(beginAddr: Int64, untilAddr: Int64, timeout: Int64, count: Int64) =
        match binding.EmuStart(_eng.[0], uint64 beginAddr, uint64 untilAddr, uint64 timeout, uint64 count) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.EmuStop() =
        match binding.EmuStop(_eng.[0]) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.Close() =
        match binding.Close(_eng.[0]) |> checkResult with
        | Some e -> raise e | None -> ()

    member this.ArchSupported(arch: Int32) =
        binding.ArchSupported(arch)

    member this.ErrNo() =
        binding.Errono(_eng.[0])

    member this.AddCodeHook(callback: CodeHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            callback.Invoke(this, addr, size, userData)

        let codeHookInternal = new CodeHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(codeHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_CODE, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _codeHooks.Add(callback, (hh, userData, codeHookInternal))

    member this.AddCodeHook(callback: CodeHook, beginAddr: Int64, endAddr: Int64) =
        this.AddCodeHook(callback, null, beginAddr, endAddr)

    member this.HookDel(callback: CodeHook) =
        hookDel _codeHooks callback

    member this.AddBlockHook(callback: BlockHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (addr: Int64) (size: Int32) (user: IntPtr) =
            callback.Invoke(this, addr, size, userData)

        let blockHookInternal = new BlockHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(blockHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_BLOCK, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _blockHooks.Add(callback, (hh, userData, blockHookInternal))

    member this.HookDel(callback: BlockHook) =
        hookDel _blockHooks callback

    member this.AddInterruptHook(callback: InterruptHook, userData: Object, hookBegin: UInt64, hookEnd : UInt64) =
        let trampoline(u: IntPtr) (intNumber: Int32) (user: IntPtr) =
            callback.Invoke(this, intNumber, userData)

        let interruptHookInternal = new InterruptHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(interruptHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_INTR, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, hookBegin, hookEnd) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _interruptHooks.Add(callback, (hh, userData, interruptHookInternal))

    member this.AddInterruptHook(callback: InterruptHook) =
        this.AddInterruptHook(callback, null, uint64 1, uint64 0)

    member this.HookDel(callback: InterruptHook) =
        hookDel _interruptHooks callback

    member this.AddMemReadHook(callback: MemReadHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (_eventType: Int32) (addr: Int64) (size: Int32) (user: IntPtr) =
            callback.Invoke(this, addr, size, userData)

        let memReadHookInternal = new MemReadHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(memReadHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_MEM_READ, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _memReadHooks.Add(callback, (hh, userData, memReadHookInternal))

    member this.HookDel(callback: MemReadHook) =
        hookDel _memReadHooks callback

    member this.AddMemWriteHook(callback: MemWriteHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (_eventType: Int32) (addr: Int64) (size: Int32) (value: Int64) (user: IntPtr) =
           callback.Invoke(this, addr, size, value, userData)

        let memWriteHookInternal = new MemWriteHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(memWriteHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddNoarg(_eng.[0], hh, Common.UC_HOOK_MEM_WRITE, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _memWriteHooks.Add(callback, (hh, userData, memWriteHookInternal))

    member this.HookDel(callback: MemWriteHook) =
        hookDel _memWriteHooks callback

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (eventType: Int32) (addr: Int64) (size: Int32) (value: Int64) (user: IntPtr) =
            callback.Invoke(this, eventType, addr, size, value, userData)

        // register the event if not already done
        _memEventHooks.Keys
        |> Seq.filter(fun eventFlag -> (eventType &&& eventFlag) <> 0)
        |> Seq.iter(fun eventFlag ->
            let memEventHookInternal = new EventMemHookInternal(trampoline)
            let funcPointer = Marshal.GetFunctionPointerForDelegate(memEventHookInternal)
            let hh = new UIntPtr(allocate(IntPtr.Size))
            match binding.HookAddNoarg(_eng.[0], hh, eventFlag, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr) |> checkResult with
            | Some e -> raise e | None -> ()

            let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
            _memEventHooks.[eventFlag].Add((callback, (hh, userData, memEventHookInternal)))
        )

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32, userData: Object) =
        this.AddEventMemHook(callback, eventType, userData, 1, 0)

    member this.AddEventMemHook(callback: EventMemHook, eventType: Int32) =
        this.AddEventMemHook(callback, eventType, null)

    member this.HookDel(callback: EventMemHook) =
        _memEventHooks.Keys
        |> Seq.iter(fun eventFlag -> hookDel _memEventHooks.[eventFlag] callback)

    member this.AddInHook(callback: InHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (user: IntPtr) =
            callback.Invoke(this, port, size, userData)

        let inHookInternal = new InHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(inHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr, X86.UC_X86_INS_IN) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _inHooks.Add(callback, (hh, userData, inHookInternal))

    member this.AddInHook(callback: InHook, userData: Object) =
        this.AddInHook(callback, userData, 1, 0)

    member this.AddInHook(callback: InHook) =
        this.AddInHook(callback, null)

    member this.HookDel(callback: InHook) =
        hookDel _inHooks callback

    member this.AddOutHook(callback: OutHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (port: Int32) (size: Int32) (value: Int32) (user: IntPtr) =
            callback.Invoke(this, port, size, value, userData)

        let outHookInternal = new OutHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(outHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr, X86.UC_X86_INS_OUT) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _outHooks.Add(callback, (hh, userData, outHookInternal))

    member this.AddOutHook(callback: OutHook, userData: Object) =
        this.AddOutHook(callback, userData, 1, 0)

    member this.AddOutHook(callback: OutHook) =
        this.AddOutHook(callback, null)

     member this.HookDel(callback: OutHook) =
        hookDel _outHooks callback

    member this.AddSyscallHook(callback: SyscallHook, userData: Object, beginAddr: Int64, endAddr: Int64) =
        let trampoline(u: IntPtr) (user: IntPtr) =
            callback.Invoke(this, userData)

        let syscallHookInternal = new SyscallHookInternal(trampoline)
        let funcPointer = Marshal.GetFunctionPointerForDelegate(syscallHookInternal)
        let hh = new UIntPtr(allocate(IntPtr.Size))
        match binding.HookAddArg0(_eng.[0], hh, Common.UC_HOOK_INSN, new UIntPtr(funcPointer.ToPointer()), IntPtr.Zero, uint64 beginAddr, uint64 endAddr, X86.UC_X86_INS_SYSCALL) |> checkResult with
        | Some e -> raise e | None -> ()

        let hh = (unativeint)(Marshal.ReadIntPtr((nativeint)hh))
        _syscallHooks.Add(callback, (hh, userData, syscallHookInternal))

    member this.AddSyscallHook(callback: SyscallHook, userData: Object) =
        this.AddSyscallHook(callback, userData, 1, 0)

    member this.AddSyscallHook(callback: SyscallHook) =
        this.AddSyscallHook(callback, null)

     member this.HookDel(callback: SyscallHook) =
        hookDel _syscallHooks callback

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
