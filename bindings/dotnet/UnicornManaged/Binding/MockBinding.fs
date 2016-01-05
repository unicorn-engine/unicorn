namespace UnicornManaged.Binding

open System

module internal MockBinding =
    // by using a mutables variables it is easier to create testing code
    let mutable version = fun(major, minor) -> 0
    let mutable uc_open = fun(arch, mode, uc) ->  0
    let mutable close = fun(eng) ->  0
    let mutable mem_map = fun(eng, adress, size, perm) -> 0
    let mutable mem_map_ptr = fun(eng, address, size, perms, ptr) -> 0
    let mutable mem_unmap = fun(eng, address, size) -> 0
    let mutable mem_protect = fun(eng, address, size, perms) -> 0
    let mutable mem_write = fun(eng, adress, value, size) -> 0
    let mutable mem_read = fun(eng, adress, value, size) -> 0
    let mutable reg_write = fun(eng, regId, value) -> 0
    let mutable reg_read = fun(eng, regId, value) -> 0
    let mutable emu_start = fun(eng, beginAddr, untilAddr, timeout, count) -> 0
    let mutable emu_stop = fun(eng) -> 0
    let mutable hook_del = fun(eng, hook) -> 0
    let mutable arch_supported = fun(arch) -> true
    let mutable errno = fun(eng) -> 0
    let mutable strerror = fun(err) -> new nativeint(0)
    let mutable hook_add_noarg = fun(eng, hh, callbackType, callback, userData) -> 0
    let mutable hook_add_arg0 = fun(eng, hh, callbackType, callback, userData, arg0) -> 0
    let mutable hook_add_arg0_arg1 = fun(eng, hh, callbackType, callback, userData, arg0, arg1) -> 0

    let instance =
        {new IBinding with
            member thi.Version(major, minor) = version(major, minor)
            member thi.UcOpen(arch, mode, uc) = uc_open(arch, mode, uc)
            member thi.Close(eng) = close(eng)
            member thi.MemMap(eng, adress, size, perm) = mem_map(eng, adress, size, perm)
            member thi.MemWrite(eng, adress, value, size) = mem_write(eng, adress, value, size)
            member thi.MemRead(eng, adress, value, size) = mem_read(eng, adress, value, size)
            member thi.RegWrite(eng, regId, value) = reg_write(eng, regId, value)
            member thi.RegRead(eng, regId, value) = reg_read(eng, regId, value)
            member thi.EmuStart(eng, beginAddr, untilAddr, timeout, count) = emu_start(eng, beginAddr, untilAddr, timeout, count)
            member thi.EmuStop(eng) = emu_stop(eng)
            member this.HookDel(eng, hook) = hook_del(eng, hook)
            member thi.ArchSupported(arch) = arch_supported(arch)
            member thi.Errono(eng) = errno(eng)
            member thi.Strerror(err) = strerror(err)
            member this.MemMapPtr(eng, address, size, perms, ptr)  = mem_map_ptr(eng, address, size, perms, ptr)
            member this.MemUnmap(eng, address, size) = mem_unmap(eng, address, size)
            member this.MemProtect(eng, address, size, perms) = mem_protect(eng, address, size, perms)
            member thi.HookAddNoarg(eng, hh, callbackType, callback, userData) = hook_add_noarg(eng, hh, callbackType, callback, userData)
            member thi.HookAddArg0(eng, hh, callbackType, callback, userData, arg0) = hook_add_arg0(eng, hh, callbackType, callback, userData, arg0)
            member thi.HookAddArg0Arg1(eng, hh, callbackType, callback, userData, arg0, arg1) = hook_add_arg0_arg1(eng, hh, callbackType, callback, userData, arg0, arg1)
        }
    
