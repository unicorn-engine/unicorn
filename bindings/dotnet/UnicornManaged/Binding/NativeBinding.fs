namespace UnicornManaged.Binding

open System
open System.Runtime.InteropServices

module NativeBinding =

    [<AutoOpen>]
    module private Imported = 

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_version(UIntPtr major, UIntPtr minor)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_open(UInt32 arch, UInt32 mode, UIntPtr[] engine)          

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_close(UIntPtr eng)          

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_map(UIntPtr eng, UInt64 address, UIntPtr size, UInt32 perm)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_map_ptr(UIntPtr eng, UInt64 address, UIntPtr size, UInt32 perm, UIntPtr ptr)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_unmap(UIntPtr eng, UInt64 address, UIntPtr size)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_protect(UIntPtr eng, UInt64 address, UIntPtr size, UInt32 perms)
                
        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_write(UIntPtr eng, UInt64 address, Byte[] value, UIntPtr size)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_read(UIntPtr eng, UInt64 address, Byte[] value, UIntPtr size)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_reg_write(UIntPtr eng, Int32 regId, Byte[] value)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_reg_read(UIntPtr eng, Int32 regId, Byte[] value)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_emu_start(UIntPtr eng, UInt64 beginAddr, UInt64 untilAddr, UInt64 timeout, UInt64 count)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_emu_stop(UIntPtr eng)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_hook_del(UIntPtr eng, UIntPtr hook)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Boolean uc_arch_supported(Int32 arch)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_errno(UIntPtr eng)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern IntPtr uc_strerror(Int32 err)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")>]
        extern Int32 uc_hook_add_noarg(UIntPtr eng, UIntPtr hh, Int32 callbackType, UIntPtr callback, IntPtr userData)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")>]
        extern Int32 uc_hook_add_arg0(UIntPtr eng, UIntPtr hh, Int32 callbackType, UIntPtr callback, IntPtr userData, Int32 arg0)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")>]
        extern Int32 uc_hook_add_arg0_arg1(UIntPtr eng, UIntPtr hh, Int32 callbackType, UIntPtr callback, IntPtr userData, UInt64 arg0, UInt64 arg1)
            
    let instance =
        {new IBinding with
            member thi.Version(major, minor) = uc_version(major, minor)
            member thi.UcOpen(arch, mode, uc) = uc_open(arch, mode, uc)
            member thi.Close(eng) = uc_close(eng)
            member thi.MemMap(eng, adress, size, perm) = uc_mem_map(eng, adress, size, perm)
            member thi.MemWrite(eng, adress, value, size) = uc_mem_write(eng, adress, value, size)
            member thi.MemRead(eng, adress, value, size) = uc_mem_read(eng, adress, value, size)
            member thi.RegWrite(eng, regId, value) = uc_reg_write(eng, regId, value)
            member thi.RegRead(eng, regId, value) = uc_reg_read(eng, regId, value)
            member thi.EmuStart(eng, beginAddr, untilAddr, timeout, count) = uc_emu_start(eng, beginAddr, untilAddr, timeout, count)
            member thi.EmuStop(eng) = uc_emu_stop(eng)
            member this.HookDel(eng, hook) = uc_hook_del(eng, hook)
            member thi.ArchSupported(arch) = uc_arch_supported(arch)
            member thi.Errono(eng) = uc_errno(eng)
            member thi.Strerror(err) = uc_strerror(err)
            member this.MemMapPtr(eng, address, size, perms, ptr)  = uc_mem_map_ptr(eng, address, size, perms, ptr)
            member this.MemUnmap(eng, address, size) = uc_mem_unmap(eng, address, size)
            member this.MemProtect(eng, address, size, perms) = uc_mem_protect(eng, address, size, perms)
            member thi.HookAddNoarg(eng, hh, callbackType, callback, userData) = uc_hook_add_noarg(eng, hh, callbackType, callback, userData)
            member thi.HookAddArg0(eng, hh, callbackType, callback, userData, arg0) = uc_hook_add_arg0(eng, hh, callbackType, callback, userData, arg0)
            member thi.HookAddArg0Arg1(eng, hh, callbackType, callback, userData, arg0, arg1) = uc_hook_add_arg0_arg1(eng, hh, callbackType, callback, userData, arg0, arg1)
        }