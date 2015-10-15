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
open System.Runtime.InteropServices

module NativeUnicornEngine =

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
        extern Int32 uc_mem_write(UIntPtr eng, UInt64 address, Byte[] value, UIntPtr size)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_mem_read(UIntPtr eng, UInt64 address, Byte[] value, UIntPtr size)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_reg_write(UIntPtr eng, Int32 regId, Byte[] value)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_reg_read(UIntPtr eng, Int32 regId, Byte[] value)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_emu_start(UIntPtr eng, UInt64 beginAddr, UInt64 untilAddr, UInt64 timeout, UIntPtr count)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_emu_stop(UIntPtr eng)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Boolean uc_arch_supported(Int32 arch)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern Int32 uc_errno(UIntPtr eng)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)>]
        extern IntPtr uc_strerror(Int32 err)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")>]
        extern Int32 uc_hook_add_noarg(UIntPtr eng, UIntPtr hh, Int32 callbackType, UIntPtr callback, IntPtr userData)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")>]
        extern Int32 uc_hook_add_arg0(UIntPtr eng, UIntPtr hh, Int32 callbackType, UIntPtr callback, IntPtr userData, IntPtr arg0)

        [<DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")>]
        extern Int32 uc_hook_add_arg0_arg1(UIntPtr eng, UIntPtr hh, Int32 callbackType, UIntPtr callback, IntPtr userData, UInt64 arg0, UInt64 arg1)
            
    // by using a mutables variables it is easier to create testing code
    let mutable version = fun(major, minor) -> Imported.uc_version(major, minor)
    let mutable uc_open = fun(arch, mode, uc) ->  Imported.uc_open(arch, mode, uc)
    let mutable close = fun(eng) ->  Imported.uc_close(eng)
    let mutable mem_map = fun(eng, adress, size, perm) -> Imported.uc_mem_map(eng, adress, size, perm)
    let mutable mem_write = fun(eng, adress, value, size) -> Imported.uc_mem_write(eng, adress, value, size)
    let mutable mem_read = fun(eng, adress, value, size) -> Imported.uc_mem_read(eng, adress, value, size)
    let mutable reg_write = fun(eng, regId, value) -> Imported.uc_reg_write(eng, regId, value)
    let mutable reg_read = fun(eng, regId, value) -> Imported.uc_reg_read(eng, regId, value)
    let mutable emu_start = fun(eng, beginAddr, untilAddr, timeout, count) -> Imported.uc_emu_start(eng, beginAddr, untilAddr, timeout, count)
    let mutable emu_stop = fun(eng) -> Imported.uc_emu_stop(eng)
    let mutable arch_supported = fun(arch) -> Imported.uc_arch_supported(arch)
    let mutable errno = fun(eng) -> Imported.uc_errno(eng)
    let mutable strerror = fun(err) -> Imported.uc_strerror(err)
    let mutable hook_add_noarg = fun(eng, hh, callbackType, callback, userData) -> Imported.uc_hook_add_noarg(eng, hh, callbackType, callback, userData)
    let mutable hook_add_arg0 = fun(eng, hh, callbackType, callback, userData, arg0) -> Imported.uc_hook_add_arg0(eng, hh, callbackType, callback, userData, arg0)
    let mutable hook_add_arg0_arg1 = fun(eng, hh, callbackType, callback, userData, arg0, arg1) -> Imported.uc_hook_add_arg0_arg1(eng, hh, callbackType, callback, userData, arg0, arg1)