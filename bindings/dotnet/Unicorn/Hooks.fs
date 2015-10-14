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

// internal hooks to be passed to native Unicorn library
[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal CodeHookInternal = delegate of IntPtr * UInt64 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal BlockHookInternal = delegate of IntPtr * UInt64 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal InterruptHookInternal = delegate of IntPtr * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal MemReadHookInternal = delegate of IntPtr * UInt64 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal MemWriteHookInternal = delegate of IntPtr * UInt64 * Int32 * UInt64 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal EventMemHookInternal = delegate of IntPtr * UInt64 * Int32 * UInt64 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal InHookInternal = delegate of IntPtr * Int32 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal OutHookInternal = delegate of IntPtr * Int32 * Int32 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal SyscallHookInternal = delegate of IntPtr * IntPtr -> unit