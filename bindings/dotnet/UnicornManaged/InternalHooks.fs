namespace UnicornManaged

open System
open System.Runtime.InteropServices

// internal hooks to be passed to native Unicorn library
[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal CodeHookInternal = delegate of IntPtr * Int64 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal BlockHookInternal = delegate of IntPtr * Int64 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal InterruptHookInternal = delegate of IntPtr * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal MemReadHookInternal = delegate of IntPtr * Int64 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal MemWriteHookInternal = delegate of IntPtr * Int64 * Int32 * Int64 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal EventMemHookInternal = delegate of IntPtr * Int32 * Int64 * Int32 * Int64 * IntPtr-> Boolean

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal InHookInternal = delegate of IntPtr * Int32 * Int32 * IntPtr -> Int32

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal OutHookInternal = delegate of IntPtr * Int32 * Int32 * Int32 * IntPtr -> unit

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type internal SyscallHookInternal = delegate of IntPtr * IntPtr -> unit