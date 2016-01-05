namespace UnicornManaged.Binding

open System

type IBinding =
    interface
        abstract Version : UIntPtr * UIntPtr -> Int32
        abstract ArchSupported : Int32 -> Boolean
        abstract UcOpen : UInt32 * UInt32 * UIntPtr array -> Int32
        abstract Close : UIntPtr -> Int32
        abstract Strerror : Int32 -> IntPtr
        abstract Errono : UIntPtr -> Int32
        abstract RegRead : UIntPtr * Int32 * Byte array -> Int32
        abstract RegWrite : UIntPtr * Int32 * Byte array -> Int32
        abstract MemRead : UIntPtr * UInt64 * Byte array * UIntPtr -> Int32
        abstract MemWrite : UIntPtr * UInt64 * Byte array * UIntPtr -> Int32
        abstract EmuStart : UIntPtr * UInt64 * UInt64 * UInt64 * UInt64 -> Int32
        abstract EmuStop : UIntPtr -> Int32        
        abstract HookDel : UIntPtr * UIntPtr -> Int32
        abstract MemMap : UIntPtr * UInt64 * UIntPtr * UInt32 -> Int32
        abstract MemMapPtr : UIntPtr * UInt64 * UIntPtr * UInt32 * UIntPtr -> Int32
        abstract MemUnmap : UIntPtr * UInt64 * UIntPtr -> Int32
        abstract MemProtect : UIntPtr * UInt64 * UIntPtr * UInt32 -> Int32
        abstract HookAddNoarg : UIntPtr * UIntPtr * Int32 * UIntPtr * IntPtr -> Int32
        abstract HookAddArg0 : UIntPtr * UIntPtr * Int32 * UIntPtr * IntPtr * Int32 -> Int32
        abstract HookAddArg0Arg1 : UIntPtr * UIntPtr * Int32 * UIntPtr * IntPtr * UInt64 * UInt64 -> Int32
    end

