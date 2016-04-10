{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.Internal.Hook
Description : Unicorn hooks.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Low-level bindings for inserting hook points into the Unicorn emulator engine.

This module should not be directly imported; it is only exposed because of the
way cabal handles ordering of chs files.
-}
module Unicorn.Internal.Hook (
    -- * Types
    Hook,
    HookType(..),
    MemoryHookType(..),
    MemoryEventHookType(..),
    MemoryAccess(..),

    -- * Hook callback bindings
    CodeHook,
    InterruptHook,
    BlockHook,
    InHook,
    OutHook,
    SyscallHook,
    MemoryHook,
    MemoryReadHook,
    MemoryWriteHook,
    MemoryEventHook,

    -- * Hook marshalling
    marshalCodeHook,
    marshalInterruptHook,
    marshalBlockHook,
    marshalInHook,
    marshalOutHook,
    marshalSyscallHook,
    marshalMemoryHook,
    marshalMemoryReadHook,
    marshalMemoryWriteHook,
    marshalMemoryEventHook,

    -- * Hook registration and deletion bindings
    ucHookAdd,
    ucInsnHookAdd,
    ucHookDel,
) where

import Control.Monad
import Foreign

import Unicorn.Internal.Util

{# context lib="unicorn" #}

{# import Unicorn.Internal.Core #}
{# import Unicorn.CPU.X86 #}

#include <unicorn/unicorn.h>
#include "unicorn_wrapper.h"

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- When we pass a Unicorn engine to a hook callback, we do not want this engine
-- object to be freed automatically when the callback returns (which is what
-- would typically occur when using a ForeignPtr), because we want to continue
-- using the Unicorn engine outside the callback. To avoid this,
-- unicorn_wrapper.h provides a dummy "close" function that does nothing. When
-- we go to create a Unicorn engine to pass to a callback, we use a pointer to
-- this dummy close function as the finalizer pointer. When the callback
-- returns, the Unicorn engine remains untouched!
--
-- XX Is there a better way to do this?
foreign import ccall "&uc_close_dummy"
    closeDummy :: FunPtr (EnginePtr -> IO ())

mkEngineNC :: EnginePtr -> IO Engine
mkEngineNC ptr =
    liftM Engine (newForeignPtr closeDummy ptr)

-- | A Unicorn hook.
type Hook = {# type uc_hook #}

-- Hook types. These are used internally within this module by the callback
-- registration functions and are not exposed to the user.
--
-- Note that the both valid and invalid memory access hooks are omitted from
-- this enum (and are exposed to the user).
{# enum uc_hook_type as HookType
    {underscoreToCase}
    omit (UC_HOOK_MEM_READ_UNMAPPED,
          UC_HOOK_MEM_WRITE_UNMAPPED,
          UC_HOOK_MEM_FETCH_UNMAPPED,
          UC_HOOK_MEM_READ_PROT,
          UC_HOOK_MEM_WRITE_PROT,
          UC_HOOK_MEM_FETCH_PROT,
          UC_HOOK_MEM_READ,
          UC_HOOK_MEM_WRITE,
          UC_HOOK_MEM_FETCH)
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-- | Memory hook types (for valid memory accesses).
{# enum uc_hook_type as MemoryHookType
    {underscoreToCase}
    omit (UC_HOOK_INTR,
          UC_HOOK_INSN,
          UC_HOOK_CODE,
          UC_HOOK_BLOCK,
          UC_HOOK_MEM_READ_UNMAPPED,
          UC_HOOK_MEM_WRITE_UNMAPPED,
          UC_HOOK_MEM_FETCH_UNMAPPED,
          UC_HOOK_MEM_READ_PROT,
          UC_HOOK_MEM_WRITE_PROT,
          UC_HOOK_MEM_FETCH_PROT)
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-- | Memory event hook types (for invalid memory accesses).
{# enum uc_hook_type as MemoryEventHookType
    {underscoreToCase}
    omit (UC_HOOK_INTR,
          UC_HOOK_INSN,
          UC_HOOK_CODE,
          UC_HOOK_BLOCK,
          UC_HOOK_MEM_READ,
          UC_HOOK_MEM_WRITE,
          UC_HOOK_MEM_FETCH)
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-- | Unify the hook types with a type class
class Enum a => HookTypeC a

instance HookTypeC HookType
instance HookTypeC MemoryHookType
instance HookTypeC MemoryEventHookType

-- | Memory access.
{# enum uc_mem_type as MemoryAccess
    {underscoreToCase}
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-------------------------------------------------------------------------------
-- Hook callbacks
-------------------------------------------------------------------------------

-- | Callback function for tracing code.
type CodeHook a =  Engine       -- ^ 'Unicorn' engine handle
                -> Word64       -- ^ Addres where the code is being executed
                -> Maybe Int    -- ^ Size of machine instruction(s) being
                                -- executed, or 'Nothing' when size is unknown
                -> a            -- ^ User data passed to tracing APIs
                -> IO ()

type CCodeHook =  EnginePtr -> Word64 -> Word32 -> Ptr () -> IO ()

foreign import ccall "wrapper"
    mkCodeHook :: CCodeHook -> IO {# type uc_cb_hookcode_t #}

marshalCodeHook :: Storable a
                => CodeHook a -> IO {# type uc_cb_hookcode_t #}
marshalCodeHook codeHook =
    mkCodeHook $ \ucPtr address size userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        let maybeSize = if size == 0 then Nothing
                        else Just $ fromIntegral size
        codeHook uc address maybeSize userData

-- | Callback function for tracing interrupts.
type InterruptHook a =  Engine  -- ^ 'Unicorn' engine handle
                     -> Int     -- ^ Interrupt number
                     -> a       -- ^ User data passed to tracing APIs
                     -> IO ()

type CInterruptHook = EnginePtr -> Word32 -> Ptr () -> IO ()

foreign import ccall "wrapper"
    mkInterruptHook :: CInterruptHook -> IO {# type uc_cb_hookintr_t #}

marshalInterruptHook :: Storable a
                     => InterruptHook a -> IO {# type uc_cb_hookintr_t #}
marshalInterruptHook interruptHook =
    mkInterruptHook $ \ucPtr intNo userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        interruptHook uc (fromIntegral intNo) userData

-- | Callback function for tracing blocks.
type BlockHook a = CodeHook a

marshalBlockHook :: Storable a
                 => BlockHook a -> IO {# type uc_cb_hookcode_t #}
marshalBlockHook =
    marshalCodeHook

-- | Callback function for tracing IN instructions (X86).
type InHook a =  Engine     -- ^ 'Unicorn' engine handle
              -> Int        -- ^ Port number
              -> Int        -- ^ Data size (1/2/4) to be read from this port
              -> a          -- ^ User data passed to tracing APIs
              -> IO Word32  -- ^ The data read from the port

type CInHook = EnginePtr -> Word32 -> Int32 -> Ptr () -> IO Word32

foreign import ccall "wrapper"
    mkInHook :: CInHook -> IO {# type uc_cb_insn_in_t #}

marshalInHook :: Storable a
              => InHook a -> IO {# type uc_cb_insn_in_t #}
marshalInHook inHook =
    mkInHook $ \ucPtr port size userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        inHook uc (fromIntegral port) (fromIntegral size) userData

-- | Callback function for tracing OUT instructions (X86).
type OutHook a =  Engine    -- ^ 'Unicorn' engine handle
               -> Int       -- ^ Port number
               -> Int       -- ^ Data size (1/2/4) to be written to this port
               -> Int       -- ^ Data value to be written to this port
               -> a         -- ^ User data passed to tracing APIs
               -> IO ()

type COutHook = EnginePtr -> Word32 -> Int32 -> Word32 -> Ptr () -> IO ()

foreign import ccall "wrapper"
    mkOutHook :: COutHook -> IO {# type uc_cb_insn_out_t #}

marshalOutHook :: Storable a
               => OutHook a -> IO {# type uc_cb_insn_out_t #}
marshalOutHook outHook =
    mkOutHook $ \ucPtr port size value userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        outHook uc (fromIntegral port) (fromIntegral size) (fromIntegral value)
                userData

-- | Callback function for tracing SYSCALL instructions (X86).
type SyscallHook a =  Engine    -- ^ 'Unicorn' engine handle
                   -> a         -- ^ User data passed to tracing APIs
                   -> IO ()

type CSyscallHook = Ptr () -> Ptr () -> IO ()

foreign import ccall "wrapper"
    mkSyscallHook :: CSyscallHook -> IO {# type uc_cb_insn_syscall_t #}

marshalSyscallHook :: Storable a
                   => SyscallHook a -> IO {# type uc_cb_insn_syscall_t #}
marshalSyscallHook syscallHook =
    mkSyscallHook $ \ucPtr userDataPtr -> do
        uc <- mkEngineNC $ castPtr ucPtr
        userData <- castPtrAndPeek userDataPtr
        syscallHook uc userData

-- | Callback function for hooking memory operations.
type MemoryHook a =  Engine         -- ^ 'Unicorn' engine handle
                  -> MemoryAccess   -- ^ Memory access; read or write
                  -> Word64         -- ^ Address where the code is being
                                    -- executed
                  -> Int            -- ^ Size of data being read or written
                  -> Maybe Int      -- ^ Value of data being wrriten, or
                                    -- 'Nothing' if read
                  -> a              -- ^ User data passed to tracing APIs
                  -> IO ()

type CMemoryHook =  EnginePtr
                 -> Int32
                 -> Word64
                 -> Int32
                 -> Int64
                 -> Ptr ()
                 -> IO ()

foreign import ccall "wrapper"
    mkMemoryHook :: CMemoryHook -> IO {# type uc_cb_hookmem_t #}

marshalMemoryHook :: Storable a
                  => MemoryHook a -> IO {# type uc_cb_hookmem_t #}
marshalMemoryHook memoryHook =
    mkMemoryHook $ \ucPtr memAccessI address size value userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        let memAccess  = toMemAccess memAccessI
            maybeValue = case memAccess of
                             MemRead  -> Nothing
                             MemWrite -> Just $ fromIntegral value
                             _        -> undefined  -- XX Handle this?
        memoryHook uc memAccess address (fromIntegral size) maybeValue userData

-- | Callback function for hooking memory reads.
type MemoryReadHook a =  Engine -- ^ 'Unicorn' engine handle
                      -> Word64 -- ^ Address where the code is being executed
                      -> Int    -- ^ Size of data being read
                      -> a      -- ^ User data passed to tracing APIs
                      -> IO ()

marshalMemoryReadHook :: Storable a
                      => MemoryReadHook a -> IO {# type uc_cb_hookmem_t #}
marshalMemoryReadHook memoryReadHook =
    mkMemoryHook $ \ucPtr _ address size _ userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        memoryReadHook uc address (fromIntegral size) userData

-- | Callback function for hooking memory writes.
type MemoryWriteHook a =  Engine    -- ^ 'Unicorn' engine handle
                       -> Word64    -- ^ Address where the code is being
                                    -- executed
                       -> Int       -- ^ Size of data being written
                       -> Int       -- ^ Value of data being written
                       -> a         -- ^ User data passed to tracing APIs
                       -> IO ()

marshalMemoryWriteHook :: Storable a
                       => MemoryWriteHook a -> IO {# type uc_cb_hookmem_t #}
marshalMemoryWriteHook memoryWriteHook =
    mkMemoryHook $ \ucPtr _ address size value userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        memoryWriteHook uc address (fromIntegral size) (fromIntegral value)
                        userData

-- | Callback function for handling invalid memory access events.
type MemoryEventHook a =  Engine        -- ^ 'Unicorn' engine handle
                       -> MemoryAccess  -- ^ Memory access; read or write
                       -> Word64        -- ^ Address where the code is being
                                        -- executed
                       -> Int           -- ^ Size of data being read or written
                       -> Maybe Int     -- ^ Value of data being written, or
                                        -- 'Nothing' if read
                       -> a             -- ^ User data passed to tracing APIs
                       -> IO Bool       -- ^ Return 'True' to continue, or
                                        -- 'False' to stop the program (due to
                                        -- invalid memory)

type CMemoryEventHook =  EnginePtr
                      -> Int32
                      -> Word64
                      -> Int32
                      -> Int64
                      -> Ptr ()
                      -> IO Int32

foreign import ccall "wrapper"
    mkMemoryEventHook :: CMemoryEventHook -> IO {# type uc_cb_eventmem_t #}

marshalMemoryEventHook :: Storable a
                       => MemoryEventHook a -> IO {# type uc_cb_eventmem_t #}
marshalMemoryEventHook eventMemoryHook =
    mkMemoryEventHook $ \ucPtr memAccessI address size value userDataPtr -> do
        uc <- mkEngineNC ucPtr
        userData <- castPtrAndPeek userDataPtr
        let memAccess = toMemAccess memAccessI
            maybeValue = case memAccess of
                             MemReadUnmapped  -> Nothing
                             MemReadProt      -> Nothing
                             MemWriteUnmapped -> Just $ fromIntegral value
                             MemWriteProt     -> Just $ fromIntegral value
                             _                -> undefined  -- XX Handle this?
        res <- eventMemoryHook uc memAccess address (fromIntegral size)
                               maybeValue userData
        return $ boolToInt res
    where boolToInt True = 1
          boolToInt False = 0


-------------------------------------------------------------------------------
-- Hook callback registration (and deletion)
-------------------------------------------------------------------------------

{# fun variadic uc_hook_add as ucHookAdd
    `(Storable a, HookTypeC h)' =>
    {`Engine',
     alloca- `Hook' peek*,
     enumToNum `h',
     castFunPtrToPtr `FunPtr b',
     castPtr `Ptr a',
     `Word64',
     `Word64'}
    -> `Error' #}

{# fun variadic uc_hook_add[int] as ucInsnHookAdd
    `(Storable a, HookTypeC h)' =>
    {`Engine',
     alloca- `Hook' peek*,
     enumToNum `h',
     castFunPtrToPtr `FunPtr b',
     castPtr `Ptr a',
     `Word64',
     `Word64',
     enumToNum `Instruction'}
    -> `Error' #}

-- | Unregister (remove) a hook callback.
{# fun uc_hook_del as ^
    {`Engine',
     fromIntegral `Hook'}
    -> `Error' #}

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------

toMemAccess :: Integral a => a -> MemoryAccess
toMemAccess =
    toEnum . fromIntegral
