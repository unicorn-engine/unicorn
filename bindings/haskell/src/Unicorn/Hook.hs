{-|
Module      : Unicorn.Hook
Description : Unicorn hooks.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Insert hook points into the Unicorn emulator engine.
-}
module Unicorn.Hook (
    -- * Hook types
    Hook,
    MemoryHookType(..),
    MemoryEventHookType(..),
    MemoryAccess(..),

    -- * Hook callbacks
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

    -- * Hook callback management
    codeHookAdd,
    interruptHookAdd,
    blockHookAdd,
    inHookAdd,
    outHookAdd,
    syscallHookAdd,
    memoryHookAdd,
    memoryEventHookAdd,
    hookDel,
) where

import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.Trans.Either (hoistEither, left, right)
import Foreign

import Unicorn.Internal.Core
import Unicorn.Internal.Hook
import qualified Unicorn.CPU.X86 as X86

-------------------------------------------------------------------------------
-- Hook callback management (registration and deletion)
-------------------------------------------------------------------------------

-- | Register a callback for a code hook event.
codeHookAdd :: Storable a
            => Engine           -- ^ 'Unicorn' engine handle
            -> CodeHook a       -- ^ Code hook callback
            -> a                -- ^ User-defined data. This will be passed to
                                -- the callback function
            -> Word64           -- ^ Start address
            -> Word64           -- ^ End address
            -> Emulator Hook    -- ^ The hook handle on success, or an 'Error'
                                -- on failure
codeHookAdd uc callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalCodeHook callback
        getResult $ ucHookAdd uc HookCode funPtr userDataPtr begin end
    hoistEither result

-- | Register a callback for an interrupt hook event.
interruptHookAdd :: Storable a
                 => Engine          -- ^ 'Unicorn' engine handle
                 -> InterruptHook a -- ^ Interrupt callback
                 -> a               -- ^ User-defined data. This will be passed
                                    -- to the callback function
                 -> Word64          -- ^ Start address
                 -> Word64          -- ^ End address
                 -> Emulator Hook   -- ^ The hook handle on success, or 'Error'
                                    -- on failure
interruptHookAdd uc callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalInterruptHook callback
        getResult $ ucHookAdd uc HookIntr funPtr userDataPtr begin end
    hoistEither result

-- | Register a callback for a block hook event.
blockHookAdd :: Storable a
             => Engine          -- ^ 'Unicorn' engine handle
             -> BlockHook a     -- ^ Block callback
             -> a               -- ^ User-defined data. This will be passed to
                                -- the callback function
             -> Word64          -- ^ Start address
             -> Word64          -- ^ End address
             -> Emulator Hook   -- ^ The hook handle on success, or an 'Error'
                                -- on failure
blockHookAdd uc callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalBlockHook callback
        getResult $ ucHookAdd uc HookBlock funPtr userDataPtr begin end
    hoistEither result

-- | Register a callback for an IN instruction hook event (X86).
inHookAdd :: Storable a
          => Engine         -- ^ 'Unicorn' engine handle
          -> InHook a       -- ^ IN instruction callback
          -> a              -- ^ User-defined data. This will be passed to the
                            -- callback function
          -> Word64         -- ^ Start address
          -> Word64         -- ^ End address
          -> Emulator Hook  -- ^ The hook handle on success, or an 'Error' on
                            -- failure
inHookAdd uc callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalInHook callback
        getResult $ ucInsnHookAdd uc HookInsn funPtr userDataPtr begin end
                                  X86.In
    hoistEither result

-- | Register a callback for an OUT instruction hook event (X86).
outHookAdd :: Storable a
           => Engine        -- ^ 'Unicorn' engine handle
           -> OutHook a     -- ^ OUT instruction callback
           -> a             -- ^ User-defined data. This will be passed to the
                            -- callback function
           -> Word64        -- ^ Start address
           -> Word64        -- ^ End address
           -> Emulator Hook -- ^ The hook handle on success, or an 'Error' on
                            -- failure
outHookAdd uc callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalOutHook callback
        getResult $ ucInsnHookAdd uc HookInsn funPtr userDataPtr begin end
                                  X86.Out
    hoistEither result

-- | Register a callback for a SYSCALL instruction hook event (X86).
syscallHookAdd :: Storable a
               => Engine        -- ^ 'Unicorn' engine handle
               -> SyscallHook a -- ^ SYSCALL instruction callback
               -> a             -- ^ User-defined data. This will be passed to
                                -- the callback function
               -> Word64        -- ^ Start address
               -> Word64        -- ^ End address
               -> Emulator Hook -- ^ The hook handle on success, or an 'Error'
                                -- on failure
syscallHookAdd uc callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalSyscallHook callback
        getResult $ ucInsnHookAdd uc HookInsn funPtr userDataPtr begin end
                                  X86.Syscall
    hoistEither result

-- | Register a callback for a valid memory access event.
memoryHookAdd :: Storable a
              => Engine         -- ^ 'Unicorn' engine handle
              -> MemoryHookType -- ^ A valid memory access (e.g. read, write,
                                -- etc.) to trigger the callback on
              -> MemoryHook a   -- ^ Memory access callback
              -> a              -- ^ User-defined data. This will be passed to
                                -- the callback function
              -> Word64         -- ^ Start address
              -> Word64         -- ^ End address
              -> Emulator Hook  -- ^ The hook handle on success, or an 'Error'
                                -- on failure
memoryHookAdd uc memHookType callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalMemoryHook callback
        getResult $ ucHookAdd uc memHookType funPtr userDataPtr begin end
    hoistEither result

-- | Register a callback for an invalid memory access event.
memoryEventHookAdd :: Storable a
                   => Engine                -- ^ 'Unicorn' engine handle
                   -> MemoryEventHookType   -- ^ An invalid memory access (e.g.
                                            -- read, write, etc.) to trigger
                                            -- the callback on
                   -> MemoryEventHook a     -- ^ Invalid memory access callback
                   -> a                     -- ^ User-defined data. This will
                                            -- be passed to the callback
                                            -- function
                   -> Word64                -- ^ Start address
                   -> Word64                -- ^ End address
                   -> Emulator Hook         -- ^ The hook handle on success, or
                                            -- an 'Error' on failure
memoryEventHookAdd uc memEventHookType callback userData begin end = do
    result <- lift . alloca $ \userDataPtr -> do
        poke userDataPtr userData
        funPtr <- marshalMemoryEventHook callback
        getResult $ ucHookAdd uc memEventHookType funPtr userDataPtr begin end
    hoistEither result

-- | Unregister (remove) a hook callback.
hookDel :: Engine       -- ^ 'Unicorn' engine handle
        -> Hook         -- ^ 'Hook' handle
        -> Emulator ()  -- ^ 'ErrOk' on success, or other value on failure
hookDel uc hook = do
    err <- lift $ ucHookDel uc hook
    if err == ErrOk then
        right ()
    else
        left err

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------

-- Takes the tuple returned by `ucHookAdd`, an IO (Error, Hook), and
-- returns either a `Right Hook` if no error occurred or a `Left Error` if an
-- error occurred
getResult :: IO (Error, Hook) -> IO (Either Error Hook)
getResult =
    liftM (uncurry checkResult)
    where checkResult err hook =
            if err == ErrOk then
                Right hook
            else
                Left err
