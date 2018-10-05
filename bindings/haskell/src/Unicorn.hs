{-|
Module      : Unicorn
Description : The Unicorn CPU emulator.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator
framework based on QEMU.

Further information is available at <http://www.unicorn-engine.org>.
-}
module Unicorn
    ( -- * Emulator control
      Emulator
    , Engine
    , Architecture(..)
    , Mode(..)
    , QueryType(..)
    , runEmulator
    , open
    , query
    , start
    , stop

      -- * Register operations
    , regWrite
    , regRead
    , regWriteBatch
    , regReadBatch

      -- * Memory operations
    , MemoryPermission(..)
    , MemoryRegion(..)
    , memWrite
    , memRead
    , memMap
    , memUnmap
    , memProtect
    , memRegions

      -- * Context operations
    , Context
    , contextAllocate
    , contextSave
    , contextRestore

      -- * Error handling
    , Error(..)
    , errno
    , strerror

      -- * Misc.
    , version
    ) where

import Control.Monad (join, liftM)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (throwE, runExceptT)
import Data.ByteString (ByteString, pack)
import Foreign
import Prelude hiding (until)

import Unicorn.Internal.Core
import Unicorn.Internal.Unicorn

-------------------------------------------------------------------------------
-- Emulator control
-------------------------------------------------------------------------------

-- | Run the Unicorn emulator and return a result on success, or an 'Error' on
-- failure.
runEmulator :: Emulator a           -- ^ The emulation code to execute
            -> IO (Either Error a)  -- ^ A result on success, or an 'Error' on
                                    -- failure
runEmulator =
    runExceptT

-- | Create a new instance of the Unicorn engine.
open :: Architecture    -- ^ CPU architecture
     -> [Mode]          -- ^ CPU hardware mode
     -> Emulator Engine -- ^ A 'Unicorn' engine on success, or an 'Error' on
                        -- failure
open arch mode = do
    (err, ucPtr) <- lift $ ucOpen arch mode
    if err == ErrOk then
        -- Return a pointer to the Unicorn engine if ucOpen completed
        -- successfully
        lift $ mkEngine ucPtr
    else
        -- Otherwise return the error
        throwE err

-- | Query internal status of the Unicorn engine.
query :: Engine         -- ^ 'Unicorn' engine handle
      -> QueryType      -- ^ Query type
      -> Emulator Int   -- ^ The result of the query
query uc queryType = do
    (err, result) <- lift $ ucQuery uc queryType
    if err == ErrOk then
        pure result
    else
        throwE err

-- | Emulate machine code for a specific duration of time.
start :: Engine         -- ^ 'Unicorn' engine handle
      -> Word64         -- ^ Address where emulation starts
      -> Word64         -- ^ Address where emulation stops (i.e. when this
                        -- address is hit)
      -> Maybe Int      -- ^ Optional duration to emulate code (in
                        -- microseconds).
                        -- If 'Nothing' is provided, continue to emulate
                        -- until the code is finished
      -> Maybe Int      -- ^ Optional number of instructions to emulate. If
                        -- 'Nothing' is provided, emulate all the code
                        -- available, until the code is finished
      -> Emulator ()    -- ^ An 'Error' on failure
start uc begin until timeout count = do
    err <- lift $ ucEmuStart uc begin until (maybeZ timeout) (maybeZ count)
    if err == ErrOk then
        pure ()
    else
        throwE err
    where maybeZ = maybe 0 id

-- | Stop emulation (which was started by 'start').
-- This is typically called from callback functions registered by tracing APIs.
--
-- NOTE: For now, this will stop execution only after the current block.
stop :: Engine      -- ^ 'Unicorn' engine handle
     -> Emulator () -- ^ An 'Error' on failure
stop uc = do
    err <- lift $ ucEmuStop uc
    if err == ErrOk then
        pure ()
    else
        throwE err

-------------------------------------------------------------------------------
-- Register operations
-------------------------------------------------------------------------------

-- | Write to register.
regWrite :: Reg r
         => Engine      -- ^ 'Unicorn' engine handle
         -> r           -- ^ Register to write to
         -> Int64       -- ^ Value to write to register
         -> Emulator () -- ^ An 'Error' on failure
regWrite uc reg value = do
    err <- lift $ ucRegWrite uc reg value
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Read register value.
regRead :: Reg r
        => Engine           -- ^ 'Unicorn' engine handle
        -> r                -- ^ Register to read from
        -> Emulator Int64   -- ^ The value read from the register on success,
                            -- or an 'Error' on failure
regRead uc reg = do
    (err, val) <- lift $ ucRegRead uc reg
    if err == ErrOk then
        pure val
    else
        throwE err

-- | Write multiple register values.
regWriteBatch :: Reg r
              => Engine         -- ^ 'Unicorn' engine handle
              -> [r]            -- ^ List of registers to write to
              -> [Int64]        -- ^ List of values to write to the registers
              -> Emulator ()    -- ^ An 'Error' on failure
regWriteBatch uc regs vals = do
    err <- lift $ ucRegWriteBatch uc regs vals (length regs)
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Read multiple register values.
regReadBatch ::  Reg r
             => Engine              -- ^ 'Unicorn' engine handle
             -> [r]                 -- ^ List of registers to read from
             -> Emulator [Int64]    -- ^ A list of register values on success,
                                    -- or an 'Error' on failure
regReadBatch uc regs = do
    -- Allocate an array of the given size
    let size = length regs
    join . lift . allocaArray size $ \array -> do
        err <- ucRegReadBatch uc regs array size
        if err == ErrOk then
            -- If ucRegReadBatch completed successfully, pack the contents of
            -- the array into a list and return it
            liftM pure (peekArray size array)
        else
            -- Otherwise return the error
            return $ throwE err

-------------------------------------------------------------------------------
-- Memory operations
-------------------------------------------------------------------------------

-- | Write to memory.
memWrite :: Engine      -- ^ 'Unicorn' engine handle
         -> Word64      -- ^ Starting memory address of bytes to write
         -> ByteString  -- ^ The data to write
         -> Emulator () -- ^ An 'Error' on failure
memWrite uc address bytes = do
    err <- lift $ ucMemWrite uc address bytes
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Read memory contents.
memRead :: Engine                       -- ^ 'Unicorn' engine handle
        -> Word64                       -- ^ Starting memory address to read
                                        -- from
        -> Int                          -- ^ Size of memory to read (in bytes)
        -> Emulator ByteString          -- ^ The memory contents on success, or
                                        -- an 'Error' on failure
memRead uc address size = do
    -- Allocate an array of the given size
    join . lift . allocaArray size $ \array -> do
        err <- ucMemRead uc address array size
        if err == ErrOk then
            -- If ucMemRead completed successfully, pack the contents of the
            -- array into a ByteString and return it
            liftM (pure . pack) (peekArray size array)
        else
            -- Otherwise return the error
            return $ throwE err

-- | Map a range of memory.
memMap :: Engine                -- ^ 'Unicorn' engine handle
       -> Word64                -- ^ Start address of the new memory region to
                                -- be mapped in. This address must be
                                -- aligned to 4KB, or this will return with
                                -- 'ErrArg' error
       -> Int                   -- ^ Size of the new memory region to be mapped
                                -- in. This size must be a multiple of 4KB, or
                                -- this will return with an 'ErrArg' error
       -> [MemoryPermission]    -- ^ Permissions for the newly mapped region
       -> Emulator ()           -- ^ An 'Error' on failure
memMap uc address size perms = do
    err <- lift $ ucMemMap uc address size perms
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Unmap a range of memory.
memUnmap :: Engine      -- ^ 'Unicorn' engine handle
         -> Word64      -- ^ Start addres of the memory region to be unmapped.
                        -- This address must be aligned to 4KB or this will
                        -- return with an 'ErrArg' error
         -> Int         -- ^ Size of the memory region to be modified. This
                        -- must be a multiple of 4KB, or this will return with
                        -- an 'ErrArg' error
         -> Emulator () -- ^ An 'Error' on failure
memUnmap uc address size = do
    err <- lift $ ucMemUnmap uc address size
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Change permissions on a range of memory.
memProtect :: Engine                -- ^ 'Unicorn' engine handle
           -> Word64                -- ^ Start address of the memory region to
                                    -- modify. This address must be aligned to
                                    -- 4KB, or this will return with an
                                    -- 'ErrArg' error
           -> Int                   -- ^ Size of the memory region to be
                                    -- modified. This size must be a multiple
                                    -- of 4KB, or this will return with an
                                    -- 'ErrArg' error
           -> [MemoryPermission]    -- ^ New permissions for the mapped region
           -> Emulator ()           -- ^ An 'Error' on failure
memProtect uc address size perms = do
    err <- lift $ ucMemProtect uc address size perms
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Retrieve all memory regions mapped by 'memMap'. 
memRegions :: Engine                    -- ^ 'Unicorn' engine handle
           -> Emulator [MemoryRegion]   -- ^ A list of memory regions
memRegions uc = do
    (err, regionPtr, count) <- lift $ ucMemRegions uc
    if err == ErrOk then do
        regions <- lift $ peekArray count regionPtr
        pure regions
    else
        throwE err

-------------------------------------------------------------------------------
-- Context operations
-------------------------------------------------------------------------------

-- | Allocate a region that can be used to perform quick save/rollback of the
-- CPU context, which includes registers and some internal metadata. Contexts
-- may not be shared across engine instances with differing architectures or
-- modes.
contextAllocate :: Engine           -- ^ 'Unicon' engine handle
                -> Emulator Context -- ^ A CPU context
contextAllocate uc = do
    (err, contextPtr) <- lift $ ucContextAlloc uc
    if err == ErrOk then
        -- Return a CPU context if ucContextAlloc completed successfully
        lift $ mkContext contextPtr
    else
        throwE err

-- | Save a copy of the internal CPU context.
contextSave :: Engine       -- ^ 'Unicorn' engine handle
            -> Context      -- ^ A CPU context
            -> Emulator ()  -- ^ An error on failure
contextSave uc context = do
    err <- lift $ ucContextSave uc context
    if err == ErrOk then
        pure ()
    else
        throwE err

-- | Restore the current CPU context from a saved copy.
contextRestore :: Engine        -- ^ 'Unicorn' engine handle
               -> Context       -- ^ A CPU context
               -> Emulator ()   -- ^ An error on failure
contextRestore uc context = do
    err <- lift $ ucContextRestore uc context
    if err == ErrOk then
        pure ()
    else
        throwE err

-------------------------------------------------------------------------------
-- Misc.
-------------------------------------------------------------------------------

-- | Combined API version & major and minor version numbers. Returns a
-- hexadecimal number as (major << 8 | minor), which encodes both major and
-- minor versions.
version :: Int
version =
    ucVersion nullPtr nullPtr

-- | Report the 'Error' of the last failed API call.
errno :: Engine         -- ^ 'Unicorn' engine handle
      -> Emulator Error -- ^ The last 'Error' code
errno =
    lift . ucErrno

-- | Return a string describing the given 'Error'.
strerror :: Error   -- ^ The 'Error' code
         -> String  -- ^ Description of the error code
strerror =
    ucStrerror
