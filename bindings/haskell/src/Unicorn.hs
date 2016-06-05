{-|
Module      : Unicorn
Description : The Unicorn CPU emulator.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator
framework based on QEMU.

Further information is available at <http://www.unicorn-engine.org>.
-}
module Unicorn (
    -- * Emulator control
    Emulator,
    Engine,
    Architecture(..),
    Mode(..),
    QueryType(..),
    runEmulator,
    open,
    query,
    start,
    stop,

    -- * Register operations
    regWrite,
    regRead,

    -- * Memory operations
    MemoryPermission(..),
    MemoryRegion(..),
    memWrite,
    memRead,
    memMap,
    memUnmap,
    memProtect,
    memRegions,

    -- * Error handling
    Error(..),
    errno,
    strerror,

    -- * Misc.
    version,
) where

import Control.Monad (liftM)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Either (hoistEither, left, right, runEitherT)
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
    runEitherT

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
        left err

-- | Query internal status of the Unicorn engine.
query :: Engine         -- ^ 'Unicorn' engine handle
      -> QueryType      -- ^ Query type
      -> Emulator Int   -- ^ The result of the query
query uc queryType = do
    (err, result) <- lift $ ucQuery uc queryType
    if err == ErrOk then
        right result
    else
        left err

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
        right ()
    else
        left err
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
        right ()
    else
        left err

-------------------------------------------------------------------------------
-- Register operations
-------------------------------------------------------------------------------

-- | Write to register.
regWrite :: Reg r =>
            Engine      -- ^ 'Unicorn' engine handle
         -> r           -- ^ Register ID to write to
         -> Int64       -- ^ Value to write to register
         -> Emulator () -- ^ An 'Error' on failure
regWrite uc regId value = do
    err <- lift . alloca $ \ptr -> do
        poke ptr value
        ucRegWrite uc regId ptr
    if err == ErrOk then
        right ()
    else
        left err

-- | Read register value.
regRead :: Reg r =>
           Engine           -- ^ 'Unicorn' engine handle
        -> r                -- ^ Register ID to read from
        -> Emulator Int64   -- ^ The value read from the register on success,
                            -- or an 'Error' on failure
regRead uc regId = do
    (err, val) <- lift $ ucRegRead uc regId
    if err == ErrOk then
        right val
    else
        left err

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
        right ()
    else
        left err

-- | Read memory contents.
memRead :: Engine                       -- ^ 'Unicorn' engine handle
        -> Word64                       -- ^ Starting memory address to read
                                        -- from
        -> Int                          -- ^ Size of memory to read (in bytes)
        -> Emulator ByteString          -- ^ The memory contents on success, or
                                        -- an 'Error' on failure
memRead uc address size = do
    -- Allocate an array of the given size
    result <- lift . allocaArray size $ \ptr -> do
        err <- ucMemRead uc address ptr size
        if err == ErrOk then
            -- If ucMemRead completed successfully, pack the contents of the
            -- array into a ByteString and return it
            liftM (Right . pack) (peekArray size ptr)
        else
            -- Otherwise return the error
            return $ Left err
    hoistEither result

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
        right ()
    else
        left err

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
        right ()
    else
        left err

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
        right ()
    else
        left err

-- | Retrieve all memory regions mapped by 'memMap'. 
memRegions :: Engine                    -- ^ 'Unicorn' engine handle
           -> Emulator [MemoryRegion]   -- ^ A list of memory regions
memRegions uc = do
    (err, regionPtr, count) <- lift $ ucMemRegions uc
    if err == ErrOk then do
        regions <- lift $ peekArray count regionPtr
        right regions
    else
        left err

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
