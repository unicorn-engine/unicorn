{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-|
Module      : Unicorn.Internal.Unicorn
Description : The Unicorn CPU emulator.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Low-level bindings for the Unicorn CPU emulator framework.

This module should not be directly imported; it is only exposed because of the
way cabal handles ordering of chs files.
-}
module Unicorn.Internal.Unicorn (
    -- * Types
    Architecture(..),
    Mode(..),
    MemoryPermission(..),
    MemoryRegion(..),
    QueryType(..),

    -- * Function bindings
    ucOpen,
    ucQuery,
    ucEmuStart,
    ucEmuStop,
    ucRegWrite,
    ucRegRead,
    ucMemWrite,
    ucMemRead,
    ucMemMap,
    ucMemUnmap,
    ucMemProtect,
    ucMemRegions,
    ucVersion,
    ucErrno,
    ucStrerror,
) where

import Foreign
import Foreign.C

import Control.Applicative
import Data.ByteString (ByteString, useAsCStringLen)
import Prelude hiding (until)

import Unicorn.Internal.Util

{# context lib="unicorn" #}

{# import Unicorn.Internal.Core #}

#include <unicorn/unicorn.h>

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | CPU architecture.
{# enum uc_arch as Architecture
    {underscoreToCase}
    with prefix = "UC_"
    deriving (Show, Eq, Bounded) #}

-- | CPU hardware mode.
{# enum uc_mode as Mode
    {underscoreToCase}
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-- | Memory permissions.
{# enum uc_prot as MemoryPermission
    {underscoreToCase}
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-- | Memory region mapped by 'memMap'. Retrieve the list of memory regions with
-- 'memRegions'.
data MemoryRegion = MemoryRegion {
    mrBegin :: Word64,            -- ^ Begin address of the region (inclusive)
    mrEnd   :: Word64,            -- ^ End address of the region (inclusive)
    mrPerms :: [MemoryPermission] -- ^ Memory permissions of the region
}

instance Storable MemoryRegion where
    sizeOf _    = {# sizeof uc_mem_region #}
    alignment _ = {# alignof uc_mem_region #}
    peek p      = MemoryRegion
                    <$> liftA fromIntegral ({# get uc_mem_region->begin #} p)
                    <*> liftA fromIntegral ({# get uc_mem_region->end #} p)
                    <*> liftA expandMemPerms ({# get uc_mem_region->perms #} p)
    poke p mr   = do
        {# set uc_mem_region.begin #} p (fromIntegral $ mrBegin mr)
        {# set uc_mem_region.end #} p (fromIntegral $ mrEnd mr)
        {# set uc_mem_region.perms #} p (combineEnums $ mrPerms mr)

-- | A pointer to a memory region.
{# pointer *uc_mem_region as MemoryRegionPtr -> MemoryRegion #}

-- | Query types for the 'query' API.
{# enum uc_query_type as QueryType
    {underscoreToCase}
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-------------------------------------------------------------------------------
-- Emulator control
-------------------------------------------------------------------------------

{# fun uc_open as ^
    {`Architecture',
     combineEnums `[Mode]',
     alloca- `EnginePtr' peek*}
    -> `Error' #}

{# fun uc_query as ^
    {`Engine',
     `QueryType',
     alloca- `Int' castPtrAndPeek*}
    -> `Error' #}

{# fun uc_emu_start as ^
    {`Engine',
     `Word64',
     `Word64',
     `Int',
     `Int'}
    -> `Error' #}

{# fun uc_emu_stop as ^
    {`Engine'}
    -> `Error' #}

-------------------------------------------------------------------------------
-- Register operations
-------------------------------------------------------------------------------

{# fun uc_reg_write as ^
    `Reg r' =>
    {`Engine',
     enumToNum `r',
     castPtr `Ptr Int64'}
    -> `Error' #}

{# fun uc_reg_read as ^
    `Reg r' =>
    {`Engine',
     enumToNum `r',
     allocaInt64ToVoid- `Int64' castPtrAndPeek*}
    -> `Error' #}

-------------------------------------------------------------------------------
-- Memory operations
-------------------------------------------------------------------------------

{# fun uc_mem_write as ^
    {`Engine',
     `Word64',
     withByteStringLen* `ByteString'&}
    -> `Error' #}

{# fun uc_mem_read as ^
    {`Engine',
     `Word64',
     castPtr `Ptr Word8',
     `Int'}
    -> `Error' #}

{# fun uc_mem_map as ^
    {`Engine',
     `Word64',
     `Int',
     combineEnums `[MemoryPermission]'}
    -> `Error' #}

{# fun uc_mem_unmap as ^
    {`Engine',
     `Word64',
     `Int'}
    -> `Error' #}

{# fun uc_mem_protect as ^
    {`Engine',
     `Word64',
     `Int',
     combineEnums `[MemoryPermission]'}
    -> `Error' #}

{# fun uc_mem_regions as ^
    {`Engine',
     alloca- `MemoryRegionPtr' peek*,
     alloca- `Int' castPtrAndPeek*}
    -> `Error' #}

-------------------------------------------------------------------------------
-- Misc.
-------------------------------------------------------------------------------

{# fun pure unsafe uc_version as ^
    {id `Ptr CUInt',
     id `Ptr CUInt'}
    -> `Int' #}

{# fun unsafe uc_errno as ^
    {`Engine'}
    -> `Error' #}

{# fun pure unsafe uc_strerror as ^
    {`Error'}
    -> `String' #}

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------

expandMemPerms :: (Integral a, Bits a) => a -> [MemoryPermission]
expandMemPerms perms =
    -- Only interested in the 3 least-significant bits
    let maskedPerms = fromIntegral $ perms .&. 0x7 in
    if maskedPerms == 0x0 then
        [ProtNone]
    else if maskedPerms == 0x7 then
        [ProtAll]
    else
        checkRWE maskedPerms [ProtRead, ProtWrite, ProtExec]
    where
        checkRWE p (x:xs) =
            if p .&. (fromEnum x) /= 0 then
                x : checkRWE p xs
            else
                checkRWE p xs
        checkRWE _ [] =
            []

allocaInt64ToVoid :: (Ptr () -> IO b) -> IO b
allocaInt64ToVoid f =
    alloca $ \(ptr :: Ptr Int64) -> poke ptr 0 >> f (castPtr ptr)

withByteStringLen :: ByteString -> ((Ptr (), CULong) -> IO a) -> IO a
withByteStringLen bs f =
    useAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr, fromIntegral len)
