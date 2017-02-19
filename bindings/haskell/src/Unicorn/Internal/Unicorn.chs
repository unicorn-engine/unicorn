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
module Unicorn.Internal.Unicorn
    ( -- * Types
      Architecture(..)
    , Mode(..)
    , MemoryPermission(..)
    , MemoryRegion(..)
    , QueryType(..)
    , Context

      -- * Function bindings
    , ucOpen
    , ucQuery
    , ucEmuStart
    , ucEmuStop
    , ucRegWrite
    , ucRegRead
    , ucRegWriteBatch
    , ucRegReadBatch
    , ucMemWrite
    , ucMemRead
    , ucMemMap
    , ucMemUnmap
    , ucMemProtect
    , ucMemRegions
    , mkContext
    , ucContextAlloc
    , ucContextSave
    , ucContextRestore
    , ucVersion
    , ucErrno
    , ucStrerror
    ) where

import Control.Applicative
import Control.Monad
import Data.ByteString (ByteString, useAsCStringLen)
import Foreign
import Foreign.C
import Prelude hiding (until)

import Unicorn.Internal.Util

{# import Unicorn.Internal.Core #}

{# context lib = "unicorn" #}

#include <unicorn/unicorn.h>
#include "unicorn_wrapper.h"

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | CPU architecture.
{# enum uc_arch as Architecture
   { underscoreToCase }
   with prefix = "UC_"
   deriving (Show, Eq, Bounded)
#}

-- | CPU hardware mode.
{# enum uc_mode as Mode
   { underscoreToCase }
   with prefix = "UC_"
   deriving (Show, Eq, Bounded)
#}

-- | Memory permissions.
{# enum uc_prot as MemoryPermission
   { underscoreToCase }
   with prefix = "UC_"
   deriving (Show, Eq, Bounded)
#}

-- | Memory region mapped by 'memMap'. Retrieve the list of memory regions with
-- 'memRegions'.
data MemoryRegion = MemoryRegion
    {
      mrBegin :: Word64             -- ^ Begin address of the region (inclusive)
    , mrEnd   :: Word64             -- ^ End address of the region (inclusive)
    , mrPerms :: [MemoryPermission] -- ^ Memory permissions of the region
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
   { underscoreToCase }
   with prefix = "UC_"
   deriving (Show, Eq, Bounded)
#}

-- | Opaque storage for CPU context, used with the context functions.
{# pointer *uc_context as Context
   foreign finalizer uc_free_wrapper as memFree
   newtype
#}

-- | A pointer to a CPU context.
{# pointer *uc_context as ContextPtr -> Context #}

-- | Make a CPU context out of a context pointer. The returned CPU context will
-- automatically call 'uc_free' when it goes out of scope.
mkContext :: ContextPtr
          -> IO Context
mkContext ptr =
    liftM Context (newForeignPtr memFree ptr)

-------------------------------------------------------------------------------
-- Emulator control
-------------------------------------------------------------------------------

{# fun uc_open as ^
   { `Architecture'
   , combineEnums `[Mode]'
   , alloca- `EnginePtr' peek*
   } -> `Error'
#}

{# fun uc_query as ^
   { `Engine'
   , `QueryType'
   , alloca- `Int' castPtrAndPeek*
   } -> `Error'
#}

{# fun uc_emu_start as ^
   { `Engine'
   , `Word64'
   , `Word64'
   , `Int'
   , `Int'
   } -> `Error'
#}

{# fun uc_emu_stop as ^
   { `Engine'
   } -> `Error'
#}

-------------------------------------------------------------------------------
-- Register operations
-------------------------------------------------------------------------------

{# fun uc_reg_write_wrapper as ucRegWrite
   `Reg r' =>
   { `Engine'
   , enumToNum `r'
   , withIntegral* `Int64'
   } -> `Error'
#}

{# fun uc_reg_read_wrapper as ucRegRead
   `Reg r' =>
   { `Engine'
   , enumToNum `r'
   , alloca- `Int64' castPtrAndPeek*
   } -> `Error'
#}

{# fun uc_reg_write_batch_wrapper as ucRegWriteBatch
   `Reg r' =>
   { `Engine'
   , withEnums* `[r]'
   , integralListToArray* `[Int64]'
   , `Int'
   } -> `Error'
#}

{# fun uc_reg_read_batch_wrapper as ucRegReadBatch
   `Reg r' =>
   { `Engine'
   , withEnums* `[r]'
   , castPtr `Ptr Int64'
   , `Int'
   } -> `Error'
#}

-------------------------------------------------------------------------------
-- Memory operations
-------------------------------------------------------------------------------

{# fun uc_mem_write as ^
   { `Engine'
   , `Word64'
   , withByteStringLen* `ByteString'&
   } -> `Error'
#}

{# fun uc_mem_read as ^
   { `Engine'
   , `Word64'
   , castPtr `Ptr Word8'
   , `Int'
   } -> `Error'
#}

{# fun uc_mem_map as ^
   { `Engine'
   , `Word64'
   , `Int'
   , combineEnums `[MemoryPermission]'
   } -> `Error'
#}

{# fun uc_mem_unmap as ^
   { `Engine'
   , `Word64'
   , `Int'
   } -> `Error'
#}

{# fun uc_mem_protect as ^
   { `Engine'
   , `Word64'
   , `Int'
   , combineEnums `[MemoryPermission]'
   } -> `Error'
#}

{# fun uc_mem_regions as ^
   { `Engine'
   , alloca- `MemoryRegionPtr' peek*
   , alloca- `Int' castPtrAndPeek*
   } -> `Error'
#}

-------------------------------------------------------------------------------
-- Context
-------------------------------------------------------------------------------

{# fun uc_context_alloc as ^
   { `Engine'
   , alloca- `ContextPtr' peek*
   } -> `Error'
#}

{# fun uc_context_save as ^
   { `Engine'
   , `Context'
   } -> `Error'
#}

{# fun uc_context_restore as ^
   { `Engine'
   , `Context'
   } -> `Error'
#}

-------------------------------------------------------------------------------
-- Misc.
-------------------------------------------------------------------------------

{# fun pure unsafe uc_version as ^
   { id `Ptr CUInt'
   , id `Ptr CUInt'
   } -> `Int'
#}

{# fun unsafe uc_errno as ^
   { `Engine'
   } -> `Error'
#}

{# fun pure unsafe uc_strerror as ^
   { `Error'
   } -> `String'
#}

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------

expandMemPerms :: (Integral a, Bits a)
               => a
               -> [MemoryPermission]
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

withIntegral :: (Integral a, Num b, Storable b)
             => a
             -> (Ptr b -> IO c)
             -> IO c
withIntegral =
    with . fromIntegral

withByteStringLen :: Integral a
                  => ByteString
                  -> ((Ptr (), a) -> IO b)
                  -> IO b
withByteStringLen bs f =
    useAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr, fromIntegral len)

withEnums :: Enum a
          => [a]
          -> (Ptr b -> IO c)
          -> IO c
withEnums l f =
    let ints :: [CInt] = map enumToNum l in
    withArray ints $ \ptr -> f (castPtr ptr)

integralListToArray :: (Integral a, Storable b, Num b)
                    => [a]
                    -> (Ptr b -> IO c)
                    -> IO c
integralListToArray l f =
    let l' = map fromIntegral l in
    withArray l' $ \array -> f array
