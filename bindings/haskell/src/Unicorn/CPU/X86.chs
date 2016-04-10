{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.X86
Description : Definitions for the X86 architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the X86 architecture.
-}
module Unicorn.CPU.X86 (
    Mmr(..),
    Register(..),
    Instruction(..),
) where

import Control.Applicative
import Data.Word
import Foreign

import Unicorn.Internal.Core (Reg)

{# context lib="unicorn" #}

#include <unicorn/x86.h>

-- | Memory-managemen Register for instructions IDTR, GDTR, LDTR, TR.
-- Borrow from SegmentCache in qemu/target-i386/cpu.h
data Mmr = Mmr {
    mmrSelector :: Word16,  -- ^ Not used by GDTR and IDTR
    mmrBase     :: Word64,  -- ^ Handle 32 or 64 bit CPUs
    mmrLimit    :: Word32,
    mmrFlags    :: Word32   -- ^ Not used by GDTR and IDTR
}

instance Storable Mmr where
    sizeOf _    = {# sizeof uc_x86_mmr #}
    alignment _ = {# alignof uc_x86_mmr #}
    peek p      = Mmr <$> liftA fromIntegral ({# get uc_x86_mmr->selector #} p)
                      <*> liftA fromIntegral ({# get uc_x86_mmr->base #} p)
                      <*> liftA fromIntegral ({# get uc_x86_mmr->limit #} p)
                      <*> liftA fromIntegral ({# get uc_x86_mmr->flags #} p)
    poke p mmr  = do
        {# set uc_x86_mmr.selector #} p (fromIntegral $ mmrSelector mmr)
        {# set uc_x86_mmr.base #} p (fromIntegral $ mmrBase mmr)
        {# set uc_x86_mmr.limit #} p (fromIntegral $ mmrLimit mmr)
        {# set uc_x86_mmr.flags #} p (fromIntegral $ mmrFlags mmr)

-- | X86 registers.
{# enum uc_x86_reg as Register
    {underscoreToCase}
    omit (UC_X86_REG_INVALID,
          UC_X86_REG_ENDING)
    with prefix="UC_X86_REG_"
    deriving (Show, Eq, Bounded) #}

instance Reg Register

-- | X86 instructions.
{# enum uc_x86_insn as Instruction
    {underscoreToCase}
    omit (UC_X86_INS_INVALID,
          UC_X86_INS_ENDING)
    with prefix="UC_X86_INS_"
    deriving (Show, Eq, Bounded) #}
