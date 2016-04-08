{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.Arm64
Description : Definitions for the ARM64 (ARMv8) architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the ARM64 (ARMv8) architecture.
-}
module Unicorn.CPU.Arm64 (
    Register(..),
) where

import Unicorn.Internal.Core (Reg)

{# context lib="unicorn" #}

#include <unicorn/arm64.h>

-- | ARM64 registers.
{# enum uc_arm64_reg as Register
    {underscoreToCase}
    omit (UC_ARM64_REG_INVALID,
          UC_ARM64_REG_ENDING)
    with prefix="UC_ARM64_REG_"
    deriving (Show, Eq, Bounded) #}

instance Reg Register
