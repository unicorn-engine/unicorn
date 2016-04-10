{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.Arm
Description : Definitions for the ARM architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the ARM architecture.
-}
module Unicorn.CPU.Arm (
    Register(..),
) where

import Unicorn.Internal.Core (Reg)

{# context lib="unicorn" #}

#include <unicorn/arm.h>

-- | ARM registers.
{# enum uc_arm_reg as Register
    {underscoreToCase}
    omit (UC_ARM_REG_INVALID,
          UC_ARM_REG_ENDING)
    with prefix="UC_ARM_REG_"
    deriving (Show, Eq, Bounded) #}

instance Reg Register
