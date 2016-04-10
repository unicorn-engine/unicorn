{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.Mk68k
Description : Definitions for the MK68K architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the MK68K architecture.
-}
module Unicorn.CPU.M68k (
    Register(..),
) where

import Unicorn.Internal.Core (Reg)

{# context lib="unicorn" #}

#include <unicorn/m68k.h>

-- | M68K registers.
{# enum uc_m68k_reg as Register
    {underscoreToCase}
    omit (UC_M68K_REG_INVALID,
          UC_M68K_REG_ENDING)
    with prefix="UC_M68K_REG_"
    deriving (Show, Eq, Bounded) #}

instance Reg Register
