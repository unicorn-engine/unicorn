{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.Sparc
Description : Definitions for the SPARC architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the SPARC architecture.
-}
module Unicorn.CPU.Sparc (
    Register(..),
) where

import Unicorn.Internal.Core (Reg)

{# context lib="unicorn" #}

#include <unicorn/sparc.h>

-- | SPARC registers.
{# enum uc_sparc_reg as Register
    {underscoreToCase}
    omit (UC_SPARC_REG_INVALID,
          UC_SPARC_REG_ENDING)
    with prefix="UC_SPARC_REG_"
    deriving (Show, Eq, Bounded) #}

instance Reg Register
