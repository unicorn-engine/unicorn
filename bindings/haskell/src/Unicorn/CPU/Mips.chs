{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.Mips
Description : Definitions for the MIPS architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the MIPS architecture.
-}
module Unicorn.CPU.Mips (
    Register(..),
) where

import Unicorn.Internal.Core (Reg)

{# context lib="unicorn" #}

#include <unicorn/mips.h>

-- | MIPS registers.
{# enum UC_MIPS_REG as Register
    {underscoreToCase,
     UC_MIPS_REG_0 as Reg0,
     UC_MIPS_REG_1 as Reg1,
     UC_MIPS_REG_2 as Reg2,
     UC_MIPS_REG_3 as Reg3,
     UC_MIPS_REG_4 as Reg4,
     UC_MIPS_REG_5 as Reg5,
     UC_MIPS_REG_6 as Reg6,
     UC_MIPS_REG_7 as Reg7,
     UC_MIPS_REG_8 as Reg8,
     UC_MIPS_REG_9 as Reg9,
     UC_MIPS_REG_10 as Reg10,
     UC_MIPS_REG_11 as Reg11,
     UC_MIPS_REG_12 as Reg12,
     UC_MIPS_REG_13 as Reg13,
     UC_MIPS_REG_14 as Reg14,
     UC_MIPS_REG_15 as Reg15,
     UC_MIPS_REG_16 as Reg16,
     UC_MIPS_REG_17 as Reg17,
     UC_MIPS_REG_18 as Reg18,
     UC_MIPS_REG_19 as Reg19,
     UC_MIPS_REG_20 as Reg20,
     UC_MIPS_REG_21 as Reg21,
     UC_MIPS_REG_22 as Reg22,
     UC_MIPS_REG_23 as Reg23,
     UC_MIPS_REG_24 as Reg24,
     UC_MIPS_REG_25 as Reg25,
     UC_MIPS_REG_26 as Reg26,
     UC_MIPS_REG_27 as Reg27,
     UC_MIPS_REG_28 as Reg28,
     UC_MIPS_REG_29 as Reg29,
     UC_MIPS_REG_30 as Reg30,
     UC_MIPS_REG_31 as Reg31}
    omit (UC_MIPS_REG_INVALID,
          UC_MIPS_REG_ENDING)
    with prefix="UC_MIPS_REG_"
    deriving (Show, Eq, Bounded) #}

instance Reg Register
