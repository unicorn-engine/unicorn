{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.CPU.Mips
Description : Definitions for the MIPS architecture.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Definitions for the MIPS architecture.
-}
module Unicorn.CPU.Mips
    (
      Register(..)
    ) where

import Unicorn.Internal.Core (Reg)

{# context lib = "unicorn" #}

#include <unicorn/mips.h>

-- | MIPS registers.
{# enum UC_MIPS_REG as Register
   { underscoreToCase
   , UC_MIPS_REG_0  as Reg0g
   , UC_MIPS_REG_1  as Reg1g
   , UC_MIPS_REG_2  as Reg2g
   , UC_MIPS_REG_3  as Reg3g
   , UC_MIPS_REG_4  as Reg4g
   , UC_MIPS_REG_5  as Reg5g
   , UC_MIPS_REG_6  as Reg6g
   , UC_MIPS_REG_7  as Reg7g
   , UC_MIPS_REG_8  as Reg8g
   , UC_MIPS_REG_9  as Reg9g
   , UC_MIPS_REG_10 as Reg10g
   , UC_MIPS_REG_11 as Reg11g
   , UC_MIPS_REG_12 as Reg12g
   , UC_MIPS_REG_13 as Reg13g
   , UC_MIPS_REG_14 as Reg14g
   , UC_MIPS_REG_15 as Reg15g
   , UC_MIPS_REG_16 as Reg16g
   , UC_MIPS_REG_17 as Reg17g
   , UC_MIPS_REG_18 as Reg18g
   , UC_MIPS_REG_19 as Reg19g
   , UC_MIPS_REG_20 as Reg20g
   , UC_MIPS_REG_21 as Reg21g
   , UC_MIPS_REG_22 as Reg22g
   , UC_MIPS_REG_23 as Reg23g
   , UC_MIPS_REG_24 as Reg24g
   , UC_MIPS_REG_25 as Reg25g
   , UC_MIPS_REG_26 as Reg26g
   , UC_MIPS_REG_27 as Reg27g
   , UC_MIPS_REG_28 as Reg28g
   , UC_MIPS_REG_29 as Reg29g
   , UC_MIPS_REG_30 as Reg30g
   , UC_MIPS_REG_31 as Reg31
   }
   omit ( UC_MIPS_REG_INVALID
        , UC_MIPS_REG_ENDING
        )
   with prefix = "UC_MIPS_REG_"
   deriving (Show, Eq, Bounded)
#}

instance Reg Register
