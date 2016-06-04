{-# LANGUAGE ForeignFunctionInterface #-}

{-|
Module      : Unicorn.Internal.Core
Description : Core Unicorn components.
Copyright   : (c) Adrian Herrera, 2016
License     : GPL-2

Defines core Unicorn components.

This module should not be directly imported; it is only exposed because of the
way cabal handles ordering of chs files.
-}
module Unicorn.Internal.Core where

import Control.Monad
import Control.Monad.Trans.Either (EitherT)
import Foreign

{# context lib="unicorn" #}

#include <unicorn/unicorn.h>
#include "unicorn_wrapper.h"

-- | The Unicorn engine.
{# pointer *uc_engine as Engine
    foreign finalizer uc_close_wrapper as close
    newtype #}

-- | A pointer to a Unicorn engine.
{# pointer *uc_engine as EnginePtr -> Engine #}

-- | Make a new Unicorn engine out of an engine pointer. The returned Unicorn
-- engine will automatically call 'uc_close_wrapper' when it goes out of scope.
mkEngine :: EnginePtr -> IO Engine
mkEngine ptr =
    liftM Engine (newForeignPtr close ptr)

-- | Errors encountered by the Unicorn API. These values are returned by
-- 'errno'.
{# enum uc_err as Error
    {underscoreToCase}
    with prefix="UC_"
    deriving (Show, Eq, Bounded) #}

-- | The emulator runs in the IO monad and allows for the handling of errors
-- "under the hood".
type Emulator a = EitherT Error IO a

-- | An architecture-dependent register.
class Enum a => Reg a
