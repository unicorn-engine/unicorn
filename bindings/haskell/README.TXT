This documentation explains how to install Haskell binding for Unicorn
from source.


0. Install the core engine as dependency

   Follow README in the root directory to compile & install the core.

   On *nix, this can simply be done by (project root directory):

        $ sudo ./make.sh install


1. Change directories into the Haskell bindings, build and install

    $ cd bindings/haskell
    $ cabal install


If you are installing into a sandbox, run `cabal sandbox init` before
installing Unicorn's dependencies.

If the build fails, install c2hs manually `cabal install c2hs` (note that this
will probably also require you to run `cabal install alex` and `cabal install
happy` as well). If you are NOT using a sandbox, ensure that `$HOME/.cabal/bin`
is on your PATH.

To build a sample (after having built and installed the Haskell bindings)

    $ cd bindings/haskell
    $ ghc --make samples/SampleArm.hs
