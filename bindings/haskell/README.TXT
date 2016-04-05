This documentation explains how to install Haskell binding for Unicorn
from source.


0. Install the core engine as dependency

   Follow README in the root directory to compile & install the core.

   On *nix, this can simply be done by (project root directory):

        $ sudo ./make.sh install


1. Change directories into the Haskell bindings, build and install

    $ cd bindings/haskell
    $ cabal build
    $ cabal install

If the build fails, try installing c2hs manually (cabal install c2hs) and make
sure that $HOME/.cabal/bin is on your PATH.
