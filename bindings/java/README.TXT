This documentation explains how to install the Java binding for Unicorn
from source.

0. Install the core engine as dependency

   Follow README in the root directory to compile & install the core.

   On *nix, this can simply done by:

        $ sudo ./make.sh install


1. Install a JDK for your platform. When done, make sure the JDK tools
   are in your PATH.

2. Change directories into the java bindings, build and install

   $ cd bindings/java
   $ make
   $ sudo make install
   $ make samples

The samples directory contains some sample code to show how to use Unicorn API.

- Sample_<arch>.java
  These show how to access architecture-specific information for each
  architecture.

- Shellcode.java
  This shows how to analyze a Linux shellcode.

- SampleNetworkAuditing.java
  Unicorn sample for auditing network connection and file handling in shellcode.

