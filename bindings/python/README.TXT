This documentation explains how to install Python binding for Unicorn
from source.


0. Install the core engine as dependency

   Follow README in the root directory to compile & install the core.

   On *nix, this can simply be done by (project root directory):

        $ sudo ./make.sh install


1. To install pure Python binding on *nix, run the command below in the Python bindings directory:

		$ sudo make install

  To install Python3 binding package, run the command below:
  (Note: this requires python3 installed in your machine)

		$ sudo make install3



This directory contains some sample code to show how to use Unicorn API.

- sample_<arch>.py
  These code show how to access architecture-specific information for each
  architecture.

- shellcode.py
  This shows how to analyze a Linux shellcode.

- sample_network_auditing.py
  This shows how to analyze & interpret Linux shellcode.


2. To install Python binding on Windows:

	Run the following command in command prompt:

		C:\> C:\location_to_python\python.exe setup.py install

	Next, copy all the DLL files from the 'Core engine for Windows' package available
	on the same Unicorn download page and paste it in the path:

		C:\location_to_python\Lib\site-packages\unicorn\
