This documentation explains how to install Python binding for Unicorn
from source. If you want to install it from PyPi package, see the below
docs instead:

   - README.pypi-src: How to compile the Unicorn core & install binding
     at the same time from PyPi package "unicorn"

   - README.pypi-win: How to install binding for Windows from PyPi package
     "unicorn-windows". Note that this package already has prebuilt core
     inside, so no compilation is needed.


0. Install the core engine as dependency

   Follow README in the root directory to compile & install the core.

   On *nix, this can simply done by:

        $ sudo ./make.sh install


1. To install pure Python binding on *nix, run the command below:

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


2. To install Python binding on Windows:

Recommended method:

	Use the Python module installer for 32/64 bit Windows from:

		http://www.unicorn-engine.org/download.html


Manual method:

	If the module installer fails to locate your Python install, or if you have
	additional Python installs (e.g. Anaconda / virtualenv), run the following
	command in command prompt:

		C:\> C:\location_to_python\python.exe setup.py install

	Next, copy unicorn.dll from the 'Core engine for Windows' package available
	on the same Unicorn download page and paste it in the path:

		C:\location_to_python\Lib\site-packages\unicorn\
