This documentation explains how to install the python binding for Unicorn
from source.

1. Installing on Linux:

	$ sudo python setup.py install

	This will build the core C library, package it with the python bindings, 
	and install it to your system.

    If you want to prevent the build of the native library during the python installation,
    set the environment variable LIBUNICORN_PATH. You may also set this to a directory
    containing libunicorn.so if you wish to use a verison of the native library other than
    the globally installed one.


2. Installing on Windows:

	Run the following command in command prompt:

		C:\> C:\location_to_python\python.exe setup.py install

	Next, copy all the DLL files from the 'Core engine for Windows' package available
	on the Unicorn download page and paste it in the path:

		C:\location_to_python\Lib\site-packages\unicorn\


3. Sample code

	This directory contains some sample code to show how to use Unicorn API.

	- sample_<arch>.py
	  These code show how to access architecture-specific information for each
	  architecture.

	- shellcode.py
	  This shows how to analyze a Linux shellcode.

	- sample_network_auditing.py
	  This shows how to analyze & interpret Linux shellcode.
