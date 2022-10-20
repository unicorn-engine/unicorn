This documentation explains how to use the .NET binding for Unicorn
from source. 

0. Install the core engine as a dependency

   Follow README in the root directory to compile & install the core.

1. Compile the code

    You need to have at least version 5.0 of .NET installed.

    1. Windows

        To compile the code open the UnicornSln.sln with Microsoft Visual
        Studio 12 or with a newer version and just press Ctrl+Shift+B to build 
        the solution.

    2. Linux

        To compile the code open a terminal in this directory
        and enter the following command to build the solution:
        `dotnet build`
	
2. Usage

	The solution includes the testing project UnicornTests with examples 
	of usage. 
	
	In order to use the library in your project just add a reference to 
	the .NET library and be sure to copy the unmanaged unicorn.dll 
	library in the output directory.

	The naming convention used is the Upper Camel Case, this mean that to 
	invoke the uc_mem_read method you have to search for the MemRead method.
