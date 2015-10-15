This documentation explains how to use the .NET binding for Unicorn
from source. 

0. Install the core engine as a dependency

   Follow README in the root directory to compile & install the core.

1. Compile the code

	[Windows]
	To compile the code open the UnicornSln.sln with Microsoft Visual 
	Studio 12 or with a newer version and just press Ctrl+Shift+B to build 
	the solution.
	
	You need to have installed at least version 4.5 of the .NET framework.
	
	[Linux]
	TODO
	
2. Usage

	The solution includes the testing project UnicornTests with examples 
	of usage. 
	
	In order to use the library in your project just add a reference to 
	the .NET library and be sure to copy the unmanaged unicorn.dll 
	library in the output directory.

	The naming convention used is the Upper Camel Case, this mean that to 
	invoke the uc_mem_read method you have to search for the MemRead method.
