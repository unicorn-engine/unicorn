

:: Overview

This documentation explains how to use Unicorn with Microsoft Visual C++ (MSVC).
This will not build the Unicorn Engine itself, it just allows you to use the
prebuilt Windows binaries when writing projects in Microsoft Visual C++.

The prebuilt windows binaries can be found under the "Windows Core engine"
heading on the following page. Be sure to use the 32bit package when making
32bit applications (even in 64bit windows). And use the 64bit package to
build 64bit applications.
http://www.unicorn-engine.org/download/

It is not possible to use the prebuilt static Unicorn library "unicorn.lib"
with Microsoft Visual C++ because it will complain about a bunch of missing
functions, variables etc.

We therefore use the prebuilt dynamic Unicorn library "unicorn.dll".
There are two ways to use this with your Microsoft Visual C++ project:
1) By dynamically linking the dll into your project.
2) By statically linking the dll into your project.

There are pre-prepared sample projects that use each method, but in the event
you wish to set up your own projects there are details to do so below.




:: 1) Dynamic Linking

The files unicorn_dynload.c and unicorn_dynload.h are used for dynamic linking.
Ensure that unicorn_dynload.h is in the main unicorn includes directory.
(It should be in the same directory as "unicorn.h".)
Then include unicorn_dynload.c in your project so that it gets build along
with your other project files. You could alternatively compile it first into a
static library and then link that library into your project.

Now where you would normally include "unicorn.h" in your project you instead
include "unicorn_dynload.h". You should also define DYNLOAD above the include
of "unicorn_dynload.h", or instead add DYNLOAD to your project settings in:
Configuration Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions.

Some example code for including this header is as follows:

#define DYNLOAD	1

#ifdef DYNLOAD
#include <unicorn/unicorn_dynload.h>
#else
#include <unicorn/unicorn.h>
#endif

Now build your application as normal.




:: 2) Static Linking

To perform static linking of unicorn.dll, you need to first generate some
static import libraries. To do this run "make_staload.bat".
You may need to edit the first line in "make_staload.bat" to point to the
location of your "vcvars32.bat" file. This will build separate import libraries
for importing the 32bit or 64bit version of the dlls.
unicorn_staload.lib is used to link to the 32bit version of unicorn.dll.
unicorn_staload64.lib is used to link to the 64bit version of unicorn.dll.

Now you make a unicorn project like usual, including "unicorn.h", and
then you need to also link in "unicorn_staload.lib" or "unicorn_staload64.lib".

The first step to doing this is to make sure the directory that contains
"unicorn_staload.lib" is added to your project by adding it in:
Configuration Properties -> C/C++ -> Linker -> General -> Additional Library Directories
(So for example add here "C:\unicorn\bindings\msvc" if that is where they are)

The second step is to link in the library. You can do this by either adding
this line to your C sourcecode:
#pragma comment(lib, "unicorn_staload.lib")

Or by adding "unicorn_staload.lib" to your project in:
Configuration Properties -> C/C++ -> Linker -> Input -> Additional Dependencies




:: Notes about Visual Studio versions.

These solution and project files were created using Visual Studio 2012.
They should be able to be opened in newer versions of Visual Studio.
For older versions of Visual Studio you could try a little hack of changing
the line in the solution file "samples.sln" from:
	Microsoft Visual Studio Solution File, Format Version 12.00
to
	Microsoft Visual Studio Solution File, Format Version 11.00

Or whatever version number your Visual Studio version uses.
(Hint: Check an existing solution file you have created with your version
 of Visual Studio to know what this value is expected to be.)

Also note that all instructions below are for Visual Studio 2012. So if you
are using a different version then the settings may be located in different
areas or have different names.




:: Building the pre-prepared sample projects

Some sample projects have been included in the bindings\msvc\samples directory.
The solution file in this directory is "samples.sln".
This was created with Visual Studio 2012 and once opened contains 2 projects
"dynload" and "staload".

The "dynload" project is an example of a project that uses dynamic linking.
The "satload" project is an example of a project that uses static linking.

Both projects have 32bit (win32) and 64bit (x64) target platforms.
The 32bit platform (win32) will create a 32bit app that can run on either
32bit or 64bit Windows. The 64bit platform (x64) can only run on 64bit Windows.

All variants can be built at once by using the batch build function:
Go to "Build -> Batch Build" and tick all checkboxes, or at least the ones
that you wish to build. Then click on the Build or Rebuild button.
Note that when building the "staload" projects you must first have built
the static import libraries as mentioned above.




:: Running the pre-prepared sample projects

When running the samples they will need to be able to load the unicorn dlls.

The unicorn dlls required for 32bit apps are:
	libgcc_s_dw2-1.dll
	libglib-2.0-0.dll
	libiconv-2.dll
	libintl-8.dll
	libwinpthread-1.dll
	unicorn.dll

The unicorn dlls required for 64bit apps are:
	libgcc_s_seh-1.dll
	libglib-2.0-0.dll
	libiconv-2.dll
	libintl-8.dll
	libwinpthread-1.dll
	unicorn.dll

Note that while some of the 32bit and 64bit dlls have the same filename,
they are internally different in that they are either 32bit or 64bit files
themselves. So you will have to have separate directories to store them in.
I suggest using directory names such as "unicorn32" and "unicorn64" when
installing the prebuilt windows binaries. This will make it easy to
differentiate between them.

If running the sample exe files from the command line or from Windows Explorer
then you need ensure that the exe file is in the same directory as either the
32bit or 64bit set of dlls.

To run the samples from inside Visual Studio so that you can debug them or just
easily test various changes you should set the working directory to point to a
directory that contains all of the dlls. Assuming you are running a 32bit app
and have the 32bit unicorn dlls in the directory "C:\unicorn32" then do:

1) Go to the Solution Explorer window in Visual Studio.
You can use "View -> Solution Explorer" to get to it.

2) Highlight one or more projects that you want to run/debu from in
Visual Studio. Use hold control when selecting to select multiples,
or hold Shift to select ranges of projects.

3) Right click on the selected projects and go to Properties.

4) Now go to "Configuration Properties -> Debugging -> Working Directory".
Change the value for this to "C:\unicorn32".
You will need to change this for both Debug and Release configurations.
You can change between configurations on the top left of the Property Pages
dialog box that you are currently on.

6) Click OK when done and then you are ready to run or debug the projects.
Do "Debug -> Start Debugging" or press F5 to debug the current project.
Do "Debug -> Start Without Debugging" or press Ctrl+F5 to run the current project.
You can change the current project by right clicking on a project in
Solution Explorer and selecting "Set as StartUp Project"

