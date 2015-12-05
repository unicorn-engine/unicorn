This documentation explains how to use Unicorn with Microsoft Visual C++ (MSVC).
This will not build the Unicorn Engine itself, it just allows you to use the
prebuilt Windows binaries when writing projects in Microsoft Visual C++.

The prebuilt windows binaries can be found under the "Windows Core engine"
heading on the following page. Be sure to use the 32bit package when making
32bit applications (even in 64bit windows). And use the 64bit package to
build 64bit applications.
http://www.unicorn-engine.org/download/



It is not possible to use the prebuilt static Unicorn library, unicorn.lib,
with Microsoft Visual C++ because it will complain about a bunch of missing
functions, variables etc.

We therefore use the prebuilt dynamic Unicorn library, unicorn.dll.
There are two ways to use this with your Microsoft Visual C++ project:
1) By dynamically linking the dll into your project.
2) By statically linking the dll into your project.



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


