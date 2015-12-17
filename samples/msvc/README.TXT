

:: Notes about Visual Studio versions.

These solution and project files were created using Visual Studio 2012.
They should be able to be opened in newer versions of Visual Studio.
For older versions of Visual Studio you could try a little hack of changing
the line in the solution file "msvc.sln" from:
	Microsoft Visual Studio Solution File, Format Version 12.00
to
	Microsoft Visual Studio Solution File, Format Version 11.00

Or whatever version number your Visual Studio version uses.
(Hint: Check an existing solution file you have created with your version
 of Visual Studio to know what this value is expected to be.)

Also note that all instructions below are for Visual Studio 2012. So if you
are using a different version then the settings may be located in different
areas or have different names.




:: Notes about the building the sample projects

The projects have 32bit (win32) and 64bit (x64) target platforms.
The 32bit platform (win32) will create a 32bit app that can run on either
32bit or 64bit Windows. The 64bit platform (x64) can only run on 64bit Windows.

All variants can be built at once by using the batch build function:
Go to "Build -> Batch Build" and tick all checkboxes, or at least the ones
that you wish to build. Then click on the Build or Rebuild button.
Note that when building the "staload" projects you must first have built
the static import libraries as mentioned above.

The samples projects all come preset to be built using dynamic loading of
the unicorn dlls. If you wish to use static loading of the unicorn dlls
then you need see the next section.




:: Using static linking of dlls

It is possible to perform static linking of the unicorn dlls which will
load and import the dlls when the exe file itself is loaded. Personally
I prefer dynamic loading in which you load the dlls in your program code
at runtime. This way if it fails you have the opportunity to display a
more meaning error message. Dynamic loading also gives you more
advanced options for where to load the dll files from.

If you do wish to do static linking of dlls then the following changes
need to be made to each project. Note that multiple projects can be
highlighted and have their settings changed at the one time.

1) First ensure the static linking library has been built.
Run bindings\msvc\make_staload.bat to build these.
You may need to first alter this batch file to point to the correct
location of your "vcvars32.bat" file.
If successful you will now have the files "bindings\msvc\unicorn_staload.lib"
and "bindings\msvc\unicorn_staload64.lib".

2) Go to the Solution Explorer window in Visual Studio.
You can use "View -> Solution Explorer" to get to it.

3) Highlight one or more projects that you want to change to use
static linking. Use hold control when selecting to select multiples,
or hold Shift to select ranges of projects.

4) Right click on the selected projects and go to Properties.

5) Now go to "Configuration Properties -> C/C++ -> Preprocessor ->
Preprocessor Definitions". Remove the DYNLOAD entry and its preceeding
semi-colon. You will need to remove DYNLOAD for both Debug and Release
configurations. You can change between configurations on the top left
of the Property Pages dialog box that you are currently on.

6) Click OK when done and then rebuild the altered projects.
Be sure to Rebuild and not just Build to ensure that the change you
made are used.




:: Running the samples

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

