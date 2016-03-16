// 
// Dynamic loader for unicorn shared library in windows and linux.
// This was made for v1.0 of unicorn.
// Newer versions of unicorn may require changes to these files.
// 
// Windows Notes:
// If an absolute path to unicorn.dll is passed into uc_dyn_load() it will
// still try to load the rest of the dependent dlls (ie libglib-2.0-0.dll etc)
// from standard dll paths. This is usually the directory that the main
// exe file, that loaded unicorn.dll, is in. This is standard behaviour for
// Windows dll files, and not specific to unicorn dlls.
// 
// So putting all dlls in their own directory and then attempting to load
// unicorn.dll from that directory via an absolute path will cause
// uc_dyn_load() to fail.
// 
// The easiest way around this is to place all dlls in the same directory
// as your main exe file. Other ways around this are using various flags
// for LoadLibraryEx() or by calling SetDllDirectory().
// 
// LoadLibraryEx info:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
// SetDllDirectory() info:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms686203(v=vs.85).aspx
// 
// Zak Escano  -  November 2015
// 

#ifndef UNICORN_DYNLOAD_H
#define UNICORN_DYNLOAD_H

// Undefine shared here so that functions aren't defined as: "__declspec(dllexport)"
#ifdef UNICORN_SHARED
#undef UNICORN_SHARED
#endif
#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 Dynamically load shared library.
 Check the notes at the top for info regarding dll file locations in windows.
 
 @path: path to shared library file. (NULL to use default path)
 @flags: system specific flags for loading shared library file. (0 for default)

 @return true on success, false if failed.
*/
bool uc_dyn_load(const char* path, int flags);

/*
 Free resources when done using shared library.

 @return true on success, false if failed.
*/
bool uc_dyn_free(void);


#ifdef __cplusplus
}
#endif

#endif // UNICORN_DYNLOAD_H

