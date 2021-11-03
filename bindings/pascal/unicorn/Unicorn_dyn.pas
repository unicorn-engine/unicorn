{
  FreePascal/Delphi bindings for the UnicornEngine Emulator Engine \
  Tested On Mac - Win - Linux >> with FreePascal v3.0.4 & Delphi Berlin 10.2 .

  Copyright(c) 2018 Coldzer0 <Coldzer0 [at] protonmail.ch> .

  License: GPLv2 .
}

unit Unicorn_dyn;

{$IFDEF FPC}
    {$MODE Delphi}
    {$PackRecords C}
{$ENDIF}

interface

uses
  {$IFDEF FPC}dynlibs,Crt{$ELSE}
    {$ifdef mswindows}
       windows,sysutils
    {$ENDIF}
  {$ENDIF};


const
{$IFDEF Darwin}
    UNICORN_LIB = './libunicorn.dylib';
{$ENDIF}
{$ifdef Linux}
    UNICORN_LIB = './libunicorn.so';
{$endif}
{$ifdef mswindows}
    UNICORN_LIB = './unicorn.dll';
{$endif}

type
  uc_engine     = Pointer;
  uc_context    = Pointer; // Opaque storage for CPU context, used with uc_context_*()
  uc_hook       = UIntPtr;
  uc_arch       = Cardinal;
  uc_mode       = Cardinal;
  uc_err        = Cardinal;
  uc_query_type = Cardinal;

  {$IFNDEF FPC} // Delphi Support .
   PUInt32 = ^UInt32;
  {$ENDIF}

type
   {
     Callback functions
     Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
     @address: address where the code is being executed
     @size: size of machine instruction(s) being executed, or 0 when size is unknown
     @user_data: user data passed to tracing APIs.
  }
  uc_cb_hookcode_t = procedure(uc : uc_engine; address : UInt64; size : UInt32; user_data : Pointer); cdecl;

  {
     Callback function for tracing interrupts (for uc_hook_intr())
     @intno: interrupt number
     @user_data: user data passed to tracing APIs.
  }
  uc_cb_hookintr_t = procedure(uc : uc_engine; intno : UInt32; user_data : Pointer); cdecl;

  {
     Callback function for tracing IN instruction of X86
     @port: port number
     @size: data size (1/2/4) to be read from this port
     @user_data: user data passed to tracing APIs.
  }
  uc_cb_insn_in_t = function(uc : uc_engine; port : UInt32; siz : integer; user_data : Pointer) : UInt32; cdecl;

  {
     Callback function for OUT instruction of X86 .
     @port: port number
     @size: data size (1/2/4) to be written to this port
     @value: data value to be written to this port
  }
  uc_cb_insn_out_t = procedure(uc : uc_engine; port : UInt32; size : integer; value : UInt32; user_data : Pointer); cdecl;

  // All type of memory accesses for UC_HOOK_MEM_*
  uc_mem_type = integer;

  // All type of hooks for uc_hook_add() API.
  uc_hook_type = integer;

   {
     Callback function for hooking memory (UC_MEM_READ, UC_MEM_WRITE & UC_MEM_FETCH)
     @type: this memory is being READ, or WRITE
     @address: address where the code is being executed
     @size: size of data being read or written
     @value: value of data being written to memory, or irrelevant if type = READ.
     @user_data: user data passed to tracing APIs
   }
   uc_cb_hookmem_t = procedure(uc : uc_engine; _type : uc_mem_type; address : UInt64; size : integer; value : Int64; user_data : Pointer); cdecl;

  {
  Callback function for handling invalid memory access events (UNMAPPED and
    PROT events)

  @type: this memory is being READ, or WRITE
  @address: address where the code is being executed
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs

  @return: return true to continue, or false to stop program (due to invalid memory).
           NOTE: returning true to continue execution will only work if the accessed
           memory is made accessible with the correct permissions during the hook.

           In the event of a UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED callback,
           the memory should be uc_mem_map()-ed with the correct permissions, and the
           instruction will then read or write to the address as it was supposed to.

           In the event of a UC_MEM_FETCH_UNMAPPED callback, the memory can be mapped
           in as executable, in which case execution will resume from the fetched address.
           The instruction pointer may be written to in order to change where execution resumes,
           but the fetch must succeed if execution is to resume.
  }
  uc_cb_eventmem_t = function(uc : uc_engine; _type : uc_mem_type; address : UInt64; size : integer; value : Int64; user_data : Pointer) : LongBool; cdecl;


type
  {
    Memory region mapped by uc_mem_map() and uc_mem_map_ptr()
    Retrieve the list of memory regions with uc_mem_regions()
  }
  uc_mem_region = record
    rBegin : UInt64; // begin address of the region (inclusive)
    rEnd   : UInt64; // end address of the region (inclusive)
    rPerms : UInt32; // memory permissions of the region
  end;
  uc_mem_regionArray  = array[0..(MaxInt div SizeOf(uc_mem_region))-1] of uc_mem_region;
  Puc_mem_regionArray = ^uc_mem_regionArray;


// Exports
var
(*
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
     major & minor versions.
     NOTE: This returned value can be compared with version number made
     with macro UC_MAKE_VERSION .

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
*)
  uc_version : function (var major, minor : Cardinal) : Cardinal; cdecl;

(*
 Determine if the given architecture is supported by this library.

 @arch: architecture type (UC_ARCH_* )

 @return True if this library supports the given arch.
*)
  uc_arch_supported : function (arch : uc_arch) : LongBool; cdecl;

(*
 Create new instance of unicorn engine.

 @arch: architecture type (UC_ARCH_* )
 @mode: hardware mode. This is combined of UC_MODE_*
 @uc: pointer to uc_engine, which will be updated at return time

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_open : function (arch : uc_arch; mode : uc_mode; var uc : uc_engine) : uc_err; cdecl;

(*
 Close UC instance: MUST do to release the handle when it is not used anymore.
 NOTE: this must be called only when there is no longer usage of Unicorn.
 The reason is the this API releases some cached memory, thus access to any
 Unicorn API after uc_close() might crash your application.
 After this, @uc is invalid, and nolonger usable.

 @uc: pointer to a handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_close : function (uc : uc_engine) : uc_err; cdecl;

(*
 Query internal status of engine.

 @uc: handle returned by uc_open()
 @type: query type. See uc_query_type

 @result: save the internal status queried .

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*)
  uc_query : function (uc : uc_engine; qtype : uc_query_type; result : PCardinal) : uc_err ; cdecl;


(*
 Report the last error number when some API function fail.
 Like glibc's errno, uc_errno might not retain its old value once accessed.

 @uc: handle returned by uc_open()

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*)
  uc_errno : function (uc : uc_engine) : uc_err; cdecl;

(*
 Return a string describing given error code.

 @code: error code (see UC_ERR_* )

 @return: returns a pointer to a string that describes the error code
 passed in the argument @code
*)
  uc_strerror : function (code : uc_err) : PAnsiChar; cdecl;

(*
 Write to register.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will set to register @regid .

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
 for detailed error).
*)
  uc_reg_write : function (uc : uc_engine; regid : Integer; const value : Pointer) : uc_err; cdecl;

(*
 Read register value.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_reg_read: function (uc : uc_engine; regid : Integer; value : Pointer) : uc_err; cdecl ;


(*
 Write multiple register values.

 @uc: handle returned by uc_open()
 @rges:  array of register IDs to store
 @value: pointer to array of register values
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*)
  uc_reg_write_batch : function(uc : uc_engine; regs : PIntegerArray; const values : Pointer; count : Integer) : uc_err; cdecl;

(*
 Read multiple register values.

 @uc: handle returned by uc_open()
 @rges:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*)
  uc_reg_read_batch : function(uc : uc_engine; regs : PIntegerArray; var values : Pointer; count : integer) : uc_err; cdecl;

(*
 Write to a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to set.
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
 for detailed error).
*)
  uc_mem_write_ : function (uc : uc_engine; address : UInt64; const bytes : Pointer;
                            size : Cardinal) : uc_err; cdecl;

(*
 Read a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to get.
 @bytes:   pointer to a variable containing data copied from memory.
 @size:   size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_mem_read_ : function (uc : uc_engine; address : UInt64; bytes : Pointer;
                           size : Cardinal) : uc_err; cdecl;

(*
 Emulate machine code in a specific duration of time.

 @uc: handle returned by uc_open()
 @begin: address where emulation starts
 @until: address where emulation stops (i.e when this address is hit)
 @timeout: duration to emulate the code (in microseconds). When this value is 0,
        we will emulate the code in infinite time, until the code is finished.
 @count: the number of instructions to be emulated. When this value is 0,
        we will emulate all the code available, until the code is finished.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_emu_start : function (uc : uc_engine; _begin, _until , timeout : UInt64;
                           count : Cardinal) : uc_err; cdecl;

(*
 Stop emulation (which was started by uc_emu_start() API.
 This is typically called from callback functions registered via tracing APIs.
 NOTE: for now, this will stop the execution only after the current block.

 @uc: handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_emu_stop : function (uc : uc_engine) : uc_err; cdecl;

(*
function (uc : uc_engine; var hh : uc_hook; _type : integer;
         callback : Pointer; user_data : Pointer; _Begin, _End : UInt64; args : Array Of Const) : uc_err; cdecl;

Register callback for a hook event.
The callback will be run when the hook event is hit.

@uc: handle returned by uc_open()
@hh: hook handle returned from this registration. To be used in uc_hook_del() API
@type: hook type
@callback: callback to be run when instruction is hit
@user_data: user-defined data. This will be passed to callback function in its
     last argument @user_data
@begin: start address of the area where the callback is effect (inclusive)
@end: end address of the area where the callback is effect (inclusive)
  NOTE 1: the callback is called only if related address is in range [@begin, @end]
  NOTE 2: if @begin > @end, callback is called whenever this hook type is triggered
@...: variable arguments (depending on @type)
  NOTE: if @type = UC_HOOK_INSN, this is the instruction ID (ex: UC_X86_INS_OUT)

@return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
  for detailed error).
*)
  uc_hook_add : function (uc : uc_engine; var hh : uc_hook; _type : integer;
                            callback : Pointer; user_data : Pointer; _Begin, _End : UInt64; args : Array Of Const) : uc_err; cdecl;

  //uc_hook_add_1 : function (uc : uc_engine; var hh : uc_hook; _type : integer;
  //                          callback : Pointer; user_data : Pointer; _Begin, _End : UInt64; arg1 : integer) : uc_err; cdecl;
  //
  //uc_hook_add_2 : function (uc : uc_engine; var hh : uc_hook; _type : integer;
  //                          callback : Pointer; user_data : Pointer; _Begin, _End : UInt64; arg1, arg2 : UInt64) : uc_err; cdecl;
  //
(*
 Unregister (remove) a hook callback.
 This API removes the hook callback registered by uc_hook_add().
 NOTE: this should be called only when you no longer want to trace.
 After this, @hh is invalid, and nolonger usable.

 @uc: handle returned by uc_open()
 @hh: handle returned by uc_hook_add()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
 for detailed error).
*)
  uc_hook_del : function (uc : uc_engine; hh : uc_hook) : uc_err; cdecl ;

(*
 Map memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the new memory region to be mapped in.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*)
  uc_mem_map : function (uc : uc_engine; address : UInt64; size : Cardinal; perms : UInt32) : uc_err; cdecl;


(*
 Map existing host memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the new memory region to be mapped in.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.
 @ptr: pointer to host memory backing the newly mapped memory. This host memory is
    expected to be an equal or larger size than provided, and be mapped with at
    least PROT_READ | PROT_WRITE. If it is not, the resulting behavior is undefined.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*)
  uc_mem_map_ptr : function(uc : uc_engine; address : UInt64; size : Cardinal; perms : UInt32; ptr : Pointer) : uc_err; cdecl;


(*
 Unmap a region of emulation memory.
 This API deletes a memory mapping from the emulation memory space.

 @handle: handle returned by uc_open()
 @address: starting address of the memory region to be unmapped.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the memory region to be modified.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
 for detailed error).
*)
  uc_mem_unmap : function (uc : uc_engine; address : UInt64; size : Cardinal) : uc_err; cdecl ;

(*
 Set memory permissions for emulation memory.
 This API changes permissions on an existing memory region.

 @handle: handle returned by uc_open()
 @address: starting address of the memory region to be modified.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the memory region to be modified.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: New permissions for the mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
 for detailed error).
*)
  uc_mem_protect : function (uc : uc_engine; address : UInt64; size : Cardinal; perms : UInt32) : uc_err; cdecl ;

(*
 Retrieve all memory regions mapped by uc_mem_map() and uc_mem_map_ptr()
 This API allocates memory for @regions, and user must free this memory later
 by free() to avoid leaking memory.
 NOTE: memory regions may be splitted by uc_mem_unmap()

 @uc: handle returned by uc_open()
 @regions: pointer to an array of uc_mem_region struct. >> Check "Puc_mem_regionArray"
 This is allocated by Unicorn, and must be freed by user later.
 @count: pointer to number of struct uc_mem_region contained in @regions

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*)
  uc_mem_regions : function(uc : uc_engine; var regions : Puc_mem_regionArray; count : PUInt32) : uc_err; cdecl ;

(*
  Allocate a region that can be used with uc_context_{save,restore} to perform
  quick save/rollback of the CPU context, which includes registers and some
  internal metadata. Contexts may not be shared across engine instances with
  differing arches or modes.

  @uc: handle returned by uc_open()
  @context: pointer to a uc_engine*. This will be updated with the pointer to
    the new context on successful return of this function.
    Later, this allocated memory must be freed with uc_free().

  @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
    for detailed error).
*)
  uc_context_alloc : function ( uc : uc_engine;  var context : uc_context) : uc_err; cdecl ;

(*
  Free the memory allocated by uc_context_alloc & uc_mem_regions.

  @mem: memory allocated by uc_context_alloc (returned in *context), or
        by uc_mem_regions (returned in *regions)

  @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
    for detailed error).
*)
  uc_free : function (context : Pointer) : uc_err; cdecl ;


(*
  Save a copy of the internal CPU context.
  This API should be used to efficiently make or update a saved copy of the
  internal CPU state.

  @uc: handle returned by uc_open()
  @context: handle returned by uc_context_alloc()

  @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
    for detailed error).
*)
  uc_context_save : function ( uc : uc_engine; context : uc_context) : uc_err; cdecl;

(*
  Restore the current CPU context from a saved copy.
  This API should be used to roll the CPU context back to a previous
  state saved by uc_context_save().

  @uc: handle returned by uc_open()
  @context: handle returned by uc_context_alloc that has been used with uc_context_save

  @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum \
    for detailed error).
*)
  uc_context_restore : function(uc : uc_engine; context : uc_context) : uc_err; cdecl;


{============================= Global Functions ================================}

//  function uc_hook_add(uc : uc_engine; var hh : uc_hook; _type : integer;
//                          callback : Pointer; user_data : Pointer; mBegin, mEnd : UInt64) : uc_err; overload;
  //function uc_hook_add(uc : uc_engine; var hh : uc_hook; _type : integer;
  //                        callback : Pointer; user_data : Pointer; mBegin, mEnd , arg1 : UInt64) : uc_err; overload;
  //function uc_hook_add(uc : uc_engine; var hh : uc_hook; _type : integer;
  //                        callback : Pointer; user_data : Pointer; mBegin, mEnd , arg1, arg2 : UInt64) : uc_err; overload;
  //

  function UC_MAKE_VERSION(major,minor : Cardinal): Cardinal;

implementation

function UC_MAKE_VERSION(major,minor : Cardinal): Cardinal;
begin
  Result := ((major shl 8) + minor);
end;

var
  UC_Handle : {$IFDEF FPC}dynlibs.{$ENDIF}HModule;

function dyn_loadfunc(name : {$IFDEF FPC}string{$ELSE}PChar{$ENDIF}) : Pointer;
begin
  Result := {$IFDEF FPC}dynlibs.{$ENDIF}GetProcAddress(UC_Handle,name);
end;

function loadUC(): Boolean;
var
  LastError : String;
begin
  Result := false;
  UC_Handle := {$IFDEF FPC}dynlibs.{$ENDIF}LoadLibrary(UNICORN_LIB);
  if UC_Handle <> 0 then
  begin
    @uc_version := dyn_loadfunc('uc_version');
    if (@uc_version = nil) then exit(false);

    @uc_arch_supported := dyn_loadfunc('uc_arch_supported');
    if (@uc_arch_supported = nil) then exit(false);

    @uc_open := dyn_loadfunc('uc_open');
    if (@uc_open = nil) then exit(false);

    @uc_close := dyn_loadfunc('uc_close');
    if (@uc_close = nil) then exit(false);

    @uc_query := dyn_loadfunc('uc_query');
    if (@uc_query = nil) then exit(false);

    @uc_errno := dyn_loadfunc('uc_errno');
    if (@uc_errno = nil) then exit(false);

    @uc_strerror := dyn_loadfunc('uc_strerror');
    if (@uc_strerror = nil) then exit(false);

    @uc_reg_write := dyn_loadfunc('uc_reg_write');
    if (@uc_reg_write = nil) then exit(false);

    @uc_reg_read := dyn_loadfunc('uc_reg_read');
    if (@uc_reg_read = nil) then exit(false);

    @uc_reg_write_batch := dyn_loadfunc('uc_reg_write_batch');
    if (@uc_reg_write_batch = nil) then exit(false);

    @uc_reg_read_batch := dyn_loadfunc('uc_reg_read_batch');
    if (@uc_reg_read_batch = nil) then exit(false);

    @uc_mem_write_ := dyn_loadfunc('uc_mem_write');
    if (@uc_mem_write_ = nil) then exit(false);

    @uc_mem_read_ := dyn_loadfunc('uc_mem_read');
    if (@uc_mem_read_ = nil) then exit(false);

    @uc_emu_start := dyn_loadfunc('uc_emu_start');
    if (@uc_emu_start = nil) then exit(false);

    @uc_emu_stop := dyn_loadfunc('uc_emu_stop');
    if (@uc_emu_stop = nil) then exit(false);

    @uc_hook_add := dyn_loadfunc('uc_hook_add');
    if (@uc_hook_add = nil) then exit(false);

    @uc_hook_del := dyn_loadfunc('uc_hook_del');
    if (@uc_hook_del = nil) then exit(false);

    @uc_mem_map := dyn_loadfunc('uc_mem_map');
    if (@uc_mem_map = nil) then exit(false);

    @uc_mem_map_ptr := dyn_loadfunc('uc_mem_map_ptr');
    if (@uc_mem_map_ptr = nil) then exit(false);

    @uc_mem_unmap := dyn_loadfunc('uc_mem_unmap');
    if (@uc_mem_unmap = nil) then exit(false);

    @uc_mem_protect := dyn_loadfunc('uc_mem_protect');
    if (@uc_mem_protect = nil) then exit(false);

    @uc_mem_regions := dyn_loadfunc('uc_mem_regions');
    if (@uc_mem_regions = nil) then exit(false);

    @uc_context_alloc := dyn_loadfunc('uc_context_alloc');
    if (@uc_context_alloc = nil) then exit(false);

    @uc_context_save := dyn_loadfunc('uc_context_save');
    if (@uc_context_save = nil) then exit(false);

    @uc_context_restore := dyn_loadfunc('uc_context_restore');
    if (@uc_context_restore = nil) then exit(false);

    @uc_free := dyn_loadfunc('uc_free');
    if (@uc_free = nil) then exit(false);

    Result := true;
  end
  else
  begin
    {$IFDEF FPC}TextColor(LightRed);{$ENDIF}
    LastError := {$IFDEF FPC}GetLoadErrorStr;{$ELSE}
      {$ifdef mswindows}
       SysErrorMessage(GetLastError,UC_Handle);
       SetLastError(0);
      {$ENDIF}
    {$ENDIF}
    WriteLn('error while loading unicorn library : ',LastError,#10);
    {$IFDEF FPC}NormVideo;{$ENDIF}
  end;
end;

procedure FreeUC();
begin
  if UC_Handle <> 0 then
     {$IFDEF FPC}dynlibs.{$ENDIF}FreeLibrary(UC_Handle);
end;

initialization
  UC_Handle := 0;
  if not loadUC then halt(0);

finalization
  FreeUC();
end.
