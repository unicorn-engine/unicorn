
Unicorn engine bindings for VB6 

A sample class for the 32bit x86 emulator is provided.

Contributed by: FireEye FLARE team
Author:         David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
License:        Apache

' supported api: 
'        ucs_version
'        ucs_arch_supported
'        ucs_open
'        ucs_close
'        uc_reg_write
'        uc_reg_read
'        uc_mem_write
'        UC_MEM_READ
'        uc_emu_start
'        uc_emu_stop
'        ucs_hook_add
'        uc_mem_map
'        uc_hook_del
'        uc_mem_regions
'        uc_mem_map_ptr
'        uc_context_alloc
'        uc_free
'        uc_context_save
'        uc_context_restore
'        uc_mem_unmap
'        uc_mem_protect
'        uc_strerror
'        uc_errno
'
' supported hooks:
'        UC_HOOK_CODE
'        UC_HOOK_BLOCK
'        memory READ/WRITE/FETCH
'        invalid memory access
'        interrupts
'
' bonus:
'        disasm_addr     (conditional compile - uses libdasm)
'        mem_write_block (map and write data auto handles alignment)
'        get_memMap      (wrapper for uc_mem_regions)
'

dependancies: (all in same directory or unicorn package in %windir%)
   vb6Test.exe
     ucvbshim.dll           _
       unicorn.dll           -
         libgcc_s_dw2-1.dll   \
         libiconv-2.dll        \__ unicorn package
         libintl-8.dll         /
         libpcre-1.dll        /
         libwinpthread-1.dll_-

Notes:

   c dll was built using VS2008
   build notes are included at the top of main.c
   this dll serves as a stdcall shim so vb6 can access the cdecl api and receive data from the callbacks.
 
   huge thanks to the unicorn and qemu authors who took on a gigantic task to create this library!


   

   


