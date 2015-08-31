/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

package unicorn;  

import java.util.*;

public class Unicorn implements UnicornConst, ArmConst, Arm64Const, M68kConst, SparcConst, MipsConst, X86Const { 

   private long blockHandle = 0;
   private long interruptHandle = 0;
   private long codeHandle = 0;

   private long memInvalidHandle = 0;
   private long readHandle = 0;
   private long writeHandle = 0;
   private long readWriteHandle = 0;
   private long inHandle = 0;
   private long outHandle = 0;
   private long syscallHandle = 0;

   private class Tuple {
      public Hook function;
      public Object data;
      public Tuple(Hook f, Object d) {
         function = f;
         data = d;
      }
   }

   private ArrayList<Tuple> blockList = new ArrayList<Tuple>();     
   private ArrayList<Tuple> intrList = new ArrayList<Tuple>();      
   private ArrayList<Tuple> codeList = new ArrayList<Tuple>();      
   private ArrayList<Tuple> memInvalidList = new ArrayList<Tuple>();
   private ArrayList<Tuple> readList = new ArrayList<Tuple>();      
   private ArrayList<Tuple> writeList = new ArrayList<Tuple>();     
   private ArrayList<Tuple> readWriteList = new ArrayList<Tuple>(); 
   private ArrayList<Tuple> inList = new ArrayList<Tuple>();        
   private ArrayList<Tuple> outList = new ArrayList<Tuple>();       
   private ArrayList<Tuple> syscallList = new ArrayList<Tuple>();   
   
   private ArrayList<ArrayList<Tuple>> allLists = new ArrayList<ArrayList<Tuple>>();

   private static Hashtable<Long,Unicorn> unicorns = new Hashtable<Long,Unicorn>();

   //required to load native method implementations   
   static { 
      System.loadLibrary("unicorn_java");    //loads unicorn.dll  or libunicorn.so
   } 

/**
 * Invoke all UC_HOOK_BLOCK callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_BLOCK 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  address The address of the instruction being executed
 * @param  size    The size of the basic block being executed
 * @see         hook_add, unicorn.BlockHook
 */
    private static void invokeBlockCallbacks(long handle, long address, int size) {
      Unicorn u = unicorns.get(handle);
      if (u != null) {
         for (Tuple p : u.blockList) {
            BlockHook bh = (BlockHook)p.function;
            bh.hook(u, address, size, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_INTR callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_INTR 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  intno   The interrupt number
 * @see         hook_add, unicorn.InterruptHook
 */
   private static void invokeInterruptCallbacks(long handle, int intno) {
      Unicorn u = unicorns.get(handle);
      if (u != null) {
         for (Tuple p : u.intrList) {
            InterruptHook ih = (InterruptHook)p.function;
            ih.hook(u, intno, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_CODE callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_CODE 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  address The address of the instruction being executed
 * @param  size    The size of the instruction being executed
 * @see         hook_add, unicorn.CodeHook
 */
   private static void invokeCodeCallbacks(long handle, long address, int size) {
      Unicorn u = unicorns.get(handle);
      if (u != null) {
         for (Tuple p : u.codeList) {
            CodeHook ch = (CodeHook)p.function;
            ch.hook(u, address, size, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_MEM_INVALID callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_MEM_INVALID 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  type    This memory is being read (UC_MEM_READ), or written (UC_MEM_WRITE)
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read or written
 * @param  value   Value of data being written to memory, or irrelevant if type = READ.
 * @return         true to continue, or false to stop program (due to invalid memory).
 * @see         hook_add, unicorn.MemoryInvalidHook
 */
   private static boolean invokeMemInvalidCallbacks(long handle, int type, long address, int size, long value) {
      Unicorn u = unicorns.get(handle);
      boolean result = true;
      if (u != null) {
         for (Tuple p : u.memInvalidList) {
            MemoryInvalidHook mh = (MemoryInvalidHook)p.function;
            result &= mh.hook(u, type, address, size, value, p.data);
         }
      }
      return result;
   }

/**
 * Invoke all UC_HOOK_MEM_READ callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_MEM_READ 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read
 * @see         hook_add, unicorn.ReadHook
 */
   private static void invokeReadCallbacks(long handle, long address, int size) {
      Unicorn u = unicorns.get(handle);
      if (u != null) {
         for (Tuple p : u.readList) {
            ReadHook rh = (ReadHook)p.function;
            rh.hook(u, address, size, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_MEM_WRITE callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_MEM_WRITE 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read
 * @param  value   value being written
 * @see         hook_add, unicorn.WriteHook
 */
   private static void invokeWriteCallbacks(long handle, long address, int size, long value) {
      Unicorn u = unicorns.get(handle);
      if (u != null) {
         for (Tuple p : u.writeList) {
            WriteHook wh = (WriteHook)p.function;
            wh.hook(u, address, size, value, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_MEM_READ_WRITE callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_MEM_READ_WRITE 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  type    Type of access being performed (UC_MEM_READ, UC_MEM_WRITE, UC_MEM_READ_WRITE)
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read
 * @param  value   value being written (if applicable)
 * @see         hook_add, unicorn.ReadWriteHook
 */
   private static void invokeReadWriteCallbacks(long handle, int type, long address, int size, long value) {
      Unicorn u = unicorns.get(handle);
      if (u != null) {
         for (Tuple p : u.readWriteList) {
            ReadWriteHook rwh = (ReadWriteHook)p.function;
            rwh.hook(u, type, address, size, value, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_INSN callbacks registered for a specific Unicorn.
 * This is specifically for the x86 IN instruction.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_INSN 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  port    I/O Port number
 * @param  size    Data size (1/2/4) to be read from this port
 * @return  Data supplied from the input port
 * @see         hook_add, unicorn.InHook
 */
   private static int invokeInCallbacks(long handle, int port, int size) {
      Unicorn u = unicorns.get(handle);
      int result = 0;
      if (u != null) {
         for (Tuple p : u.inList) {
            InHook ih = (InHook)p.function;
            result = ih.hook(u, port, size, p.data);
         }
      }
      return result;
   }

/**
 * Invoke all UC_HOOK_INSN callbacks registered for a specific Unicorn.
 * This is specifically for the x86 OUT instruction.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_INSN 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @param  port    I/O Port number
 * @param  size    Data size (1/2/4) to be written to this port
 * @see         hook_add, unicorn.OutHook
 */
   private static void invokeOutCallbacks(long handle, int port, int size, int value) {
      Unicorn u = unicorns.get(handle);
      int result = 0;
      if (u != null) {
         for (Tuple p : u.outList) {
            OutHook oh = (OutHook)p.function;
            oh.hook(u, port, size, value, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_INSN callbacks registered for a specific Unicorn.
 * This is specifically for the x86 SYSCALL and SYSENTER instruction.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_INSN 
 *
 * @param  handle  A Unicorn uch handle returned by uc_open
 * @see         hook_add, unicorn.SyscallHook
 */
   private static void invokeSyscallCallbacks(long handle) {
      Unicorn u = unicorns.get(handle);
      int result = 0;
      if (u != null) {
         for (Tuple p : u.syscallList) {
            SyscallHook sh = (SyscallHook)p.function;
            sh.hook(u, p.data);
         }
      }
   }

/**
 * Native access to uc_open 
 *
 * @param  arch  Architecture type (UC_ARCH_*)
 * @param  mode  Hardware mode. This is combined of UC_MODE_*
 */
   private native long open(int arch, int mode) throws UnicornException;
   
   private long handle;

/**
 * Create a new Unicorn object 
 *
 * @param  arch  Architecture type (UC_ARCH_*)
 * @param  mode  Hardware mode. This is combined of UC_MODE_*
 * @see    unicorn.UnicornArchs, unicorn.UnicornModes
 *
 */
   public Unicorn(int arch, int mode) throws UnicornException {
      handle = open(arch, mode);
      unicorns.put(handle, this);
      allLists.add(blockList);
      allLists.add(intrList);
      allLists.add(codeList);
      allLists.add(memInvalidList);
      allLists.add(readList);
      allLists.add(writeList);
      allLists.add(readWriteList);
      allLists.add(inList);
      allLists.add(outList);
      allLists.add(syscallList);
   }
   
/**
 * Perform native cleanup tasks associated with a Unicorn object 
 *
 */
   protected void finalize() {
      unicorns.remove(handle);
      close();
   }

/**
 * Return combined API version & major and minor version numbers.
 *
 * @return hexadecimal number as (major << 8 | minor), which encodes both major & minor versions.
 *
 * For example Unicorn version 1.2 whould yield 0x0102
 */
   public native static int version();

/**
 *  Determine if the given architecture is supported by this library.
 *
 *  @param   arch   Architecture type (UC_ARCH_*)
 *  @return  true if this library supports the given arch.
 *  @see     unicorn.UnicornArchs
 */
   public native static boolean arch_supported(int arch);

/**
 * Close the underlying uch handle associated with this Unicorn object 
 *
 */
   public native void close() throws UnicornException;
   
/**
 * Report the last error number when some API function fail.
 * Like glibc's errno, uc_errno might not retain its old value once accessed.
 *
 * @return Error code of uc_err enum type (UC_ERR_*, see above)
 * @see unicorn.UnicornErrors
 */
   public native int errno();

/**
 * Return a string describing given error code.
 *
 * @param  code   Error code (see UC_ERR_* above)
 * @return Returns a String that describes the error code
 * @see unicorn.UnicornErrors
 */
   public native static String strerror(int code);

/** 
 * Write to register.
 *
 * @param  regid  Register ID that is to be modified.
 * @param  value  Array containing value that will be written into register @regid
 */
   public native void reg_write(int regid, byte[] value) throws UnicornException;

/**
 * Read register value.
 *
 * @param regid  Register ID that is to be retrieved.
 * @param regsz  Size of the register being retrieved.
 * @return Byte array containing the requested register value.
 */
   public native byte[] reg_read(int regid, int regsz) throws UnicornException;

/** 
 * Write to memory.
 *
 * @param  address  Start addres of the memory region to be written.
 * @param  bytes    The values to be written into memory. bytes.length bytes will be written.
 */
   public native void mem_write(long address, byte[] bytes) throws UnicornException;

/**
 * Read memory contents.
 *
 * @param address  Start addres of the memory region to be read.
 * @param size     Number of bytes to be retrieved.
 * @return Byte array containing the contents of the requested memory range.
 */
   public native byte[] mem_read(long address, long size) throws UnicornException;

/**
 * Emulate machine code in a specific duration of time.
 *
 * @param begin    Address where emulation starts
 * @param until    Address where emulation stops (i.e when this address is hit)
 * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
 * @param count    The number of instructions to be emulated. When this value is 0, we will emulate all the code available, until the code is finished.
 */
   public native void emu_start(long begin, long until, long timeout, long count) throws UnicornException;

/**
 * Stop emulation (which was started by emu_start() ).
 * This is typically called from callback functions registered via tracing APIs.
 * NOTE: for now, this will stop the execution only after the current block.
 */
   public native void emu_stop() throws UnicornException;

/**
 * Hook registration helper for hook types that require no additional arguments.
 *
 * @param handle   Internal unicorn uch handle associated with hooking Unicorn object
 * @param type     UC_HOOK_* hook type
 * @return         Unicorn uch returned for registered hook function
 */
   private native static long registerHook(long handle, int type);

/**
 * Hook registration helper for hook types that require one additional argument.
 *
 * @param handle   Internal unicorn uch handle associated with hooking Unicorn object
 * @param type     UC_HOOK_* hook type
 * @param arg1     Additional varargs argument
 * @return         Unicorn uch returned for registered hook function
 */
   private native static long registerHook(long handle, int type, int arg1);

/**
 * Hook registration helper for hook types that require two additional arguments.
 *
 * @param handle   Internal unicorn uch handle associated with hooking Unicorn object
 * @param type     UC_HOOK_* hook type
 * @param arg1     First additional varargs argument
 * @param arg2     Second additional varargs argument
 * @return         Unicorn uch returned for registered hook function
 */
   private native static long registerHook(long handle, int type, long arg1, long arg2);

/**
 * Hook registration for UC_HOOK_BLOCK hooks. The registered callback function will be
 * invoked when a basic block is entered and the address of the basic block (BB) falls in the
 * range begin <= BB <= end. For the special case in which begin > end, the callback will be
 * invoked whenver any basic block is entered.
 *
 * @param callback Implementation of a BlockHook interface
 * @param begin    Start address of hooking range
 * @param end      End address of hooking range
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(BlockHook callback, long begin, long end, Object user_data) throws UnicornException {
      if (blockHandle == 0) {
         blockHandle = registerHook(handle, UC_HOOK_BLOCK, begin, end);
      }
      blockList.add(new Tuple(callback, user_data));
   }

/**
 * Hook registration for UC_HOOK_INTR hooks. The registered callback function will be
 * invoked whenever an interrupt instruction is executed.
 *
 * @param callback Implementation of a InterruptHook interface
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(InterruptHook callback, Object user_data) throws UnicornException {
      if (interruptHandle == 0) {
         interruptHandle = registerHook(handle, UC_HOOK_INTR);
      }
      intrList.add(new Tuple(callback, user_data));
   }

/**
 * Hook registration for UC_HOOK_CODE hooks. The registered callback function will be
 * invoked when an instruction is executed from the address range begin <= PC <= end. For
 * the special case in which begin > end, the callback will be invoked for ALL instructions.
 *
 * @param callback Implementation of a CodeHook interface
 * @param begin    Start address of hooking range
 * @param end      End address of hooking range
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(CodeHook callback, long begin, long end, Object user_data) throws UnicornException {
      if (codeHandle == 0) {
         codeHandle = registerHook(handle, UC_HOOK_CODE, begin, end);
      }
      codeList.add(new Tuple(callback, user_data));
   }

/**
 * Hook registration for UC_HOOK_MEM_READ hooks. The registered callback function will be
 * invoked whenever a memory read is performed within the address range begin <= read_addr <= end. For
 * the special case in which begin > end, the callback will be invoked for ALL memory reads.
 *
 * @param callback Implementation of a ReadHook interface
 * @param begin    Start address of memory read range
 * @param end      End address of memory read range
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(ReadHook callback, long begin, long end, Object user_data) throws UnicornException {
      if (readHandle == 0) {
         readHandle = registerHook(handle, UC_HOOK_MEM_READ, begin, end);
      }
      readList.add(new Tuple(callback, user_data));
   }
   
/**
 * Hook registration for UC_HOOK_MEM_WRITE hooks. The registered callback function will be
 * invoked whenever a memory write is performed within the address range begin <= write_addr <= end. For
 * the special case in which begin > end, the callback will be invoked for ALL memory writes.
 *
 * @param callback Implementation of a WriteHook interface
 * @param begin    Start address of memory write range
 * @param end      End address of memory write range
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(WriteHook callback, long begin, long end, Object user_data) throws UnicornException {
      if (writeHandle == 0) {
         writeHandle = registerHook(handle, UC_HOOK_MEM_WRITE, begin, end);
      }
      writeList.add(new Tuple(callback, user_data));
   }
   
/**
 * Hook registration for UC_HOOK_MEM_READ_WRITE hooks. The registered callback function will be
 * invoked whenever a memory read or write is performed within the address range begin <= mem_addr <= end. For
 * the special case in which begin > end, the callback will be invoked for ALL memory reads and writes.
 *
 * @param callback Implementation of a ReadWriteHook interface
 * @param begin    Start address of memory read/write range
 * @param end      End address of memory read/write range
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(ReadWriteHook callback, long begin, long end, Object user_data) throws UnicornException {
      if (readWriteHandle == 0) {
         readWriteHandle = registerHook(handle, UC_HOOK_MEM_READ_WRITE, begin, end);
      }
      readWriteList.add(new Tuple(callback, user_data));
   }

/**
 * Hook registration for UC_HOOK_MEM_INVALID hooks. The registered callback function will be
 * invoked whenever a read or write is attempted from an unmapped memory address.
 *
 * @param callback Implementation of a MemoryInvalidHook interface
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(MemoryInvalidHook callback, Object user_data) throws UnicornException {
      if (memInvalidHandle == 0) {
         memInvalidHandle = registerHook(handle, UC_HOOK_MEM_INVALID);
      }
      memInvalidList.add(new Tuple(callback, user_data));
   }

/**
 * Hook registration for UC_HOOK_INSN hooks (x86 IN instruction only). The registered callback 
 * function will be invoked whenever an x86 IN instruction is executed.
 *
 * @param callback Implementation of a InHook interface
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(InHook callback, Object user_data) throws UnicornException {
      if (inHandle == 0) {
         inHandle = registerHook(handle, UC_HOOK_INSN, Unicorn.UC_X86_INS_IN);
      }
      inList.add(new Tuple(callback, user_data));
   }
   
/**
 * Hook registration for UC_HOOK_INSN hooks (x86 OUT instruction only). The registered callback 
 * function will be invoked whenever an x86 OUT instruction is executed.
 *
 * @param callback Implementation of a OutHook interface
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(OutHook callback, Object user_data) throws UnicornException {
      if (outHandle == 0) {
         outHandle = registerHook(handle, UC_HOOK_INSN, Unicorn.UC_X86_INS_OUT);
      }
      outList.add(new Tuple(callback, user_data));
   }

/**
 * Hook registration for UC_HOOK_INSN hooks (x86 SYSCALL/SYSENTER instruction only). The registered callback 
 * function will be invoked whenever an x86 SYSCALL or SYSENTER instruction is executed.
 *
 * @param callback Implementation of a SyscallHook interface
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(SyscallHook callback, Object user_data) throws UnicornException {
      if (syscallHandle == 0) {
         syscallHandle = registerHook(handle, UC_HOOK_INSN, Unicorn.UC_X86_INS_SYSCALL);
      }
      syscallList.add(new Tuple(callback, user_data));
   }

   public void hook_del(Hook hook) throws UnicornException {
      for (ArrayList<Tuple> l : allLists) {
         for (Tuple t : l) {
            if (t.function.equals(hook)) {
               allLists.remove(t);
               return;
            }
         }
      }
   }

/**
 * Map a range of memory.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 * @param perms   Permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
 */
   public native void mem_map(long address, long size, int perms) throws UnicornException;

/**
 * Unmap a range of memory.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 */
   public native void mem_unmap(long address, long size) throws UnicornException;

/**
 * Change permissions on a range of memory.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 * @param perms   New permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
 */
   public native void mem_protect(long address, long size, int perms) throws UnicornException;

}

