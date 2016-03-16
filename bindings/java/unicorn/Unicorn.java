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

   private long eng;
   private int arch;
   private int mode;

   private long blockHandle = 0;
   private long interruptHandle = 0;
   private long codeHandle = 0;

   private Hashtable<Integer, Long> eventMemHandles = new Hashtable<Integer, Long>();
   private long readInvalidHandle = 0;
   private long writeInvalidHandle = 0;
   private long fetchProtHandle = 0;
   private long readProtHandle = 0;
   private long writeProtHandle = 0;

   private long readHandle = 0;
   private long writeHandle = 0;
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
   private ArrayList<Tuple> readList = new ArrayList<Tuple>();      
   private ArrayList<Tuple> writeList = new ArrayList<Tuple>();     
   private ArrayList<Tuple> inList = new ArrayList<Tuple>();        
   private ArrayList<Tuple> outList = new ArrayList<Tuple>();       
   private ArrayList<Tuple> syscallList = new ArrayList<Tuple>();   
   
   private Hashtable<Integer, ArrayList<Tuple> > eventMemLists = new Hashtable<Integer, ArrayList<Tuple> >();
   
   private ArrayList<ArrayList<Tuple>> allLists = new ArrayList<ArrayList<Tuple>>();

   private static Hashtable<Integer,Integer> eventMemMap = new Hashtable<Integer,Integer>();
   private static Hashtable<Long,Unicorn> unicorns = new Hashtable<Long,Unicorn>();

   //required to load native method implementations   
   static { 
      System.loadLibrary("unicorn_java");    //loads unicorn.dll  or libunicorn.so
      eventMemMap.put(UC_HOOK_MEM_READ_UNMAPPED, UC_MEM_READ_UNMAPPED);
      eventMemMap.put(UC_HOOK_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_UNMAPPED);
      eventMemMap.put(UC_HOOK_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_UNMAPPED);
      eventMemMap.put(UC_HOOK_MEM_READ_PROT, UC_MEM_READ_PROT);
      eventMemMap.put(UC_HOOK_MEM_WRITE_PROT, UC_MEM_WRITE_PROT);
      eventMemMap.put(UC_HOOK_MEM_FETCH_PROT, UC_MEM_FETCH_PROT);
   } 

/**
 * Invoke all UC_HOOK_BLOCK callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_BLOCK 
 *
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  address The address of the instruction being executed
 * @param  size    The size of the basic block being executed
 * @see         hook_add, unicorn.BlockHook
 */
    private static void invokeBlockCallbacks(long eng, long address, int size) {
      Unicorn u = unicorns.get(eng);
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
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  intno   The interrupt number
 * @see         hook_add, unicorn.InterruptHook
 */
   private static void invokeInterruptCallbacks(long eng, int intno) {
      Unicorn u = unicorns.get(eng);
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
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  address The address of the instruction being executed
 * @param  size    The size of the instruction being executed
 * @see         hook_add, unicorn.CodeHook
 */
   private static void invokeCodeCallbacks(long eng, long address, int size) {
      Unicorn u = unicorns.get(eng);
      if (u != null) {
         for (Tuple p : u.codeList) {
            CodeHook ch = (CodeHook)p.function;
            ch.hook(u, address, size, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_MEM_XXX_UNMAPPED andor UC_HOOK_MEM_XXX_PROT callbacks registered
 * for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_MEM_XXX_UNMAPPED or UC_HOOK_MEM_XXX_PROT
 *
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  type    The type of event that is taking place
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read or written
 * @param  value   Value of data being written to memory, or irrelevant if type = READ.
 * @return         true to continue, or false to stop program (due to invalid memory).
 * @see            hook_add, unicorn.EventMemHook
 */
   private static boolean invokeEventMemCallbacks(long eng, int type, long address, int size, long value) {
      Unicorn u = unicorns.get(eng);
      boolean result = true;
      if (u != null) {
         ArrayList<Tuple> funcList = u.eventMemLists.get(type);
         if (funcList != null) {
            for (Tuple p : funcList) {
               EventMemHook emh = (EventMemHook)p.function;
               result &= emh.hook(u, address, size, value, p.data);
            }
         }
      }
      return result;
   }

/**
 * Invoke all UC_HOOK_MEM_READ callbacks registered for a specific Unicorn.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_MEM_READ 
 *
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read
 * @see         hook_add, unicorn.ReadHook
 */
   private static void invokeReadCallbacks(long eng, long address, int size) {
      Unicorn u = unicorns.get(eng);
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
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  address Address of instruction being executed
 * @param  size    Size of data being read
 * @param  value   value being written
 * @see         hook_add, unicorn.WriteHook
 */
   private static void invokeWriteCallbacks(long eng, long address, int size, long value) {
      Unicorn u = unicorns.get(eng);
      if (u != null) {
         for (Tuple p : u.writeList) {
            WriteHook wh = (WriteHook)p.function;
            wh.hook(u, address, size, value, p.data);
         }
      }
   }

/**
 * Invoke all UC_HOOK_INSN callbacks registered for a specific Unicorn.
 * This is specifically for the x86 IN instruction.
 * This function gets invoked from the native C callback registered for
 * for UC_HOOK_INSN 
 *
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  port    I/O Port number
 * @param  size    Data size (1/2/4) to be read from this port
 * @return  Data supplied from the input port
 * @see         hook_add, unicorn.InHook
 */
   private static int invokeInCallbacks(long eng, int port, int size) {
      Unicorn u = unicorns.get(eng);
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
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @param  port    I/O Port number
 * @param  size    Data size (1/2/4) to be written to this port
 * @see         hook_add, unicorn.OutHook
 */
   private static void invokeOutCallbacks(long eng, int port, int size, int value) {
      Unicorn u = unicorns.get(eng);
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
 * @param  eng     A Unicorn uc_engine* eng returned by uc_open
 * @see         hook_add, unicorn.SyscallHook
 */
   private static void invokeSyscallCallbacks(long eng) {
      Unicorn u = unicorns.get(eng);
      int result = 0;
      if (u != null) {
         for (Tuple p : u.syscallList) {
            SyscallHook sh = (SyscallHook)p.function;
            sh.hook(u, p.data);
         }
      }
   }

/** 
 * Write to register.
 *
 * @param  regid  Register ID that is to be modified.
 * @param  value  Number containing the new register value
 */
   private native void reg_write_num(int regid, Number value) throws UnicornException;

/** 
 * Write to register.
 *
 * @param  regid  Register ID that is to be modified.
 * @param  value  X86 specific memory management register containing the new register value
 */
   private native void reg_write_mmr(int regid, X86_MMR value) throws UnicornException;

/**
 * Read register value.
 *
 * @param regid  Register ID that is to be retrieved.
 * @return Number containing the requested register value.
 */
   private native Number reg_read_num(int regid) throws UnicornException;

/**
 * Read register value.
 *
 * @param regid  Register ID that is to be retrieved.
 * @return X86_MMR containing the requested register value.
 */
   private native Number reg_read_mmr(int regid) throws UnicornException;

/**
 * Native access to uc_open 
 *
 * @param  arch  Architecture type (UC_ARCH_*)
 * @param  mode  Hardware mode. This is combined of UC_MODE_*
 */
   private native long open(int arch, int mode) throws UnicornException;
   
/**
 * Create a new Unicorn object 
 *
 * @param  arch  Architecture type (UC_ARCH_*)
 * @param  mode  Hardware mode. This is combined of UC_MODE_*
 * @see    unicorn.UnicornConst
 *
 */
   public Unicorn(int arch, int mode) throws UnicornException {
      //remember these in case we need arch specific code
      this.arch = arch;
      this.mode = mode;
      eng = open(arch, mode);
      unicorns.put(eng, this);
      allLists.add(blockList);
      allLists.add(intrList);
      allLists.add(codeList);
      allLists.add(readList);
      allLists.add(writeList);
      allLists.add(inList);
      allLists.add(outList);
      allLists.add(syscallList);
   }
   
/**
 * Perform native cleanup tasks associated with a Unicorn object 
 *
 */
   protected void finalize() {
      unicorns.remove(eng);
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
 *  @see     unicorn.UnicornConst
 */
   public native static boolean arch_supported(int arch);

/**
 * Close the underlying uc_engine* eng associated with this Unicorn object 
 *
 */
   public native void close() throws UnicornException;
   
/**
 * Query internal status of engine.
 *
 * @param   type     query type. See UC_QUERY_*
 * @param   result   save the internal status queried
 * 
 * @return: error code. see UC_ERR_*
 * @see     unicorn.UnicornConst
 */
   public native int query(int type) throws UnicornException;

/**
 * Report the last error number when some API function fail.
 * Like glibc's errno, uc_errno might not retain its old value once accessed.
 *
 * @return Error code of uc_err enum type (UC_ERR_*, see above)
 * @see unicorn.UnicornConst
 */
   public native int errno();

/**
 * Return a string describing given error code.
 *
 * @param  code   Error code (see UC_ERR_* above)
 * @return Returns a String that describes the error code
 * @see unicorn.UnicornConst
 */
   public native static String strerror(int code);

/** 
 * Write to register.
 *
 * @deprecated use reg_write(int regid, Object value) instead
 * @param  regid  Register ID that is to be modified.
 * @param  value  Array containing value that will be written into register @regid
 */
@Deprecated
   public native void reg_write(int regid, byte[] value) throws UnicornException;

/** 
 * Write to register.
 *
 * @param  regid  Register ID that is to be modified.
 * @param  value  Object containing the new register value. Long, BigInteger, or
 *                other custom class used to represent register values
 */
   public void reg_write(int regid, Object value) throws UnicornException {
      if (value instanceof Number) {
         reg_write_num(regid, (Number)value);
      }
      else if (arch == UC_ARCH_X86 && value instanceof X86_MMR) {
         if (regid >= UC_X86_REG_IDTR && regid <= UC_X86_REG_TR) {
            reg_write_mmr(regid, (X86_MMR)value);
         }
      }
      else {
         throw new ClassCastException("Invalid value type");
      }
   }

/**
 * Read register value.
 *
 * @deprecated use Object reg_write(int regid) instead
 * @param regid  Register ID that is to be retrieved.
 * @param regsz  Size of the register being retrieved.
 * @return Byte array containing the requested register value.
 */
@Deprecated
   public native byte[] reg_read(int regid, int regsz) throws UnicornException;

/**
 * Read register value.
 *
 * @param regid  Register ID that is to be retrieved.
 * @return Object containing the requested register value. Long, BigInteger, or
 *                other custom class used to represent register values
 */
   public Object reg_read(int regid) throws UnicornException {
      if (arch == UC_ARCH_X86 && regid >= UC_X86_REG_IDTR && regid <= UC_X86_REG_TR) {
         return reg_read_mmr(regid);
      }
      else {
         return reg_read_num(regid);
      }
   }

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
 * @param eng      Internal unicorn uc_engine* eng associated with hooking Unicorn object
 * @param type     UC_HOOK_* hook type
 * @return         Unicorn uch returned for registered hook function
 */
   private native static long registerHook(long eng, int type);

/**
 * Hook registration helper for hook types that require one additional argument.
 *
 * @param eng      Internal unicorn uc_engine* eng associated with hooking Unicorn object
 * @param type     UC_HOOK_* hook type
 * @param arg1     Additional varargs argument
 * @return         Unicorn uch returned for registered hook function
 */
   private native static long registerHook(long eng, int type, int arg1);

/**
 * Hook registration helper for hook types that require two additional arguments.
 *
 * @param eng      Internal unicorn uc_engine* eng associated with hooking Unicorn object
 * @param type     UC_HOOK_* hook type
 * @param arg1     First additional varargs argument
 * @param arg2     Second additional varargs argument
 * @return         Unicorn uch returned for registered hook function
 */
   private native static long registerHook(long eng, int type, long arg1, long arg2);

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
         blockHandle = registerHook(eng, UC_HOOK_BLOCK, begin, end);
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
         interruptHandle = registerHook(eng, UC_HOOK_INTR);
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
         codeHandle = registerHook(eng, UC_HOOK_CODE, begin, end);
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
         readHandle = registerHook(eng, UC_HOOK_MEM_READ, begin, end);
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
         writeHandle = registerHook(eng, UC_HOOK_MEM_WRITE, begin, end);
      }
      writeList.add(new Tuple(callback, user_data));
   }
   
/**
 * Hook registration for UC_HOOK_MEM_WRITE | UC_HOOK_MEM_WRITE hooks. The registered callback function will be
 * invoked whenever a memory write or read is performed within the address range begin <= addr <= end. For
 * the special case in which begin > end, the callback will be invoked for ALL memory writes.
 *
 * @param callback Implementation of a MemHook interface
 * @param begin    Start address of memory range
 * @param end      End address of memory range
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(MemHook callback, long begin, long end, Object user_data) throws UnicornException {
      hook_add((ReadHook)callback, begin, end, user_data);
      hook_add((WriteHook)callback, begin, end, user_data);
   }
   
/**
 * Hook registration for UC_HOOK_MEM_XXX_UNMAPPED and UC_HOOK_MEM_XXX_PROT hooks.
 * The registered callback function will be invoked whenever a read or write is
 * attempted from an invalid or protected memory address.
 *
 * @param callback Implementation of a EventMemHook interface
 * @param type Type of memory event being hooked such as UC_HOOK_MEM_READ_UNMAPPED or UC_HOOK_MEM_WRITE_PROT
 * @param user_data  User data to be passed to the callback function each time the event is triggered
 */
   public void hook_add(EventMemHook callback, int type, Object user_data) throws UnicornException {
      //test all of the EventMem related bits in type
      for (Integer htype : eventMemMap.keySet()) {
         if ((type & htype) != 0) { //the 'htype' bit is set in type
            Long handle = eventMemHandles.get(htype);
            if (handle == null) {
               eventMemHandles.put(htype, registerHook(eng, htype));
            }
            int cbType = eventMemMap.get(htype);
            ArrayList<Tuple> flist = eventMemLists.get(cbType);
            if (flist == null) {
               flist = new ArrayList<Tuple>();
               allLists.add(flist);
               eventMemLists.put(cbType, flist);
            }
            flist.add(new Tuple(callback, user_data));
         }
      }
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
         inHandle = registerHook(eng, UC_HOOK_INSN, Unicorn.UC_X86_INS_IN);
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
         outHandle = registerHook(eng, UC_HOOK_INSN, Unicorn.UC_X86_INS_OUT);
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
         syscallHandle = registerHook(eng, UC_HOOK_INSN, Unicorn.UC_X86_INS_SYSCALL);
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
 *  Map existing host memory in for emulation.
 *  This API adds a memory region that can be used by emulation.
 *
 * @param address Base address of the memory range
 * @param size    Size of the memory block.
 * @param perms   Permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
 * @param ptr     Block of host memory backing the newly mapped memory. This block is
 *                expected to be an equal or larger size than provided, and be mapped with at
 *                least PROT_READ | PROT_WRITE. If it is not, the resulting behavior is undefined.
 */
   public native void mem_map_ptr(long address, long size, int perms, byte[] block) throws UnicornException;

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

/**
 * Retrieve all memory regions mapped by mem_map() and mem_map_ptr()
 * NOTE: memory regions may be split by mem_unmap()
 * 
 * @return  list of mapped regions.
*/
   public native MemRegion[] mem_regions() throws UnicornException;

}

