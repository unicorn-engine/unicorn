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

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to demonstrate how to emulate X86 code */

import unicorn.*;

public class Sample_x86 {

   // code to be emulated
   public static final byte[] X86_CODE32 = {65,74};
   public static final byte[] X86_CODE32_JUMP = {-21,2,-112,-112,-112,-112,-112,-112};
   public static final byte[] X86_CODE32_SELF = {-21,28,90,-119,-42,-117,2,102,61,-54,125,117,6,102,5,3,3,-119,2,-2,-62,61,65,65,65,65,117,-23,-1,-26,-24,-33,-1,-1,-1,49,-46,106,11,88,-103,82,104,47,47,115,104,104,47,98,105,110,-119,-29,82,83,-119,-31,-54,125,65,65,65,65};
   public static final byte[] X86_CODE32_LOOP = {65,74,-21,-2};
   public static final byte[] X86_CODE32_MEM_WRITE = {-119,13,-86,-86,-86,-86,65,74};
   public static final byte[] X86_CODE32_MEM_READ = {-117,13,-86,-86,-86,-86,65,74};
   public static final byte[] X86_CODE32_JMP_INVALID = {-23,-23,-18,-18,-18,65,74};
   public static final byte[] X86_CODE32_INOUT = {65,-28,63,74,-26,70,67};
   public static final byte[] X86_CODE64 = {65,-68,59,-80,40,42,73,15,-55,-112,77,15,-83,-49,73,-121,-3,-112,72,-127,-46,-118,-50,119,53,72,-9,-39,77,41,-12,73,-127,-55,-10,-118,-58,83,77,-121,-19,72,15,-83,-46,73,-9,-44,72,-9,-31,77,25,-59,77,-119,-59,72,-9,-42,65,-72,79,-115,107,89,77,-121,-48,104,106,30,9,60,89};
   public static final byte[] X86_CODE16 = {0, 0}; // add   byte ptr [bx + si], al
   
   // memory address where emulation starts
   public static final int ADDRESS = 0x1000000;
   
   public static final long toInt(byte val[]) {
      long res = 0;
      for (int i = 0; i < val.length; i++) {
         long v = val[i] & 0xff;
         res = res + (v << (i * 8));
      }
      return res;
   }

   public static final byte[] toBytes(long val) {
      byte[] res = new byte[8];
      for (int i = 0; i < 8; i++) {
         res[i] = (byte)(val & 0xff);
         val >>>= 8;
      }
      return res;
   }
   
   // callback for tracing basic blocks
   // callback for tracing instruction
   private static class MyBlockHook implements BlockHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
         System.out.printf(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size);
      }
   }
      
   // callback for tracing instruction
   private static class MyCodeHook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
         System.out.printf(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size);
         
         Long eflags = (Long)u.reg_read(Unicorn.UC_X86_REG_EFLAGS);
         System.out.printf(">>> --- EFLAGS is 0x%x\n", eflags.intValue());
         
         // Uncomment below code to stop the emulation using uc_emu_stop()
         // if (address == 0x1000009)
         //    u.emu_stop();
      }
   }
   
   private static class MyWriteInvalidHook implements EventMemHook {
      public boolean hook(Unicorn u, long address, int size, long value, Object user) {
         System.out.printf(">>> Missing memory is being WRITE at 0x%x, data size = %d, data value = 0x%x\n",
                          address, size, value);
         // map this memory in with 2MB in size
         u.mem_map(0xaaaa0000, 2 * 1024*1024, Unicorn.UC_PROT_ALL);
         // return true to indicate we want to continue
         return true;
      }
   }
   
   // callback for tracing instruction
   private static class MyCode64Hook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {      
         Long r_rip = (Long)u.reg_read(Unicorn.UC_X86_REG_RIP);
         System.out.printf(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size);
         System.out.printf(">>> RIP is 0x%x\n", r_rip.longValue());
         
         // Uncomment below code to stop the emulation using uc_emu_stop()
         // if (address == 0x1000009)
         //    uc_emu_stop(handle);
      }
   }

      
   private static class MyRead64Hook implements ReadHook {
      public void hook(Unicorn u, long address, int size, Object user) {
         System.out.printf(">>> Memory is being READ at 0x%x, data size = %d\n", address, size);
      }
   }

   private static class MyWrite64Hook implements WriteHook {
      public void hook(Unicorn u, long address, int size, long value, Object user) {
         System.out.printf(">>> Memory is being WRITE at 0x%x, data size = %d, data value = 0x%x\n",
                          address, size, value);
      }
   }
   
   // callback for IN instruction (X86).
   // this returns the data read from the port
   private static class MyInHook implements InHook {
      public int hook(Unicorn u, int port, int size, Object user_data) {
         Long r_eip = (Long)u.reg_read(Unicorn.UC_X86_REG_EIP);
         
         System.out.printf("--- reading from port 0x%x, size: %d, address: 0x%x\n", port, size, r_eip.intValue());
      
         switch(size) {
            case 1:
               // read 1 byte to AL
               return 0xf1;
            case 2:
               // read 2 byte to AX
               return 0xf2;
            case 4:
               // read 4 byte to EAX
               return 0xf4;
         }
         return 0;
      }
   }
   
   // callback for OUT instruction (X86).
   private static class MyOutHook implements OutHook {
      public void hook(Unicorn u, int port, int size, int value, Object user) {
         Long eip = (Long)u.reg_read(Unicorn.UC_X86_REG_EIP);
         Long tmp = null;
         System.out.printf("--- writing to port 0x%x, size: %d, value: 0x%x, address: 0x%x\n", port, size, value, eip.intValue());
         
         // confirm that value is indeed the value of AL/AX/EAX
         switch(size) {
            default:
               return;   // should never reach this
            case 1:
               tmp = (Long)u.reg_read(Unicorn.UC_X86_REG_AL);
               break;
            case 2:
               tmp = (Long)u.reg_read(Unicorn.UC_X86_REG_AX);
               break;
            case 4:
               tmp = (Long)u.reg_read(Unicorn.UC_X86_REG_EAX);
               break;
         }
      
         System.out.printf("--- register value = 0x%x\n", tmp.intValue());
      }
   }
   
   static void test_i386() {
       Long r_ecx = new Long(0x1234);     // ECX register
       Long r_edx = new Long(0x7890);     // EDX register
   
       System.out.print("Emulate i386 code\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn uc;
       try {
         uc = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
       } catch (UnicornException uex) {
          System.out.println("Failed on uc_open() with error returned: " + uex);
          return;
       }
   
       // map 2MB memory for this emulation
       uc.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       try {
          uc.mem_write(ADDRESS, X86_CODE32);
       } catch (UnicornException uex) {
          System.out.println("Failed to write emulation code to memory, quit!\n");
          return;
       }
   
       // initialize machine registers
       uc.reg_write(Unicorn.UC_X86_REG_ECX, r_ecx);
       uc.reg_write(Unicorn.UC_X86_REG_EDX, r_edx);
   
       // tracing all basic blocks with customized callback
       uc.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing all instruction by having @begin > @end
       uc.hook_add(new MyCodeHook(), 1, 0, null);
   
       // emulate machine code in infinite time
       try {
          uc.emu_start(ADDRESS, ADDRESS + X86_CODE32.length, 0, 0);
       } catch (UnicornException uex) {
           System.out.printf("Failed on uc_emu_start() with error : %s\n",
                   uex.getMessage());
       }
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r_ecx = (Long)uc.reg_read(Unicorn.UC_X86_REG_ECX);
       r_edx = (Long)uc.reg_read(Unicorn.UC_X86_REG_EDX);
       System.out.printf(">>> ECX = 0x%x\n", r_ecx.intValue());
       System.out.printf(">>> EDX = 0x%x\n", r_edx.intValue());
   
       // read from memory
       try {
          byte[] tmp = uc.mem_read(ADDRESS, 4);
           System.out.printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", ADDRESS, toInt(tmp));
        } catch (UnicornException ex) {
           System.out.printf(">>> Failed to read 4 bytes from [0x%x]\n", ADDRESS);
       }
       uc.close();
   }

   static void test_i386_inout()
   {
       Long r_eax = new Long(0x1234);     // ECX register
       Long r_ecx = new Long(0x6789);     // EDX register
   
       System.out.print("===================================\n");
       System.out.print("Emulate i386 code with IN/OUT instructions\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_INOUT);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_EAX, r_eax);
       u.reg_write(Unicorn.UC_X86_REG_ECX, r_ecx);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing all instructions
       u.hook_add(new MyCodeHook(), 1, 0, null);
   
       // handle IN instruction
       u.hook_add(new MyInHook(), null);
       // handle OUT instruction
       u.hook_add(new MyOutHook(), null);
   
       // emulate machine code in infinite time
       u.emu_start(ADDRESS, ADDRESS + X86_CODE32_INOUT.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r_eax = (Long)u.reg_read(Unicorn.UC_X86_REG_EAX);
       r_ecx = (Long)u.reg_read(Unicorn.UC_X86_REG_ECX);
       System.out.printf(">>> EAX = 0x%x\n", r_eax.intValue());
       System.out.printf(">>> ECX = 0x%x\n", r_ecx.intValue());
   
       u.close();
   }

   static void test_i386_jump()
   {
       System.out.print("===================================\n");
       System.out.print("Emulate i386 code with jump\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_JUMP);
   
       // tracing 1 basic block with customized callback
       u.hook_add(new MyBlockHook(), ADDRESS, ADDRESS, null);
   
       // tracing 1 instruction at ADDRESS
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time
       u.emu_start(ADDRESS, ADDRESS + X86_CODE32_JUMP.length, 0, 0);
   
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       u.close();
   }

   // emulate code that loop forever
   static void test_i386_loop()
   {
       Long r_ecx = new Long(0x1234);     // ECX register
       Long r_edx = new Long(0x7890);     // EDX register
   
       System.out.print("===================================\n");
       System.out.print("Emulate i386 code that loop forever\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_LOOP);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_ECX, r_ecx);
       u.reg_write(Unicorn.UC_X86_REG_EDX, r_edx);
   
       // emulate machine code in 2 seconds, so we can quit even
       // if the code loops
       u.emu_start(ADDRESS, ADDRESS + X86_CODE32_LOOP.length, 2 * Unicorn.UC_SECOND_SCALE, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r_ecx = (Long)u.reg_read(Unicorn.UC_X86_REG_ECX);
       r_edx = (Long)u.reg_read(Unicorn.UC_X86_REG_EDX);
       System.out.printf(">>> ECX = 0x%x\n", r_ecx.intValue());
       System.out.printf(">>> EDX = 0x%x\n", r_edx.intValue());
   
       u.close();
   }
   
   // emulate code that read invalid memory
   static void test_i386_invalid_mem_read()
   {
       Long r_ecx = new Long(0x1234);     // ECX register
       Long r_edx = new Long(0x7890);     // EDX register
   
       System.out.print("===================================\n");
       System.out.print("Emulate i386 code that read from invalid memory\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_MEM_READ);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_ECX, r_ecx);
       u.reg_write(Unicorn.UC_X86_REG_EDX, r_edx);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing all instruction by having @begin > @end
       u.hook_add(new MyCodeHook(), 1, 0, null);
   
       // emulate machine code in infinite time
       try {
          u.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_READ.length, 0, 0);
       } catch (UnicornException uex) {
          int err = u.errno();
          System.out.printf("Failed on u.emu_start() with error returned: %s\n", uex.getMessage());       
       } 
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r_ecx = (Long)u.reg_read(Unicorn.UC_X86_REG_ECX);
       r_edx = (Long)u.reg_read(Unicorn.UC_X86_REG_EDX);
       System.out.printf(">>> ECX = 0x%x\n", r_ecx.intValue());
       System.out.printf(">>> EDX = 0x%x\n", r_edx.intValue());
   
       u.close();
   }
   
   // emulate code that read invalid memory
   static void test_i386_invalid_mem_write()
   {
       Long r_ecx = new Long(0x1234);     // ECX register
       Long r_edx = new Long(0x7890);     // EDX register
   
       System.out.print("===================================\n");
       System.out.print("Emulate i386 code that write to invalid memory\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_MEM_WRITE);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_ECX, r_ecx);
       u.reg_write(Unicorn.UC_X86_REG_EDX, r_edx);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing all instruction by having @begin > @end
       u.hook_add(new MyCodeHook(), 1, 0, null);
   
       // intercept invalid memory events
       u.hook_add(new MyWriteInvalidHook(), Unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, null);
   
       // emulate machine code in infinite time
       try {
           u.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_WRITE.length, 0, 0);
       } catch (UnicornException uex) {
           System.out.printf("Failed on uc_emu_start() with error returned: %s\n", uex.getMessage());
       }
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r_ecx = (Long)u.reg_read(Unicorn.UC_X86_REG_ECX);
       r_edx = (Long)u.reg_read(Unicorn.UC_X86_REG_EDX);
       System.out.printf(">>> ECX = 0x%x\n", r_ecx.intValue());
       System.out.printf(">>> EDX = 0x%x\n", r_edx.intValue());
   
       // read from memory
       byte tmp[] = u.mem_read(0xaaaaaaaa, 4);
       System.out.printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xaaaaaaaa, toInt(tmp));
   
       try {
           u.mem_read(0xffffffaa, 4);
           System.out.printf(">>> Read 4 bytes from [0x%x] = 0x%x\n", 0xffffffaa, toInt(tmp));
       } catch (UnicornException uex) {
           System.out.printf(">>> Failed to read 4 bytes from [0x%x]\n", 0xffffffaa);
       }
   
       u.close();
   }

   // emulate code that jump to invalid memory
   static void test_i386_jump_invalid()
   {
       Long r_ecx = new Long(0x1234);     // ECX register
       Long r_edx = new Long(0x7890);     // EDX register
   
       System.out.print("===================================\n");
       System.out.print("Emulate i386 code that jumps to invalid memory\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_JMP_INVALID);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_ECX, r_ecx);
       u.reg_write(Unicorn.UC_X86_REG_EDX, r_edx);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing all instructions by having @begin > @end
       u.hook_add(new MyCodeHook(), 1, 0, null);
   
       // emulate machine code in infinite time
       try {
           u.emu_start(ADDRESS, ADDRESS + X86_CODE32_JMP_INVALID.length, 0, 0);
       } catch (UnicornException uex) {
           System.out.printf("Failed on uc_emu_start() with error returned: %s\n", uex.getMessage());
       }
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r_ecx = (Long)u.reg_read(Unicorn.UC_X86_REG_ECX);
       r_edx = (Long)u.reg_read(Unicorn.UC_X86_REG_EDX);
       System.out.printf(">>> ECX = 0x%x\n", r_ecx.intValue());
       System.out.printf(">>> EDX = 0x%x\n", r_edx.intValue());
   
       u.close();
   }

   static void test_x86_64()
   {   
       long rax = 0x71f3029efd49d41dL;
       long rbx = 0xd87b45277f133ddbL;
       long rcx = 0xab40d1ffd8afc461L;
       long rdx = 0x919317b4a733f01L;
       long rsi = 0x4c24e753a17ea358L;
       long rdi = 0xe509a57d2571ce96L;
       long r8 = 0xea5b108cc2b9ab1fL;
       long r9 = 0x19ec097c8eb618c1L;
       long r10 = 0xec45774f00c5f682L;
       long r11 = 0xe17e9dbec8c074aaL;
       long r12 = 0x80f86a8dc0f6d457L;
       long r13 = 0x48288ca5671c5492L;
       long r14 = 0x595f72f6e4017f6eL;
       long r15 = 0x1efd97aea331ccccL;
   
       long rsp = ADDRESS + 0x200000;
      
       System.out.print("Emulate x86_64 code\n");
   
       // Initialize emulator in X86-64bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_64);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE64);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_RSP, new Long(rsp));
   
       u.reg_write(Unicorn.UC_X86_REG_RAX, new Long(rax));
       u.reg_write(Unicorn.UC_X86_REG_RBX, new Long(rbx));
       u.reg_write(Unicorn.UC_X86_REG_RCX, new Long(rcx));
       u.reg_write(Unicorn.UC_X86_REG_RDX, new Long(rdx));
       u.reg_write(Unicorn.UC_X86_REG_RSI, new Long(rsi));
       u.reg_write(Unicorn.UC_X86_REG_RDI, new Long(rdi));
       u.reg_write(Unicorn.UC_X86_REG_R8, new Long(r8));
       u.reg_write(Unicorn.UC_X86_REG_R9, new Long(r9));
       u.reg_write(Unicorn.UC_X86_REG_R10, new Long(r10));
       u.reg_write(Unicorn.UC_X86_REG_R11, new Long(r11));
       u.reg_write(Unicorn.UC_X86_REG_R12, new Long(r12));
       u.reg_write(Unicorn.UC_X86_REG_R13, new Long(r13));
       u.reg_write(Unicorn.UC_X86_REG_R14, new Long(r14));
       u.reg_write(Unicorn.UC_X86_REG_R15, new Long(r15));
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing all instructions in the range [ADDRESS, ADDRESS+20]
       u.hook_add(new MyCode64Hook(), ADDRESS, ADDRESS+20, null);
   
       // tracing all memory WRITE access (with @begin > @end)
       u.hook_add(new MyWrite64Hook(), 1, 0, null);
   
       // tracing all memory READ access (with @begin > @end)
       u.hook_add(new MyRead64Hook(), 1, 0, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + X86_CODE64.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       Long r_rax = (Long)u.reg_read(Unicorn.UC_X86_REG_RAX);
       Long r_rbx = (Long)u.reg_read(Unicorn.UC_X86_REG_RBX);
       Long r_rcx = (Long)u.reg_read(Unicorn.UC_X86_REG_RCX);
       Long r_rdx = (Long)u.reg_read(Unicorn.UC_X86_REG_RDX);
       Long r_rsi = (Long)u.reg_read(Unicorn.UC_X86_REG_RSI);
       Long r_rdi = (Long)u.reg_read(Unicorn.UC_X86_REG_RDI);
       Long r_r8 = (Long)u.reg_read(Unicorn.UC_X86_REG_R8);
       Long r_r9 = (Long)u.reg_read(Unicorn.UC_X86_REG_R9);
       Long r_r10 = (Long)u.reg_read(Unicorn.UC_X86_REG_R10);
       Long r_r11 = (Long)u.reg_read(Unicorn.UC_X86_REG_R11);
       Long r_r12 = (Long)u.reg_read(Unicorn.UC_X86_REG_R12);
       Long r_r13 = (Long)u.reg_read(Unicorn.UC_X86_REG_R13);
       Long r_r14 = (Long)u.reg_read(Unicorn.UC_X86_REG_R14);
       Long r_r15 = (Long)u.reg_read(Unicorn.UC_X86_REG_R15);
   
       System.out.printf(">>> RAX = 0x%x\n", r_rax.longValue());
       System.out.printf(">>> RBX = 0x%x\n", r_rbx.longValue());
       System.out.printf(">>> RCX = 0x%x\n", r_rcx.longValue());
       System.out.printf(">>> RDX = 0x%x\n", r_rdx.longValue());
       System.out.printf(">>> RSI = 0x%x\n", r_rsi.longValue());
       System.out.printf(">>> RDI = 0x%x\n", r_rdi.longValue());
       System.out.printf(">>> R8 = 0x%x\n", r_r8.longValue());
       System.out.printf(">>> R9 = 0x%x\n", r_r9.longValue());
       System.out.printf(">>> R10 = 0x%x\n", r_r10.longValue());
       System.out.printf(">>> R11 = 0x%x\n", r_r11.longValue());
       System.out.printf(">>> R12 = 0x%x\n", r_r12.longValue());
       System.out.printf(">>> R13 = 0x%x\n", r_r13.longValue());
       System.out.printf(">>> R14 = 0x%x\n", r_r14.longValue());
       System.out.printf(">>> R15 = 0x%x\n", r_r15.longValue());
   
       u.close();
   }

   static void test_x86_16()
   {
       Long eax = new Long(7);
       Long ebx = new Long(5);
       Long esi = new Long(6);
   
       System.out.print("Emulate x86 16-bit code\n");
   
       // Initialize emulator in X86-16bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_16);
   
       // map 8KB memory for this emulation
       u.mem_map(0, 8 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(0, X86_CODE16);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_EAX, eax);
       u.reg_write(Unicorn.UC_X86_REG_EBX, ebx);
       u.reg_write(Unicorn.UC_X86_REG_ESI, esi);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(0, X86_CODE16.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       // read from memory
       byte[] tmp = u.mem_read(11, 1);
       System.out.printf(">>> Read 1 bytes from [0x%x] = 0x%x\n", 11, toInt(tmp));

       u.close();
   }

   public static void main(String args[])
   {
       if (args.length == 1) {
           if (args[0].equals("-32")) {
               test_i386();
               test_i386_inout();
               test_i386_jump();
               test_i386_loop();
               test_i386_invalid_mem_read();
               test_i386_invalid_mem_write();
               test_i386_jump_invalid();
           }
   
           if (args[0].equals("-64")) {
               test_x86_64();
           }
   
           if (args[0].equals("-16")) {
               test_x86_16();
           }

           // test memleak
           if (args[0].equals("-0")) {
               while(true) {
                   test_i386();
                   // test_x86_64();
               }
           }
       } else {
           System.out.print("Syntax: java Sample_x86 <-16|-32|-64>\n");
       }
   
   }

}
