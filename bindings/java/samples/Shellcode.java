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

/* Sample code to trace code with Linux code with syscall */

import unicorn.*;
import java.math.*;

public class Shellcode {

   public static final byte[] X86_CODE32 = {-21,25,49,-64,49,-37,49,-46,49,-55,-80,4,-77,1,89,-78,5,-51,-128,49,-64,-80,1,49,-37,-51,-128,-24,-30,-1,-1,-1,104,101,108,108,111};
   public static final byte[] X86_CODE32_SELF = {-21,28,90,-119,-42,-117,2,102,61,-54,125,117,6,102,5,3,3,-119,2,-2,-62,61,65,65,65,65,117,-23,-1,-26,-24,-33,-1,-1,-1,49,-46,106,11,88,-103,82,104,47,47,115,104,104,47,98,105,110,-119,-29,82,83,-119,-31,-54,125,65,65,65,65,65,65,65,65};
   
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
         
   public static class MyCodeHook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user) {
         
         System.out.print(String.format("Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size));
         
         byte[] r_eip = u.reg_read(Unicorn.UC_X86_REG_EIP, 4);
         System.out.print(String.format("*** EIP = %x ***: ", toInt(r_eip)));
         
         size = Math.min(16, size);

         byte[] tmp = u.mem_read(address, size);
         for (int i = 0; i < tmp.length; i++) {
            System.out.print(String.format("%x ", 0xff & tmp[i]));
         }
         System.out.print("\n");
      }
   };

   public static class MyInterruptHook implements InterruptHook {
      public void hook(Unicorn u, int intno, Object user) {
         long r_ecx;
         long r_edx;
         int size;
         
         // only handle Linux syscall
         if (intno != 0x80) {
            return;
         }
         
         long r_eax = toInt(u.reg_read(Unicorn.UC_X86_REG_EAX, 4));
         long r_eip = toInt(u.reg_read(Unicorn.UC_X86_REG_EIP, 4));
         
         switch ((int)r_eax) {
            default:
               System.out.print(String.format(">>> 0x%x: interrupt 0x%x, EAX = 0x%x\n", r_eip, intno, r_eax));
               break;
            case 1: // sys_exit
               System.out.print(String.format(">>> 0x%x: interrupt 0x%x, SYS_EXIT. quit!\n\n", r_eip, intno));
               u.emu_stop();
               break;
            case 4: // sys_write
               // ECX = buffer address
               r_ecx = toInt(u.reg_read(Unicorn.UC_X86_REG_ECX, 4));
               
               // EDX = buffer size
               r_edx = toInt(u.reg_read(Unicorn.UC_X86_REG_EDX, 4));
               
               // read the buffer in
               size = (int)Math.min(256, r_edx);
               
               byte[] buffer = u.mem_read(r_ecx, size);
               System.out.print(String.format(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = '%s'\n",
                        r_eip, intno, r_ecx, r_edx, new String(buffer)));
               break;
         }
      }
   }

   static void test_i386()
   {
       long r_esp = ADDRESS + 0x200000;  // ESP register
   
       System.out.print("Emulate i386 code\n");
   
       // Initialize emulator in X86-32bit mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, X86_CODE32_SELF);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_X86_REG_ESP, toBytes(r_esp));
   
       // tracing all instructions by having @begin > @end
       u.hook_add(new MyCodeHook(), 1, 0, null);
   
       // handle interrupt ourself
       u.hook_add(new MyInterruptHook(), null);
   
       System.out.print("\n>>> Start tracing this Linux code\n");
   
       // emulate machine code in infinite time
       // u.emu_start(ADDRESS, ADDRESS + X86_CODE32_SELF.length, 0, 12); <--- emulate only 12 instructions
       u.emu_start(ADDRESS, ADDRESS + X86_CODE32_SELF.length, 0, 0);
   
       System.out.print("\n>>> Emulation done.\n");
   
       u.close();
   }
   
   public static void main(String args[])
   {
       if (args.length == 1) {
           if ("-32".equals(args[0])) {
               test_i386();
           }
       } else {
           System.out.print("Syntax: java Shellcode <-32|-64>\n");
       }
   
   }

}