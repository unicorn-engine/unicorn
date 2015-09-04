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
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM64 code */

import unicorn.*;

public class Sample_arm64 {

   // code to be emulated
   public static final byte[] ARM_CODE = {-85,1,15,-117}; // add x11, x13, x15
   
   // memory address where emulation starts
   public static final int ADDRESS = 0x10000;
   
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
   private static class MyBlockHook implements BlockHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
         System.out.print(String.format(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size));
      }
   }
      
   // callback for tracing instruction
   private static class MyCodeHook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
         System.out.print(String.format(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size));
      }
   }
   
   static void test_arm64()
   {
   
       byte[] x11 = toBytes(0x1234);     // X11 register
       byte[] x13 = toBytes(0x6789);     // X13 register
       byte[] x15 = toBytes(0x3333);     // X15 register
   
       System.out.print("Emulate ARM64 code\n");
   
       // Initialize emulator in ARM mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM64, Unicorn.UC_MODE_ARM);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, ARM_CODE);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_ARM64_REG_X11, x11);
       u.reg_write(Unicorn.UC_ARM64_REG_X13, x13);
       u.reg_write(Unicorn.UC_ARM64_REG_X15, x15);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + ARM_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       x11 = u.reg_read(Unicorn.UC_ARM64_REG_X11, 8);
       System.out.print(String.format(">>> X11 = 0x%x\n", toInt(x11)));
   
       u.close();
   }
   
   public static void main(String args[])
   {
       test_arm64();
   }
}
