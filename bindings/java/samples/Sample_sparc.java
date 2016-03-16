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

/* Sample code to demonstrate how to emulate Sparc code */

import unicorn.*;

public class Sample_sparc {

   // code to be emulated
   public static final byte[] SPARC_CODE = {-122,0,64,2};
   //public static final byte[] SPARC_CODE = {-69,112,0,0}; //illegal code
   
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
      
   static void test_sparc()
   {
       byte[] g1 = toBytes(0x1230);     // G1 register
       byte[] g2 = toBytes(0x6789);     // G2 register
       byte[] g3 = toBytes(0x5555);     // G3 register
   
       System.out.print("Emulate SPARC code\n");
   
       // Initialize emulator in Sparc mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_SPARC, Unicorn.UC_MODE_32 + Unicorn.UC_MODE_BIG_ENDIAN);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, SPARC_CODE);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_SPARC_REG_G1, g1);
       u.reg_write(Unicorn.UC_SPARC_REG_G2, g2);
       u.reg_write(Unicorn.UC_SPARC_REG_G3, g3);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);

       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + SPARC_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       g3 = u.reg_read(Unicorn.UC_SPARC_REG_G3, 4);
       System.out.print(String.format(">>> G3 = 0x%x\n", toInt(g3)));
   
       u.close();
   }
   
   public static void main(String args[])
   {
      test_sparc();
   }
}
