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

/* Sample code to demonstrate how to emulate Mips code (big endian) */

import unicorn.*;

public class Sample_mips {

   // code to be emulated
   public static final byte[] MIPS_CODE_EB = {52,33,52,86};
   public static final byte[] MIPS_CODE_EL = {86,52,33,52};

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
   
   static void test_mips_eb()
   {
   
       byte[] r1 = toBytes(0x6789);     // R1 register
   
       System.out.print("Emulate MIPS code (big-endian)\n");
   
       // Initialize emulator in MIPS mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_MIPS, Unicorn.UC_MODE_MIPS32 + Unicorn.UC_MODE_BIG_ENDIAN);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, MIPS_CODE_EB);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_MIPS_REG_1, r1);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + MIPS_CODE_EB.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r1 = u.reg_read(Unicorn.UC_MIPS_REG_1, 4);
       System.out.print(String.format(">>> R1 = 0x%x\n", toInt(r1)));
   
       u.close();
   }
   
   static void test_mips_el()
   {
       byte[] r1 = toBytes(0x6789);     // R1 register
   
       System.out.print("===========================\n");
       System.out.print("Emulate MIPS code (little-endian)\n");
   
       // Initialize emulator in MIPS mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_MIPS, Unicorn.UC_MODE_MIPS32 + Unicorn.UC_MODE_LITTLE_ENDIAN);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, MIPS_CODE_EL);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_MIPS_REG_1, r1);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + MIPS_CODE_EL.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r1 = u.reg_read(Unicorn.UC_MIPS_REG_1, 4);
       System.out.print(String.format(">>> R1 = 0x%x\n", toInt(r1)));
   
       u.close();
   }
   
   public static void main(String args[])
   {
       test_mips_eb();
       test_mips_el();
   }
}
