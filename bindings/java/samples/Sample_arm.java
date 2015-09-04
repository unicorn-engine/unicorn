/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM code */

import unicorn.*;

public class Sample_arm {

   // code to be emulated
   public static final byte[] ARM_CODE = {55,0,(byte)0xa0,(byte)0xe3,3,16,66,(byte)0xe0}; // mov r0, #0x37; sub r1, r2, r3
   public static final byte[] THUMB_CODE = {(byte)0x83, (byte)0xb0}; // sub    sp, #0xc
   
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

   private static class MyBlockHook implements BlockHook {
      public void hook(Unicorn u, long address, int size, Object user_data)
      {
          System.out.print(String.format(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size));
      }
   }
      
   // callback for tracing instruction
   private static class MyCodeHook implements CodeHook {
      public void hook(Unicorn u, long address, int size, Object user_data) {
       System.out.print(String.format(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size));   
      }
   }
   
   static void test_arm()
   {
   
       byte[] r0 = {0x34, 0x12, 0, 0};     // R0 register
       byte[] r2 = {(byte)0x89, 0x67, 0, 0};     // R1 register
       byte[] r3 = {0x33, 0x33, 0, 0};     // R2 register
       byte[] r1;     // R1 register
   
       System.out.print("Emulate ARM code\n");
   
       // Initialize emulator in ARM mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_ARM);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, ARM_CODE);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_ARM_REG_R0, r0);
       u.reg_write(Unicorn.UC_ARM_REG_R2, r2);
       u.reg_write(Unicorn.UC_ARM_REG_R3, r3);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + ARM_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       r0 = u.reg_read(Unicorn.UC_ARM_REG_R0, 4);
       r1 = u.reg_read(Unicorn.UC_ARM_REG_R1, 4);
       System.out.print(String.format(">>> R0 = 0x%x\n", toInt(r0)));
       System.out.print(String.format(">>> R1 = 0x%x\n", toInt(r1)));
   
       u.close();
   }
   
   static void test_thumb()
   {
   
       byte[] sp = {0x34, 0x12, 0, 0};     // R0 register
   
       System.out.print("Emulate THUMB code\n");
   
       // Initialize emulator in ARM mode
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_THUMB);
   
       // map 2MB memory for this emulation
       u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
   
       // write machine code to be emulated to memory
       u.mem_write(ADDRESS, THUMB_CODE);
   
       // initialize machine registers
       u.reg_write(Unicorn.UC_ARM_REG_SP, sp);
   
       // tracing all basic blocks with customized callback
       u.hook_add(new MyBlockHook(), 1, 0, null);
   
       // tracing one instruction at ADDRESS with customized callback
       u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
   
       // emulate machine code in infinite time (last param = 0), or when
       // finishing all the code.
       u.emu_start(ADDRESS, ADDRESS + THUMB_CODE.length, 0, 0);
   
       // now print out some registers
       System.out.print(">>> Emulation done. Below is the CPU context\n");
   
       sp = u.reg_read(Unicorn.UC_ARM_REG_SP, 4);
       System.out.print(String.format(">>> SP = 0x%x\n", toInt(sp)));
   
       u.close();
   }
   
   public static void main(String args[])
   {
       test_arm();
       System.out.print("==========================\n");
       test_thumb();   
   }

}
