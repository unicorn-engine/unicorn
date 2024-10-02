/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2016 Chris Eagle

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

/* Sample code to demonstrate how to register read/write API */

package samples;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import unicorn.*;

public class Sample_x86_mmr implements UnicornConst, X86Const {

    private static final MemHook hook_mem =
        (uc, type, address, size, value, user_data) -> {
            switch (type) {
            case UC_MEM_WRITE:
                System.out.format(
                    "mem write at 0x%x, size = %d, value = 0x%x\n",
                    address, size, value);
                break;
            default:
                break;
            }
        };
    private static final CodeHook hook_code =
        (uc, address, size, user_data) -> {
            System.out.format("Executing at 0x%x, ilen = 0x%x\n", address,
                size);
        };

    public static class SegmentDescriptor {
        public static final int BYTES = 8;

        int base;
        int limit;

        byte type; // 4 bits
        byte system; // 1 bit: S flag
        byte dpl; // 2 bits
        byte present; // 1 bit: P flag
        byte avail; // 1 bit
        byte is_64_code; // 1 bit: L flag
        byte db; // 1 bit: DB flag
        byte granularity; // 1 bit: G flag

        public SegmentDescriptor() {
        }

        // VERY basic descriptor init function, sets many fields to user space sane
        // defaults
        public SegmentDescriptor(int base, int limit, boolean is_code) {
            this.base = base;
            if (limit > 0xfffff) {
                // need Giant granularity
                limit >>= 12;
                this.granularity = 1;
            }
            this.limit = limit;

            // some sane defaults
            this.dpl = 3;
            this.present = 1;
            this.db = 1; // 32 bit
            this.type = is_code ? (byte) 0xb : 3;
            this.system = 1; // code or data
        }

        public void appendToBuffer(ByteBuffer buf) {
            buf.putShort((short) limit);
            buf.putShort((short) base);
            buf.put((byte) (base >>> 16));
            buf.put(
                (byte) (type | (system << 4) | (dpl << 5) | (present << 7)));
            buf.put((byte) (((limit >>> 16) & 0xf) | (avail << 4) |
                (is_64_code << 5) | (db << 6) | (granularity << 7)));
            buf.put((byte) (base >>> 24));
        }
    }

    public static void test_x86_mmr() {
        System.out.println("Test x86 MMR read/write");
        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);

        // map 4k 
        uc.mem_map(0x400000, 0x1000, UC_PROT_ALL);

        X86_MMR ldtr1 = new X86_MMR(0x1111111122222222L, 0x33333333, 0x44444444,
            (short) 0x5555);
        X86_MMR ldtr2;
        X86_MMR gdtr1 = new X86_MMR(0x6666666677777777L, 0x88888888, 0x99999999,
            (short) 0xaaaa);
        X86_MMR gdtr2;

        long eax;

        // initialize machine registers

        uc.reg_write(UC_X86_REG_LDTR, ldtr1);
        uc.reg_write(UC_X86_REG_GDTR, gdtr1);
        uc.reg_write(UC_X86_REG_EAX, 0xddddddddL);

        // read the registers back out   
        eax = uc.reg_read(UC_X86_REG_EAX);
        ldtr2 = (X86_MMR) uc.reg_read(UC_X86_REG_LDTR, null);
        gdtr2 = (X86_MMR) uc.reg_read(UC_X86_REG_GDTR, null);

        System.out.printf(">>> EAX = 0x%x\n", eax);

        System.out.printf(">>> LDTR.base = 0x%x\n", ldtr2.base);
        System.out.printf(">>> LDTR.limit = 0x%x\n", ldtr2.limit);
        System.out.printf(">>> LDTR.flags = 0x%x\n", ldtr2.flags);
        System.out.printf(">>> LDTR.selector = 0x%x\n\n", ldtr2.selector);

        System.out.printf(">>> GDTR.base = 0x%x\n", gdtr2.base);
        System.out.printf(">>> GDTR.limit = 0x%x\n", gdtr2.limit);
    }

    public static void gdt_demo() {
        System.out.println("Demonstrate GDT usage");
        /*
           bits 32
        
           push dword 0x01234567
           push dword 0x89abcdef
        
           mov dword [fs:0], 0x01234567
           mov dword [fs:4], 0x89abcdef
         */
        final byte[] code =
            Utils.hexToBytes("686745230168efcdab8964c70500000000" +
                "6745230164c70504000000efcdab89");
        final long code_address = 0x1000000L;
        final long stack_address = 0x120000L;
        final long gdt_address = 0xc0000000L;
        final long fs_address = 0x7efdd000L;

        SegmentDescriptor[] gdt = new SegmentDescriptor[31];

        int r_esp = (int) stack_address + 0x1000; // initial esp
        int r_cs = 0x73;
        int r_ss = 0x88; // ring 0
        int r_ds = 0x7b;
        int r_es = 0x7b;
        int r_fs = 0x83;

        X86_MMR gdtr =
            new X86_MMR(gdt_address, gdt.length * SegmentDescriptor.BYTES - 1);

        gdt[14] = new SegmentDescriptor(0, 0xfffff000, true); // code segment
        gdt[15] = new SegmentDescriptor(0, 0xfffff000, false); // data segment
        gdt[16] = new SegmentDescriptor((int) fs_address, 0xfff, false); // one page data segment simulate fs
        gdt[17] = new SegmentDescriptor(0, 0xfffff000, false); // ring 0 data
        gdt[17].dpl = 0; // set descriptor privilege level

        // Initialize emulator in X86-32bit mode
        Unicorn uc = new Unicorn(UC_ARCH_X86, UC_MODE_32);
        uc.hook_add(hook_code, code_address, code_address + code.length, null);
        uc.hook_add(hook_mem, UC_HOOK_MEM_WRITE, 1, 0, null);

        // map 1 page of code for this emulation
        uc.mem_map(code_address, 0x1000, UC_PROT_ALL);
        // map 1 page of stack for this emulation
        uc.mem_map(stack_address, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
        // map 64k for a GDT
        uc.mem_map(gdt_address, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
        // set up a GDT BEFORE you manipulate any segment registers
        uc.reg_write(UC_X86_REG_GDTR, gdtr);
        // write gdt to be emulated to memory
        ByteBuffer gdt_buf =
            ByteBuffer.allocate(gdt.length * SegmentDescriptor.BYTES)
                    .order(ByteOrder.LITTLE_ENDIAN);
        for (SegmentDescriptor desc : gdt) {
            if (desc == null) {
                gdt_buf.put(new byte[SegmentDescriptor.BYTES]);
            } else {
                desc.appendToBuffer(gdt_buf);
            }
        }
        uc.mem_write(gdt_address, gdt_buf.array());
        // map 1 page for FS
        uc.mem_map(fs_address, 0x1000, UC_PROT_WRITE | UC_PROT_READ);
        // write machine code to be emulated to memory
        uc.mem_write(code_address, code);
        // initialize machine registers
        uc.reg_write(UC_X86_REG_ESP, r_esp);
        // when setting SS, need rpl == cpl && dpl == cpl
        // emulator starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0
        // selector
        uc.reg_write(UC_X86_REG_SS, r_ss);
        uc.reg_write(UC_X86_REG_CS, r_cs);
        uc.reg_write(UC_X86_REG_DS, r_ds);
        uc.reg_write(UC_X86_REG_ES, r_es);
        uc.reg_write(UC_X86_REG_FS, r_fs);
        // emulate machine code in infinite time
        uc.emu_start(code_address, code_address + code.length, 0, 0);

        // read from memory
        byte[] buf = uc.mem_read(r_esp - 8, 8);
        for (int i = 0; i < 8; i++) {
            System.out.format("%02x", buf[i] & 0xff);
        }
        System.out.println();

        assert Arrays.equals(buf, Utils.hexToBytes("efcdab8967452301"));

        // read from memory
        buf = uc.mem_read(fs_address, 8);
        assert Arrays.equals(buf, Utils.hexToBytes("67452301efcdab89"));
    }

    public static void main(String args[]) {
        test_x86_mmr();
        System.out.println("===================================");
        gdt_demo();
    }

}
