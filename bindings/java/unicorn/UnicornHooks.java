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

public interface UnicornHooks {

   public static final int UC_MEM_READ = 16;        // Memory is read from
   public static final int UC_MEM_WRITE = 17;       // Memory is written to
   public static final int UC_MEM_READ_WRITE = 18;  // Memory is accessed (either READ or WRITE)

   public static final int UC_HOOK_INTR = 32;           // Hook all interrupt events
   public static final int UC_HOOK_INSN = 33;           // Hook a particular instruction
   public static final int UC_HOOK_CODE = 34;           // Hook a range of code
   public static final int UC_HOOK_BLOCK = 35;          // Hook basic blocks
   public static final int UC_HOOK_MEM_INVALID = 36;    // Hook for all invalid memory access events
   public static final int UC_HOOK_MEM_READ = 37;       // Hook all memory read events.
   public static final int UC_HOOK_MEM_WRITE = 38;      // Hook all memory write events.
   public static final int UC_HOOK_MEM_READ_WRITE = 39; // Hook all memory accesses (either READ or WRITE).
}
