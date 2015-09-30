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

public interface UnicornErrors {
   public static final int UC_ERR_OK = 0;       // No error: everything was fine
   public static final int UC_ERR_OOM = 1;      // Out-Of-Memory error: uc_open(), uc_emulate()
   public static final int UC_ERR_ARCH = 2;     // Unsupported architecture: uc_open()
   public static final int UC_ERR_HANDLE = 3;   // Invalid handle
   public static final int UC_ERR_UCH = 4;      // Invalid handle (uch)
   public static final int UC_ERR_MODE = 5;     // Invalid/unsupported mode: uc_open()
   public static final int UC_ERR_VERSION = 6;  // Unsupported version (bindings)
   public static final int UC_ERR_MEM_READ = 7; // Quit emulation due to invalid memory READ: uc_emu_start()
   public static final int UC_ERR_MEM_WRITE = 8; // Quit emulation due to invalid memory WRITE: uc_emu_start()
   public static final int UC_ERR_HOOK = 9;    // Invalid hook type: uc_hook_add()
   public static final int UC_ERR_INSN_INVALID = 10; // Quit emulation due to invalid instruction: uc_emu_start()
   public static final int UC_ERR_MAP = 11;     // Invalid memory mapping: uc_mem_map()
}

