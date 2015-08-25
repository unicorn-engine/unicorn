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

public interface UnicornArchs {
   public static final int UC_ARCH_ARM   = 1;      // ARM architecture (including Thumb, Thumb-2)
   public static final int UC_ARCH_ARM64 = 2;      // ARM-64, also called AArch64
   public static final int UC_ARCH_MIPS  = 3;      // Mips architecture
   public static final int UC_ARCH_X86   = 4;      // X86 architecture (including x86 & x86-64)
   public static final int UC_ARCH_PPC   = 5;      // PowerPC architecture
   public static final int UC_ARCH_SPARC = 6;      // Sparc architecture
   public static final int UC_ARCH_M68K  = 7;      // M68K architecture
   public static final int UC_ARCH_MAX   = 8;
   public static final int UC_ARCH_ALL   = 0xFFFF; // All architectures - for uc_support()
}
