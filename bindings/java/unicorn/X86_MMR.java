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

package unicorn;

public class X86_MMR {

   public long base;
   public int limit;
   public int flags;
   public short selector;

   public X86_MMR(long base, int limit, int flags, short selector) {
      this.base = base;
      this.limit = limit;
      this.flags = flags;
      this.selector = selector;
   }

   public X86_MMR(long base, int limit) {
      this.base = base;
      this.limit = limit;
      selector = 0;
      flags = 0;
   }

}

