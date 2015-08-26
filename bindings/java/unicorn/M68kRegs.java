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

public interface M68kRegs {
   public static final int UC_M68K_REG_INVALID = 0;
   public static final int UC_M68K_REG_A0 = 1;
   public static final int UC_M68K_REG_A1 = 2;
   public static final int UC_M68K_REG_A2 = 3;
   public static final int UC_M68K_REG_A3 = 4;
   public static final int UC_M68K_REG_A4 = 5;
   public static final int UC_M68K_REG_A5 = 6;
   public static final int UC_M68K_REG_A6 = 7;
   public static final int UC_M68K_REG_A7 = 8;
   public static final int UC_M68K_REG_D0 = 9;
   public static final int UC_M68K_REG_D1 = 10;
   public static final int UC_M68K_REG_D2 = 11;
   public static final int UC_M68K_REG_D3 = 12;
   public static final int UC_M68K_REG_D4 = 13;
   public static final int UC_M68K_REG_D5 = 14;
   public static final int UC_M68K_REG_D6 = 15;
   public static final int UC_M68K_REG_D7 = 16;
   public static final int UC_M68K_REG_SR = 17;
   public static final int UC_M68K_REG_PC = 18;
   public static final int UC_M68K_REG_ENDING = 19;
}
