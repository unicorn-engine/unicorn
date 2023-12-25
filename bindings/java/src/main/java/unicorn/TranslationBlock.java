/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2023 Robert Xiao

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

/** uc_tb */
public class TranslationBlock {
    public long pc;
    public int icount;
    public int size;

    public TranslationBlock(long pc, int icount, int size) {
        this.pc = pc;
        this.icount = icount;
        this.size = size;
    }

    @Override
    public String toString() {
        return String.format("TranslationBlock [pc=0x%x, icount=%d, size=%d]",
            pc, icount, size);
    }
}
