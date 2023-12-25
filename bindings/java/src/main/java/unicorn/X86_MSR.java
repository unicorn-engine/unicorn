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

/** Model-specific register */
public class X86_MSR {
    public int rid;
    public long value;

    public X86_MSR(int rid) {
        this(rid, 0);
    }

    public X86_MSR(int rid, long value) {
        this.rid = rid;
        this.value = value;
    }

    @Override
    public String toString() {
        return "X86_MSR [rid=" + rid + ", value=" + value + "]";
    }
}
