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

/** ARM64 coprocessor registers for instructions MRS, MSR, SYS, SYSL */
public class Arm64_CP {
    public int crn, crm, op0, op1, op2;
    public long val;

    public Arm64_CP(int crn, int crm, int op0, int op1, int op2) {
        this(crn, crm, op0, op1, op2, 0);
    }

    public Arm64_CP(int crn, int crm, int op0, int op1, int op2, long val) {
        this.crn = crn;
        this.crm = crm;
        this.op0 = op0;
        this.op1 = op1;
        this.op2 = op2;
        this.val = val;
    }

    @Override
    public String toString() {
        return "Arm64_CP [crn=" + crn + ", crm=" + crm + ", op0=" + op0 +
            ", op1=" + op1 + ", op2=" + op2 + ", val=" + val + "]";
    }
}
