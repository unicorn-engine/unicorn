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

public class X86_Float80 {
    public long mantissa;
    public short exponent;

    public X86_Float80(long mantissa, short exponent) {
        this.mantissa = mantissa;
        this.exponent = exponent;
    }

    public double toDouble() {
        boolean sign = (exponent & 0x8000) != 0;
        int exp = exponent & 0x7fff;
        if (exp == 0) {
            return sign ? -0.0 : 0.0;
        } else if (exp == 0x7fff) {
            if (((mantissa >> 62) & 1) == 0) {
                return sign ? Double.NEGATIVE_INFINITY
                        : Double.POSITIVE_INFINITY;
            } else {
                return Double.NaN;
            }
        } else {
            exp -= 16383;
            double f = mantissa >>> 1;
            return Math.scalb(sign ? -f : f, exp - 62);
        }
    }

    public static X86_Float80 fromDouble(double val) {
        if (Double.isNaN(val)) {
            return new X86_Float80(-1L, (short) -1);
        } else if (Double.isInfinite(val)) {
            return new X86_Float80(1L << 63,
                (short) (val < 0 ? 0xffff : 0x7fff));
        } else {
            int exp = Math.getExponent(val);
            long mantissa = ((long) Math.scalb(Math.abs(val), 62 - exp)) << 1;
            exp += 16383;
            return new X86_Float80(mantissa,
                (short) (val < 0 ? (exp | 0x8000) : exp));
        }
    }

    @Override
    public String toString() {
        return "X86_Float80 [mantissa=" + mantissa + ", exponent=" + exponent +
            "]";
    }
}
