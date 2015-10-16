/*

.NET bindings for the UnicornEngine Emulator Engine

Copyright(c) 2015 Antonio Parata

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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UnicornEngine.Const;

namespace UnicornTests
{
    internal static class Utils
    {
        public static UInt64 ToInt(Byte[] val)
        {
            UInt64 res = 0;
            for (var i = 0; i < val.Length; i++)
            {
                var v = val[i] & 0xFF;
                res += (UInt64)(v << (i * 8));
            }
            return res;
        }

        public static Byte[] Int64ToBytes(UInt64 intVal)
        {
            var res = new Byte[8];
            for (var i = 0; i < res.Length; i++)
            {
                res[i] = (Byte)(intVal & 0xff);
                intVal = intVal >> 8;
            }
            return res;
        }
    }
}
