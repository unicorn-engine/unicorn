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
using System.Text;
using UnicornEngine;
using UnicornEngine.Const;

namespace UnicornTests
{
    class Program
    {
        private const Int64 ADDRESS = 0x1000000;
        
        private static Int32[] X86_CODE32_SELF =
            {
                -21, 28, 90, -119, -42, -117, 2, 102, 61, -54, 125, 117, 6, 102, 5, 3, 3, -119, 2, -2, -62, 61, 65, 65,
                65, 65, 117, -23, -1, -26, -24, -33, -1, -1, -1, 49, -46, 106, 11, 88, -103, 82, 104, 47, 47, 115, 104,
                104, 47, 98, 105, 110, -119, -29, 82, 83, -119, -31, -54, 125, 65, 65, 65, 65, 65, 65, 65, 65
            };

        private static UInt64 ToInt(Byte[] val)
        {
            UInt64 res = 0;
            for (var i = 0; i < val.Length; i++)
            {
                var v = val[i] & 0xFF;
                res += (UInt64)(v << (i * 8));
            }
            return res;
        }


        private static void CheckError(Int32 err)
        {
            if (err != Common.UC_ERR_OK)
            {
                throw new ApplicationException("Operation failed, error: " + UcError.toErrorDesc(err));
            }
        }

        private static Byte[] Int64ToBytes(Int64 intVal)
        {
            var res = new Byte[8];
            for (var i = 0; i < res.Length; i++)
            {
                res[i] = (Byte)(intVal & 0xff);
                intVal = (Int64)((UInt64)intVal >> 8);
            }
            return res;
        }

        private static Byte[] ToBytes(IEnumerable<int> ints)
        {
            var bytes = new List<Byte>();
            foreach (var i in ints)
            {
                var b = (Byte) i;
                bytes.Add(b);
            }
            return bytes.ToArray();
        }

        private static void CodeHookCallback(Unicorn u, UInt64 addr, Int32 size, Object userData)
        {
            Console.Write("Tracing >>> 0x{0} ", addr.ToString("X"));

            var eipBuffer = new Byte[4];
            CheckError(u.RegRead(X86.UC_X86_REG_EIP, eipBuffer));
         
            var effectiveSize = Math.Min(16, size);
            var tmp = new Byte[effectiveSize];
            CheckError(u.MemRead(addr, tmp));

            foreach (var t in tmp)
            {
                Console.Write("{0} ", (0xFF & t).ToString("X"));
            }

            Console.WriteLine();
        }

        private static void InterruptHookCallback(Unicorn u, Int32 intNumber, Object userData)
        {
            // only handle Linux syscall
            if (intNumber != 0x80)
            {
                return;
            }

            var eaxBuffer = new Byte[4];
            var eipBuffer = new Byte[4];

            CheckError(u.RegRead(X86.UC_X86_REG_EAX, eaxBuffer));
            CheckError(u.RegRead(X86.UC_X86_REG_EIP, eipBuffer));

            var eax = ToInt(eaxBuffer);
            var eip = ToInt(eipBuffer);

            switch (eax)
            {
                default:
                    Console.WriteLine("Interrupt >>> 0x{0} num {1}, EAX=0x{2}", eip.ToString("X"), intNumber.ToString("X"), eax.ToString("X"));
                    break;
                case 1: // sys_exit
                    Console.WriteLine("Interrupt >>> 0x{0} num {1}, SYS_EXIT", eip.ToString("X"), intNumber.ToString("X"));
                    u.EmuStop();
                    break;
                case 4: // sys_write
                    
                    // ECX = buffer address
                    var ecxBuffer = new Byte[4];

                    // EDX = buffer size
                    var edxBuffer = new Byte[4];

                    CheckError(u.RegRead(X86.UC_X86_REG_ECX, ecxBuffer));
                    CheckError(u.RegRead(X86.UC_X86_REG_EDX, edxBuffer));

                    var ecx = ToInt(ecxBuffer);
                    var edx = ToInt(edxBuffer);

                    // read the buffer in
                    var size = Math.Min(256, edx);
                    var buffer = new Byte[size];
                    CheckError(u.MemRead(ecx, buffer));
                    var content = Encoding.Default.GetString(buffer);

                    Console.WriteLine(
                        "Interrupt >>> 0x{0}: num {1}, SYS_WRITE. buffer = 0x{2}, size = , content = '{3}'", 
                        eip.ToString("X"), 
                        ecx.ToString("X"),
                        edx.ToString("X"),
                        content);

                    break;
            }
        }
        
        static unsafe void Main(String[] args)
        {
            var u = new Unicorn((UInt32)Common.UC_ARCH_X86, (UInt32)Common.UC_MODE_32);
            Console.WriteLine("Unicorn version: {0}", u.Version());

            // map 2MB of memory for this emulation
            CheckError(u.MemMap(ADDRESS, new UIntPtr(2 * 1024 * 1024), Common.UC_PROT_ALL));

            // write machine code to be emulated to memory
            CheckError(u.MemWrite(ADDRESS, ToBytes(X86_CODE32_SELF)));

            // initialize machine registers
            CheckError(u.RegWrite(X86.UC_X86_REG_ESP, Int64ToBytes(ADDRESS + 0x200000)));

            // tracing all instructions by having @begin > @end
            CheckError(u.AddCodeHook(CodeHookCallback, null, 1, 0).Item1);

            // handle interrupt ourself
            CheckError(u.AddInterruptHook(InterruptHookCallback, null).Item1);

            Console.WriteLine();
            Console.WriteLine(">>> Start tracing linux code");

            // emulate machine code in infinite time
            u.EmuStart(ADDRESS, (UInt64)(ADDRESS + X86_CODE32_SELF.Length), 0u, new UIntPtr(0));

            Console.WriteLine();
            Console.WriteLine(">>> Emulation Done!");
        }
    }
}
