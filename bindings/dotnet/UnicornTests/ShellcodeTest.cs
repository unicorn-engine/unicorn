using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using UnicornEngine;
using UnicornEngine.Const;

namespace UnicornTests
{
    internal class ShellcodeTest
    {
        private const UInt64 ADDRESS = 0x1000000;

        public static void TestX86Code32Self()
        {
            Byte[] X86_CODE32_SELF =
            {
                0xeb, 0x1c, 0x5a, 0x89, 0xd6, 0x8b, 0x02, 0x66, 0x3d, 0xca, 0x7d, 0x75, 0x06, 0x66, 0x05, 0x03, 0x03,
                0x89, 0x02, 0xfe, 0xc2, 0x3d, 0x41, 0x41, 0x41, 0x41, 0x75, 0xe9, 0xff, 0xe6, 0xe8, 0xdf, 0xff, 0xff,
                0xff, 0x31, 0xd2, 0x6a, 0x0b, 0x58, 0x99, 0x52, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69,
                0x6e, 0x89, 0xe3, 0x52, 0x53, 0x89, 0xe1, 0xca, 0x7d, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
            };

            Console.WriteLine();
            Console.WriteLine("*** Start Shellcode: " + MethodInfo.GetCurrentMethod().Name);
            RunTest(X86_CODE32_SELF, ADDRESS);
            Console.WriteLine("End Shellcode: " + MethodInfo.GetCurrentMethod().Name);
            Console.WriteLine();
        }

        public static void TestX86Code32()
        {
            Byte[] X86_CODE32 =
            {
                0xeb, 0x19, 0x31, 0xc0, 0x31, 0xdb, 0x31, 0xd2, 0x31, 0xc9, 0xb0, 0x04, 0xb3, 0x01, 0x59, 0xb2, 0x05,
                0xcd, 0x80, 0x31, 0xc0, 0xb0, 0x01, 0x31, 0xdb, 0xcd, 0x80, 0xe8, 0xe2, 0xff, 0xff, 0xff, 0x68, 0x65,
                0x6c, 0x6c, 0x6f
            };

            Console.WriteLine();
            Console.WriteLine("*** Start Shellcode: " + MethodInfo.GetCurrentMethod().Name);
            RunTest(X86_CODE32, ADDRESS);
            Console.WriteLine("End Shellcode: " + MethodInfo.GetCurrentMethod().Name);
            Console.WriteLine();
        }
        

        public static void RunTest(Byte[] code, UInt64 address)
        {
            var u = new Unicorn(Common.UC_ARCH_X86, Common.UC_MODE_32);
            Console.WriteLine("Unicorn version: {0}", u.Version());

            // map 2MB of memory for this emulation
            Utils.CheckError(u.MemMap(address, new UIntPtr(2 * 1024 * 1024), Common.UC_PROT_ALL));

            // write machine code to be emulated to memory
            Utils.CheckError(u.MemWrite(address, code));

            // initialize machine registers
            Utils.CheckError(u.RegWrite(X86.UC_X86_REG_ESP, Utils.Int64ToBytes(address + 0x200000)));

            // tracing all instructions by having @begin > @end
            Utils.CheckError(u.AddCodeHook(CodeHookCallback, null, 1, 0).Item1);

            // handle interrupt ourself
            Utils.CheckError(u.AddInterruptHook(InterruptHookCallback, null).Item1);

            // handle SYSCALL
            Utils.CheckError(u.AddSyscallHook(SyscallHookCallback, null).Item1);

            Console.WriteLine(">>> Start tracing linux code");

            // emulate machine code in infinite time
            u.EmuStart(address, address + (UInt64)code.Length, 0u, new UIntPtr(0));

            Console.WriteLine(">>> Emulation Done!");
        }

        private static void CodeHookCallback(Unicorn u, UInt64 addr, Int32 size, Object userData)
        {
            Console.Write("Tracing >>> 0x{0} ", addr.ToString("X"));

            var eipBuffer = new Byte[4];
            Utils.CheckError(u.RegRead(X86.UC_X86_REG_EIP, eipBuffer));

            var effectiveSize = Math.Min(16, size);
            var tmp = new Byte[effectiveSize];
            Utils.CheckError(u.MemRead(addr, tmp));

            foreach (var t in tmp)
            {
                Console.Write("{0} ", (0xFF & t).ToString("X"));
            }

            Console.WriteLine();
        }

        private static void SyscallHookCallback(Unicorn u, Object userData)
        {
            var eaxBuffer = new Byte[4];
            Utils.CheckError(u.RegRead(X86.UC_X86_REG_EAX, eaxBuffer));
            var eax = Utils.ToInt(eaxBuffer);

            Console.WriteLine("Syscall >>> EAX = 0x{0}", eax.ToString("X"));

            u.EmuStop();
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

            Utils.CheckError(u.RegRead(X86.UC_X86_REG_EAX, eaxBuffer));
            Utils.CheckError(u.RegRead(X86.UC_X86_REG_EIP, eipBuffer));

            var eax = Utils.ToInt(eaxBuffer);
            var eip = Utils.ToInt(eipBuffer);

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

                    Utils.CheckError(u.RegRead(X86.UC_X86_REG_ECX, ecxBuffer));
                    Utils.CheckError(u.RegRead(X86.UC_X86_REG_EDX, edxBuffer));

                    var ecx = Utils.ToInt(ecxBuffer);
                    var edx = Utils.ToInt(edxBuffer);

                    // read the buffer in
                    var size = Math.Min(256, edx);
                    var buffer = new Byte[size];
                    Utils.CheckError(u.MemRead(ecx, buffer));
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
    }
}
