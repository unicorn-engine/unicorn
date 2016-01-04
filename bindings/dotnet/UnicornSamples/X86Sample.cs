using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using UnicornManaged;
using UnicornManaged.Const;

namespace UnicornSamples
{
    internal class X86Sample
    {
        private const Int64 ADDRESS = 0x1000000;

        public static void X86Code32()
        {
            Byte[] X86_CODE32 =
            {
                // INC ecx; DEC edx
                0x41, 0x4a
            };
            Run(X86_CODE32);
        }

        public static void X86Code32Loop()
        {
            Byte[] X86_CODE32_LOOP =
            {
                // INC ecx; DEC edx; JMP self-loop
                0x41, 0x4a, 0xeb, 0xfe
            };
            Run(X86_CODE32_LOOP);
        }

        public static void X86Code32InvalidMemRead()
        {
            Byte[] X86_CODE32_MEM_READ =
            {
                // mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
                0x8B, 0x0D, 0xAA, 0xAA, 0xAA, 0xAA, 0x41, 0x4a
            };
            Run(X86_CODE32_MEM_READ, true);
        }

        public static void X86Code32InvalidMemWrite()
        {
            Byte[] X86_CODE32_MEM_WRITE =
            {
                // mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
                0x89, 0x0D, 0xAA, 0xAA, 0xAA, 0xAA, 0x41, 0x4a
            };
            Run(X86_CODE32_MEM_WRITE, true);
        }

        private static void Run(Byte[] code, Boolean raiseException = false)
        {
            Console.WriteLine();
            var stackTrace = new StackTrace();
            var stackFrame = stackTrace.GetFrames()[1];
            var methodName = stackFrame.GetMethod().Name;

            Console.WriteLine("*** Start: " + methodName);
            Exception e = null;
            try
            {
                RunTest(code, ADDRESS);
            }
            catch (UnicornEngineException ex)
            {
                e = ex;
            }

            if (!raiseException && e != null)
            {
                Console.Error.WriteLine("Emulation FAILED! " + e.Message);
            }

            Console.WriteLine("*** End: " + methodName);
            Console.WriteLine();
        }

        private static void RunTest(Byte[] code, Int64 address)
        {
            using (var u = new Unicorn(Common.UC_ARCH_X86, Common.UC_MODE_32))
            using (var disassembler = CapstoneDisassembler.CreateX86Disassembler(DisassembleMode.Bit32))
            {
                Console.WriteLine("Unicorn version: {0}", u.Version());

                // map 2MB of memory for this emulation
                u.MemMap(address, 2 * 1024 * 1024, Common.UC_PROT_ALL);

                // write machine code to be emulated to memory
                u.MemWrite(address, code);

                // initialize machine registers
                u.RegWrite(X86.UC_X86_REG_ESP, Utils.Int64ToBytes(address + 0x200000));

                // tracing all instructions by having @begin > @end
                u.AddCodeHook((uc, addr, size, userData) => CodeHookCallback(disassembler, uc, addr, size, userData), 1, 0);

                // handle interrupt ourself
                u.AddInterruptHook(InterruptHookCallback);

                // handle SYSCALL
                u.AddSyscallHook(SyscallHookCallback);

                Console.WriteLine(">>> Start tracing code");

                // emulate machine code in infinite time
                u.EmuStart(address, address + code.Length, 0u, 0u);

                Console.WriteLine(">>> Emulation Done!");
            }
        }        

        private static void CodeHookCallback(
            CapstoneDisassembler<X86Instruction, X86Register, X86InstructionGroup, X86InstructionDetail> disassembler,
            Unicorn u,
            Int64 addr,
            Int32 size,
            Object userData)
        {
            Console.Write("[+] 0x{0}: ", addr.ToString("X"));

            var eipBuffer = new Byte[4];
            u.RegRead(X86.UC_X86_REG_EIP, eipBuffer);

            var effectiveSize = Math.Min(16, size);
            var tmp = new Byte[effectiveSize];
            u.MemRead(addr, tmp);

            var sb = new StringBuilder();
            foreach (var t in tmp)
            {
                sb.AppendFormat("{0} ", (0xFF & t).ToString("X"));
            }
            Console.Write("{0,-20}", sb);
            Console.WriteLine(Utils.Disassemble(disassembler, tmp));
        }

        private static void SyscallHookCallback(Unicorn u, Object userData)
        {
            var eaxBuffer = new Byte[4];
            u.RegRead(X86.UC_X86_REG_EAX, eaxBuffer);
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

            u.RegRead(X86.UC_X86_REG_EAX, eaxBuffer);
            u.RegRead(X86.UC_X86_REG_EIP, eipBuffer);

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

                    u.RegRead(X86.UC_X86_REG_ECX, ecxBuffer);
                    u.RegRead(X86.UC_X86_REG_EDX, edxBuffer);

                    var ecx = Utils.ToInt(ecxBuffer);
                    var edx = Utils.ToInt(edxBuffer);

                    // read the buffer in
                    var size = Math.Min(256, edx);
                    var buffer = new Byte[size];
                    u.MemRead(ecx, buffer);
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
