using System;

namespace UnicornSamples
{
    class Program
    {
        static void Main(string[] args)
        {
            // X86 tests 32bit
            X86Sample32.X86Code32();
            X86Sample32.X86Code32InvalidMemRead();
            X86Sample32.X86Code32InvalidMemWriteWithRuntimeFix();
            X86Sample32.X86Code32InOut();

            // Run all shellcode tests
            ShellcodeSample.X86Code32Self();
            ShellcodeSample.X86Code32();

            Console.Write("Tests completed");
            Console.ReadLine();
        }
    }
}
