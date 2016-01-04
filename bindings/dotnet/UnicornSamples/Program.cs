using System;

namespace UnicornSamples
{
    class Program
    {
        static void Main(string[] args)
        {
            // X86 tests
            X86Sample.X86Code32();
            //X86Sample.X86Code32Loop();
            X86Sample.X86Code32InvalidMemRead();
            X86Sample.X86Code32InvalidMemWrite();

            // Run all shellcode tests
            ShellcodeSample.X86Code32Self();
            ShellcodeSample.X86Code32();

            Console.Write("Tests completed");
            Console.ReadLine();
        }
    }
}
