using Gee.External.Capstone.X86;
using System;
using System.Text;

namespace UnicornSamples
{
    internal static class Utils
    {
        public static long ToInt(byte[] val)
        {
            ulong res = 0;
            for (var i = 0; i < val.Length; i++)
            {
                var v = val[i] & 0xFF;
                res += (ulong)(v << (i * 8));
            }
            return (long)res;
        }

        public static byte[] Int64ToBytes(long intVal)
        {
            var res = new byte[8];
            var uval = (ulong)intVal;
            for (var i = 0; i < res.Length; i++)
            {
                res[i] = (byte)(uval & 0xff);
                uval = uval >> 8;
            }
            return res;
        }

        public static string Disassemble(CapstoneX86Disassembler disassembler, byte[] code)
        {
            var sb = new StringBuilder();
            var instructions = disassembler.Disassemble(code);
            foreach (var instruction in instructions)
            {
                sb.AppendFormat($"{instruction.Mnemonic} {instruction.Operand}{Environment.NewLine}");
            }
            return sb.ToString().Trim();
        }
    }
}
