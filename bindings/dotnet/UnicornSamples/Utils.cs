using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnicornSamples
{
    internal static class Utils
    {
        public static Int64 ToInt(Byte[] val)
        {
            UInt64 res = 0;
            for (var i = 0; i < val.Length; i++)
            {
                var v = val[i] & 0xFF;
                res += (UInt64)(v << (i * 8));
            }
            return (Int64)res;
        }

        public static Byte[] Int64ToBytes(Int64 intVal)
        {
            var res = new Byte[8];
            var uval = (UInt64)intVal;
            for (var i = 0; i < res.Length; i++)
            {
                res[i] = (Byte)(uval & 0xff);
                uval = uval >> 8;
            }
            return res;
        }

        public static String Disassemble(CapstoneDisassembler<X86Instruction, X86Register, X86InstructionGroup, X86InstructionDetail> disassembler, Byte[] code)
        {
            var sb = new StringBuilder();
            var instructions = disassembler.DisassembleAll(code);
            foreach (var instruction in instructions)
            {
                sb.AppendFormat("{0} {1}{2}", instruction.Mnemonic, instruction.Operand, Environment.NewLine);
            }
            return sb.ToString().Trim();
        }
    }
}
