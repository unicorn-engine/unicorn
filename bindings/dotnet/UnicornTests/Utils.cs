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

        public static void CheckError(Int32 err)
        {
            if (err != Common.UC_ERR_OK)
            {
                throw new ApplicationException("Operation failed, error: " + err);
            }
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
