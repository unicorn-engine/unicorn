namespace UnicornManaged

open System

[<AutoOpen>]
module internal ConvertUtility =

    let int64ToBytes(v: Int64) =
        let res = Array.zeroCreate<Byte> 8
        let mutable uv = uint64 v
        for i = 0 to res.Length-1 do
            res.[i] <- byte (uv &&& uint64 0xFF) 
            uv <- uv >>> 8
        res

    let bytesToInt64(v: Byte array) =
        let mutable res = uint64 0
        for i = 0 to v.Length-1 do
            let tmpV = v.[i] &&& byte 0xFF
            res <- res + (uint64 tmpV <<< (i * 8))
        int64 res