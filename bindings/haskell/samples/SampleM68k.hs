-- Sample code to demonstrate how to emulate m68k code

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.M68k as M68k

import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)

-- Code to be emulated
--
-- movq #-19, %d3
m68kCode :: BS.ByteString
m68kCode = BS.pack [0x76, 0xed]

-- Memory address where emulation starts
address :: Word64
address = 0x10000

-- Pretty-print integral as hex
showHex :: (Integral a, Show a) => a -> String
showHex =
    flip N.showHex ""

-- Calculate code length
codeLength :: Num a => BS.ByteString -> a
codeLength =
    fromIntegral . BS.length

hookBlock :: BlockHook ()
hookBlock _ addr size _ =
    putStrLn $ ">>> Tracing basic block at 0x" ++ showHex addr ++
               ", block size = 0x" ++ (maybe "0" showHex size)

hookCode :: CodeHook ()
hookCode _ addr size _ =
    putStrLn $ ">>> Tracing instruction at 0x" ++ showHex addr ++
               ", instruction size = 0x" ++ (maybe "0" showHex size)

testM68k :: IO ()
testM68k = do
    putStrLn "Emulate M68K code"

    result <- runEmulator $ do
        -- Initialize emulator in M68K mode
        uc <- open ArchM68k [ModeBigEndian]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address m68kCode

        -- Initialize machine registers
        regWrite uc M68k.D0 0x0000
        regWrite uc M68k.D1 0x0000
        regWrite uc M68k.D2 0x0000
        regWrite uc M68k.D3 0x0000
        regWrite uc M68k.D4 0x0000
        regWrite uc M68k.D5 0x0000
        regWrite uc M68k.D6 0x0000
        regWrite uc M68k.D7 0x0000

        regWrite uc M68k.A0 0x0000
        regWrite uc M68k.A1 0x0000
        regWrite uc M68k.A2 0x0000
        regWrite uc M68k.A3 0x0000
        regWrite uc M68k.A4 0x0000
        regWrite uc M68k.A5 0x0000
        regWrite uc M68k.A6 0x0000
        regWrite uc M68k.A7 0x0000

        regWrite uc M68k.Pc 0x0000
        regWrite uc M68k.Sr 0x0000

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instruction
        codeHookAdd uc hookCode () 1 0

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength m68kCode
        start uc address (address + codeLen) Nothing Nothing

        -- Return the results
        d0 <- regRead uc M68k.D0
        d1 <- regRead uc M68k.D1
        d2 <- regRead uc M68k.D2
        d3 <- regRead uc M68k.D3
        d4 <- regRead uc M68k.D4
        d5 <- regRead uc M68k.D5
        d6 <- regRead uc M68k.D6
        d7 <- regRead uc M68k.D7

        a0 <- regRead uc M68k.A0
        a1 <- regRead uc M68k.A1
        a2 <- regRead uc M68k.A2
        a3 <- regRead uc M68k.A3
        a4 <- regRead uc M68k.A4
        a5 <- regRead uc M68k.A5
        a6 <- regRead uc M68k.A6
        a7 <- regRead uc M68k.A7

        pc <- regRead uc M68k.Pc
        sr <- regRead uc M68k.Sr

        return (d0, d1, d2, d3, d4, d5, d6, d7,
                a0, a1, a2, a3, a4, a5, a6, a7,
                pc, sr)
    case result of
        Right (d0, d1, d2, d3, d4, d5, d6, d7,
               a0, a1, a2, a3, a4, a5, a6, a7,
               pc, sr) -> do
            -- Now print out some registers
            putStrLn ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> A0 = 0x" ++ showHex a0 ++
                       "\t\t>>> D0 = 0x" ++ showHex d0
            putStrLn $ ">>> A1 = 0x" ++ showHex a1 ++
                       "\t\t>>> D1 = 0x" ++ showHex d1
            putStrLn $ ">>> A2 = 0x" ++ showHex a2 ++
                       "\t\t>>> D2 = 0x" ++ showHex d2
            putStrLn $ ">>> A3 = 0x" ++ showHex a3 ++
                       "\t\t>>> D3 = 0x" ++ showHex d3
            putStrLn $ ">>> A4 = 0x" ++ showHex a4 ++
                       "\t\t>>> D4 = 0x" ++ showHex d4
            putStrLn $ ">>> A5 = 0x" ++ showHex a5 ++
                       "\t\t>>> D5 = 0x" ++ showHex d5
            putStrLn $ ">>> A6 = 0x" ++ showHex a6 ++
                       "\t\t>>> D6 = 0x" ++ showHex d6
            putStrLn $ ">>> A7 = 0x" ++ showHex a7 ++
                       "\t\t>>> D7 = 0x" ++ showHex d7
            putStrLn $ ">>> PC = 0x" ++ showHex pc
            putStrLn $ ">>> SR = 0x" ++ showHex sr
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

main :: IO ()
main =
    testM68k
