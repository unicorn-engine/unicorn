-- Sample code to demonstrate how to emulate Sparc code

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.Sparc as Sparc

import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)

-- Code to be emulated
--
-- add %g1, %g2, %g3
sparcCode :: BS.ByteString
sparcCode = BS.pack [0x86, 0x00, 0x40, 0x02]

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

testSparc :: IO ()
testSparc = do
    putStrLn "Emulate SPARC code"

    result <- runEmulator $ do
        -- Initialize emulator in Sparc mode
        uc <- open ArchSparc [ModeSparc32, ModeBigEndian]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address sparcCode

        -- Initialize machine registers
        regWrite uc Sparc.G1 0x1230
        regWrite uc Sparc.G2 0x6789
        regWrite uc Sparc.G3 0x5555

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instructions with customized callback
        codeHookAdd uc hookCode () 1 0

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength sparcCode
        start uc address (address + codeLen) Nothing Nothing

        -- Return results
        g3 <- regRead uc Sparc.G3

        return g3
    case result of
        Right g3 -> do
            -- Now print out some registers
            putStrLn ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> G3 = 0x" ++ showHex g3
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

main :: IO ()
main =
    testSparc
