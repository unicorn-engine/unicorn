-- Sample code to demonstrate how to emulate ARM64 code

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.Arm64 as Arm64

import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)

-- Code to be emulated
--
-- add x11, x13, x15
armCode :: BS.ByteString
armCode = BS.pack [0xab, 0x01, 0x0f, 0x8b]

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

testArm64 :: IO ()
testArm64 = do
    putStrLn "Emulate ARM64 code"

    result <- runEmulator $ do
        -- Initialize emulator in ARM mode
        uc <- open ArchArm64 [ModeArm]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address armCode

        -- Initialize machine registers
        regWrite uc Arm64.X11 0x1234
        regWrite uc Arm64.X13 0x6789
        regWrite uc Arm64.X15 0x3333

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing one instruction at address with customized callback
        codeHookAdd uc hookCode () address address

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength armCode
        start uc address (address + codeLen) Nothing Nothing

        -- Return the results
        x11 <- regRead uc Arm64.X11

        return x11
    case result of
        Right x11 -> do
            -- Now print out some registers
            putStrLn $ ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> X11 = 0x" ++ showHex x11
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

main :: IO ()
main =
    testArm64
