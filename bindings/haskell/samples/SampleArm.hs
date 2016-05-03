-- Sample code to demonstrate how to emulate ARM code

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.Arm as Arm

import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)

-- Code to be emulated
--
-- mov r0, #0x37; sub r1, r2, r3
armCode :: BS.ByteString
armCode = BS.pack [0x37, 0x00, 0xa0, 0xe3, 0x03, 0x10, 0x42, 0xe0]

-- sub sp, #0xc
thumbCode :: BS.ByteString
thumbCode = BS.pack [0x83, 0xb0]

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

testArm :: IO ()
testArm = do
    putStrLn "Emulate ARM code"

    result <- runEmulator $ do
        -- Initialize emulator in ARM mode
        uc <- open ArchArm [ModeArm]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address armCode

        -- Initialize machine registers
        regWrite uc Arm.R0 0x1234
        regWrite uc Arm.R2 0x6789
        regWrite uc Arm.R3 0x3333

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing one instruction at address with customized callback
        codeHookAdd uc hookCode () address address

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength armCode
        start uc address (address + codeLen) Nothing Nothing

        -- Return the results
        r0 <- regRead uc Arm.R0
        r1 <- regRead uc Arm.R1

        return (r0, r1)
    case result of
        Right (r0, r1) -> do
            -- Now print out some registers
            putStrLn ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> R0 = 0x" ++ showHex r0
            putStrLn $ ">>> R1 = 0x" ++ showHex r1
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                                strerror err ++ ")"

testThumb :: IO ()
testThumb = do
    putStrLn "Emulate THUMB code"

    result <- runEmulator $ do
        -- Initialize emulator in ARM mode
        uc <- open ArchArm [ModeThumb]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address thumbCode

        -- Initialize machine registers
        regWrite uc Arm.Sp 0x1234

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing one instruction at address with customized callback
        codeHookAdd uc hookCode () address address

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength thumbCode
        start uc address (address + codeLen) Nothing Nothing

        -- Return the results
        sp <- regRead uc Arm.Sp

        return sp
    case result of
        Right sp -> do
            -- Now print out some registers
            putStrLn ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> SP = 0x" ++ showHex sp
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

main :: IO ()
main = do
    testArm
    putStrLn "=========================="
    testThumb
