-- Sample code to demonstrate how to emulate Mips code (big endian)

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.Mips as Mips

import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)

-- Code to be emulated
--
-- ori $at, $at, 0x3456
mipsCodeEb :: BS.ByteString
mipsCodeEb = BS.pack [0x34, 0x21, 0x34, 0x56]

-- ori $at, $at, 0x3456
mipsCodeEl :: BS.ByteString
mipsCodeEl = BS.pack [0x56, 0x34, 0x21, 0x34]

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

testMipsEb :: IO ()
testMipsEb = do
    putStrLn "Emulate MIPS code (big-endian)"

    result <- runEmulator $ do
        -- Initialize emulator in MIPS mode
        uc <- open ArchMips [ModeMips32, ModeBigEndian]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address mipsCodeEb

        -- Initialise machine registers
        regWrite uc Mips.Reg1 0x6789

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing one instruction at address with customized callback
        codeHookAdd uc hookCode () address address

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength mipsCodeEb
        start uc address (address + codeLen) Nothing Nothing

        -- Return the results
        r1 <- regRead uc Mips.Reg1

        return r1
    case result of
        Right r1 -> do
            -- Now print out some registers
            putStrLn ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> R1 = 0x" ++ showHex r1
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

testMipsEl :: IO ()
testMipsEl = do
    putStrLn "==========================="
    putStrLn "Emulate MIPS code (little-endian)"

    result <- runEmulator $ do
        -- Initialize emulator in MIPS mode
        uc <- open ArchMips [ModeMips32, ModeLittleEndian]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address mipsCodeEl

        -- Initialize machine registers
        regWrite uc Mips.Reg1 0x6789

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing one instruction at address with customized callback
        codeHookAdd uc hookCode () address address

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength mipsCodeEl
        start uc address (address + codeLen) Nothing Nothing

        -- Return the results
        r1 <- regRead uc Mips.Reg1

        return r1
    case result of
        Right r1 -> do
            -- Now print out some registers
            putStrLn ">>> Emulation done. Below is the CPU context"
            putStrLn $ ">>> R1 = 0x" ++ showHex r1
        Left err -> putStrLn $ "Failed with error: " ++ show err ++ " (" ++
                               strerror err ++ ")"

main :: IO ()
main = do
    testMipsEb
    testMipsEl
