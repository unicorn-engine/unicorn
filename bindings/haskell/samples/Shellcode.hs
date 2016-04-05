-- Sample code to trace code with Linux code with syscall

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.X86 as X86

import Control.Monad.Trans.Class (lift)
import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)
import System.Environment

-- Code to be emulated
x86Code32 :: BS.ByteString
x86Code32 = BS.pack [0xeb, 0x19, 0x31, 0xc0, 0x31, 0xdb, 0x31, 0xd2, 0x31,
                     0xc9, 0xb0, 0x04, 0xb3, 0x01, 0x59, 0xb2, 0x05, 0xcd,
                     0x80, 0x31, 0xc0, 0xb0, 0x01, 0x31, 0xdb, 0xcd, 0x80,
                     0xe8, 0xe2, 0xff, 0xff, 0xff, 0x68, 0x65, 0x6c, 0x6c,
                     0x6f]

x86Code32Self :: BS.ByteString
x86Code32Self = BS.pack [0xeb, 0x1c, 0x5a, 0x89, 0xd6, 0x8b, 0x02, 0x66, 0x3d,
                         0xca, 0x7d, 0x75, 0x06, 0x66, 0x05, 0x03, 0x03, 0x89,
                         0x02, 0xfe, 0xc2, 0x3d, 0x41, 0x41, 0x41, 0x41, 0x75,
                         0xe9, 0xff, 0xe6, 0xe8, 0xdf, 0xff, 0xff, 0xff, 0x31,
                         0xd2, 0x6a, 0x0b, 0x58, 0x99, 0x52, 0x68, 0x2f, 0x2f,
                         0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3,
                         0x52, 0x53, 0x89, 0xe1, 0xca, 0x7d, 0x41, 0x41, 0x41,
                         0x41, 0x41, 0x41, 0x41, 0x41]

-- Memory address where emulation starts
address :: Word64
address = 0x1000000

-- Pretty-print integral as hex
showHex :: (Integral a, Show a) => a -> String
showHex =
    flip N.showHex ""

-- Pretty-print byte string as hex
showHexBS :: BS.ByteString -> String
showHexBS =
    concatMap (flip N.showHex " ") . BS.unpack

-- Write a string (with a newline character) to standard output in the emulator
emuPutStrLn :: String -> Emulator ()
emuPutStrLn =
    lift . putStrLn

-- Calculate code length
codeLength :: Num a => BS.ByteString -> a
codeLength =
    fromIntegral . BS.length

-- Callback for tracing instructions
hookCode :: CodeHook ()
hookCode uc addr size _ = do
    runEmulator $ do
        emuPutStrLn $ "Tracing instruction at 0x" ++ showHex addr ++
                      ", instruction size = 0x" ++ (maybe "0" showHex size)

        eip <- regRead uc X86.Eip
        tmp <- memRead uc addr (maybe 0 id size)

        emuPutStrLn $ "*** EIP = " ++ showHex eip ++ " ***: " ++ showHexBS tmp
    return ()

-- Callback for handling interrupts
-- ref: http://syscalls.kernelgrok.com
hookIntr :: InterruptHook ()
hookIntr uc intno _
    | intno == 0x80 = do
        runEmulator $ do
            eax <- regRead uc X86.Eax
            eip <- regRead uc X86.Eip
    
            case eax of
                -- sys_exit
                1 -> do
                    emuPutStrLn $ ">>> 0x" ++ showHex eip ++
                                  ": interrupt 0x" ++ showHex intno ++
                                  ", SYS_EXIT. quit!\n"
                    stop uc
                -- sys_write
                4 -> do
                    -- ECX = buffer address
                    ecx <- regRead uc X86.Ecx
    
                    -- EDX = buffer size
                    edx <- regRead uc X86.Edx
    
                    -- Read the buffer in
                    buffer <- memRead uc (fromIntegral ecx) (fromIntegral edx)
                    err <- errno uc
                    if err == ErrOk then
                        emuPutStrLn $ ">>> 0x" ++ showHex eip ++
                                      ": interrupt 0x" ++ showHex intno ++
                                      ", SYS_WRITE. buffer = 0x" ++
                                      showHex ecx ++ ", size = " ++
                                      show edx ++ ", content = " ++
                                      showHexBS buffer
                    else
                        emuPutStrLn $ ">>> 0x" ++ showHex eip ++
                                      ": interrupt 0x" ++ showHex intno ++
                                      ", SYS_WRITE. buffer = 0x" ++
                                      showHex ecx ++ ", size = " ++ show edx ++
                                      " (cannot get content)"
                _ -> emuPutStrLn $ ">>> 0x" ++ showHex eip ++
                                   ": interrupt 0x" ++ showHex intno ++
                                   ", EAX = 0x" ++ showHex eax
        return ()
    | otherwise = return ()

testI386 :: IO ()
testI386 = do
    result <- runEmulator $ do
        emuPutStrLn "Emulate i386 code"

        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32Self

        -- Initialize machine registers
        regWrite uc X86.Esp (fromIntegral address + 0x200000)

        -- Tracing all instructions by having @begin > @end
        codeHookAdd uc hookCode () 1 0

        -- Handle interrupt ourself
        interruptHookAdd uc hookIntr () 1 0

        emuPutStrLn "\n>>> Start tracing this Linux code"

        -- Emulate machine code in infinite time
        let codeLen = codeLength x86Code32Self
        start uc address (address + codeLen) Nothing Nothing
    case result of
        Right _  -> putStrLn "\n>>> Emulation done."
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

main :: IO ()
main = do
    progName <- getProgName
    args <- getArgs
    case args of
        ["-32"] -> testI386
        _       -> putStrLn $ "Syntax: " ++ progName ++ " <-32|-64>"
