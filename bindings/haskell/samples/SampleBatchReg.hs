import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.X86 as X86

import Control.Monad.Trans.Class (lift)
import qualified Data.ByteString as BS
import Data.Int
import Data.List (intercalate)
import Data.Word
import qualified Numeric as N (showHex)
import System.IO (hPutStrLn, stderr)

syscallABI :: [X86.Register]
syscallABI = [ X86.Rax
             , X86.Rdi
             , X86.Rsi
             , X86.Rdx
             , X86.R10
             , X86.R8
             , X86.R9
             ]

vals :: [Int64]
vals = [ 200
       , 10
       , 11
       , 12
       , 13
       , 14
       , 15
       ]

ucPerror :: Error
         -> IO ()
ucPerror err =
    hPutStrLn stderr $ "Error " ++ ": " ++ strerror err

base :: Word64
base = 0x10000

-- mov rax, 100; mov rdi, 1; mov rsi, 2; mov rdx, 3; mov r10, 4; mov r8, 5; mov r9, 6; syscall
code :: BS.ByteString
code = BS.pack [ 0x48, 0xc7, 0xc0, 0x64, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc7
               , 0x01, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00
               , 0x00, 0x48, 0xc7, 0xc2, 0x03, 0x00, 0x00, 0x00, 0x49, 0xc7
               , 0xc2, 0x04, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc0, 0x05, 0x00
               , 0x00, 0x00, 0x49, 0xc7, 0xc1, 0x06, 0x00, 0x00, 0x00, 0x0f
               , 0x05
               ]

-- Pretty-print integral as hex
showHex :: (Integral a, Show a) => a -> String
showHex i =
    N.showHex (fromIntegral i :: Word64) ""

-- Write a string (with a newline character) to standard output in the emulator
emuPutStrLn :: String -> Emulator ()
emuPutStrLn =
    lift . putStrLn

hookSyscall :: SyscallHook ()
hookSyscall uc _ = do
    runEmulator $ do
        readVals <- regReadBatch uc syscallABI
        emuPutStrLn $ "syscall: {"
                      ++ intercalate ", " (map show readVals)
                      ++ "}"
    return ()

hookCode :: CodeHook ()
hookCode _ addr size _ = do
    putStrLn $ "HOOK_CODE: 0x" ++ showHex addr ++ ", 0x" ++
               maybe "0" showHex size

main :: IO ()
main = do
    result <- runEmulator $ do
        uc <- open ArchX86 [Mode64]

        -- regWriteBatch
        emuPutStrLn "regWriteBatch {200, 10, 11, 12, 13, 14, 15}"
        regWriteBatch uc syscallABI vals

        readVals <- regReadBatch uc syscallABI
    
        emuPutStrLn $ "regReadBatch = {"
                      ++ intercalate ", " (map show readVals)
                      ++ "}"

        -- syscall
        emuPutStrLn "running syscall shellcode"
        syscallHookAdd uc hookSyscall () 1 0
        memMap uc base (0x1000) [ProtAll]
        memWrite uc base code
        let codeLen = fromIntegral $ BS.length code
        start uc base (base + codeLen) Nothing Nothing
    case result of
        Right _  -> return ()
        Left err -> ucPerror err
