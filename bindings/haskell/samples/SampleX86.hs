-- Sample code to demonstrate how to emulate X86 code

import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.X86 as X86

import Control.Monad.Trans.Class (lift)
import qualified Data.ByteString as BS
import Data.Word
import qualified Numeric as N (showHex)
import System.Environment

-- Code to be emulated
--
-- inc ecx; dec edx
x86Code32 :: BS.ByteString
x86Code32 = BS.pack [0x41, 0x4a]

-- jmp 4; nop; nop; nop; nop; nop; nop
x86Code32Jump :: BS.ByteString
x86Code32Jump = BS.pack [0xeb, 0x02, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]

-- inc ecx; dec edx; jmp self-loop
x86Code32Loop :: BS.ByteString
x86Code32Loop = BS.pack [0x41, 0x4a, 0xeb, 0xfe]

-- mov [0xaaaaaaaa], ecx; inc ecx; dec edx
x86Code32MemWrite :: BS.ByteString
x86Code32MemWrite = BS.pack [0x89, 0x0d, 0xaa, 0xaa, 0xaa, 0xaa, 0x41, 0x4a]

-- mov ecx, [0xaaaaaaaa]; inc ecx; dec edx
x86Code32MemRead :: BS.ByteString
x86Code32MemRead = BS.pack [0x8b, 0x0d, 0xaa, 0xaa, 0xaa, 0xaa, 0x41, 0x4a]

-- jmp ouside; inc ecx; dec edx
x86Code32JmpInvalid :: BS.ByteString
x86Code32JmpInvalid = BS.pack [0xe9, 0xe9, 0xee, 0xee, 0xee, 0x41, 0x4a]

-- inc ecx; in al, 0x3f; dec edx; out 0x46, al; inc ebx
x86Code32InOut :: BS.ByteString
x86Code32InOut = BS.pack [0x41, 0xe4, 0x3f, 0x4a, 0xe6, 0x46, 0x43]

x86Code64 :: BS.ByteString
x86Code64 = BS.pack [0x41, 0xbc, 0x3b, 0xb0, 0x28, 0x2a, 0x49, 0x0f, 0xc9,
                     0x90, 0x4d, 0x0f, 0xad, 0xcf, 0x49, 0x87, 0xfd, 0x90,
                     0x48, 0x81, 0xd2, 0x8a, 0xce, 0x77, 0x35, 0x48, 0xf7,
                     0xd9, 0x4d, 0x29, 0xf4, 0x49, 0x81, 0xc9, 0xf6, 0x8a,
                     0xc6, 0x53, 0x4d, 0x87, 0xed, 0x48, 0x0f, 0xad, 0xd2,
                     0x49, 0xf7, 0xd4, 0x48, 0xf7, 0xe1, 0x4d, 0x19, 0xc5,
                     0x4d, 0x89, 0xc5, 0x48, 0xf7, 0xd6, 0x41, 0xb8, 0x4f,
                     0x8d, 0x6b, 0x59, 0x4d, 0x87, 0xd0, 0x68, 0x6a, 0x1e,
                     0x09, 0x3c, 0x59]

-- add byte ptr [bx + si], al
x86Code16 :: BS.ByteString
x86Code16 = BS.pack [0x00, 0x00]

-- SYSCALL
x86Code64Syscall :: BS.ByteString
x86Code64Syscall = BS.pack [0x0f, 0x05]

-- Memory address where emulation starts
address :: Word64
address = 0x1000000

-- Pretty-print integral as hex
showHex :: (Integral a, Show a) => a -> String
showHex i =
    N.showHex (fromIntegral i :: Word64) ""

-- Pretty-print byte string as hex
showHexBS :: BS.ByteString -> String
showHexBS =
    concatMap (flip N.showHex "") . reverse . BS.unpack

-- Write a string (with a newline character) to standard output in the emulator
emuPutStrLn :: String -> Emulator ()
emuPutStrLn =
    lift . putStrLn

-- Calculate code length
codeLength :: Num a => BS.ByteString -> a
codeLength =
    fromIntegral . BS.length

-- Callback for tracing basic blocks
hookBlock :: BlockHook ()
hookBlock _ addr size _ =
    putStrLn $ ">>> Tracing basic block at 0x" ++ showHex addr ++
               ", block size = 0x" ++ (maybe "0" showHex size)

-- Callback for tracing instruction
hookCode :: CodeHook ()
hookCode uc addr size _ = do
    runEmulator $ do
        emuPutStrLn $ ">>> Tracing instruction at 0x" ++ showHex addr ++
                      ", instruction size = 0x" ++ (maybe "0" showHex size)

        eflags <- regRead uc X86.Eflags
        emuPutStrLn $ ">>> --- EFLAGS is 0x" ++ showHex eflags
    return ()

-- Callback for tracing instruction
hookCode64 :: CodeHook ()
hookCode64 uc addr size _ = do
    runEmulator $ do
        rip <- regRead uc X86.Rip
        emuPutStrLn $ ">>> Tracing instruction at 0x" ++ showHex addr ++
                       ", instruction size = 0x" ++ (maybe "0" showHex size)
        emuPutStrLn $ ">>> RIP is 0x" ++ showHex rip
    return ()

-- Callback for tracing memory access (READ or WRITE)
hookMemInvalid :: MemoryEventHook ()
hookMemInvalid uc MemWriteUnmapped addr size (Just value) _ = do
    runEmulator $ do
        emuPutStrLn $ ">>> Missing memory is being WRITE at 0x" ++
                      showHex addr ++ ", data size = " ++ show size ++
                      ", data value = 0x" ++ showHex value
        memMap uc 0xaaaa0000 (2 * 1024 * 1024) [ProtAll]
    return True
hookMemInvalid _ _ _ _ _ _ =
    return False

hookMem64 :: MemoryHook ()
hookMem64 _ MemRead addr size _ _ =
    putStrLn $ ">>> Memory is being READ at 0x" ++ showHex addr ++
               ", data size = " ++ show size
hookMem64 _ MemWrite addr size (Just value) _ =
    putStrLn $ ">>> Memory is being WRITE at 0x" ++ showHex addr ++
               ", data size = " ++ show size ++ ", data value = 0x" ++
               showHex value

-- Callback for IN instruction (X86)
-- This returns the data read from the port
hookIn :: InHook ()
hookIn uc port size _ = do
    result <- runEmulator $ do
        eip <- regRead uc X86.Eip

        emuPutStrLn $ "--- reading from port 0x" ++ showHex port ++
                      ", size: " ++ show size ++ ", address: 0x" ++ showHex eip

        case size of
            -- Read 1 byte to AL
            1 -> return 0xf1
            -- Read 2 byte to AX
            2 -> return 0xf2
            -- Read 4 byte to EAX
            4 -> return 0xf4
            -- Should never reach this
            _ -> return 0
    case result of
        Right r -> return r
        Left _  -> return 0

-- Callback for OUT instruction (X86)
hookOut :: OutHook ()
hookOut uc port size value _ = do
    runEmulator $ do
        eip <- regRead uc X86.Eip

        emuPutStrLn $ "--- writing to port 0x" ++ showHex port ++ ", size: " ++
                      show size ++ ", value: 0x" ++ showHex value ++
                      ", address: 0x" ++ showHex eip

        -- Confirm that value is indeed the value of AL/AX/EAX
        case size of
            1 -> do
                tmp <- regRead uc X86.Al
                emuPutStrLn $ "--- register value = 0x" ++ showHex tmp
            2 -> do
                tmp <- regRead uc X86.Ax
                emuPutStrLn $ "--- register value = 0x" ++ showHex tmp
            4 -> do
                tmp <- regRead uc X86.Eax
                emuPutStrLn $ "--- register value = 0x" ++ showHex tmp
            -- Should never reach this
            _ -> return ()
    return ()

-- Callback for SYSCALL instruction (X86)
hookSyscall :: SyscallHook ()
hookSyscall uc _ = do
    runEmulator $ do
        rax <- regRead uc X86.Rax
        if rax == 0x100 then
            regWrite uc X86.Rax 0x200
        else
            emuPutStrLn $ "ERROR: was not expecting rax=0x" ++ showHex rax ++
                          " in syscall"
    return ()

testI386 :: IO ()
testI386 = do
    putStrLn "Emulate i386 code"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32

        -- Initialize machine registers
        regWrite uc X86.Ecx 0x1234
        regWrite uc X86.Edx 0x7890

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instruction by having @begin > @end
        codeHookAdd uc hookCode () 1 0

        -- Emulate machine code in infinite time
        let codeLen = codeLength x86Code32
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        ecx <- regRead uc X86.Ecx
        edx <- regRead uc X86.Edx
        emuPutStrLn $ ">>> ECX = 0x" ++ showHex ecx
        emuPutStrLn $ ">>> EDX = 0x" ++ showHex edx

        -- Read from memory
        tmp <- memRead uc address 4
        emuPutStrLn $ ">>> Read 4 bytes from [0x" ++ showHex address ++
                      "] = 0x" ++ showHexBS tmp
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

testI386Jump :: IO ()
testI386Jump = do
    putStrLn "==================================="
    putStrLn "Emulate i386 code with jump"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32Jump

        -- Tracing 1 basic block with customized callback
        blockHookAdd uc hookBlock () address address

        -- Tracing 1 instruction at address
        codeHookAdd uc hookCode () address address

        -- Emulate machine code ininfinite time
        let codeLen = codeLength x86Code32Jump
        start uc address (address + codeLen) Nothing Nothing

        emuPutStrLn ">>> Emulation done. Below is the CPU context"
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

-- Emulate code that loop forever
testI386Loop :: IO ()
testI386Loop = do
    putStrLn "==================================="
    putStrLn "Emulate i386 code that loop forever"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated in memory
        memWrite uc address x86Code32Loop

        -- Initialize machine registers
        regWrite uc X86.Ecx 0x1234
        regWrite uc X86.Edx 0x7890

        -- Emulate machine code in 2 seconds, so we can quit even if the code
        -- loops
        let codeLen = codeLength x86Code32Loop
        start uc address (address + codeLen) (Just $ 2 * 1000000) Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        ecx <- regRead uc X86.Ecx
        edx <- regRead uc X86.Edx

        emuPutStrLn $ ">>> ECX = 0x" ++ showHex ecx
        emuPutStrLn $ ">>> EDX = 0x" ++ showHex edx
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

-- Emulate code that read invalid memory
testI386InvalidMemRead :: IO ()
testI386InvalidMemRead = do
    putStrLn "==================================="
    putStrLn "Emulate i386 code that read from invalid memory"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32MemRead

        -- Initialize machine registers
        regWrite uc X86.Ecx 0x1234
        regWrite uc X86.Edx 0x7890

        -- Tracing all basic block with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instructions by having @beegin > @end
        codeHookAdd uc hookCode () 1 0

        -- Emulate machine code in infinite time
        let codeLen = codeLength x86Code32MemRead
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        ecx <- regRead uc X86.Ecx
        edx <- regRead uc X86.Edx

        emuPutStrLn $ ">>> ECX = 0x" ++ showHex ecx
        emuPutStrLn $ ">>> EDX = 0x" ++ showHex edx
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

-- Emulate code that write invalid memory
testI386InvalidMemWrite :: IO ()
testI386InvalidMemWrite = do
    putStrLn "==================================="
    putStrLn "Emulate i386 code that write to invalid memory"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32MemWrite

        -- Initialize machine registers
        regWrite uc X86.Ecx 0x1234
        regWrite uc X86.Edx 0x7890

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instruction by having @begin > @end
        codeHookAdd uc hookCode () 1 0

        -- Intercept invalid memory events
        memoryEventHookAdd uc HookMemReadUnmapped hookMemInvalid () 1 0
        memoryEventHookAdd uc HookMemWriteUnmapped hookMemInvalid () 1 0

        -- Emulate machine code in infinite time
        let codeLen = codeLength x86Code32MemWrite
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        ecx <- regRead uc X86.Ecx
        edx <- regRead uc X86.Edx
        emuPutStrLn $ ">>> ECX = 0x" ++ showHex ecx
        emuPutStrLn $ ">>> EDX = 0x" ++ showHex edx

        -- Read from memory
        tmp <- memRead uc 0xaaaaaaaa 4
        emuPutStrLn $ ">>> Read 4 bytes from [0x" ++ showHex 0xaaaaaaaa ++
                      "] = 0x" ++ showHexBS tmp

        tmp <- memRead uc 0xffffffaa 4
        emuPutStrLn $ ">>> Read 4 bytes from [0x" ++ showHex 0xffffffaa ++
                      "] = 0x" ++ showHexBS tmp
    case result of
        Right _ -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

-- Emulate code that jump to invalid memory
testI386JumpInvalid :: IO ()
testI386JumpInvalid = do
    putStrLn "==================================="
    putStrLn "Emulate i386 code that jumps to invalid memory"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32JmpInvalid

        -- Initialize machine registers
        regWrite uc X86.Ecx 0x1234
        regWrite uc X86.Edx 0x7890

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instructions by having @begin > @end
        codeHookAdd uc hookCode () 1 0

        -- Emulate machine code in infinite time
        let codeLen = codeLength x86Code32JmpInvalid
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        ecx <- regRead uc X86.Ecx
        edx <- regRead uc X86.Edx

        emuPutStrLn $ ">>> ECX = 0x" ++ showHex ecx
        emuPutStrLn $ ">>> EDX = 0x" ++ showHex edx
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

testI386InOut :: IO ()
testI386InOut = do
    putStrLn "==================================="
    putStrLn "Emulate i386 code with IN/OUT instructions"

    result <- runEmulator $ do
        -- Initialize emulator in X86-32bit mode
        uc <- open ArchX86 [Mode32]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code32InOut

        -- Initialize machine registers
        regWrite uc X86.Eax 0x1234
        regWrite uc X86.Ecx 0x6789

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instructions
        codeHookAdd uc hookCode () 1 0

        -- uc IN instruction
        inHookAdd uc hookIn () 1 0
 
        -- uc OUT instruction
        outHookAdd uc hookOut () 1 0

        -- Emulate machine code in infinite time
        let codeLen = codeLength x86Code32InOut
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        eax <- regRead uc X86.Eax
        ecx <- regRead uc X86.Ecx

        emuPutStrLn $ ">>> EAX = 0x" ++ showHex eax
        emuPutStrLn $ ">>> ECX = 0x" ++ showHex ecx
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

testX8664 :: IO ()
testX8664 = do
    putStrLn "Emulate x86_64 code"

    result <- runEmulator $ do
        -- Initialize emualator in X86-64bit mode
        uc <- open ArchX86 [Mode64]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code64

        -- Initialize machine registers
        regWrite uc X86.Rsp (fromIntegral address + 0x200000)

        regWrite uc X86.Rax 0x71f3029efd49d41d
        regWrite uc X86.Rbx 0xd87b45277f133ddb
        regWrite uc X86.Rcx 0xab40d1ffd8afc461
        regWrite uc X86.Rdx 0x919317b4a733f01
        regWrite uc X86.Rsi 0x4c24e753a17ea358
        regWrite uc X86.Rdi 0xe509a57d2571ce96
        regWrite uc X86.R8  0xea5b108cc2b9ab1f
        regWrite uc X86.R9  0x19ec097c8eb618c1
        regWrite uc X86.R10 0xec45774f00c5f682
        regWrite uc X86.R11 0xe17e9dbec8c074aa
        regWrite uc X86.R12 0x80f86a8dc0f6d457
        regWrite uc X86.R13 0x48288ca5671c5492
        regWrite uc X86.R14 0x595f72f6e4017f6e
        regWrite uc X86.R15 0x1efd97aea331cccc

        -- Tracing all basic blocks with customized callback
        blockHookAdd uc hookBlock () 1 0

        -- Tracing all instructions in the range [address, address+20]
        codeHookAdd uc hookCode64 () address (address + 20)

        -- Tracing all memory WRITE access (with @begin > @end)
        memoryHookAdd uc HookMemWrite hookMem64 () 1 0

        -- Tracing all memory READ access (with @begin > @end)
        memoryHookAdd uc HookMemRead hookMem64 () 1 0

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength x86Code64
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        rax <- regRead uc X86.Rax
        rbx <- regRead uc X86.Rbx
        rcx <- regRead uc X86.Rcx
        rdx <- regRead uc X86.Rdx
        rsi <- regRead uc X86.Rsi
        rdi <- regRead uc X86.Rdi
        r8  <- regRead uc X86.R8
        r9  <- regRead uc X86.R9
        r10 <- regRead uc X86.R10
        r11 <- regRead uc X86.R11
        r12 <- regRead uc X86.R12
        r13 <- regRead uc X86.R13
        r14 <- regRead uc X86.R14
        r15 <- regRead uc X86.R15

        emuPutStrLn $ ">>> RAX = 0x" ++ showHex rax
        emuPutStrLn $ ">>> RBX = 0x" ++ showHex rbx
        emuPutStrLn $ ">>> RCX = 0x" ++ showHex rcx
        emuPutStrLn $ ">>> RDX = 0x" ++ showHex rdx
        emuPutStrLn $ ">>> RSI = 0x" ++ showHex rsi
        emuPutStrLn $ ">>> RDI = 0x" ++ showHex rdi
        emuPutStrLn $ ">>> R8 = 0x"  ++ showHex r8
        emuPutStrLn $ ">>> R9 = 0x"  ++ showHex r9
        emuPutStrLn $ ">>> R10 = 0x" ++ showHex r10
        emuPutStrLn $ ">>> R11 = 0x" ++ showHex r11
        emuPutStrLn $ ">>> R12 = 0x" ++ showHex r12
        emuPutStrLn $ ">>> R13 = 0x" ++ showHex r13
        emuPutStrLn $ ">>> R14 = 0x" ++ showHex r14
        emuPutStrLn $ ">>> R15 = 0x" ++ showHex r15
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

testX8664Syscall :: IO ()
testX8664Syscall = do
    putStrLn "==================================="
    putStrLn "Emulate x86_64 code with 'syscall' instruction"

    result <- runEmulator $ do
        -- Initialize emulator in X86-64bit mode
        uc <- open ArchX86 [Mode64]

        -- Map 2MB memory for this emulation
        memMap uc address (2 * 1024 * 1024) [ProtAll]

        -- Write machine code to be emulated to memory
        memWrite uc address x86Code64Syscall

        -- Hook interrupts for syscall
        syscallHookAdd uc hookSyscall () 1 0

        -- Initialize machine registers
        regWrite uc X86.Rax 0x100

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all code
        let codeLen = codeLength x86Code64Syscall
        start uc address (address + codeLen) Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        rax <- regRead uc X86.Rax
        emuPutStrLn $ ">>> RAX = 0x" ++ showHex rax
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

testX8616 :: IO ()
testX8616 = do
    putStrLn "Emulate x86 16-bit code"

    result <- runEmulator $ do
        -- Initialize emulator in X86-16bit mode
        uc <- open ArchX86 [Mode16]

        -- Map 8KB memory for this emulation
        memMap uc 0 (8 * 1024) [ProtAll]

        -- Write machine code to be emulated in memory
        memWrite uc 0 x86Code16

        -- Initialize machine registers
        regWrite uc X86.Eax 7
        regWrite uc X86.Ebx 5
        regWrite uc X86.Esi 6

        -- Emulate machine code in infinite time (last param = Nothing), or
        -- when finishing all the code
        let codeLen = codeLength x86Code16
        start uc 0 codeLen Nothing Nothing

        -- Now print out some registers
        emuPutStrLn ">>> Emulation done. Below is the CPU context"

        -- Read from memory
        tmp <- memRead uc 11 1
        emuPutStrLn $ ">>> Read 1 bytes from [0x" ++ showHex 11 ++
                      "] = 0x" ++ showHexBS tmp
    case result of
        Right _  -> return ()
        Left err -> putStrLn $ "Failed with error " ++ show err ++ ": " ++
                               strerror err

main :: IO ()
main = do
    progName <- getProgName
    args <- getArgs
    case args of
        ["-32"] -> do
            testI386
            testI386InOut
            testI386Jump
            testI386Loop
            testI386InvalidMemRead
            testI386InvalidMemWrite
            testI386JumpInvalid
        ["-64"] -> do
            testX8664
            testX8664Syscall
        ["-16"] -> testX8616
        -- Test memleak
        ["-0"]  -> testI386
        _       -> putStrLn $ "Syntax: " ++ progName ++ " <-16|-32|-64>"

