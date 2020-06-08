from __future__ import print_function
from unicorn import *
from unicorn.ppc_const import *
from keystone import *
import unittest
import struct
import math
import sys

PAGE_SIZE = 4096

ks = Ks(KS_ARCH_PPC,KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)

def asm(instruction):
    code = ks.asm(instruction)[0]
    if sys.version_info[0] >= 3:
        return bytes(code)
    else:
        return str(bytearray(code))

def u32(data):
    """
    unpack big endian integer
    """
    return struct.unpack(">I",data)[0]
def p32(value):
    """
    pack big endian integer
    """
    return struct.pack(">I",value)

def ufloat(data):
    """
    unpack big endian float
    """
    return struct.unpack(">f",data)[0]

def pfloat(value):
    """
    pack big endian float
    """
    return struct.pack(">f",value)

def udouble(data):
    """
    unpack big endian double
    """
    return struct.unpack(">d",data)[0]

def pdouble(value):
    """
    pack big endian double 
    """
    return struct.pack(">d",value)

def d2long(value):
    return struct.unpack(">Q",pdouble(value))[0]

def long2d(value):
    return udouble(struct.pack(">Q",value))


# memory address where emulation starts
ADDRESS      = 0x10000
# memory address where data starts
DATA         = 0x400000


def hook_intr(uc, intno, user_data):
    # print("Interrupt : %d" % intno)
    user_data.call = True
    user_data.intno = intno

def hook_mem_read(uc,access,address,size,value,user_data):
    user_data.call = True
    user_data.address = address
    user_data.size = size
    user_data.value = value
    user_data.access = access

def hook_mem_read_unmapped(uc,access,address,size,value,user_data):
    user_data.call = True
    user_data.address = address
    user_data.size = size
    user_data.value = value
    user_data.access = access
    
class CallbackInfo:
    def __init__(self):
        self.call = False

class CallbackMem(CallbackInfo):
    def __init__(self):
        CallbackInfo.__init__(self)

class CallbackIntr(CallbackInfo):
    def __init__(self):
        CallbackInfo.__init__(self)
    
class TestInstructionSet(unittest.TestCase):
    
    def assertReg(self,regid,expected,msg):
        value = self.engine.reg_read(regid)
        self.assertEqual(value,expected,msg)

    def setUp(self):
        # Initialize emulator in POWERPC
        self.engine = Uc(UC_ARCH_PPC, UC_MODE_BIG_ENDIAN | UC_MODE_32)
        # map 2MB memory for this emulation
        self.engine.mem_map(ADDRESS, 2 * 1024 * 1024)
        # enable FPU
        msr = self.engine.reg_read(UC_PPC_REG_MSR)
        self.engine.reg_write(UC_PPC_REG_MSR,(1 << 13) | msr) 

    # Test integers arithmetic instructions 
    def test_addi(self):
        self.engine.mem_write(ADDRESS,asm("addi    %r0,%r1,1"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect compute')

    def test_addis(self):
        self.engine.mem_write(ADDRESS,asm("addis %r0,%r1,1"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,0x00010001,'incorrect compute')
    
    def test_add(self):
        self.engine.mem_write(ADDRESS,asm("add %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,3,'incorrect compute')
        
    def test_addcr(self):
        self.engine.mem_write(ADDRESS,asm("add. %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,-2)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xFFFFFFFF,'incorrect compute')
        self.assertReg(UC_PPC_REG_CR_0,0b1000,'incorrect flags')

    def test_addo(self):
        self.engine.mem_write(ADDRESS,asm("addo %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0xFFFFFFFF)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        result = self.engine.reg_read(UC_PPC_REG_GPR_0)
        self.assertEqual(result,1,'incorrect compute')
        
        self.assertReg(UC_PPC_REG_OV,1,'incorrect flags')
        self.assertReg(UC_PPC_REG_SO,0,'incorrect flags')
        
    def test_subf(self):
        self.engine.mem_write(ADDRESS,asm("subf %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,0)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xFFFFFFFF,'incorrect compute')
        
    def test_subfcr(self):
        self.engine.mem_write(ADDRESS,asm("subf. %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0,'incorrect compute')
        self.assertReg(UC_PPC_REG_CR_0 ,0b0010,'incorrect flags')

    def test_addic(self):
        self.engine.mem_write(ADDRESS,asm("addic %r0,%r1,1"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0xFFFFFFFF)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0,'incorrect compute')
        self.assertReg(UC_PPC_REG_CA,1,'incorrect flags')
    
    def test_subfic(self):
        self.engine.mem_write(ADDRESS,asm("subfic %r0,%r1,0x7000"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0x7000,'incorrect compute')
        self.assertReg(UC_PPC_REG_CA,1,'incorrect flags')

    def test_addc(self):
        self.engine.mem_write(ADDRESS,asm("addc %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0xFFFFFFFF)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0,'incorrect compute')
        self.assertReg(UC_PPC_REG_CA,1,'incorrect flags')
        
    def test_subfc(self):
        self.engine.mem_write(ADDRESS,asm("subfc %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_0,0)
        self.engine.reg_write(UC_PPC_REG_GPR_2,0x7000)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0x7000,'incorrect compute')
        self.assertReg(UC_PPC_REG_CA,1,'incorrect flags')

    def test_adde(self):
        self.engine.mem_write(ADDRESS,asm("adde %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_CA,1)
        self.engine.reg_write(UC_PPC_REG_GPR_1,0)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect compute')
    
    def test_subfe(self):
        self.engine.mem_write(ADDRESS,asm("subfe %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_CA,0)
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xFFFFFFFF,'incorrect compute')
    
    def test_neg(self):
        self.engine.mem_write(ADDRESS,asm("neg %r0,%r1"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,8)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xfffffff8,'incorrect compute')
        
    def test_mulli(self):
        self.engine.mem_write(ADDRESS,asm("mulli %r0,%r1,7"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,80)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,80 * 7,'incorrect compute')
    
    def test_mullw(self):
        self.engine.mem_write(ADDRESS,asm("mullw %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,80)
        self.engine.reg_write(UC_PPC_REG_GPR_2,4123486)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,4123486 * 80,'incorrect compute')

    def test_mulhw(self):
        self.engine.mem_write(ADDRESS,asm("mulhw %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,9054)
        self.engine.reg_write(UC_PPC_REG_GPR_2,4123486)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,8,'incorrect compute')

    def test_divw(self):
        self.engine.mem_write(ADDRESS,asm("divw %r0,%r1,%r2"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,123456)
        self.engine.reg_write(UC_PPC_REG_GPR_2,48)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,123456 / 48,'incorrect compute')
        
    # Integer Logical instructionss
    def test_andis(self):
        self.engine.mem_write(ADDRESS,asm("andis. %r0,%r1,0x9DF0"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0xF0FF845F)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xF0FF845F & 0x9DF00000,'incorrect compute')
        
    def test_oris(self):
        self.engine.mem_write(ADDRESS,asm("oris %r0,%r1,0x9DF0"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0xF0FF845F)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xF0FF845F | 0x9DF00000,'incorrect compute')
        
    def test_xoris(self):
        self.engine.mem_write(ADDRESS,asm("xoris %r0,%r1,0x9DF0"))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,0xF0FF845F)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,0xF0FF845F ^ 0x9DF00000,'incorrect compute')

    # Integer rotate instructions
    def test_rlwinm(self):
        self.engine.mem_write(ADDRESS,asm("rlwinm %r0,%r1,7,4,8"))

        self.engine.reg_write(UC_PPC_REG_GPR_1,0x45239642)
        
        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        mask = 0b00001111100000000000000000000000
        expectedResult = (0x45239642 << 7) & (mask)
        self.assertReg(UC_PPC_REG_GPR_0,expectedResult,'incorrect compute')

    def test_rlwnm(self):
        self.engine.mem_write(ADDRESS,asm("rlwnm %r0,%r1,%r2,4,8"))

        self.engine.reg_write(UC_PPC_REG_GPR_1,0x45239642)
        self.engine.reg_write(UC_PPC_REG_GPR_2,7)
        
        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        mask = 0b00001111100000000000000000000000
        expectedResult = (0x45239642 << 7) & (mask)
        self.assertReg(UC_PPC_REG_GPR_0,expectedResult,'incorrect compute')
        
    def test_rlwimi(self):
        self.engine.mem_write(ADDRESS,asm("rlwimi %r0,%r1,7,4,8"))

        self.engine.reg_write(UC_PPC_REG_GPR_0,0x12345678)
        self.engine.reg_write(UC_PPC_REG_GPR_1,0x45239642)
        
        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        mask = 0b00001111100000000000000000000000
        expectedResult = (0x12345678 & ~mask) | ((0x45239642 << 7) & (mask))
        self.assertReg(UC_PPC_REG_GPR_0,expectedResult,'incorrect compute')

    # Test integer comparaison
    def test_cmpi(self):
        self.engine.mem_write(ADDRESS,asm("cmpi 2,0,%r0,1000"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,1000)
        
        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_CR_2,0b0010,'incorrect flags')

    def test_cmp(self):
        self.engine.mem_write(ADDRESS,asm("cmp 2,0,%r0,%r1"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,1000)
        self.engine.reg_write(UC_PPC_REG_GPR_1,1000)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_CR_2,0b0010,'incorrect flags')

    def test_cmpli(self):
        self.engine.mem_write(ADDRESS,asm("cmpli 2,0,%r0,0"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,-1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_CR_2,0b0100,'incorrect flags')
    
    def test_cmpl(self):
        self.engine.mem_write(ADDRESS,asm("cmpl 2,0,%r0,%r1"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,-1)
        self.engine.reg_write(UC_PPC_REG_GPR_1,0)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_CR_2,0b0100,'incorrect flags')

    # Test load instructions
    def test_lbz(self):
        self.engine.mem_write(ADDRESS,asm("lbz %r0,0(%r1)"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x01\x02\x03\x04")
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,1,'incorrect loaded value')

    def test_lbzx(self):
        self.engine.mem_write(ADDRESS,asm("lbzx %r0,%r1,%r2"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x01\x02\x03\x04")
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect loaded value')
        
    def test_lbzu(self):
        self.engine.mem_write(ADDRESS,asm("lbzu %r0,1(%r1)"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x01\x02\x03\x04")
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_1,DATA + 1,'incorrect update address')
        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect loaded value')

    def test_lbzux(self):
        self.engine.mem_write(ADDRESS,asm("lbzux %r0,%r1,%r2"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x01\x02\x03\x04")
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect loaded value')
        self.assertReg(UC_PPC_REG_GPR_1,DATA + 1,'incorrect update address')
        
    # Test store instructions
    def test_stb(self):
        self.engine.mem_write(ADDRESS,asm("stb %r0,0(%r1)"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x00\x00\x00\x00")
        
        self.engine.reg_write(UC_PPC_REG_GPR_0,0x01020304)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        result = ord(self.engine.mem_read(DATA,1))
        self.assertEqual(result,4,'incorrect stored value')

    def test_stbx(self):
        self.engine.mem_write(ADDRESS,asm("stbx %r0,%r1,%r2"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x00\x00\x00\x00")
        
        self.engine.reg_write(UC_PPC_REG_GPR_0,0x01020304)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        result = ord(self.engine.mem_read(DATA + 1,1))
        self.assertEqual(result,4,'incorrect stored value')

    def test_stbu(self):
        self.engine.mem_write(ADDRESS,asm("stbu %r0,4(%r1)"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA + 4,b"\x00\x00\x00\x00")
        
        self.engine.reg_write(UC_PPC_REG_GPR_0,0x01020304)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        addr  = self.engine.reg_read(UC_PPC_REG_GPR_1)
        result = ord(self.engine.mem_read(DATA + 4,1))
        self.assertEqual(result,4,'incorrect stored value')
        self.assertEqual(addr,DATA + 4,'incorrect updated address')

    def test_stbux(self):
        self.engine.mem_write(ADDRESS,asm("stbux %r0,%r1,%r2"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x00\x00\x00\x00")
        
        self.engine.reg_write(UC_PPC_REG_GPR_0,0x01020304)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        addr  = self.engine.reg_read(UC_PPC_REG_GPR_1)
        result = ord(self.engine.mem_read(DATA + 1,1))
        self.assertEqual(result,4,'incorrect stored value')
        self.assertEqual(addr,DATA + 1,'incorrect updated address')


    # Test LR,XER,CTR
    def test_mfxer(self):
        self.engine.mem_write(ADDRESS,asm("mfxer %r0"))
        self.engine.reg_write(UC_PPC_REG_XER,0xdeadbeef)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,0xdeadbeef,'incorrect value')
        
    def test_mflr(self):
        self.engine.mem_write(ADDRESS,asm("mflr %r0"))
        self.engine.reg_write(UC_PPC_REG_LR,0xdeadbeef)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,0xdeadbeef,'incorrect value')
        
    def test_mfctr(self):
        self.engine.mem_write(ADDRESS,asm("mfctr %r0"))
        self.engine.reg_write(UC_PPC_REG_CTR,0xdeadbeef)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_0,0xdeadbeef,'incorrect value')
        
    def test_mtxer(self):
        self.engine.mem_write(ADDRESS,asm("mtxer %r0"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,0x0eadbeef)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_XER,0x0eadbeef,'incorrect value')

    def test_mtlr(self):
        self.engine.mem_write(ADDRESS,asm("mtlr %r0"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,0xdeadbeef)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_LR,0xdeadbeef,'incorrect value')
        
    def test_mtctr(self):
        self.engine.mem_write(ADDRESS,asm("mtctr %r0"))
        self.engine.reg_write(UC_PPC_REG_GPR_0,0xdeadbeef)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_CTR,0xdeadbeef,'incorrect value')
        
    # Floating-Point operations instructions
    def test_faddcr(self):
        info = CallbackIntr()

        self.engine.mem_write(ADDRESS,asm("fadd. %f0,%f1,%f2"))

        self.engine.reg_write(UC_PPC_REG_FPR_1,0.4)
        self.engine.reg_write(UC_PPC_REG_FPR_2,0.5)
        
        self.engine.hook_add(UC_HOOK_INTR,hook_intr,user_data=info)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        result = self.engine.reg_read(UC_PPC_REG_FPR_0)

        self.assertAlmostEqual(result,0.9,msg='incorrect value',places=4)

    def test_fsubcr(self):
        info = CallbackIntr()

        self.engine.mem_write(ADDRESS,asm("fsub. %f0,%f1,%f2"))

        self.engine.reg_write(UC_PPC_REG_FPR_1,0.8)
        self.engine.reg_write(UC_PPC_REG_FPR_2,0.5)
        
        self.engine.hook_add(UC_HOOK_INTR,hook_intr,user_data=info)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        result = self.engine.reg_read(UC_PPC_REG_FPR_0)

        self.assertAlmostEqual(result,0.3,msg='incorrect value',places=4)

    def test_fmulcr(self):
        info = CallbackIntr()

        self.engine.mem_write(ADDRESS,asm("fmul. %f0,%f1,%f2"))

        self.engine.reg_write(UC_PPC_REG_FPR_1,0.8)
        self.engine.reg_write(UC_PPC_REG_FPR_2,0.5)
        
        self.engine.hook_add(UC_HOOK_INTR,hook_intr,user_data=info)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        result = self.engine.reg_read(UC_PPC_REG_FPR_0)

        self.assertAlmostEqual(result,0.8 * 0.5,msg='incorrect value',places=4)
        
    def test_fdivcr(self):
        info = CallbackIntr()

        self.engine.mem_write(ADDRESS,asm("fdiv. %f0,%f1,%f2"))

        self.engine.reg_write(UC_PPC_REG_FPR_1,0.8)
        self.engine.reg_write(UC_PPC_REG_FPR_2,0.3)
        
        self.engine.hook_add(UC_HOOK_INTR,hook_intr,user_data=info)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        result = self.engine.reg_read(UC_PPC_REG_FPR_0)

        self.assertAlmostEqual(result,0.8 / 0.3,msg='incorrect value',places=4)
    
    def test_fsqrtcr(self):
        info = CallbackIntr()

        self.engine.mem_write(ADDRESS,asm("fsqrt. %f0,%f1"))

        self.engine.reg_write(UC_PPC_REG_FPR_1,2)

        self.engine.hook_add(UC_HOOK_INTR,hook_intr,user_data=info)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        result = self.engine.reg_read(UC_PPC_REG_FPR_0)

        self.assertAlmostEqual(result,math.sqrt(2),msg='incorrect value',places=4)    

    # Floating-Point load instructions
    def test_lfd(self):
        self.engine.mem_write(ADDRESS,asm("lfd %f0,0(%r1)"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,pdouble(0.8))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        result = self.engine.reg_read(UC_PPC_REG_FPR_0)
        self.assertEqual(result,0.8,'incorrect loaded value')
        
    # Floating-Point store instructions
    def test_stfd(self):
        self.engine.mem_write(ADDRESS,asm("stfd %f0,0(%r1)"))
    
        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,pdouble(0.8))
        
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_FPR_0,0.8)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        result = udouble(self.engine.mem_read(DATA,8))

        self.assertEqual(result,0.8,'incorrect stored value')

    # Vector Load instructions
    def test_lvebx(self):
        self.engine.mem_write(ADDRESS,asm("lvebx %v0,%r1,%r2"))

        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")

        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_GPR_2,1)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
    
        result = self.engine.reg_read(UC_PPC_REG_VR_0)
        
    def test_isellt(self):
        self.engine.mem_write(ADDRESS,asm("isel %r0,%r1,%r2,0"))

        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)
        # case LT = 1
        self.engine.reg_write(UC_PPC_REG_CR_0,0b1000)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,1,'incorrect value')

        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)
        # case LT = 0
        self.engine.reg_write(UC_PPC_REG_CR_0,0b0000)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect value')

    
    def test_iselgt(self):
        self.engine.mem_write(ADDRESS,asm("isel %r0,%r1,%r2,1"))

        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)

        # case GT = 1
        self.engine.reg_write(UC_PPC_REG_CR_0,0b0100)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,1,'incorrect value')

        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)

        # case GT = 0
        self.engine.reg_write(UC_PPC_REG_CR_0,0b0000)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect value')
    
    def test_iseleq(self):
        self.engine.mem_write(ADDRESS,asm("isel %r0,%r1,%r2,2"))

        # case EQ = 1
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)

        self.engine.reg_write(UC_PPC_REG_CR_0,0b0010)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,1,'incorrect value')

        # case EQ = 0
        self.engine.reg_write(UC_PPC_REG_GPR_1,1)
        self.engine.reg_write(UC_PPC_REG_GPR_2,2)

        self.engine.reg_write(UC_PPC_REG_CR_0,0b0000)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)
        
        self.assertReg(UC_PPC_REG_GPR_0,2,'incorrect value')

    # Syscall instruction
    def test_sc(self):
        self.engine.mem_write(ADDRESS,asm("sc"))

        info = CallbackIntr()

        self.engine.hook_add(UC_HOOK_INTR,hook_intr,user_data=info)
        
        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertEqual(info.call,True,'no exception')
        self.assertEqual(info.intno,8,'incorrect exception number')

    def test_evlwwsplat(self):
        DATA = 0x2000

        self.engine.mem_write(ADDRESS,asm("evlwwsplat %r2,0(%r1)"))

        self.engine.mem_map(DATA,4096)
        self.engine.mem_write(DATA,b"\xFF" * 8)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_MSR,1 << 25)

        self.engine.emu_start(ADDRESS,ADDRESS + 4)

        self.assertReg(UC_PPC_REG_GPR_2,0xFFFFFFFF, 'incorrect value')
        self.assertReg(UC_PPC_REG_GPRH_2,0xFFFFFFFF, 'incorrect value')

    def test_exec_unmapped(self):        
        try:
            self.engine.emu_start(8,8 + 4)
        except UcError as e:
            error = e
        
        self.assertEqual(error.errno,UC_ERR_FETCH_UNMAPPED,'incorrect error')

    def test_exec_prot(self):
        self.engine.mem_map(DATA,4096,perms=UC_PROT_READ|UC_PROT_WRITE)
        self.engine.mem_write(DATA,asm("addi    %r0,%r1,1"))
        try:
            self.engine.emu_start(DATA,DATA + 4)
        except UcError as e:
            error = e
        
        self.assertEqual(error.errno,UC_ERR_FETCH_PROT,'incorrect error')
    
    def test_read_unmapped(self):
        self.engine.mem_write(ADDRESS,asm("lbz %r0,0(%r1)"))

        callback_read = CallbackInfo()
        callback_read_unmapped = CallbackInfo()

        self.engine.hook_add(UC_HOOK_MEM_READ,hook_mem_read,user_data=callback_read)
        self.engine.hook_add(UC_HOOK_MEM_READ_UNMAPPED,hook_mem_read_unmapped,user_data=callback_read_unmapped)

        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        
        error = None
        try:
            self.engine.emu_start(ADDRESS,ADDRESS + 4)
        except UcError as e:
            error = e
        
        result = self.engine.reg_read(UC_PPC_REG_GPR_0)
        self.assertEqual(result,0,'incorrect value')
        self.assertEqual(error.errno,UC_ERR_READ_UNMAPPED,'incorrect error')
        self.assertEqual(callback_read.call,False,'callback read called')
        self.assertEqual(callback_read_unmapped.call,True,'callback read unmmaped not called')
        self.assertEqual(callback_read_unmapped.address,DATA,'invalid address')
        self.assertEqual(callback_read_unmapped.size,1,'invalid size')
        self.assertEqual(callback_read_unmapped.access,UC_MEM_READ_UNMAPPED,'invalid access')

    def test_read_prot(self):
        self.engine.mem_write(ADDRESS,asm("lbz %r0,0(%r1)"))
        
        self.engine.mem_map(DATA,PAGE_SIZE,perms=UC_PROT_WRITE)

        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        self.engine.reg_write(UC_PPC_REG_GPR_0,0xdeadbeef)

        error = None
        try:
            self.engine.emu_start(ADDRESS,ADDRESS + 4)
        except UcError as e:
            error = e
        
        self.assertReg(UC_PPC_REG_GPR_0,0xdeadbeef,'incorrect value')
        self.assertEqual(error.errno,UC_ERR_READ_PROT,'incorrect error')
        
    def test_write_unmapped(self):

        self.engine.mem_write(ADDRESS,asm("stb %r0,0(%r1)"))

        self.engine.reg_write(UC_PPC_REG_GPR_0,0xFFFFFFFF)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        
        try:
            self.engine.emu_start(ADDRESS,ADDRESS + 4)
        except UcError as e:
            error = e
    
        self.assertEqual(error.errno,UC_ERR_WRITE_UNMAPPED,'incorrect error')
        
    def test_write_prot(self):
        
        self.engine.mem_map(DATA,PAGE_SIZE,perms=UC_PROT_READ)
        self.engine.mem_write(DATA,b"\x00" * 8)
        
        self.engine.mem_write(ADDRESS,asm("stb %r0,0(%r1)"))

        self.engine.reg_write(UC_PPC_REG_GPR_0,0xFFFFFFFF)
        self.engine.reg_write(UC_PPC_REG_GPR_1,DATA)
        
        try:
            self.engine.emu_start(ADDRESS,ADDRESS + 4)
        except UcError as e:
            error = e
    
        self.assertEqual(error.errno,UC_ERR_WRITE_PROT,'incorrect error')
        self.assertNotEqual(self.engine.mem_read(DATA,1),"\xFF",'incorrect memory state')

if __name__=='__main__':
    unittest.main()
