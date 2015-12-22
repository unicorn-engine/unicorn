from unicorn import *
from unicorn.arm_const import *
import binascii

MB = 1024 * 1024
PAGE = 4 * 1024

def PrintArmRegisters(uc_emu):
    print 'R0 : '+hex(uc_emu.reg_read(UC_ARM_REG_R0))
    print 'R1 : '+hex(uc_emu.reg_read(UC_ARM_REG_R1))
    print 'R2 : '+hex(uc_emu.reg_read(UC_ARM_REG_R2))
    print 'R3 : '+hex(uc_emu.reg_read(UC_ARM_REG_R3))
    print 'R4 : '+hex(uc_emu.reg_read(UC_ARM_REG_R4))
    print 'R5 : '+hex(uc_emu.reg_read(UC_ARM_REG_R5))
    print 'R6 : '+hex(uc_emu.reg_read(UC_ARM_REG_R6))
    print 'R7 : '+hex(uc_emu.reg_read(UC_ARM_REG_R7))
    print 'R8 : '+hex(uc_emu.reg_read(UC_ARM_REG_R8))
    print 'R9 : '+hex(uc_emu.reg_read(UC_ARM_REG_R9))
    print 'R10 : '+hex(uc_emu.reg_read(UC_ARM_REG_R10))
    print 'R11 : '+hex(uc_emu.reg_read(UC_ARM_REG_R11))
    print 'R12 : '+hex(uc_emu.reg_read(UC_ARM_REG_R12))
    print 'SP : '+hex(uc_emu.reg_read(UC_ARM_REG_SP))
    print 'LR : '+hex(uc_emu.reg_read(UC_ARM_REG_LR))
    print 'PC : '+hex(uc_emu.reg_read(UC_ARM_REG_PC))
    flags = uc_emu.reg_read(UC_ARM_REG_CPSR)
    print 'carry : '+str(flags >> 29 & 0x1)
    print 'overflow : '+str(flags >> 28 & 0x1)
    print 'negative : '+str(flags >> 31 & 0x1)
    print 'zero : '+str(flags >> 30 & 0x1)
  
'''
    issue #287
    Initial Register States: R0=3, R1=24, R2=16, R3=0
    -----  code start -----
    CMP R0,R1,LSR#3        
    SUBCS R0,R0,R1,LSR#3   # CPU flags got changed in these two instructions, and *REMEMBERED*, now NF == VF == 0
    CMP R0,#1              # CPU flags changed again, now NF == 1, VF == 0, but they are not properly *REMEMBERED*
    MOV R1,R1,LSR#4
    SUBGES R2,R2,#4        # according to the result of CMP, we should skip this op
    
    MOVGE R3,#100          # since changed flags are not *REMEMBERED* in CMP, now NF == VF == 0, which result in wrong branch
                           # at the end of this code block, should R3 == 0 
    ----- code end ------

    # TCG ops are correct, plain op translation is done correctly, 
    # but there're In-Memory bits invisible from ops that control the host code generation.
    # all these codes are in one TCG translation-block, so wrong things could happen.
    # detail explanation is given on the right side.
    # remember, both set_label and brcond are point to refresh the dead_temps and mem_temps states in TCG
    ----- TCG ops  ------
    	ld_i32 tmp5,env,$0xfffffffffffffff4
	movi_i32 tmp6,$0x0
	brcond_i32 tmp5,tmp6,ne,$0x0
	mov_i32 tmp5,r1	-------------------------
	movi_i32 tmp6,$0x3                     	|
	shr_i32 tmp5,r1,tmp6                   	|
	mov_i32 tmp6,r0                        	|
	sub_i32 NF,r0,tmp5                     	|
	mov_i32 ZF,NF				|
	setcond_i32 CF,r0,tmp5,geu   		|	# This part is "CMP R0,R1,LSR#3"
	xor_i32 VF,NF,r0			|----->	# and "SUBCS R0,R0,R1,LSR#3"
	xor_i32 tmp7,r0,tmp5			|	# the last op in this block, set_label get a chance to refresh the TCG globals memory states, 
	and_i32 VF,VF,tmp7			|	# so things get back to normal states
	mov_i32 tmp6,NF				|	# these codes are not affected by the bug. Let's called this Part-D
	movi_i32 tmp5,$0x0			|
	brcond_i32 CF,tmp5,eq,$0x1		|
	mov_i32 tmp5,r1				|
	movi_i32 tmp6,$0x3			|
	shr_i32 tmp5,r1,tmp6			|
	mov_i32 tmp6,r0				|
	sub_i32 tmp6,r0,tmp5			|   
	mov_i32 r0,tmp6        			|
	set_label $0x1	-------------------------         
	movi_i32 tmp5,$0x1	-----------------	# Let's called this Part-C
	mov_i32 tmp6,r0				|	# NF is used as output operand again!
	sub_i32 NF,r0,tmp5	----------------|----->	# but it is stated as Not-In-Memory,
	mov_i32 ZF,NF				|	# no need to sync it after calculation.
	setcond_i32 CF,r0,tmp5,geu		|	# the generated host code does not write NF
	xor_i32 VF,NF,r0			|	# back to its memory location, hence forgot. And the CPU flags after this calculation is not changed.
	xor_i32 tmp7,r0,tmp5			|	# Caution: the following SUBGES's condition check is right, even though the generated host code does not *REMEMBER* NF, it will cache the calculated result and serve SUBGES correctly
	and_i32 VF,VF,tmp7			|	  
	mov_i32 tmp6,NF				|
	mov_i32 tmp5,r1				|	# this part is "CMP R0,#1"
	movi_i32 tmp6,$0x4			|	# and "MOV R1,R1,LSR#4"
	shr_i32 tmp5,r1,tmp6			|	# and "SUBGES R2,R2,#4"
	mov_i32 r1,tmp5				|-----> # This is the part where problem start to arise
	xor_i32 tmp5,VF,NF			|
	movi_i32 tmp6,$0x0			|
	brcond_i32 tmp5,tmp6,lt,$0x2	--------|-----> # QEMU will refresh the InMemory bit for TCG globals here, but Unicorn won't
	movi_i32 tmp5,$0x4			|
	mov_i32 tmp6,r2				|	# this is the 1st bug-related op get analyzed.
	sub_i32 NF,r2,tmp5	----------------|-----> # here, NF is an output operand, it's flagged dead 
	mov_i32 ZF,NF				|	# and the InMemory bit is clear, tell the previous(above) ops
	setcond_i32 CF,r2,tmp5,geu		|	# if it is used as output operand again, do not sync it
	xor_i32 VF,NF,r2			|	# so the generated host-code for previous ops will not write it back to Memory
	xor_i32 tmp7,r2,tmp5			|	# Caution: the CPU flags after this calculation is also right, because the set_label is a point of refresh, make them *REMEMBERED*
	and_i32 VF,VF,tmp7			|	# Let's call this Part-B
	mov_i32 tmp6,NF				|
	mov_i32 r2,ZF				|
	set_label $0x2		-----------------
	xor_i32 tmp5,VF,NF	-----------------
	movi_i32 tmp6,$0x0			|
	brcond_i32 tmp5,tmp6,lt,$0x3		|	# Let's call this Part-A
	movi_i32 tmp5,$0x64			|	# if Part-B is not skipped, this part won't go wrong, because we'll check the CPU flags as the result of Part-B, it's *REMEMBERED*
	movi_i32 r3,$0x64			|-----> # but if Part-B is skipped,
	set_label $0x3				|	# what should we expected? we will check the condition based on the result of Part-D!!!
	call wfi,$0x0,$0,env			|	# because result of Part-C is lost. this is why things go wrong.
	set_label $0x0				|
	exit_tb $0x7f6401714013	-----------------
	###########
    ----- TCG ends ------
'''

TestCode = b'\xa1\x01\x50\xe1\xa1\x01\x40\x20\x01\x00\x50\xe3\x21\x12\xa0\xe1\x04\x20\x52\xa2\x64\x30\xa0\xa3'

def UseUcToEmulate():
    try:
        uc_emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        #if LoadCode(uc_emu, 2*MB, 0x9004):
        uc_emu.mem_map(0, 2*MB)
        uc_emu.reg_write(UC_ARM_REG_SP, 0x40000)
        uc_emu.reg_write(UC_ARM_REG_R0, 3)
        uc_emu.reg_write(UC_ARM_REG_R1, 24)
        uc_emu.reg_write(UC_ARM_REG_R2, 16)
        uc_emu.mem_write(0, TestCode)
        uc_emu.emu_start(0, 24)
        PrintArmRegisters(uc_emu)
        
    except UcError as e:
        print("ERROR: %s" % e)
        PrintArmRegisters(uc_emu)
        

UseUcToEmulate()
