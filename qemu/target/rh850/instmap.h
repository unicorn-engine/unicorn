/*
 * RH850 emulation for qemu: Instruction decode helpers
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

enum{
	/*SIGNED INT*/
	COND_RH850_BGE = 1110,
	COND_RH850_BGT = 1111,
	COND_RH850_BLE = 0111,
	COND_RH850_BLT = 0110,
	/*UNSIGNED INT*/
	COND_RH850_BH = 1011,
	COND_RH850_BL = 0001,
	COND_RH850_BNH = 0011,
	COND_RH850_BNL = 1001,
	/*COMMON*/
	COND_RH850_BE = 0010,
	COND_RH850_BNE = 1010,
	/*OTHERS*/
	COND_RH850_BC = 0001,
	COND_RH850_BF = 1010,
	COND_RH850_BN = 0100,
	COND_RH850_BNC = 1001,
	COND_RH850_BNV = 1000,
	COND_RH850_BNZ = 1010,
	COND_RH850_BP = 1100,
	COND_RH850_BR = 0101,
	COND_RH850_BSA = 1101,
	COND_RH850_BT = 0010,
	COND_RH850_BV = 0000,
	COND_RH850_BZ = 0010,
};

#define MASK_OP_MAJOR(op)  (op & (0x3F << 5)) // the major opcode in rh850 is at bits 10-5
enum {
	/* FORMAT I */						// unique opcodes and grouped instructions
	OPC_RH850_16bit_0 = (0x0 << 5),		// group with opcode 0x0 (nop, synci, synce, syncm, syncp, mov)
	OPC_RH850_NOT_reg1_reg2 	= (0x1 << 5),
	OPC_RH850_16bit_2 = (0x2 << 5),		// group with opcode 0x2 (rie, switch, divh, fetrap)
	OPC_RH850_16bit_3 = (0x3 << 5), 	// group with opcode 0x3 (jmp,sld.bu,sld.hu)
	OPC_RH850_16bit_4 = (0x4 << 5),		// group with opcode 0x4 (zyb, satsub)
	OPC_RH850_16bit_5 = (0x5 << 5),		// group with opcode 0x5 (sxb, satsub)
	OPC_RH850_16bit_6 = (0x6 << 5),		// group with opcode 0x6 (zyh, satadd)
	OPC_RH850_16bit_7 = (0x7 << 5),		// group with opcode 0x7 (sxh, mulh)
	OPC_RH850_OR_reg1_reg2 	= (0x8 << 5),
	OPC_RH850_XOR_reg1_reg2 	= (0x9 << 5),
	OPC_RH850_AND_reg1_reg2 	= (0xA << 5),
	OPC_RH850_TST_reg1_reg2 	= (0xB << 5),
	OPC_RH850_SUBR_reg1_reg2 	= (0xC << 5),
	OPC_RH850_SUB_reg1_reg2 	= (0xD << 5),
	OPC_RH850_ADD_reg1_reg2 	= (0xE << 5),
	OPC_RH850_CMP_reg1_reg2 = (0xF << 5),

	/* FORMAT II */
	OPC_RH850_16bit_16 = (0x10 << 5),	// group with opcode 0x10 (mov,callt)
	OPC_RH850_16bit_17 = (0x11 << 5),	// group with opcode 0x11 (callt, satadd)
	OPC_RH850_ADD_imm5_reg2= (0x12 << 5),   // group with opcode 0x12 (add)
	OPC_RH850_CMP_imm5_reg2 = (0x13 << 5),	// group with opcode 0x13 (cmp)
	OPC_RH850_SHR_imm5_reg2 = (0x14 << 5),
	OPC_RH850_SAR_imm5_reg2 = (0x15 << 5),
	OPC_RH850_SHL_imm5_reg2 = (0x16 << 5),
	OPC_RH850_MULH_imm5_reg2 = (0x17 << 5),

	/*FORMAT III */
	OPC_RH850_BCOND = (0xB << 7), 	// different mask! (bits 10-7)

	/* FORMAT IV */					// different mask! (bits 10-7)
	OPC_RH850_16bit_SLDB = (0x6 << 5),
	OPC_RH850_16bit_SLDH = (0x8 << 5),
	OPC_RH850_16bit_IV10 = (0xA << 5), 		// group with opcode 0xA (sld.w,sst.w)
	OPC_RH850_16bit_SSTB = (0x7 << 5),
	OPC_RH850_16bit_SSTH = (0x9 << 5),

	/* FORMAT VI */
	OPC_RH850_ADDI_imm16_reg1_reg2	=	(0x30 << 5),
	OPC_RH850_ANDI_imm16_reg1_reg2	=	(0x36 << 5),
	OPC_RH850_MOVEA	=	(0x31 << 5),     	// this is also MOV 3, which is 48 bit
	OPC_RH850_MOVHI_imm16_reg1_reg2	=	(0x32 << 5),
	OPC_RH850_ORI_imm16_reg1_reg2	=	(0x34 << 5),
	OPC_RH850_SATSUBI_imm16_reg1_reg2=	(0x33 << 5),
	OPC_RH850_XORI_imm16_reg1_reg2	=	(0x35 << 5),


	/* FORMAT VII */

	OPC_RH850_LOOP	=	(0x37 << 5), 		//same as MULHI in format VI !!!!

	OPC_RH850_LDB 	  = (0x38 << 5),
	OPC_RH850_LDH_LDW = (0x39 << 5),
	OPC_RH850_STB 	  = (0x3A << 5),
	OPC_RH850_STH_STW = (0x3B << 5), 	//the store halfword and store word instructions differ on LSB displacement bit 16 (0=ST.H, 1=ST.W) (format VII)

	OPC_RH850_ST_LD_0 = (0x3C << 5), 	//5 instructions share this opcode, sub-op bits 11-15 are 0, inst. differ in sub-op bits 16-19 (ST.B2=D, ST.W2=F) (format XIV)
	OPC_RH850_ST_LD_1 = (0x3D << 5), 	//5 instructions share this opcode, sub-op bits 11-15 are 0, inst. differ in sub-op bits 16-19 (ST.DW=F, ST.H2=D) (format XIV)
	//OPC_RH850_LDHU  = (0x3F << 5),	//bits 11-15 are not all 0

	OPC_RH850_32bit_1 = (0x3F << 5),	// 111111




	OPC_RH850_BIT_MANIPULATION_2	=	(0x3E << 5),

	OPC_RH850_FORMAT_V_XIII = (0x1E << 6),


	OPC_RH850_MULH1 = (0x7 << 5),
	OPC_RH850_MULH2 = (0x17 << 5),


};

enum{
	OPC_RH850_SET1_reg2_reg1	=	0,
	OPC_RH850_NOT1_reg2_reg1	=	2,
	OPC_RH850_CLR1_reg2_reg1	=	4,
	OPC_RH850_TST1_reg2_reg1	=	6,
};

enum{
	OPC_RH850_SET1_bit3_disp16_reg1	=	1,
	OPC_RH850_NOT1_bit3_disp16_reg1	=	3,
	OPC_RH850_CLR1_bit3_disp16_reg1	=	5,
	OPC_RH850_TST1_bit3_disp16_reg1	=	7,
};

enum{
	OPC_RH850_MOV_reg1_reg2		= 1,
	OPC_RH850_MOV_imm5_reg2		= 2,
	OPC_RH850_MOV_imm32_reg1	= 3,
	OPC_RH850_MOVEA_imm16_reg1_reg2	= 4,
};

enum{
	OPC_RH850_SATADD_reg1_reg2 		= 1,
	OPC_RH850_SATADD_imm5_reg2 		= 2,
	OPC_RH850_SATADD_reg1_reg2_reg3	= 3,
	OPC_RH850_SATSUB_reg1_reg2		= 4,
	OPC_RH850_SATSUB_reg1_reg2_reg3 = 5,
	OPC_RH850_SATSUBR_reg1_reg2		= 6,
};

enum{
	OPC_RH850_MUL_reg1_reg2_reg3	= 1,
	OPC_RH850_MUL_imm9_reg2_reg3	= 2,
	OPC_RH850_MULH_reg1_reg2		= 3,
	//OPC_RH850_MULH_imm5_reg2		= 4,
	OPC_RH850_MULHI_imm16_reg1_reg2	= 5,
	OPC_RH850_MULU_reg1_reg2_reg3	= 8,
	OPC_RH850_MULU_imm9_reg2_reg3	= 9,
};

enum{
	OPC_RH850_ADF_cccc_reg1_reg2_reg3	= 10,
	OPC_RH850_SBF_cccc_reg1_reg2_reg3	= 11,
	OPC_RH850_DIVH_reg1_reg2			= 12,
};

enum{		//enum for gen_data_manipulation cases
	OPC_RH850_SHR_reg1_reg2 		= 111,
	OPC_RH850_SHR_reg1_reg2_reg3	= 222,
	OPC_RH850_CMOV_cccc_reg1_reg2_reg3	= 333,
	OPC_RH850_CMOV_cccc_imm5_reg2_reg3	= 444,
	OPC_RH850_ROTL_reg1_reg2_reg3	= 445,
	OPC_RH850_ROTL_imm5_reg2_reg3	= 446,
	OPC_RH850_SAR_reg1_reg2			= 447,
	OPC_RH850_SAR_reg1_reg2_reg3	= 448,
	OPC_RH850_SASF_cccc_reg2		= 449,
	OPC_RH850_SETF_cccc_reg2		= 450,
	OPC_RH850_SHL_reg1_reg2			= 451,
	OPC_RH850_SHL_reg1_reg2_reg3	= 453,
	OPC_RH850_SXB_reg1				= 454,
	OPC_RH850_SXH_reg1				= 455,
	OPC_RH850_ZXB_reg1				= 456,
	OPC_RH850_ZXH_reg1				= 457,



};

enum{
	OPC_RH850_LDSR_reg2_regID_selID	= 1,
	OPC_RH850_STSR_regID_reg2_selID = 2,
	//check for unintentional matching
	OPC_RH850_PREPARE_list12_imm5	= 12,
	OPC_RH850_PREPARE_list12_imm5_sp	= 13,
	OPC_RH850_RIE 					= 3,
	OPC_RH850_CALLT_imm6			= 4,
	OPC_RH850_CAXI_reg1_reg2_reg3	= 5,
	OPC_RH850_DISPOSE_imm5_list12	= 7,
	OPC_RH850_DISPOSE_imm5_list12_reg1 = 8,
	OPC_RH850_FETRAP_vector4		= 15,
	OPC_RH850_SWITCH_reg1			= 10,
};

enum{ // magic numbers for branch opcodes
	OPC_RH850_JR_imm22			= 0,
	OPC_RH850_JR_imm32			= 1,
	OPC_RH850_JARL_disp22_reg2	= 2,
	OPC_RH850_JARL_disp32_reg1	= 3, //48-bit
	OPC_RH850_JARL_reg1_reg3	= 4,
	OPC_RH850_JMP_reg1			= 5,
	OPC_RH850_JMP_disp32_reg1	= 6,

};


#define MASK_OP_FORMAT_I_0(op)	(MASK_OP_MAJOR(op) | (op & (0x1F << 11)) | (op & (0x1F << 0)))
enum {
	OPC_RH850_NOP 	= OPC_RH850_16bit_0 | (0x0 << 11) | (0x0 << 0),
	OPC_RH850_SYNCI = OPC_RH850_16bit_0 | (0x0 << 11) | (0x1C << 0),
	OPC_RH850_SYNCE = OPC_RH850_16bit_0 | (0x0 << 11) | (0x1D << 0),
	OPC_RH850_SYNCM = OPC_RH850_16bit_0 | (0x0 << 11) | (0x1E << 0),
	OPC_RH850_SYNCP = OPC_RH850_16bit_0 | (0x0 << 11) | (0x1F << 0)
};



#define MASK_OP_ST_LD0(op)   (MASK_OP_MAJOR(op) | (op & (0x1F << 11)) | (op & (0xF << 16)))
enum {

	OPC_RH850_LDB2 	= OPC_RH850_ST_LD_0 | (0x00 << 11 ) | (0x5 << 16),
	OPC_RH850_LDH2 	= OPC_RH850_ST_LD_0 | (0x00 << 11 ) | (0x7 << 16),
	OPC_RH850_LDW2 	= OPC_RH850_ST_LD_0 | (0x00 << 11 ) | (0x9 << 16),
	OPC_RH850_STB2 	= OPC_RH850_ST_LD_0 | (0x00 << 11 ) | (0xD << 16),		//sub-op bits 11-15 are 0, inst. differ in sub-op bits 16-19 (ST.B2=D, ST.W2=F) (format XIV)
	OPC_RH850_STW2	= OPC_RH850_ST_LD_0 | (0x00 << 11 ) | (0xF << 16),

};
#define MASK_OP_ST_LD1(op)   (MASK_OP_MAJOR(op) | (op & (0x1F << 11)) | (op & (0xF << 16)))
enum {

	OPC_RH850_LDBU2 = OPC_RH850_ST_LD_1 | (0x00 << 11 ) | (0x5 << 16),
	OPC_RH850_LDHU2 = OPC_RH850_ST_LD_1 | (0x00 << 11 ) | (0x7 << 16),
	OPC_RH850_LDDW 	= OPC_RH850_ST_LD_1 | (0x00 << 11 ) | (0x9 << 16),
	OPC_RH850_STDW 	= OPC_RH850_ST_LD_1 | (0x00 << 11 ) | (0xF << 16),
	OPC_RH850_STH2 	= OPC_RH850_ST_LD_1 | (0x00 << 11 ) | (0xD << 16),
};

#define MASK_OP_32BIT_SUB(op)	(op & (0xF << 23))
enum {
	OPC_RH850_LDSR_RIE_SETF_STSR	=	(0x0 << 23),
	OPC_RH850_FORMAT_IX		=	(0x1 << 23),	// 0001
	OPC_RH850_FORMAT_X		=	(0x2 << 23),	// 0010
	OPC_RH850_MUL_INSTS		=	(0x4 << 23),	// 0100 this is also for SASF
	OPC_RH850_FORMAT_XI		=	(0x5 << 23),	// 0101
	OPC_RH850_FORMAT_XII	=	(0x6 << 23),	// 0110
	OPC_RH850_ADDIT_ARITH	=	(0x7 << 23)		// 0111
};

#define MASK_OP_FORMAT_IX(op) (op & (0x3 << 21))   //0001 on b26-b23
enum {
	OPC_RH850_BINS_0	= (0x0  << 21), //BINS0,SHR, SHR2
	OPC_RH850_BINS_1	= (0x1  << 21), //BINS1,SAR,SAR2
	OPC_RH850_BINS_2	= (0x2  << 21),	//BINS2,SHL, SHL2, ROTL, ROTL2
	OPC_RH850_BIT_MANIPULATION		= (0x3  << 21),	//clr1, set, tst1, not1, caxi in format IX
};

#define MASK_OP_FORMAT_X(op) (op & (0xFFF << 11))	//0010 on b26-b23
enum {
	OPC_RH850_CTRET		= 	(0x880 << 11),
	OPC_RH850_DI		= 	(0xC00 << 11),
	OPC_RH850_EI		= 	(0XC10 << 11),
	OPC_RH850_EIRET		= 	(0X900 << 11),
	OPC_RH850_FERET		= 	(0X940 << 11),
	OPC_RH850_HALT		= 	(0X400 << 11),
	OPC_RH850_JARL3		= 	(0XC18 << 11),
	OPC_RH850_SNOOZE	= 	(0x401 << 11),
	OPC_RH850_SYSCALL	= 	(0xC1A << 11),
	OPC_RH850_TRAP		= 	(0x000 << 11),
	OPC_RH850_PREF		= 	(0xC1B << 11),
	OPC_RH850_POPSP_rh_rt	= 	(0xC0C << 11),
	OPC_RH850_PUSHSP_rh_rt	= 	(0xC08 << 11),
	//don't forget CACHE
	OPC_RH850_CLL	= 	(0xC1F << 11),

};

#define MASK_OP_FORMAT_XI(op) (op & (0x7F << 16))
enum {
	OPC_RH850_DIVH_reg1_reg2_reg3 	= 0x0,
	OPC_RH850_DIVHU_reg1_reg2_reg3 	= 0x2,
	OPC_RH850_DIV_reg1_reg2_reg3 	= 0x40,
	OPC_RH850_DIVQ 	= 0x7C,
	OPC_RH850_DIVQU	= 0x7E,
	OPC_RH850_DIVU_reg1_reg2_reg3	= 0x42
};

#define MASK_OP_FORMAT_XII(op) (op & (0x3 << 17))
enum {
	OPC_RH850_BSW_reg2_reg3	= (0x0 << 0),
	OPC_RH850_BSH_reg2_reg3 = (0x1 << 0),
	OPC_RH850_HSW_reg2_reg3	= (0x2 << 0),
	OPC_RH850_HSH_reg2_reg3	= (0x3 << 0),
	// SCHOL, SCHOR, SCH1L, SCH1R
	OPC_RH850_SCH0R_reg2_reg3	= (0x0 << 0),
	OPC_RH850_SCH1R_reg2_reg3	= (0x1 << 0), //this is also STCW
	OPC_RH850_SCH0L_reg2_reg3	= (0x2 << 0),
	OPC_RH850_SCH1L_reg2_reg3	= (0x3 << 0),


};

#define MASK_ADDIT_ARITH_OP(op) (op & (0x3 << 21))
enum {
	OPC_RH850_SBF_SATSUB	= 0x0,
	OPC_RH850_ADF_SATADD3	= 0x1,
	OPC_RH850_MAC_reg1_reg2_reg3_reg4	= 0x2,
	OPC_RH850_MACU_reg1_reg2_reg3_reg4	= 0x3,




};

#define MASK_OP_FORMAT_V_FORMAT_XIII(op) (op & (0x1F << 6))


enum {
	operation_LDL_W = 0,
	operation_STC_W = 1,
	operation_CLL = 2,
};



//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////


#define GET_B_IMM(inst) ((extract32(inst, 8, 4) << 1) \
                         | (extract32(inst, 25, 6) << 5) \
                         | (extract32(inst, 7, 1) << 11) \
                         | (sextract64(inst, 31, 1) << 12))

#define GET_STORE_IMM(inst) ((extract32(inst, 7, 5)) \
                             | (sextract64(inst, 25, 7) << 5))

#define GET_JAL_IMM(inst) ((extract32(inst, 21, 10) << 1) \
                           | (extract32(inst, 20, 1) << 11) \
                           | (extract32(inst, 12, 8) << 12) \
                           | (sextract64(inst, 31, 1) << 20))


#define GET_RS1(inst)  extract32(inst, 0, 5)		//appropriate for RH850
#define GET_RS2(inst)  extract32(inst, 11, 5)		//appropriate for RH850
#define GET_RS3(inst)  extract32(inst, 27, 5)		//appropriate for RH850
#define GET_DISP(inst) (extract32(inst, 20, 7) | (sextract32(inst, 32, 16) << 7 ) ) //b47-b32 + b26-b20


#define GET_RM(inst)   extract32(inst, 12, 3)
#define GET_RD(inst)   extract32(inst, 7, 5)
#define GET_IMM(inst)  sextract64(inst, 20, 12)
#define GET_IMM_32(inst)	sextract64(inst, 16, 32)

/* RVC decoding macros */
#define GET_C_IMM(inst)             (extract32(inst, 2, 5) \
                                    | (sextract64(inst, 12, 1) << 5))
#define GET_C_ZIMM(inst)            (extract32(inst, 2, 5) \
                                    | (extract32(inst, 12, 1) << 5))
#define GET_C_ADDI4SPN_IMM(inst)    ((extract32(inst, 6, 1) << 2) \
                                    | (extract32(inst, 5, 1) << 3) \
                                    | (extract32(inst, 11, 2) << 4) \
                                    | (extract32(inst, 7, 4) << 6))
#define GET_C_ADDI16SP_IMM(inst)    ((extract32(inst, 6, 1) << 4) \
                                    | (extract32(inst, 2, 1) << 5) \
                                    | (extract32(inst, 5, 1) << 6) \
                                    | (extract32(inst, 3, 2) << 7) \
                                    | (sextract64(inst, 12, 1) << 9))
#define GET_C_LWSP_IMM(inst)        ((extract32(inst, 4, 3) << 2) \
                                    | (extract32(inst, 12, 1) << 5) \
                                    | (extract32(inst, 2, 2) << 6))
#define GET_C_LDSP_IMM(inst)        ((extract32(inst, 5, 2) << 3) \
                                    | (extract32(inst, 12, 1) << 5) \
                                    | (extract32(inst, 2, 3) << 6))
#define GET_C_SWSP_IMM(inst)        ((extract32(inst, 9, 4) << 2) \
                                    | (extract32(inst, 7, 2) << 6))
#define GET_C_SDSP_IMM(inst)        ((extract32(inst, 10, 3) << 3) \
                                    | (extract32(inst, 7, 3) << 6))
#define GET_C_LW_IMM(inst)          ((extract32(inst, 6, 1) << 2) \
                                    | (extract32(inst, 10, 3) << 3) \
                                    | (extract32(inst, 5, 1) << 6))
#define GET_C_LD_IMM(inst)          ((extract32(inst, 10, 3) << 3) \
                                    | (extract32(inst, 5, 2) << 6))
#define GET_C_J_IMM(inst)           ((extract32(inst, 3, 3) << 1) \
                                    | (extract32(inst, 11, 1) << 4) \
                                    | (extract32(inst, 2, 1) << 5) \
                                    | (extract32(inst, 7, 1) << 6) \
                                    | (extract32(inst, 6, 1) << 7) \
                                    | (extract32(inst, 9, 2) << 8) \
                                    | (extract32(inst, 8, 1) << 10) \
                                    | (sextract64(inst, 12, 1) << 11))
#define GET_C_B_IMM(inst)           ((extract32(inst, 3, 2) << 1) \
                                    | (extract32(inst, 10, 2) << 3) \
                                    | (extract32(inst, 2, 1) << 5) \
                                    | (extract32(inst, 5, 2) << 6) \
                                    | (sextract64(inst, 12, 1) << 8))
#define GET_C_SIMM3(inst)           extract32(inst, 10, 3)
#define GET_C_RD(inst)              GET_RD(inst)
#define GET_C_RS1(inst)             GET_RD(inst)
#define GET_C_RS2(inst)             extract32(inst, 2, 5)
#define GET_C_RS1S(inst)            (8 + extract32(inst, 7, 3))
#define GET_C_RS2S(inst)            (8 + extract32(inst, 2, 3))
