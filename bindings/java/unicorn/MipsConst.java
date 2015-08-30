// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

package unicorn;

public interface MipsConst {

// MIPS registers

   public static final int UC_MIPS_REG_INVALID = 0;

// General purpose registers
   public static final int UC_MIPS_REG_PC = 1;
   public static final int UC_MIPS_REG_0 = 2;
   public static final int UC_MIPS_REG_1 = 3;
   public static final int UC_MIPS_REG_2 = 4;
   public static final int UC_MIPS_REG_3 = 5;
   public static final int UC_MIPS_REG_4 = 6;
   public static final int UC_MIPS_REG_5 = 7;
   public static final int UC_MIPS_REG_6 = 8;
   public static final int UC_MIPS_REG_7 = 9;
   public static final int UC_MIPS_REG_8 = 10;
   public static final int UC_MIPS_REG_9 = 11;
   public static final int UC_MIPS_REG_10 = 12;
   public static final int UC_MIPS_REG_11 = 13;
   public static final int UC_MIPS_REG_12 = 14;
   public static final int UC_MIPS_REG_13 = 15;
   public static final int UC_MIPS_REG_14 = 16;
   public static final int UC_MIPS_REG_15 = 17;
   public static final int UC_MIPS_REG_16 = 18;
   public static final int UC_MIPS_REG_17 = 19;
   public static final int UC_MIPS_REG_18 = 20;
   public static final int UC_MIPS_REG_19 = 21;
   public static final int UC_MIPS_REG_20 = 22;
   public static final int UC_MIPS_REG_21 = 23;
   public static final int UC_MIPS_REG_22 = 24;
   public static final int UC_MIPS_REG_23 = 25;
   public static final int UC_MIPS_REG_24 = 26;
   public static final int UC_MIPS_REG_25 = 27;
   public static final int UC_MIPS_REG_26 = 28;
   public static final int UC_MIPS_REG_27 = 29;
   public static final int UC_MIPS_REG_28 = 30;
   public static final int UC_MIPS_REG_29 = 31;
   public static final int UC_MIPS_REG_30 = 32;
   public static final int UC_MIPS_REG_31 = 33;

// DSP registers
   public static final int UC_MIPS_REG_DSPCCOND = 34;
   public static final int UC_MIPS_REG_DSPCARRY = 35;
   public static final int UC_MIPS_REG_DSPEFI = 36;
   public static final int UC_MIPS_REG_DSPOUTFLAG = 37;
   public static final int UC_MIPS_REG_DSPOUTFLAG16_19 = 38;
   public static final int UC_MIPS_REG_DSPOUTFLAG20 = 39;
   public static final int UC_MIPS_REG_DSPOUTFLAG21 = 40;
   public static final int UC_MIPS_REG_DSPOUTFLAG22 = 41;
   public static final int UC_MIPS_REG_DSPOUTFLAG23 = 42;
   public static final int UC_MIPS_REG_DSPPOS = 43;
   public static final int UC_MIPS_REG_DSPSCOUNT = 44;

// ACC registers
   public static final int UC_MIPS_REG_AC0 = 45;
   public static final int UC_MIPS_REG_AC1 = 46;
   public static final int UC_MIPS_REG_AC2 = 47;
   public static final int UC_MIPS_REG_AC3 = 48;

// COP registers
   public static final int UC_MIPS_REG_CC0 = 49;
   public static final int UC_MIPS_REG_CC1 = 50;
   public static final int UC_MIPS_REG_CC2 = 51;
   public static final int UC_MIPS_REG_CC3 = 52;
   public static final int UC_MIPS_REG_CC4 = 53;
   public static final int UC_MIPS_REG_CC5 = 54;
   public static final int UC_MIPS_REG_CC6 = 55;
   public static final int UC_MIPS_REG_CC7 = 56;

// FPU registers
   public static final int UC_MIPS_REG_F0 = 57;
   public static final int UC_MIPS_REG_F1 = 58;
   public static final int UC_MIPS_REG_F2 = 59;
   public static final int UC_MIPS_REG_F3 = 60;
   public static final int UC_MIPS_REG_F4 = 61;
   public static final int UC_MIPS_REG_F5 = 62;
   public static final int UC_MIPS_REG_F6 = 63;
   public static final int UC_MIPS_REG_F7 = 64;
   public static final int UC_MIPS_REG_F8 = 65;
   public static final int UC_MIPS_REG_F9 = 66;
   public static final int UC_MIPS_REG_F10 = 67;
   public static final int UC_MIPS_REG_F11 = 68;
   public static final int UC_MIPS_REG_F12 = 69;
   public static final int UC_MIPS_REG_F13 = 70;
   public static final int UC_MIPS_REG_F14 = 71;
   public static final int UC_MIPS_REG_F15 = 72;
   public static final int UC_MIPS_REG_F16 = 73;
   public static final int UC_MIPS_REG_F17 = 74;
   public static final int UC_MIPS_REG_F18 = 75;
   public static final int UC_MIPS_REG_F19 = 76;
   public static final int UC_MIPS_REG_F20 = 77;
   public static final int UC_MIPS_REG_F21 = 78;
   public static final int UC_MIPS_REG_F22 = 79;
   public static final int UC_MIPS_REG_F23 = 80;
   public static final int UC_MIPS_REG_F24 = 81;
   public static final int UC_MIPS_REG_F25 = 82;
   public static final int UC_MIPS_REG_F26 = 83;
   public static final int UC_MIPS_REG_F27 = 84;
   public static final int UC_MIPS_REG_F28 = 85;
   public static final int UC_MIPS_REG_F29 = 86;
   public static final int UC_MIPS_REG_F30 = 87;
   public static final int UC_MIPS_REG_F31 = 88;
   public static final int UC_MIPS_REG_FCC0 = 89;
   public static final int UC_MIPS_REG_FCC1 = 90;
   public static final int UC_MIPS_REG_FCC2 = 91;
   public static final int UC_MIPS_REG_FCC3 = 92;
   public static final int UC_MIPS_REG_FCC4 = 93;
   public static final int UC_MIPS_REG_FCC5 = 94;
   public static final int UC_MIPS_REG_FCC6 = 95;
   public static final int UC_MIPS_REG_FCC7 = 96;

// AFPR128
   public static final int UC_MIPS_REG_W0 = 97;
   public static final int UC_MIPS_REG_W1 = 98;
   public static final int UC_MIPS_REG_W2 = 99;
   public static final int UC_MIPS_REG_W3 = 100;
   public static final int UC_MIPS_REG_W4 = 101;
   public static final int UC_MIPS_REG_W5 = 102;
   public static final int UC_MIPS_REG_W6 = 103;
   public static final int UC_MIPS_REG_W7 = 104;
   public static final int UC_MIPS_REG_W8 = 105;
   public static final int UC_MIPS_REG_W9 = 106;
   public static final int UC_MIPS_REG_W10 = 107;
   public static final int UC_MIPS_REG_W11 = 108;
   public static final int UC_MIPS_REG_W12 = 109;
   public static final int UC_MIPS_REG_W13 = 110;
   public static final int UC_MIPS_REG_W14 = 111;
   public static final int UC_MIPS_REG_W15 = 112;
   public static final int UC_MIPS_REG_W16 = 113;
   public static final int UC_MIPS_REG_W17 = 114;
   public static final int UC_MIPS_REG_W18 = 115;
   public static final int UC_MIPS_REG_W19 = 116;
   public static final int UC_MIPS_REG_W20 = 117;
   public static final int UC_MIPS_REG_W21 = 118;
   public static final int UC_MIPS_REG_W22 = 119;
   public static final int UC_MIPS_REG_W23 = 120;
   public static final int UC_MIPS_REG_W24 = 121;
   public static final int UC_MIPS_REG_W25 = 122;
   public static final int UC_MIPS_REG_W26 = 123;
   public static final int UC_MIPS_REG_W27 = 124;
   public static final int UC_MIPS_REG_W28 = 125;
   public static final int UC_MIPS_REG_W29 = 126;
   public static final int UC_MIPS_REG_W30 = 127;
   public static final int UC_MIPS_REG_W31 = 128;
   public static final int UC_MIPS_REG_HI = 129;
   public static final int UC_MIPS_REG_LO = 130;
   public static final int UC_MIPS_REG_P0 = 131;
   public static final int UC_MIPS_REG_P1 = 132;
   public static final int UC_MIPS_REG_P2 = 133;
   public static final int UC_MIPS_REG_MPL0 = 134;
   public static final int UC_MIPS_REG_MPL1 = 135;
   public static final int UC_MIPS_REG_MPL2 = 136;
   public static final int UC_MIPS_REG_ENDING = 137;
   public static final int UC_MIPS_REG_ZERO = 2;
   public static final int UC_MIPS_REG_AT = 3;
   public static final int UC_MIPS_REG_V0 = 4;
   public static final int UC_MIPS_REG_V1 = 5;
   public static final int UC_MIPS_REG_A0 = 6;
   public static final int UC_MIPS_REG_A1 = 7;
   public static final int UC_MIPS_REG_A2 = 8;
   public static final int UC_MIPS_REG_A3 = 9;
   public static final int UC_MIPS_REG_T0 = 10;
   public static final int UC_MIPS_REG_T1 = 11;
   public static final int UC_MIPS_REG_T2 = 12;
   public static final int UC_MIPS_REG_T3 = 13;
   public static final int UC_MIPS_REG_T4 = 14;
   public static final int UC_MIPS_REG_T5 = 15;
   public static final int UC_MIPS_REG_T6 = 16;
   public static final int UC_MIPS_REG_T7 = 17;
   public static final int UC_MIPS_REG_S0 = 18;
   public static final int UC_MIPS_REG_S1 = 19;
   public static final int UC_MIPS_REG_S2 = 20;
   public static final int UC_MIPS_REG_S3 = 21;
   public static final int UC_MIPS_REG_S4 = 22;
   public static final int UC_MIPS_REG_S5 = 23;
   public static final int UC_MIPS_REG_S6 = 24;
   public static final int UC_MIPS_REG_S7 = 25;
   public static final int UC_MIPS_REG_T8 = 26;
   public static final int UC_MIPS_REG_T9 = 27;
   public static final int UC_MIPS_REG_K0 = 28;
   public static final int UC_MIPS_REG_K1 = 29;
   public static final int UC_MIPS_REG_GP = 30;
   public static final int UC_MIPS_REG_SP = 31;
   public static final int UC_MIPS_REG_FP = 32;
   public static final int UC_MIPS_REG_S8 = 32;
   public static final int UC_MIPS_REG_RA = 33;
   public static final int UC_MIPS_REG_HI0 = 45;
   public static final int UC_MIPS_REG_HI1 = 46;
   public static final int UC_MIPS_REG_HI2 = 47;
   public static final int UC_MIPS_REG_HI3 = 48;
   public static final int UC_MIPS_REG_LO0 = 45;
   public static final int UC_MIPS_REG_LO1 = 46;
   public static final int UC_MIPS_REG_LO2 = 47;
   public static final int UC_MIPS_REG_LO3 = 48;

}
