// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

package unicorn;

public interface Rh850Const {
   public static final int UC_RH850_SYSREG_SELID0 = 32;
   public static final int UC_RH850_SYSREG_SELID1 = 64;
   public static final int UC_RH850_SYSREG_SELID2 = 96;
   public static final int UC_RH850_SYSREG_SELID3 = 128;
   public static final int UC_RH850_SYSREG_SELID4 = 160;
   public static final int UC_RH850_SYSREG_SELID5 = 192;
   public static final int UC_RH850_SYSREG_SELID6 = 224;
   public static final int UC_RH850_SYSREG_SELID7 = 256;

// RH850 global purpose registers

   public static final int UC_RH850_REG_R0 = 0;
   public static final int UC_RH850_REG_R1 = 1;
   public static final int UC_RH850_REG_R2 = 2;
   public static final int UC_RH850_REG_R3 = 3;
   public static final int UC_RH850_REG_R4 = 4;
   public static final int UC_RH850_REG_R5 = 5;
   public static final int UC_RH850_REG_R6 = 6;
   public static final int UC_RH850_REG_R7 = 7;
   public static final int UC_RH850_REG_R8 = 8;
   public static final int UC_RH850_REG_R9 = 9;
   public static final int UC_RH850_REG_R10 = 10;
   public static final int UC_RH850_REG_R11 = 11;
   public static final int UC_RH850_REG_R12 = 12;
   public static final int UC_RH850_REG_R13 = 13;
   public static final int UC_RH850_REG_R14 = 14;
   public static final int UC_RH850_REG_R15 = 15;
   public static final int UC_RH850_REG_R16 = 16;
   public static final int UC_RH850_REG_R17 = 17;
   public static final int UC_RH850_REG_R18 = 18;
   public static final int UC_RH850_REG_R19 = 19;
   public static final int UC_RH850_REG_R20 = 20;
   public static final int UC_RH850_REG_R21 = 21;
   public static final int UC_RH850_REG_R22 = 22;
   public static final int UC_RH850_REG_R23 = 23;
   public static final int UC_RH850_REG_R24 = 24;
   public static final int UC_RH850_REG_R25 = 25;
   public static final int UC_RH850_REG_R26 = 26;
   public static final int UC_RH850_REG_R27 = 27;
   public static final int UC_RH850_REG_R28 = 28;
   public static final int UC_RH850_REG_R29 = 29;
   public static final int UC_RH850_REG_R30 = 30;
   public static final int UC_RH850_REG_R31 = 31;

// RH850 system registers, selection ID 0
   public static final int UC_RH850_REG_EIPC = 32;
   public static final int UC_RH850_REG_EIPSW = 33;
   public static final int UC_RH850_REG_FEPC = 34;
   public static final int UC_RH850_REG_FEPSW = 35;
   public static final int UC_RH850_REG_ECR = 36;
   public static final int UC_RH850_REG_PSW = 37;
   public static final int UC_RH850_REG_FPSR = 38;
   public static final int UC_RH850_REG_FPEPC = 39;
   public static final int UC_RH850_REG_FPST = 40;
   public static final int UC_RH850_REG_FPCC = 41;
   public static final int UC_RH850_REG_FPCFG = 42;
   public static final int UC_RH850_REG_FPEC = 43;
   public static final int UC_RH850_REG_EIIC = 45;
   public static final int UC_RH850_REG_FEIC = 46;
   public static final int UC_RH850_REG_CTPC = 48;
   public static final int UC_RH850_REG_CTPSW = 49;
   public static final int UC_RH850_REG_CTBP = 52;
   public static final int UC_RH850_REG_EIWR = 60;
   public static final int UC_RH850_REG_FEWR = 61;
   public static final int UC_RH850_REG_BSEL = 63;

// RH850 system regusters, selection ID 1
   public static final int UC_RH850_REG_MCFG0 = 64;
   public static final int UC_RH850_REG_RBASE = 65;
   public static final int UC_RH850_REG_EBASE = 66;
   public static final int UC_RH850_REG_INTBP = 67;
   public static final int UC_RH850_REG_MCTL = 68;
   public static final int UC_RH850_REG_PID = 69;
   public static final int UC_RH850_REG_SCCFG = 75;
   public static final int UC_RH850_REG_SCBP = 76;

// RH850 system registers, selection ID 2
   public static final int UC_RH850_REG_HTCFG0 = 96;
   public static final int UC_RH850_REG_MEA = 102;
   public static final int UC_RH850_REG_ASID = 103;
   public static final int UC_RH850_REG_MEI = 104;
   public static final int UC_RH850_REG_PC = 288;
   public static final int UC_RH850_REG_ENDING = 289;

// RH8509 Registers aliases.

   public static final int UC_RH850_REG_ZERO = 0;
<<<<<<< HEAD
   public static final int UC_RH850_REG_SP = 3;
=======
   public static final int UC_RH850_REG_SP = 2;
>>>>>>> 4abc05b3 (Removed hook-related code (causes some issues for now).)
   public static final int UC_RH850_REG_EP = 30;
   public static final int UC_RH850_REG_LP = 31;

}
