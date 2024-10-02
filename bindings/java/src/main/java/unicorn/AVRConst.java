// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

package unicorn;

public interface AVRConst {

    // AVR architectures
    public static final int UC_AVR_ARCH_AVR1 = 10;
    public static final int UC_AVR_ARCH_AVR2 = 20;
    public static final int UC_AVR_ARCH_AVR25 = 25;
    public static final int UC_AVR_ARCH_AVR3 = 30;
    public static final int UC_AVR_ARCH_AVR4 = 40;
    public static final int UC_AVR_ARCH_AVR5 = 50;
    public static final int UC_AVR_ARCH_AVR51 = 51;
    public static final int UC_AVR_ARCH_AVR6 = 60;
    public static final int UC_AVR_ARCH_AVRXMEGA = 100;
    public static final int UC_AVR_ARCH_AVRXMEGAR2 = 101;
    public static final int UC_CPU_AVR_ARCH = 1000;

    // AVR CPU
    public static final int UC_CPU_AVR_ATMEGA16 = 50016;
    public static final int UC_CPU_AVR_ATMEGA32 = 50032;
    public static final int UC_CPU_AVR_ATMEGA64 = 50064;
    public static final int UC_CPU_AVR_ATMEGA128 = 51128;
    public static final int UC_CPU_AVR_ATMEGA128RFR2 = 51129;
    public static final int UC_CPU_AVR_ATMEGA1280 = 51130;
    public static final int UC_CPU_AVR_ATMEGA256 = 60256;
    public static final int UC_CPU_AVR_ATMEGA256RFR2 = 60257;
    public static final int UC_CPU_AVR_ATMEGA2560 = 60258;
    public static final int UC_CPU_AVR_ATXMEGA16A4 = 100016;
    public static final int UC_CPU_AVR_ATXMEGA32A4 = 100032;
    public static final int UC_CPU_AVR_ATXMEGA64A3 = 100064;
    public static final int UC_CPU_AVR_ATXMEGA64A1U = 101064;
    public static final int UC_CPU_AVR_ATXMEGA64A3U = 101065;
    public static final int UC_CPU_AVR_ATXMEGA64A4U = 101066;
    public static final int UC_CPU_AVR_ATXMEGA128A3 = 100128;
    public static final int UC_CPU_AVR_ATXMEGA128A1U = 101128;
    public static final int UC_CPU_AVR_ATXMEGA128A3U = 101129;
    public static final int UC_CPU_AVR_ATXMEGA128A4U = 101130;
    public static final int UC_CPU_AVR_ATXMEGA192A3 = 100192;
    public static final int UC_CPU_AVR_ATXMEGA192A3U = 101192;
    public static final int UC_CPU_AVR_ATXMEGA256A3 = 100256;
    public static final int UC_CPU_AVR_ATXMEGA256A3U = 101256;

    // AVR memory
    public static final int UC_AVR_MEM_FLASH = 134217728;

    // AVR registers

    public static final int UC_AVR_REG_INVALID = 0;
    public static final int UC_AVR_REG_R0 = 1;
    public static final int UC_AVR_REG_R1 = 2;
    public static final int UC_AVR_REG_R2 = 3;
    public static final int UC_AVR_REG_R3 = 4;
    public static final int UC_AVR_REG_R4 = 5;
    public static final int UC_AVR_REG_R5 = 6;
    public static final int UC_AVR_REG_R6 = 7;
    public static final int UC_AVR_REG_R7 = 8;
    public static final int UC_AVR_REG_R8 = 9;
    public static final int UC_AVR_REG_R9 = 10;
    public static final int UC_AVR_REG_R10 = 11;
    public static final int UC_AVR_REG_R11 = 12;
    public static final int UC_AVR_REG_R12 = 13;
    public static final int UC_AVR_REG_R13 = 14;
    public static final int UC_AVR_REG_R14 = 15;
    public static final int UC_AVR_REG_R15 = 16;
    public static final int UC_AVR_REG_R16 = 17;
    public static final int UC_AVR_REG_R17 = 18;
    public static final int UC_AVR_REG_R18 = 19;
    public static final int UC_AVR_REG_R19 = 20;
    public static final int UC_AVR_REG_R20 = 21;
    public static final int UC_AVR_REG_R21 = 22;
    public static final int UC_AVR_REG_R22 = 23;
    public static final int UC_AVR_REG_R23 = 24;
    public static final int UC_AVR_REG_R24 = 25;
    public static final int UC_AVR_REG_R25 = 26;
    public static final int UC_AVR_REG_R26 = 27;
    public static final int UC_AVR_REG_R27 = 28;
    public static final int UC_AVR_REG_R28 = 29;
    public static final int UC_AVR_REG_R29 = 30;
    public static final int UC_AVR_REG_R30 = 31;
    public static final int UC_AVR_REG_R31 = 32;
    public static final int UC_AVR_REG_PC = 33;
    public static final int UC_AVR_REG_SP = 34;
    public static final int UC_AVR_REG_RAMPD = 57;
    public static final int UC_AVR_REG_RAMPX = 58;
    public static final int UC_AVR_REG_RAMPY = 59;
    public static final int UC_AVR_REG_RAMPZ = 60;
    public static final int UC_AVR_REG_EIND = 61;
    public static final int UC_AVR_REG_SPL = 62;
    public static final int UC_AVR_REG_SPH = 63;
    public static final int UC_AVR_REG_SREG = 64;

    // 16-bit coalesced registers
    public static final int UC_AVR_REG_R0W = 65;
    public static final int UC_AVR_REG_R1W = 66;
    public static final int UC_AVR_REG_R2W = 67;
    public static final int UC_AVR_REG_R3W = 68;
    public static final int UC_AVR_REG_R4W = 69;
    public static final int UC_AVR_REG_R5W = 70;
    public static final int UC_AVR_REG_R6W = 71;
    public static final int UC_AVR_REG_R7W = 72;
    public static final int UC_AVR_REG_R8W = 73;
    public static final int UC_AVR_REG_R9W = 74;
    public static final int UC_AVR_REG_R10W = 75;
    public static final int UC_AVR_REG_R11W = 76;
    public static final int UC_AVR_REG_R12W = 77;
    public static final int UC_AVR_REG_R13W = 78;
    public static final int UC_AVR_REG_R14W = 79;
    public static final int UC_AVR_REG_R15W = 80;
    public static final int UC_AVR_REG_R16W = 81;
    public static final int UC_AVR_REG_R17W = 82;
    public static final int UC_AVR_REG_R18W = 83;
    public static final int UC_AVR_REG_R19W = 84;
    public static final int UC_AVR_REG_R20W = 85;
    public static final int UC_AVR_REG_R21W = 86;
    public static final int UC_AVR_REG_R22W = 87;
    public static final int UC_AVR_REG_R23W = 88;
    public static final int UC_AVR_REG_R24W = 89;
    public static final int UC_AVR_REG_R25W = 90;
    public static final int UC_AVR_REG_R26W = 91;
    public static final int UC_AVR_REG_R27W = 92;
    public static final int UC_AVR_REG_R28W = 93;
    public static final int UC_AVR_REG_R29W = 94;
    public static final int UC_AVR_REG_R30W = 95;

    // 32-bit coalesced registers
    public static final int UC_AVR_REG_R0D = 97;
    public static final int UC_AVR_REG_R1D = 98;
    public static final int UC_AVR_REG_R2D = 99;
    public static final int UC_AVR_REG_R3D = 100;
    public static final int UC_AVR_REG_R4D = 101;
    public static final int UC_AVR_REG_R5D = 102;
    public static final int UC_AVR_REG_R6D = 103;
    public static final int UC_AVR_REG_R7D = 104;
    public static final int UC_AVR_REG_R8D = 105;
    public static final int UC_AVR_REG_R9D = 106;
    public static final int UC_AVR_REG_R10D = 107;
    public static final int UC_AVR_REG_R11D = 108;
    public static final int UC_AVR_REG_R12D = 109;
    public static final int UC_AVR_REG_R13D = 110;
    public static final int UC_AVR_REG_R14D = 111;
    public static final int UC_AVR_REG_R15D = 112;
    public static final int UC_AVR_REG_R16D = 113;
    public static final int UC_AVR_REG_R17D = 114;
    public static final int UC_AVR_REG_R18D = 115;
    public static final int UC_AVR_REG_R19D = 116;
    public static final int UC_AVR_REG_R20D = 117;
    public static final int UC_AVR_REG_R21D = 118;
    public static final int UC_AVR_REG_R22D = 119;
    public static final int UC_AVR_REG_R23D = 120;
    public static final int UC_AVR_REG_R24D = 121;
    public static final int UC_AVR_REG_R25D = 122;
    public static final int UC_AVR_REG_R26D = 123;
    public static final int UC_AVR_REG_R27D = 124;
    public static final int UC_AVR_REG_R28D = 125;

    // Alias registers
    public static final int UC_AVR_REG_Xhi = 28;
    public static final int UC_AVR_REG_Xlo = 27;
    public static final int UC_AVR_REG_Yhi = 30;
    public static final int UC_AVR_REG_Ylo = 29;
    public static final int UC_AVR_REG_Zhi = 32;
    public static final int UC_AVR_REG_Zlo = 31;
    public static final int UC_AVR_REG_X = 91;
    public static final int UC_AVR_REG_Y = 93;
    public static final int UC_AVR_REG_Z = 95;

}
