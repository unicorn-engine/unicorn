package unicorn;

public interface UnicornModes {
   public static final int UC_MODE_LITTLE_ENDIAN = 0;  // little-endian mode (default mode)
   public static final int UC_MODE_ARM = 0;            // 32-bit ARM
   public static final int UC_MODE_16 = 1 << 1;        // 16-bit mode (X86)
   public static final int UC_MODE_32 = 1 << 2;        // 32-bit mode (X86)
   public static final int UC_MODE_64 = 1 << 3;        // 64-bit mode (X86; PPC)
   public static final int UC_MODE_THUMB = 1 << 4;     // ARM's Thumb mode; including Thumb-2
   public static final int UC_MODE_MCLASS = 1 << 5;    // ARM's Cortex-M series
   public static final int UC_MODE_V8 = 1 << 6;        // ARMv8 A32 encodings for ARM
   public static final int UC_MODE_MICRO = 1 << 4;     // MicroMips mode (MIPS)
   public static final int UC_MODE_MIPS3 = 1 << 5;     // Mips III ISA
   public static final int UC_MODE_MIPS32R6 = 1 << 6;  // Mips32r6 ISA
   public static final int UC_MODE_V9 = 1 << 4;        // SparcV9 mode (Sparc)
   public static final int UC_MODE_QPX = 1 << 4;       // Quad Processing eXtensions mode (PPC)
   public static final int UC_MODE_BIG_ENDIAN = 1 << 31;   // big-endian mode
   public static final int UC_MODE_MIPS32 = UC_MODE_32;    // Mips32 ISA (Mips)
   public static final int UC_MODE_MIPS64 = UC_MODE_64;    // Mips64 ISA (Mips)
}
