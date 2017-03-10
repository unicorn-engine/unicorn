#ifndef QEMU_ELF_H
#define QEMU_ELF_H

/*
 * i386 ELF relocation types
 */
#define R_386_NONE	0
#define R_386_32	1
#define R_386_PC32	2
#define R_386_GOT32	3
#define R_386_PLT32	4
#define R_386_COPY	5
#define R_386_GLOB_DAT	6
#define R_386_JMP_SLOT	7
#define R_386_RELATIVE	8
#define R_386_GOTOFF	9
#define R_386_GOTPC	10
#define R_386_NUM	11
/* Not a dynamic reloc, so not included in R_386_NUM.  Used in TCG.  */
#define R_386_PC8	23

/*
 * Mips ELF relocation types
 */
#define R_MIPS_NONE		0
#define R_MIPS_16		1
#define R_MIPS_32		2
#define R_MIPS_REL32		3
#define R_MIPS_26		4
#define R_MIPS_HI16		5
#define R_MIPS_LO16		6
#define R_MIPS_GPREL16		7
#define R_MIPS_LITERAL		8
#define R_MIPS_GOT16		9
#define R_MIPS_PC16		10
#define R_MIPS_CALL16		11
#define R_MIPS_GPREL32		12
/* The remaining relocs are defined on Irix, although they are not
   in the MIPS ELF ABI.  */
#define R_MIPS_UNUSED1		13
#define R_MIPS_UNUSED2		14
#define R_MIPS_UNUSED3		15
#define R_MIPS_SHIFT5		16
#define R_MIPS_SHIFT6		17
#define R_MIPS_64		18
#define R_MIPS_GOT_DISP		19
#define R_MIPS_GOT_PAGE		20
#define R_MIPS_GOT_OFST		21
/*
 * The following two relocation types are specified in the MIPS ABI
 * conformance guide version 1.2 but not yet in the psABI.
 */
#define R_MIPS_GOTHI16		22
#define R_MIPS_GOTLO16		23
#define R_MIPS_SUB		24
#define R_MIPS_INSERT_A		25
#define R_MIPS_INSERT_B		26
#define R_MIPS_DELETE		27
#define R_MIPS_HIGHER		28
#define R_MIPS_HIGHEST		29
/*
 * The following two relocation types are specified in the MIPS ABI
 * conformance guide version 1.2 but not yet in the psABI.
 */
#define R_MIPS_CALLHI16		30
#define R_MIPS_CALLLO16		31
/*
 * This range is reserved for vendor specific relocations.
 */
#define R_MIPS_LOVENDOR		100
#define R_MIPS_HIVENDOR		127

/*
 * Sparc ELF relocation types
 */
#define	R_SPARC_NONE		0
#define	R_SPARC_8		1
#define	R_SPARC_16		2
#define	R_SPARC_32		3
#define	R_SPARC_DISP8		4
#define	R_SPARC_DISP16		5
#define	R_SPARC_DISP32		6
#define	R_SPARC_WDISP30		7
#define	R_SPARC_WDISP22		8
#define	R_SPARC_HI22		9
#define	R_SPARC_22		10
#define	R_SPARC_13		11
#define	R_SPARC_LO10		12
#define	R_SPARC_GOT10		13
#define	R_SPARC_GOT13		14
#define	R_SPARC_GOT22		15
#define	R_SPARC_PC10		16
#define	R_SPARC_PC22		17
#define	R_SPARC_WPLT30		18
#define	R_SPARC_COPY		19
#define	R_SPARC_GLOB_DAT	20
#define	R_SPARC_JMP_SLOT	21
#define	R_SPARC_RELATIVE	22
#define	R_SPARC_UA32		23
#define R_SPARC_PLT32		24
#define R_SPARC_HIPLT22		25
#define R_SPARC_LOPLT10		26
#define R_SPARC_PCPLT32		27
#define R_SPARC_PCPLT22		28
#define R_SPARC_PCPLT10		29
#define R_SPARC_10		30
#define R_SPARC_11		31
#define R_SPARC_64		32
#define R_SPARC_OLO10           33
#define R_SPARC_HH22            34
#define R_SPARC_HM10            35
#define R_SPARC_LM22            36
#define R_SPARC_WDISP16		40
#define R_SPARC_WDISP19		41
#define R_SPARC_7		43
#define R_SPARC_5		44
#define R_SPARC_6		45


/* Bits present in AT_HWCAP for ARM.  */
#define HWCAP_ARM_IDIVA         (1 << 17)

/* Bits present in AT_HWCAP for s390.  */
#define HWCAP_S390_STFLE        4

/* Bits present in AT_HWCAP for Sparc.  */
#define HWCAP_SPARC_VIS3        0x00020000

/* Bits present in AT_HWCAP for PowerPC.  */
#define PPC_FEATURE_ARCH_2_06           0x00000100

/* Symbolic values for the entries in the auxiliary table
  put on the initial stack */
#define AT_PLATFORM 15  /* string identifying CPU for optimizations */
#define AT_HWCAP  16    /* arch dependent hints at CPU capabilities */
#define AT_DCACHEBSIZE   19  /* data cache block size */
#define AT_ICACHEBSIZE 20  /* instruction cache block size */

/*
 * 68k ELF relocation types
 */
#define R_68K_NONE	0
#define R_68K_32	1
#define R_68K_16	2
#define R_68K_8		3
#define R_68K_PC32	4
#define R_68K_PC16	5
#define R_68K_PC8	6
#define R_68K_GOT32	7
#define R_68K_GOT16	8
#define R_68K_GOT8	9
#define R_68K_GOT32O	10
#define R_68K_GOT16O	11
#define R_68K_GOT8O	12
#define R_68K_PLT32	13
#define R_68K_PLT16	14
#define R_68K_PLT8	15
#define R_68K_PLT32O	16
#define R_68K_PLT16O	17
#define R_68K_PLT8O	18
#define R_68K_COPY	19
#define R_68K_GLOB_DAT	20
#define R_68K_JMP_SLOT	21
#define R_68K_RELATIVE	22

/* PowerPC relocations defined by the ABIs */
#define R_PPC_NONE		0
#define R_PPC_ADDR32		1	/* 32bit absolute address */
#define R_PPC_ADDR24		2	/* 26bit address, 2 bits ignored.  */
#define R_PPC_ADDR16		3	/* 16bit absolute address */
#define R_PPC_ADDR16_LO		4	/* lower 16bit of absolute address */
#define R_PPC_ADDR16_HI		5	/* high 16bit of absolute address */
#define R_PPC_ADDR16_HA		6	/* adjusted high 16bit */
#define R_PPC_ADDR14		7	/* 16bit address, 2 bits ignored */
#define R_PPC_ADDR14_BRTAKEN	8
#define R_PPC_ADDR14_BRNTAKEN	9
#define R_PPC_REL24		10	/* PC relative 26 bit */
#define R_PPC_REL14		11	/* PC relative 16 bit */
#define R_PPC_REL14_BRTAKEN	12
#define R_PPC_REL14_BRNTAKEN	13
#define R_PPC_GOT16		14
#define R_PPC_GOT16_LO		15
#define R_PPC_GOT16_HI		16
#define R_PPC_GOT16_HA		17
#define R_PPC_PLTREL24		18
#define R_PPC_COPY		19
#define R_PPC_GLOB_DAT		20
#define R_PPC_JMP_SLOT		21
#define R_PPC_RELATIVE		22
#define R_PPC_LOCAL24PC		23
#define R_PPC_UADDR32		24
#define R_PPC_UADDR16		25
#define R_PPC_REL32		26
#define R_PPC_PLT32		27
#define R_PPC_PLTREL32		28
#define R_PPC_PLT16_LO		29
#define R_PPC_PLT16_HI		30
#define R_PPC_PLT16_HA		31
#define R_PPC_SDAREL16		32
#define R_PPC_SECTOFF		33
#define R_PPC_SECTOFF_LO	34
#define R_PPC_SECTOFF_HI	35
#define R_PPC_SECTOFF_HA	36
/* Keep this the last entry.  */
#ifndef R_PPC_NUM
#define R_PPC_NUM		37
#endif

/* ARM relocs.  */
#define R_ARM_NONE		0	/* No reloc */
#define R_ARM_PC24		1	/* PC relative 26 bit branch */
#define R_ARM_ABS32		2	/* Direct 32 bit  */
#define R_ARM_REL32		3	/* PC relative 32 bit */
#define R_ARM_PC13		4
#define R_ARM_ABS16		5	/* Direct 16 bit */
#define R_ARM_ABS12		6	/* Direct 12 bit */
#define R_ARM_THM_ABS5		7
#define R_ARM_ABS8		8	/* Direct 8 bit */
#define R_ARM_SBREL32		9
#define R_ARM_THM_PC22		10
#define R_ARM_THM_PC8		11
#define R_ARM_AMP_VCALL9	12
#define R_ARM_SWI24		13
#define R_ARM_THM_SWI8		14
#define R_ARM_XPC25		15
#define R_ARM_THM_XPC22		16
#define R_ARM_COPY		20	/* Copy symbol at runtime */
#define R_ARM_GLOB_DAT		21	/* Create GOT entry */
#define R_ARM_JUMP_SLOT		22	/* Create PLT entry */
#define R_ARM_RELATIVE		23	/* Adjust by program base */
#define R_ARM_GOTOFF		24	/* 32 bit offset to GOT */
#define R_ARM_GOTPC		25	/* 32 bit PC relative offset to GOT */
#define R_ARM_GOT32		26	/* 32 bit GOT entry */
#define R_ARM_PLT32		27	/* 32 bit PLT address */
#define R_ARM_CALL              28
#define R_ARM_JUMP24            29
#define R_ARM_GNU_VTENTRY	100
#define R_ARM_GNU_VTINHERIT	101
#define R_ARM_THM_PC11		102	/* thumb unconditional branch */
#define R_ARM_THM_PC9		103	/* thumb conditional branch */
#define R_ARM_RXPC25		249
#define R_ARM_RSBREL32		250
#define R_ARM_THM_RPC22		251
#define R_ARM_RREL32		252
#define R_ARM_RABS22		253
#define R_ARM_RPC24		254
#define R_ARM_RBASE		255
/* Keep this the last entry.  */
#define R_ARM_NUM		256

/* ARM Aarch64 relocation types */
#define R_AARCH64_NONE                256 /* also accepts R_ARM_NONE (0) */
/* static data relocations */
#define R_AARCH64_ABS64               257
#define R_AARCH64_ABS32               258
#define R_AARCH64_ABS16               259
#define R_AARCH64_PREL64              260
#define R_AARCH64_PREL32              261
#define R_AARCH64_PREL16              262
/* static aarch64 group relocations */
/* group relocs to create unsigned data value or address inline */
#define R_AARCH64_MOVW_UABS_G0        263
#define R_AARCH64_MOVW_UABS_G0_NC     264
#define R_AARCH64_MOVW_UABS_G1        265
#define R_AARCH64_MOVW_UABS_G1_NC     266
#define R_AARCH64_MOVW_UABS_G2        267
#define R_AARCH64_MOVW_UABS_G2_NC     268
#define R_AARCH64_MOVW_UABS_G3        269
/* group relocs to create signed data or offset value inline */
#define R_AARCH64_MOVW_SABS_G0        270
#define R_AARCH64_MOVW_SABS_G1        271
#define R_AARCH64_MOVW_SABS_G2        272
/* relocs to generate 19, 21, and 33 bit PC-relative addresses */
#define R_AARCH64_LD_PREL_LO19        273
#define R_AARCH64_ADR_PREL_LO21       274
#define R_AARCH64_ADR_PREL_PG_HI21    275
#define R_AARCH64_ADR_PREL_PG_HI21_NC 276
#define R_AARCH64_ADD_ABS_LO12_NC     277
#define R_AARCH64_LDST8_ABS_LO12_NC   278
#define R_AARCH64_LDST16_ABS_LO12_NC  284
#define R_AARCH64_LDST32_ABS_LO12_NC  285
#define R_AARCH64_LDST64_ABS_LO12_NC  286
#define R_AARCH64_LDST128_ABS_LO12_NC 299
/* relocs for control-flow - all offsets as multiple of 4 */
#define R_AARCH64_TSTBR14             279
#define R_AARCH64_CONDBR19            280
#define R_AARCH64_JUMP26              282
#define R_AARCH64_CALL26              283
/* group relocs to create pc-relative offset inline */
#define R_AARCH64_MOVW_PREL_G0        287
#define R_AARCH64_MOVW_PREL_G0_NC     288
#define R_AARCH64_MOVW_PREL_G1        289
#define R_AARCH64_MOVW_PREL_G1_NC     290
#define R_AARCH64_MOVW_PREL_G2        291
#define R_AARCH64_MOVW_PREL_G2_NC     292
#define R_AARCH64_MOVW_PREL_G3        293
/* group relocs to create a GOT-relative offset inline */
#define R_AARCH64_MOVW_GOTOFF_G0      300
#define R_AARCH64_MOVW_GOTOFF_G0_NC   301
#define R_AARCH64_MOVW_GOTOFF_G1      302
#define R_AARCH64_MOVW_GOTOFF_G1_NC   303
#define R_AARCH64_MOVW_GOTOFF_G2      304
#define R_AARCH64_MOVW_GOTOFF_G2_NC   305
#define R_AARCH64_MOVW_GOTOFF_G3      306
/* GOT-relative data relocs */
#define R_AARCH64_GOTREL64            307
#define R_AARCH64_GOTREL32            308
/* GOT-relative instr relocs */
#define R_AARCH64_GOT_LD_PREL19       309
#define R_AARCH64_LD64_GOTOFF_LO15    310
#define R_AARCH64_ADR_GOT_PAGE        311
#define R_AARCH64_LD64_GOT_LO12_NC    312
#define R_AARCH64_LD64_GOTPAGE_LO15   313
/* General Dynamic TLS relocations */
#define R_AARCH64_TLSGD_ADR_PREL21            512
#define R_AARCH64_TLSGD_ADR_PAGE21            513
#define R_AARCH64_TLSGD_ADD_LO12_NC           514
#define R_AARCH64_TLSGD_MOVW_G1               515
#define R_AARCH64_TLSGD_MOVW_G0_NC            516
/* Local Dynamic TLS relocations */
#define R_AARCH64_TLSLD_ADR_PREL21            517
#define R_AARCH64_TLSLD_ADR_PAGE21            518
#define R_AARCH64_TLSLD_ADD_LO12_NC           519
#define R_AARCH64_TLSLD_MOVW_G1               520
#define R_AARCH64_TLSLD_MOVW_G0_NC            521
#define R_AARCH64_TLSLD_LD_PREL19             522
#define R_AARCH64_TLSLD_MOVW_DTPREL_G2        523
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1        524
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC     525
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0        526
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC     527
#define R_AARCH64_TLSLD_ADD_DTPREL_HI12       528
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12       529
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC    530
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12     531
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC  532
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12    533
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC 534
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12    535
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC 536
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12    537
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC 538
/* initial exec TLS relocations */
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G1      539
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC   540
#define R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21   541
#define R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 542
#define R_AARCH64_TLSIE_LD_GOTTPREL_PREL19    543
/* local exec TLS relocations */
#define R_AARCH64_TLSLE_MOVW_TPREL_G2         544
#define R_AARCH64_TLSLE_MOVW_TPREL_G1         545
#define R_AARCH64_TLSLE_MOVW_TPREL_G1_NC      546
#define R_AARCH64_TLSLE_MOVW_TPREL_G0         547
#define R_AARCH64_TLSLE_MOVW_TPREL_G0_NC      548
#define R_AARCH64_TLSLE_ADD_TPREL_HI12        549
#define R_AARCH64_TLSLE_ADD_TPREL_LO12        550
#define R_AARCH64_TLSLE_ADD_TPREL_LO12_NC     551
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12      552
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC   553
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12     554
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC  555
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12     556
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC  557
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12     558
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC  559
/* Dynamic Relocations */
#define R_AARCH64_COPY         1024
#define R_AARCH64_GLOB_DAT     1025
#define R_AARCH64_JUMP_SLOT    1026
#define R_AARCH64_RELATIVE     1027
#define R_AARCH64_TLS_DTPREL64 1028
#define R_AARCH64_TLS_DTPMOD64 1029
#define R_AARCH64_TLS_TPREL64  1030
#define R_AARCH64_TLS_DTPREL32 1031
#define R_AARCH64_TLS_DTPMOD32 1032
#define R_AARCH64_TLS_TPREL32  1033

/* s390 relocations defined by the ABIs */
#define R_390_NONE		0	/* No reloc.  */
#define R_390_8			1	/* Direct 8 bit.  */
#define R_390_12		2	/* Direct 12 bit.  */
#define R_390_16		3	/* Direct 16 bit.  */
#define R_390_32		4	/* Direct 32 bit.  */
#define R_390_PC32		5	/* PC relative 32 bit.	*/
#define R_390_GOT12		6	/* 12 bit GOT offset.  */
#define R_390_GOT32		7	/* 32 bit GOT offset.  */
#define R_390_PLT32		8	/* 32 bit PC relative PLT address.  */
#define R_390_COPY		9	/* Copy symbol at runtime.  */
#define R_390_GLOB_DAT		10	/* Create GOT entry.  */
#define R_390_JMP_SLOT		11	/* Create PLT entry.  */
#define R_390_RELATIVE		12	/* Adjust by program base.  */
#define R_390_GOTOFF32		13	/* 32 bit offset to GOT.	 */
#define R_390_GOTPC		14	/* 32 bit PC rel. offset to GOT.  */
#define R_390_GOT16		15	/* 16 bit GOT offset.  */
#define R_390_PC16		16	/* PC relative 16 bit.	*/
#define R_390_PC16DBL		17	/* PC relative 16 bit shifted by 1.  */
#define R_390_PLT16DBL		18	/* 16 bit PC rel. PLT shifted by 1.  */
#define R_390_PC32DBL		19	/* PC relative 32 bit shifted by 1.  */
#define R_390_PLT32DBL		20	/* 32 bit PC rel. PLT shifted by 1.  */
#define R_390_GOTPCDBL		21	/* 32 bit PC rel. GOT shifted by 1.  */
#define R_390_64		22	/* Direct 64 bit.  */
#define R_390_PC64		23	/* PC relative 64 bit.	*/
#define R_390_GOT64		24	/* 64 bit GOT offset.  */
#define R_390_PLT64		25	/* 64 bit PC relative PLT address.  */
#define R_390_GOTENT		26	/* 32 bit PC rel. to GOT entry >> 1. */
#define R_390_GOTOFF16		27	/* 16 bit offset to GOT. */
#define R_390_GOTOFF64		28	/* 64 bit offset to GOT. */
#define R_390_GOTPLT12		29	/* 12 bit offset to jump slot.	*/
#define R_390_GOTPLT16		30	/* 16 bit offset to jump slot.	*/
#define R_390_GOTPLT32		31	/* 32 bit offset to jump slot.	*/
#define R_390_GOTPLT64		32	/* 64 bit offset to jump slot.	*/
#define R_390_GOTPLTENT		33	/* 32 bit rel. offset to jump slot.  */
#define R_390_PLTOFF16		34	/* 16 bit offset from GOT to PLT. */
#define R_390_PLTOFF32		35	/* 32 bit offset from GOT to PLT. */
#define R_390_PLTOFF64		36	/* 16 bit offset from GOT to PLT. */
#define R_390_TLS_LOAD		37	/* Tag for load insn in TLS code. */
#define R_390_TLS_GDCALL	38	/* Tag for function call in general
                                           dynamic TLS code.  */
#define R_390_TLS_LDCALL	39	/* Tag for function call in local
                                           dynamic TLS code.  */
#define R_390_TLS_GD32		40	/* Direct 32 bit for general dynamic
                                           thread local data.  */
#define R_390_TLS_GD64		41	/* Direct 64 bit for general dynamic
                                           thread local data.  */
#define R_390_TLS_GOTIE12	42	/* 12 bit GOT offset for static TLS
                                           block offset.  */
#define R_390_TLS_GOTIE32	43	/* 32 bit GOT offset for static TLS
                                           block offset.  */
#define R_390_TLS_GOTIE64	44	/* 64 bit GOT offset for static TLS
                                           block offset.  */
#define R_390_TLS_LDM32		45	/* Direct 32 bit for local dynamic
                                           thread local data in LD code.  */
#define R_390_TLS_LDM64		46	/* Direct 64 bit for local dynamic
                                           thread local data in LD code.  */
#define R_390_TLS_IE32		47	/* 32 bit address of GOT entry for
                                           negated static TLS block offset.  */
#define R_390_TLS_IE64		48	/* 64 bit address of GOT entry for
                                           negated static TLS block offset.  */
#define R_390_TLS_IEENT		49	/* 32 bit rel. offset to GOT entry for
                                           negated static TLS block offset.  */
#define R_390_TLS_LE32		50	/* 32 bit negated offset relative to
                                           static TLS block.  */
#define R_390_TLS_LE64		51	/* 64 bit negated offset relative to
                                           static TLS block.  */
#define R_390_TLS_LDO32		52	/* 32 bit offset relative to TLS
                                           block.  */
#define R_390_TLS_LDO64		53	/* 64 bit offset relative to TLS
                                           block.  */
#define R_390_TLS_DTPMOD	54	/* ID of module containing symbol.  */
#define R_390_TLS_DTPOFF	55	/* Offset in TLS block.  */
#define R_390_TLS_TPOFF		56	/* Negate offset in static TLS
                                           block.  */
/* Keep this the last entry.  */
#define R_390_NUM	57

/* x86-64 relocation types */
#define R_X86_64_NONE		0	/* No reloc */
#define R_X86_64_64		1	/* Direct 64 bit  */
#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
#define R_X86_64_PLT32		4	/* 32 bit PLT address */
#define R_X86_64_COPY		5	/* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
#define R_X86_64_RELATIVE	8	/* Adjust by program base */
#define R_X86_64_GOTPCREL	9	/* 32 bit signed pc relative
                       offset to GOT */
#define R_X86_64_32		10	/* Direct 32 bit zero extended */
#define R_X86_64_32S		11	/* Direct 32 bit sign extended */
#define R_X86_64_16		12	/* Direct 16 bit zero extended */
#define R_X86_64_PC16		13	/* 16 bit sign extended pc relative */
#define R_X86_64_8		14	/* Direct 8 bit sign extended  */
#define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */

#define R_X86_64_NUM		16

/* IA-64 relocations.  */
#define R_IA64_NONE		0x00	/* none */
#define R_IA64_IMM14		0x21	/* symbol + addend, add imm14 */
#define R_IA64_IMM22		0x22	/* symbol + addend, add imm22 */
#define R_IA64_IMM64		0x23	/* symbol + addend, mov imm64 */
#define R_IA64_DIR32MSB		0x24	/* symbol + addend, data4 MSB */
#define R_IA64_DIR32LSB		0x25	/* symbol + addend, data4 LSB */
#define R_IA64_DIR64MSB		0x26	/* symbol + addend, data8 MSB */
#define R_IA64_DIR64LSB		0x27	/* symbol + addend, data8 LSB */
#define R_IA64_GPREL22		0x2a	/* @gprel(sym + add), add imm22 */
#define R_IA64_GPREL64I		0x2b	/* @gprel(sym + add), mov imm64 */
#define R_IA64_GPREL32MSB	0x2c	/* @gprel(sym + add), data4 MSB */
#define R_IA64_GPREL32LSB	0x2d	/* @gprel(sym + add), data4 LSB */
#define R_IA64_GPREL64MSB	0x2e	/* @gprel(sym + add), data8 MSB */
#define R_IA64_GPREL64LSB	0x2f	/* @gprel(sym + add), data8 LSB */
#define R_IA64_LTOFF22		0x32	/* @ltoff(sym + add), add imm22 */
#define R_IA64_LTOFF64I		0x33	/* @ltoff(sym + add), mov imm64 */
#define R_IA64_PLTOFF22		0x3a	/* @pltoff(sym + add), add imm22 */
#define R_IA64_PLTOFF64I	0x3b	/* @pltoff(sym + add), mov imm64 */
#define R_IA64_PLTOFF64MSB	0x3e	/* @pltoff(sym + add), data8 MSB */
#define R_IA64_PLTOFF64LSB	0x3f	/* @pltoff(sym + add), data8 LSB */
#define R_IA64_FPTR64I		0x43	/* @fptr(sym + add), mov imm64 */
#define R_IA64_FPTR32MSB	0x44	/* @fptr(sym + add), data4 MSB */
#define R_IA64_FPTR32LSB	0x45	/* @fptr(sym + add), data4 LSB */
#define R_IA64_FPTR64MSB	0x46	/* @fptr(sym + add), data8 MSB */
#define R_IA64_FPTR64LSB	0x47	/* @fptr(sym + add), data8 LSB */
#define R_IA64_PCREL60B		0x48	/* @pcrel(sym + add), brl */
#define R_IA64_PCREL21B		0x49	/* @pcrel(sym + add), ptb, call */
#define R_IA64_PCREL21M		0x4a	/* @pcrel(sym + add), chk.s */
#define R_IA64_PCREL21F		0x4b	/* @pcrel(sym + add), fchkf */
#define R_IA64_PCREL32MSB	0x4c	/* @pcrel(sym + add), data4 MSB */
#define R_IA64_PCREL32LSB	0x4d	/* @pcrel(sym + add), data4 LSB */
#define R_IA64_PCREL64MSB	0x4e	/* @pcrel(sym + add), data8 MSB */
#define R_IA64_PCREL64LSB	0x4f	/* @pcrel(sym + add), data8 LSB */
#define R_IA64_LTOFF_FPTR22	0x52	/* @ltoff(@fptr(s+a)), imm22 */
#define R_IA64_LTOFF_FPTR64I	0x53	/* @ltoff(@fptr(s+a)), imm64 */
#define R_IA64_LTOFF_FPTR32MSB	0x54	/* @ltoff(@fptr(s+a)), data4 MSB */
#define R_IA64_LTOFF_FPTR32LSB	0x55	/* @ltoff(@fptr(s+a)), data4 LSB */
#define R_IA64_LTOFF_FPTR64MSB	0x56	/* @ltoff(@fptr(s+a)), data8 MSB */
#define R_IA64_LTOFF_FPTR64LSB	0x57	/* @ltoff(@fptr(s+a)), data8 LSB */
#define R_IA64_SEGREL32MSB	0x5c	/* @segrel(sym + add), data4 MSB */
#define R_IA64_SEGREL32LSB	0x5d	/* @segrel(sym + add), data4 LSB */
#define R_IA64_SEGREL64MSB	0x5e	/* @segrel(sym + add), data8 MSB */
#define R_IA64_SEGREL64LSB	0x5f	/* @segrel(sym + add), data8 LSB */
#define R_IA64_SECREL32MSB	0x64	/* @secrel(sym + add), data4 MSB */
#define R_IA64_SECREL32LSB	0x65	/* @secrel(sym + add), data4 LSB */
#define R_IA64_SECREL64MSB	0x66	/* @secrel(sym + add), data8 MSB */
#define R_IA64_SECREL64LSB	0x67	/* @secrel(sym + add), data8 LSB */
#define R_IA64_REL32MSB		0x6c	/* data 4 + REL */
#define R_IA64_REL32LSB		0x6d	/* data 4 + REL */
#define R_IA64_REL64MSB		0x6e	/* data 8 + REL */
#define R_IA64_REL64LSB		0x6f	/* data 8 + REL */
#define R_IA64_LTV32MSB		0x74	/* symbol + addend, data4 MSB */
#define R_IA64_LTV32LSB		0x75	/* symbol + addend, data4 LSB */
#define R_IA64_LTV64MSB		0x76	/* symbol + addend, data8 MSB */
#define R_IA64_LTV64LSB		0x77	/* symbol + addend, data8 LSB */
#define R_IA64_PCREL21BI	0x79	/* @pcrel(sym + add), 21bit inst */
#define R_IA64_PCREL22		0x7a	/* @pcrel(sym + add), 22bit inst */
#define R_IA64_PCREL64I		0x7b	/* @pcrel(sym + add), 64bit inst */
#define R_IA64_IPLTMSB		0x80	/* dynamic reloc, imported PLT, MSB */
#define R_IA64_IPLTLSB		0x81	/* dynamic reloc, imported PLT, LSB */
#define R_IA64_COPY		0x84	/* copy relocation */
#define R_IA64_SUB		0x85	/* Addend and symbol difference */
#define R_IA64_LTOFF22X		0x86	/* LTOFF22, relaxable.  */
#define R_IA64_LDXMOV		0x87	/* Use of LTOFF22X.  */
#define R_IA64_TPREL14		0x91	/* @tprel(sym + add), imm14 */
#define R_IA64_TPREL22		0x92	/* @tprel(sym + add), imm22 */
#define R_IA64_TPREL64I		0x93	/* @tprel(sym + add), imm64 */
#define R_IA64_TPREL64MSB	0x96	/* @tprel(sym + add), data8 MSB */
#define R_IA64_TPREL64LSB	0x97	/* @tprel(sym + add), data8 LSB */
#define R_IA64_LTOFF_TPREL22	0x9a	/* @ltoff(@tprel(s+a)), imm2 */
#define R_IA64_DTPMOD64MSB	0xa6	/* @dtpmod(sym + add), data8 MSB */
#define R_IA64_DTPMOD64LSB	0xa7	/* @dtpmod(sym + add), data8 LSB */
#define R_IA64_LTOFF_DTPMOD22	0xaa	/* @ltoff(@dtpmod(sym + add)), imm22 */
#define R_IA64_DTPREL14		0xb1	/* @dtprel(sym + add), imm14 */
#define R_IA64_DTPREL22		0xb2	/* @dtprel(sym + add), imm22 */
#define R_IA64_DTPREL64I	0xb3	/* @dtprel(sym + add), imm64 */
#define R_IA64_DTPREL32MSB	0xb4	/* @dtprel(sym + add), data4 MSB */
#define R_IA64_DTPREL32LSB	0xb5	/* @dtprel(sym + add), data4 LSB */
#define R_IA64_DTPREL64MSB	0xb6	/* @dtprel(sym + add), data8 MSB */
#define R_IA64_DTPREL64LSB	0xb7	/* @dtprel(sym + add), data8 LSB */
#define R_IA64_LTOFF_DTPREL22	0xba	/* @ltoff(@dtprel(s+a)), imm22 */

#endif /* QEMU_ELF_H */
