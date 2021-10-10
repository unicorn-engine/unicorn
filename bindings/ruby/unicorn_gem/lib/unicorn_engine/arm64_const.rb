# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [arm64_const.rb]

module UnicornEngine

# ARM64 registers

	UC_ARM64_REG_INVALID = 0
	UC_ARM64_REG_X29 = 1
	UC_ARM64_REG_X30 = 2
	UC_ARM64_REG_NZCV = 3
	UC_ARM64_REG_SP = 4
	UC_ARM64_REG_WSP = 5
	UC_ARM64_REG_WZR = 6
	UC_ARM64_REG_XZR = 7
	UC_ARM64_REG_B0 = 8
	UC_ARM64_REG_B1 = 9
	UC_ARM64_REG_B2 = 10
	UC_ARM64_REG_B3 = 11
	UC_ARM64_REG_B4 = 12
	UC_ARM64_REG_B5 = 13
	UC_ARM64_REG_B6 = 14
	UC_ARM64_REG_B7 = 15
	UC_ARM64_REG_B8 = 16
	UC_ARM64_REG_B9 = 17
	UC_ARM64_REG_B10 = 18
	UC_ARM64_REG_B11 = 19
	UC_ARM64_REG_B12 = 20
	UC_ARM64_REG_B13 = 21
	UC_ARM64_REG_B14 = 22
	UC_ARM64_REG_B15 = 23
	UC_ARM64_REG_B16 = 24
	UC_ARM64_REG_B17 = 25
	UC_ARM64_REG_B18 = 26
	UC_ARM64_REG_B19 = 27
	UC_ARM64_REG_B20 = 28
	UC_ARM64_REG_B21 = 29
	UC_ARM64_REG_B22 = 30
	UC_ARM64_REG_B23 = 31
	UC_ARM64_REG_B24 = 32
	UC_ARM64_REG_B25 = 33
	UC_ARM64_REG_B26 = 34
	UC_ARM64_REG_B27 = 35
	UC_ARM64_REG_B28 = 36
	UC_ARM64_REG_B29 = 37
	UC_ARM64_REG_B30 = 38
	UC_ARM64_REG_B31 = 39
	UC_ARM64_REG_D0 = 40
	UC_ARM64_REG_D1 = 41
	UC_ARM64_REG_D2 = 42
	UC_ARM64_REG_D3 = 43
	UC_ARM64_REG_D4 = 44
	UC_ARM64_REG_D5 = 45
	UC_ARM64_REG_D6 = 46
	UC_ARM64_REG_D7 = 47
	UC_ARM64_REG_D8 = 48
	UC_ARM64_REG_D9 = 49
	UC_ARM64_REG_D10 = 50
	UC_ARM64_REG_D11 = 51
	UC_ARM64_REG_D12 = 52
	UC_ARM64_REG_D13 = 53
	UC_ARM64_REG_D14 = 54
	UC_ARM64_REG_D15 = 55
	UC_ARM64_REG_D16 = 56
	UC_ARM64_REG_D17 = 57
	UC_ARM64_REG_D18 = 58
	UC_ARM64_REG_D19 = 59
	UC_ARM64_REG_D20 = 60
	UC_ARM64_REG_D21 = 61
	UC_ARM64_REG_D22 = 62
	UC_ARM64_REG_D23 = 63
	UC_ARM64_REG_D24 = 64
	UC_ARM64_REG_D25 = 65
	UC_ARM64_REG_D26 = 66
	UC_ARM64_REG_D27 = 67
	UC_ARM64_REG_D28 = 68
	UC_ARM64_REG_D29 = 69
	UC_ARM64_REG_D30 = 70
	UC_ARM64_REG_D31 = 71
	UC_ARM64_REG_H0 = 72
	UC_ARM64_REG_H1 = 73
	UC_ARM64_REG_H2 = 74
	UC_ARM64_REG_H3 = 75
	UC_ARM64_REG_H4 = 76
	UC_ARM64_REG_H5 = 77
	UC_ARM64_REG_H6 = 78
	UC_ARM64_REG_H7 = 79
	UC_ARM64_REG_H8 = 80
	UC_ARM64_REG_H9 = 81
	UC_ARM64_REG_H10 = 82
	UC_ARM64_REG_H11 = 83
	UC_ARM64_REG_H12 = 84
	UC_ARM64_REG_H13 = 85
	UC_ARM64_REG_H14 = 86
	UC_ARM64_REG_H15 = 87
	UC_ARM64_REG_H16 = 88
	UC_ARM64_REG_H17 = 89
	UC_ARM64_REG_H18 = 90
	UC_ARM64_REG_H19 = 91
	UC_ARM64_REG_H20 = 92
	UC_ARM64_REG_H21 = 93
	UC_ARM64_REG_H22 = 94
	UC_ARM64_REG_H23 = 95
	UC_ARM64_REG_H24 = 96
	UC_ARM64_REG_H25 = 97
	UC_ARM64_REG_H26 = 98
	UC_ARM64_REG_H27 = 99
	UC_ARM64_REG_H28 = 100
	UC_ARM64_REG_H29 = 101
	UC_ARM64_REG_H30 = 102
	UC_ARM64_REG_H31 = 103
	UC_ARM64_REG_Q0 = 104
	UC_ARM64_REG_Q1 = 105
	UC_ARM64_REG_Q2 = 106
	UC_ARM64_REG_Q3 = 107
	UC_ARM64_REG_Q4 = 108
	UC_ARM64_REG_Q5 = 109
	UC_ARM64_REG_Q6 = 110
	UC_ARM64_REG_Q7 = 111
	UC_ARM64_REG_Q8 = 112
	UC_ARM64_REG_Q9 = 113
	UC_ARM64_REG_Q10 = 114
	UC_ARM64_REG_Q11 = 115
	UC_ARM64_REG_Q12 = 116
	UC_ARM64_REG_Q13 = 117
	UC_ARM64_REG_Q14 = 118
	UC_ARM64_REG_Q15 = 119
	UC_ARM64_REG_Q16 = 120
	UC_ARM64_REG_Q17 = 121
	UC_ARM64_REG_Q18 = 122
	UC_ARM64_REG_Q19 = 123
	UC_ARM64_REG_Q20 = 124
	UC_ARM64_REG_Q21 = 125
	UC_ARM64_REG_Q22 = 126
	UC_ARM64_REG_Q23 = 127
	UC_ARM64_REG_Q24 = 128
	UC_ARM64_REG_Q25 = 129
	UC_ARM64_REG_Q26 = 130
	UC_ARM64_REG_Q27 = 131
	UC_ARM64_REG_Q28 = 132
	UC_ARM64_REG_Q29 = 133
	UC_ARM64_REG_Q30 = 134
	UC_ARM64_REG_Q31 = 135
	UC_ARM64_REG_S0 = 136
	UC_ARM64_REG_S1 = 137
	UC_ARM64_REG_S2 = 138
	UC_ARM64_REG_S3 = 139
	UC_ARM64_REG_S4 = 140
	UC_ARM64_REG_S5 = 141
	UC_ARM64_REG_S6 = 142
	UC_ARM64_REG_S7 = 143
	UC_ARM64_REG_S8 = 144
	UC_ARM64_REG_S9 = 145
	UC_ARM64_REG_S10 = 146
	UC_ARM64_REG_S11 = 147
	UC_ARM64_REG_S12 = 148
	UC_ARM64_REG_S13 = 149
	UC_ARM64_REG_S14 = 150
	UC_ARM64_REG_S15 = 151
	UC_ARM64_REG_S16 = 152
	UC_ARM64_REG_S17 = 153
	UC_ARM64_REG_S18 = 154
	UC_ARM64_REG_S19 = 155
	UC_ARM64_REG_S20 = 156
	UC_ARM64_REG_S21 = 157
	UC_ARM64_REG_S22 = 158
	UC_ARM64_REG_S23 = 159
	UC_ARM64_REG_S24 = 160
	UC_ARM64_REG_S25 = 161
	UC_ARM64_REG_S26 = 162
	UC_ARM64_REG_S27 = 163
	UC_ARM64_REG_S28 = 164
	UC_ARM64_REG_S29 = 165
	UC_ARM64_REG_S30 = 166
	UC_ARM64_REG_S31 = 167
	UC_ARM64_REG_W0 = 168
	UC_ARM64_REG_W1 = 169
	UC_ARM64_REG_W2 = 170
	UC_ARM64_REG_W3 = 171
	UC_ARM64_REG_W4 = 172
	UC_ARM64_REG_W5 = 173
	UC_ARM64_REG_W6 = 174
	UC_ARM64_REG_W7 = 175
	UC_ARM64_REG_W8 = 176
	UC_ARM64_REG_W9 = 177
	UC_ARM64_REG_W10 = 178
	UC_ARM64_REG_W11 = 179
	UC_ARM64_REG_W12 = 180
	UC_ARM64_REG_W13 = 181
	UC_ARM64_REG_W14 = 182
	UC_ARM64_REG_W15 = 183
	UC_ARM64_REG_W16 = 184
	UC_ARM64_REG_W17 = 185
	UC_ARM64_REG_W18 = 186
	UC_ARM64_REG_W19 = 187
	UC_ARM64_REG_W20 = 188
	UC_ARM64_REG_W21 = 189
	UC_ARM64_REG_W22 = 190
	UC_ARM64_REG_W23 = 191
	UC_ARM64_REG_W24 = 192
	UC_ARM64_REG_W25 = 193
	UC_ARM64_REG_W26 = 194
	UC_ARM64_REG_W27 = 195
	UC_ARM64_REG_W28 = 196
	UC_ARM64_REG_W29 = 197
	UC_ARM64_REG_W30 = 198
	UC_ARM64_REG_X0 = 199
	UC_ARM64_REG_X1 = 200
	UC_ARM64_REG_X2 = 201
	UC_ARM64_REG_X3 = 202
	UC_ARM64_REG_X4 = 203
	UC_ARM64_REG_X5 = 204
	UC_ARM64_REG_X6 = 205
	UC_ARM64_REG_X7 = 206
	UC_ARM64_REG_X8 = 207
	UC_ARM64_REG_X9 = 208
	UC_ARM64_REG_X10 = 209
	UC_ARM64_REG_X11 = 210
	UC_ARM64_REG_X12 = 211
	UC_ARM64_REG_X13 = 212
	UC_ARM64_REG_X14 = 213
	UC_ARM64_REG_X15 = 214
	UC_ARM64_REG_X16 = 215
	UC_ARM64_REG_X17 = 216
	UC_ARM64_REG_X18 = 217
	UC_ARM64_REG_X19 = 218
	UC_ARM64_REG_X20 = 219
	UC_ARM64_REG_X21 = 220
	UC_ARM64_REG_X22 = 221
	UC_ARM64_REG_X23 = 222
	UC_ARM64_REG_X24 = 223
	UC_ARM64_REG_X25 = 224
	UC_ARM64_REG_X26 = 225
	UC_ARM64_REG_X27 = 226
	UC_ARM64_REG_X28 = 227
	UC_ARM64_REG_V0 = 228
	UC_ARM64_REG_V1 = 229
	UC_ARM64_REG_V2 = 230
	UC_ARM64_REG_V3 = 231
	UC_ARM64_REG_V4 = 232
	UC_ARM64_REG_V5 = 233
	UC_ARM64_REG_V6 = 234
	UC_ARM64_REG_V7 = 235
	UC_ARM64_REG_V8 = 236
	UC_ARM64_REG_V9 = 237
	UC_ARM64_REG_V10 = 238
	UC_ARM64_REG_V11 = 239
	UC_ARM64_REG_V12 = 240
	UC_ARM64_REG_V13 = 241
	UC_ARM64_REG_V14 = 242
	UC_ARM64_REG_V15 = 243
	UC_ARM64_REG_V16 = 244
	UC_ARM64_REG_V17 = 245
	UC_ARM64_REG_V18 = 246
	UC_ARM64_REG_V19 = 247
	UC_ARM64_REG_V20 = 248
	UC_ARM64_REG_V21 = 249
	UC_ARM64_REG_V22 = 250
	UC_ARM64_REG_V23 = 251
	UC_ARM64_REG_V24 = 252
	UC_ARM64_REG_V25 = 253
	UC_ARM64_REG_V26 = 254
	UC_ARM64_REG_V27 = 255
	UC_ARM64_REG_V28 = 256
	UC_ARM64_REG_V29 = 257
	UC_ARM64_REG_V30 = 258
	UC_ARM64_REG_V31 = 259

# pseudo registers
	UC_ARM64_REG_PC = 260
	UC_ARM64_REG_CPACR_EL1 = 261
	UC_ARM64_REG_PSTATE = 262
	UC_ARM64_REG_ENDING = 263

# alias registers
	UC_ARM64_REG_IP0 = 215
	UC_ARM64_REG_IP1 = 216
	UC_ARM64_REG_FP = 1
	UC_ARM64_REG_LR = 2

# CP registers
	UC_ARM64_REG_ACTLR_EL1 = 2685339649
	UC_ARM64_REG_ACTLR_EL2 = 2685339681
	UC_ARM64_REG_ACTLR_EL3 = 2417225857
	UC_ARM64_REG_AFSR0_EL1 = 2685347968
	UC_ARM64_REG_AFSR0_EL2 = 2685348000
	UC_ARM64_REG_AFSR0_EL3 = 2685348016
	UC_ARM64_REG_AFSR1_EL1 = 2685347969
	UC_ARM64_REG_AFSR1_EL2 = 2685348001
	UC_ARM64_REG_AFSR1_EL3 = 2685348017
	UC_ARM64_REG_AIDR = 2685337615
	UC_ARM64_REG_AMAIR0 = 2685358464
	UC_ARM64_REG_AMAIR1 = 2685358465
	UC_ARM64_REG_AMAIR_EL2 = 2685358496
	UC_ARM64_REG_AMAIR_EL3 = 2417227032
	UC_ARM64_REG_ATS12NSOPR = 2685352964
	UC_ARM64_REG_ATS12NSOPW = 2685352965
	UC_ARM64_REG_ATS12NSOUR = 2685352966
	UC_ARM64_REG_ATS12NSOUW = 2685352967
	UC_ARM64_REG_ATS1CPR = 2685352960
	UC_ARM64_REG_ATS1CPW = 2685352961
	UC_ARM64_REG_ATS1CUR = 2685352962
	UC_ARM64_REG_ATS1CUW = 2685352963
	UC_ARM64_REG_ATS1HR = 2685352992
	UC_ARM64_REG_ATS1HW = 2685352993
	UC_ARM64_REG_AT_S12E0R = 2417189830
	UC_ARM64_REG_AT_S12E0W = 2417189831
	UC_ARM64_REG_AT_S12E1R = 2417189828
	UC_ARM64_REG_AT_S12E1W = 2417189829
	UC_ARM64_REG_AT_S1E0R = 2417181634
	UC_ARM64_REG_AT_S1E0W = 2417181635
	UC_ARM64_REG_AT_S1E1R = 2417181632
	UC_ARM64_REG_AT_S1E1W = 2417181633
	UC_ARM64_REG_AT_S1E2R = 2417189824
	UC_ARM64_REG_AT_S1E2W = 2417189825
	UC_ARM64_REG_AT_S1E3R = 2417193920
	UC_ARM64_REG_AT_S1E3W = 2417193921
	UC_ARM64_REG_BPIALL = 2685352582
	UC_ARM64_REG_BPIALLUIS = 2685352070
	UC_ARM64_REG_BPIMVA = 2685352583
	UC_ARM64_REG_CBAR = 2685368712
	UC_ARM64_REG_CBAR_EL1 = 2417217432
	UC_ARM64_REG_CCSIDR = 2685337608
	UC_ARM64_REG_CLIDR = 2685337609
	UC_ARM64_REG_CNTFRQ = 2685366272
	UC_ARM64_REG_CNTFRQ_EL0 = 2417221376
	UC_ARM64_REG_CNTHCTL_EL2 = 2685366432
	UC_ARM64_REG_CNTHP_CTL_EL2 = 2685366561
	UC_ARM64_REG_CNTHP_CVAL = 2685372208
	UC_ARM64_REG_CNTHP_CVAL_EL2 = 2417223442
	UC_ARM64_REG_CNTHP_TVAL_EL2 = 2685366560
	UC_ARM64_REG_CNTKCTL = 2685366400
	UC_ARM64_REG_CNTPCT = 2685372160
	UC_ARM64_REG_CNTPCT_EL0 = 2417221377
	UC_ARM64_REG_CNTPS_CTL_EL1 = 2417229585
	UC_ARM64_REG_CNTPS_CVAL_EL1 = 2417229586
	UC_ARM64_REG_CNTPS_TVAL_EL1 = 2417229584
	UC_ARM64_REG_CNTP_CTL = 2685366529
	UC_ARM64_REG_CNTP_CTL_EL0 = 2417221393
	UC_ARM64_REG_CNTP_CVAL = 2685372176
	UC_ARM64_REG_CNTP_CVAL_EL0 = 2417221394
	UC_ARM64_REG_CNTP_TVAL = 2685366528
	UC_ARM64_REG_CNTP_TVAL_EL0 = 2417221392
	UC_ARM64_REG_CNTVCT = 2685372168
	UC_ARM64_REG_CNTVCT_EL0 = 2417221378
	UC_ARM64_REG_CNTVOFF = 2685372192
	UC_ARM64_REG_CNTVOFF_EL2 = 2417223427
	UC_ARM64_REG_CNTV_CTL = 2685366657
	UC_ARM64_REG_CNTV_CTL_EL0 = 2417221401
	UC_ARM64_REG_CNTV_CVAL = 2685372184
	UC_ARM64_REG_CNTV_CVAL_EL0 = 2417221402
	UC_ARM64_REG_CNTV_TVAL = 2685366656
	UC_ARM64_REG_CNTV_TVAL_EL0 = 2417221400
	UC_ARM64_REG_CONTEXTIDR_EL1 = 2685364225
	UC_ARM64_REG_CPACR = 2685339650
	UC_ARM64_REG_CPTR_EL2 = 2685339810
	UC_ARM64_REG_CPTR_EL3 = 2417225866
	UC_ARM64_REG_CSSELR = 2685337616
	UC_ARM64_REG_CTR = 2685337601
	UC_ARM64_REG_CTR_EL0 = 2417219585
	UC_ARM64_REG_CURRENTEL = 2417213970
	UC_ARM64_REG_DACR32_EL2 = 2417222016
	UC_ARM64_REG_DAIF = 2417220113
	UC_ARM64_REG_DBGBCR0 = 2685272069
	UC_ARM64_REG_DBGBCR1 = 2685272197
	UC_ARM64_REG_DBGBCR2 = 2685272325
	UC_ARM64_REG_DBGBCR3 = 2685272453
	UC_ARM64_REG_DBGBCR4 = 2685272581
	UC_ARM64_REG_DBGBCR5 = 2685272709
	UC_ARM64_REG_DBGBVR0 = 2685272068
	UC_ARM64_REG_DBGBVR1 = 2685272196
	UC_ARM64_REG_DBGBVR2 = 2685272324
	UC_ARM64_REG_DBGBVR3 = 2685272452
	UC_ARM64_REG_DBGBVR4 = 2685272580
	UC_ARM64_REG_DBGBVR5 = 2685272708
	UC_ARM64_REG_DBGDIDR = 2685272064
	UC_ARM64_REG_DBGDRAR = 2685304960
	UC_ARM64_REG_DBGDSAR = 2685305088
	UC_ARM64_REG_DBGVCR = 2685272960
	UC_ARM64_REG_DBGVCR32_EL2 = 2417205304
	UC_ARM64_REG_DBGWCR0 = 2685272071
	UC_ARM64_REG_DBGWCR1 = 2685272199
	UC_ARM64_REG_DBGWCR2 = 2685272327
	UC_ARM64_REG_DBGWCR3 = 2685272455
	UC_ARM64_REG_DBGWVR0 = 2685272070
	UC_ARM64_REG_DBGWVR1 = 2685272198
	UC_ARM64_REG_DBGWVR2 = 2685272326
	UC_ARM64_REG_DBGWVR3 = 2685272454
	UC_ARM64_REG_DCCIMVAC = 2685353729
	UC_ARM64_REG_DCCISW = 2685353730
	UC_ARM64_REG_DCCMVAC = 2685353217
	UC_ARM64_REG_DCCMVAU = 2685353345
	UC_ARM64_REG_DCCSW = 2685353218
	UC_ARM64_REG_DCIMVAC = 2685352705
	UC_ARM64_REG_DCISW = 2685352706
	UC_ARM64_REG_DCZID_EL0 = 2417219591
	UC_ARM64_REG_DC_CISW = 2417181682
	UC_ARM64_REG_DC_CIVAC = 2417187825
	UC_ARM64_REG_DC_CSW = 2417181650
	UC_ARM64_REG_DC_CVAC = 2417187793
	UC_ARM64_REG_DC_CVAU = 2417187801
	UC_ARM64_REG_DC_ISW = 2417181618
	UC_ARM64_REG_DC_IVAC = 2417181617
	UC_ARM64_REG_DC_ZVA = 2417187745
	UC_ARM64_REG_DFAR = 2685349888
	UC_ARM64_REG_DFSR = 2685347840
	UC_ARM64_REG_DMB = 2685353221
	UC_ARM64_REG_DSB = 2685353220
	UC_ARM64_REG_DTLBIALL = 2685354752
	UC_ARM64_REG_DTLBIASID = 2685354754
	UC_ARM64_REG_DTLBIMVA = 2685354753
	UC_ARM64_REG_ELR_EL1 = 2417213953
	UC_ARM64_REG_ELR_EL2 = 2417222145
	UC_ARM64_REG_ELR_EL3 = 2417226241
	UC_ARM64_REG_ESR_EL1 = 2417214096
	UC_ARM64_REG_ESR_EL2 = 2685348128
	UC_ARM64_REG_ESR_EL3 = 2417226384
	UC_ARM64_REG_FAR_EL1 = 2417214208
	UC_ARM64_REG_FAR_EL2 = 2685349920
	UC_ARM64_REG_FAR_EL3 = 2417226496
	UC_ARM64_REG_FCSEIDR = 2685364224
	UC_ARM64_REG_FPCR = 2417220128
	UC_ARM64_REG_FPEXC32_EL2 = 2417222296
	UC_ARM64_REG_FPSR = 2417220129
	UC_ARM64_REG_HACR_EL2 = 2685339815
	UC_ARM64_REG_HAMAIR1 = 2685358497
	UC_ARM64_REG_HCR = 2685339808
	UC_ARM64_REG_HCR2 = 2685339812
	UC_ARM64_REG_HCR_EL2 = 2417221768
	UC_ARM64_REG_HIFAR = 2685349922
	UC_ARM64_REG_HMAIR1 = 2685358369
	UC_ARM64_REG_HPFAR = 2685349924
	UC_ARM64_REG_HPFAR_EL2 = 2417222404
	UC_ARM64_REG_HSTR_EL2 = 2685339811
	UC_ARM64_REG_HTTBR = 2685370656
	UC_ARM64_REG_ICIALLU = 2685352576
	UC_ARM64_REG_ICIALLUIS = 2685352064
	UC_ARM64_REG_ICIMVAU = 2685352577
	UC_ARM64_REG_IC_IALLU = 2417181608
	UC_ARM64_REG_IC_IALLUIS = 2417181576
	UC_ARM64_REG_IC_IVAU = 2417187753
	UC_ARM64_REG_ID_AA64AFR0_EL1 = 2417213484
	UC_ARM64_REG_ID_AA64AFR1_EL1 = 2417213485
	UC_ARM64_REG_ID_AA64AFR2_EL1_RESERVED = 2417213486
	UC_ARM64_REG_ID_AA64AFR3_EL1_RESERVED = 2417213487
	UC_ARM64_REG_ID_AA64DFR0_EL1 = 2417213480
	UC_ARM64_REG_ID_AA64DFR1_EL1 = 2417213481
	UC_ARM64_REG_ID_AA64DFR2_EL1_RESERVED = 2417213482
	UC_ARM64_REG_ID_AA64DFR3_EL1_RESERVED = 2417213483
	UC_ARM64_REG_ID_AA64ISAR0_EL1 = 2417213488
	UC_ARM64_REG_ID_AA64ISAR1_EL1 = 2417213489
	UC_ARM64_REG_ID_AA64ISAR2_EL1_RESERVED = 2417213490
	UC_ARM64_REG_ID_AA64ISAR3_EL1_RESERVED = 2417213491
	UC_ARM64_REG_ID_AA64ISAR4_EL1_RESERVED = 2417213492
	UC_ARM64_REG_ID_AA64ISAR5_EL1_RESERVED = 2417213493
	UC_ARM64_REG_ID_AA64ISAR6_EL1_RESERVED = 2417213494
	UC_ARM64_REG_ID_AA64ISAR7_EL1_RESERVED = 2417213495
	UC_ARM64_REG_ID_AA64MMFR0_EL1 = 2417213496
	UC_ARM64_REG_ID_AA64MMFR1_EL1 = 2417213497
	UC_ARM64_REG_ID_AA64MMFR2_EL1 = 2417213498
	UC_ARM64_REG_ID_AA64MMFR3_EL1_RESERVED = 2417213499
	UC_ARM64_REG_ID_AA64MMFR4_EL1_RESERVED = 2417213500
	UC_ARM64_REG_ID_AA64MMFR5_EL1_RESERVED = 2417213501
	UC_ARM64_REG_ID_AA64MMFR6_EL1_RESERVED = 2417213502
	UC_ARM64_REG_ID_AA64MMFR7_EL1_RESERVED = 2417213503
	UC_ARM64_REG_ID_AA64PFR0_EL1 = 2417213472
	UC_ARM64_REG_ID_AA64PFR1_EL1 = 2417213473
	UC_ARM64_REG_ID_AA64PFR2_EL1_RESERVED = 2417213474
	UC_ARM64_REG_ID_AA64PFR3_EL1_RESERVED = 2417213475
	UC_ARM64_REG_ID_AA64PFR5_EL1_RESERVED = 2417213477
	UC_ARM64_REG_ID_AA64PFR6_EL1_RESERVED = 2417213478
	UC_ARM64_REG_ID_AA64PFR7_EL1_RESERVED = 2417213479
	UC_ARM64_REG_ID_AA64ZFR0_EL1 = 2417213476
	UC_ARM64_REG_ID_AFR0 = 2685337731
	UC_ARM64_REG_ID_DFR0 = 2685337730
	UC_ARM64_REG_ID_ISAR0 = 2685337856
	UC_ARM64_REG_ID_ISAR1 = 2685337857
	UC_ARM64_REG_ID_ISAR2 = 2685337858
	UC_ARM64_REG_ID_ISAR3 = 2685337859
	UC_ARM64_REG_ID_ISAR4 = 2685337860
	UC_ARM64_REG_ID_ISAR5 = 2685337861
	UC_ARM64_REG_ID_ISAR6 = 2685337863
	UC_ARM64_REG_ID_MMFR0 = 2685337732
	UC_ARM64_REG_ID_MMFR1 = 2685337733
	UC_ARM64_REG_ID_MMFR2 = 2685337734
	UC_ARM64_REG_ID_MMFR3 = 2685337735
	UC_ARM64_REG_ID_MMFR4 = 2685337862
	UC_ARM64_REG_ID_PFR0 = 2685337728
	UC_ARM64_REG_ID_PFR1 = 2685337729
	UC_ARM64_REG_IFAR = 2685349890
	UC_ARM64_REG_IFSR = 2685347841
	UC_ARM64_REG_IFSR32_EL2 = 2417222273
	UC_ARM64_REG_ISB = 2685352580
	UC_ARM64_REG_ISR_EL1 = 2685362304
	UC_ARM64_REG_ITLBIALL = 2685354624
	UC_ARM64_REG_ITLBIASID = 2685354626
	UC_ARM64_REG_ITLBIMVA = 2685354625
	UC_ARM64_REG_JIDR = 2685272120
	UC_ARM64_REG_JMCR = 2685276216
	UC_ARM64_REG_JOSCR = 2685274168
	UC_ARM64_REG_MAIR0 = 2685358336
	UC_ARM64_REG_MAIR1 = 2685358337
	UC_ARM64_REG_MAIR_EL1 = 2417214736
	UC_ARM64_REG_MAIR_EL2 = 2685358368
	UC_ARM64_REG_MAIR_EL3 = 2417227024
	UC_ARM64_REG_MDCCINT_EL1 = 2685272320
	UC_ARM64_REG_MDCCSR_EL0 = 2685272192
	UC_ARM64_REG_MDCR_EL2 = 2685339809
	UC_ARM64_REG_MDCR_EL3 = 2417225881
	UC_ARM64_REG_MDRAR_EL1 = 2417197184
	UC_ARM64_REG_MDSCR_EL1 = 2685272322
	UC_ARM64_REG_MIDR_EL1 = 2685337600
	UC_ARM64_REG_MPIDR_EL1 = 2685337605
	UC_ARM64_REG_MVA_prefetch = 2685353601
	UC_ARM64_REG_MVBAR = 2685362177
	UC_ARM64_REG_MVFR0_EL1 = 2417213464
	UC_ARM64_REG_MVFR1_EL1 = 2417213465
	UC_ARM64_REG_MVFR2_EL1 = 2417213466
	UC_ARM64_REG_MVFR3_EL1_RESERVED = 2417213467
	UC_ARM64_REG_MVFR4_EL1_RESERVED = 2417213468
	UC_ARM64_REG_MVFR5_EL1_RESERVED = 2417213469
	UC_ARM64_REG_MVFR6_EL1_RESERVED = 2417213470
	UC_ARM64_REG_MVFR7_EL1_RESERVED = 2417213471
	UC_ARM64_REG_NOP = 2685351940
	UC_ARM64_REG_NSACR = 2685339778
	UC_ARM64_REG_OSDLR_EL1 = 2685274500
	UC_ARM64_REG_OSLAR_EL1 = 2685274116
	UC_ARM64_REG_OSLSR_EL1 = 2685274244
	UC_ARM64_REG_PAR = 2685352448
	UC_ARM64_REG_PAR_EL1 = 2417214368
	UC_ARM64_REG_PMCCFILTR = 2685368199
	UC_ARM64_REG_PMCCFILTR_EL0 = 2417221503
	UC_ARM64_REG_PMCCNTR = 2685357696
	UC_ARM64_REG_PMCCNTR_EL0 = 2417220840
	UC_ARM64_REG_PMCEID0 = 2685357574
	UC_ARM64_REG_PMCEID0_EL0 = 2417220838
	UC_ARM64_REG_PMCEID1 = 2685357575
	UC_ARM64_REG_PMCEID1_EL0 = 2417220839
	UC_ARM64_REG_PMCNTENCLR = 2685357570
	UC_ARM64_REG_PMCNTENCLR_EL0 = 2417220834
	UC_ARM64_REG_PMCNTENSET = 2685357569
	UC_ARM64_REG_PMCNTENSET_EL0 = 2417220833
	UC_ARM64_REG_PMCR = 2685357568
	UC_ARM64_REG_PMCR_EL0 = 2417220832
	UC_ARM64_REG_PMEVCNTR0 = 2685367296
	UC_ARM64_REG_PMEVCNTR0_EL0 = 2417221440
	UC_ARM64_REG_PMEVCNTR1 = 2685367297
	UC_ARM64_REG_PMEVCNTR1_EL0 = 2417221441
	UC_ARM64_REG_PMEVCNTR2 = 2685367298
	UC_ARM64_REG_PMEVCNTR2_EL0 = 2417221442
	UC_ARM64_REG_PMEVCNTR3 = 2685367299
	UC_ARM64_REG_PMEVCNTR3_EL0 = 2417221443
	UC_ARM64_REG_PMEVTYPER0 = 2685367808
	UC_ARM64_REG_PMEVTYPER0_EL0 = 2417221472
	UC_ARM64_REG_PMEVTYPER1 = 2685367809
	UC_ARM64_REG_PMEVTYPER1_EL0 = 2417221473
	UC_ARM64_REG_PMEVTYPER2 = 2685367810
	UC_ARM64_REG_PMEVTYPER2_EL0 = 2417221474
	UC_ARM64_REG_PMEVTYPER3 = 2685367811
	UC_ARM64_REG_PMEVTYPER3_EL0 = 2417221475
	UC_ARM64_REG_PMINTENCLR = 2685357826
	UC_ARM64_REG_PMINTENCLR_EL1 = 2417214706
	UC_ARM64_REG_PMINTENSET = 2685357825
	UC_ARM64_REG_PMINTENSET_EL1 = 2417214705
	UC_ARM64_REG_PMOVSCLR_EL0 = 2417220835
	UC_ARM64_REG_PMOVSR = 2685357571
	UC_ARM64_REG_PMOVSSET = 2685357827
	UC_ARM64_REG_PMOVSSET_EL0 = 2417220851
	UC_ARM64_REG_PMSELR = 2685357573
	UC_ARM64_REG_PMSELR_EL0 = 2417220837
	UC_ARM64_REG_PMSWINC = 2685357572
	UC_ARM64_REG_PMSWINC_EL0 = 2417220836
	UC_ARM64_REG_PMUSERENR = 2685357824
	UC_ARM64_REG_PMUSERENR_EL0 = 2417220848
	UC_ARM64_REG_PMXEVCNTR = 2685357698
	UC_ARM64_REG_PMXEVCNTR_EL0 = 2417220842
	UC_ARM64_REG_PMXEVTYPER = 2685357697
	UC_ARM64_REG_PMXEVTYPER_EL0 = 2417220841
	UC_ARM64_REG_REVIDR_EL1 = 2685337606
	UC_ARM64_REG_RVBAR_EL3 = 2417227265
	UC_ARM64_REG_SCR = 2685339776
	UC_ARM64_REG_SCR_EL3 = 2417225864
	UC_ARM64_REG_SCTLR = 2685339648
	UC_ARM64_REG_SCTLR_EL2 = 2685339680
	UC_ARM64_REG_SCTLR_EL3 = 2417225856
	UC_ARM64_REG_SDCR = 2685340033
	UC_ARM64_REG_SDER = 2685339777
	UC_ARM64_REG_SDER32_EL3 = 2417225865
	UC_ARM64_REG_SPSR_ABT = 2417222169
	UC_ARM64_REG_SPSR_EL1 = 2417213952
	UC_ARM64_REG_SPSR_EL2 = 2417222144
	UC_ARM64_REG_SPSR_EL3 = 2417226240
	UC_ARM64_REG_SPSR_FIQ = 2417222171
	UC_ARM64_REG_SPSR_IRQ = 2417222168
	UC_ARM64_REG_SPSR_UND = 2417222170
	UC_ARM64_REG_SPSel = 2417213968
	UC_ARM64_REG_SP_EL0 = 2417213960
	UC_ARM64_REG_SP_EL1 = 2417222152
	UC_ARM64_REG_SP_EL2 = 2417226248
	UC_ARM64_REG_TCMTR = 2685337602
	UC_ARM64_REG_TCR_EL1 = 2417213698
	UC_ARM64_REG_TCR_EL2 = 2685341730
	UC_ARM64_REG_TCR_EL3 = 2417225986
	UC_ARM64_REG_TLBIALL = 2685354880
	UC_ARM64_REG_TLBIALLH = 2685354912
	UC_ARM64_REG_TLBIALLHIS = 2685354400
	UC_ARM64_REG_TLBIALLIS = 2685354368
	UC_ARM64_REG_TLBIALLNSNH = 2685354916
	UC_ARM64_REG_TLBIALLNSNHIS = 2685354404
	UC_ARM64_REG_TLBIASID = 2685354882
	UC_ARM64_REG_TLBIASIDIS = 2685354370
	UC_ARM64_REG_TLBIIPAS2 = 2685354529
	UC_ARM64_REG_TLBIIPAS2IS = 2685354017
	UC_ARM64_REG_TLBIIPAS2L = 2685354533
	UC_ARM64_REG_TLBIIPAS2LIS = 2685354021
	UC_ARM64_REG_TLBIMVA = 2685354881
	UC_ARM64_REG_TLBIMVAA = 2685354883
	UC_ARM64_REG_TLBIMVAAIS = 2685354371
	UC_ARM64_REG_TLBIMVAAL = 2685354887
	UC_ARM64_REG_TLBIMVAALIS = 2685354375
	UC_ARM64_REG_TLBIMVAH = 2685354913
	UC_ARM64_REG_TLBIMVAHIS = 2685354401
	UC_ARM64_REG_TLBIMVAIS = 2685354369
	UC_ARM64_REG_TLBIMVAL = 2685354885
	UC_ARM64_REG_TLBIMVALH = 2685354917
	UC_ARM64_REG_TLBIMVALHIS = 2685354405
	UC_ARM64_REG_TLBIMVALIS = 2685354373
	UC_ARM64_REG_TLBI_ALLE1 = 2417189948
	UC_ARM64_REG_TLBI_ALLE1IS = 2417189916
	UC_ARM64_REG_TLBI_ALLE2 = 2417189944
	UC_ARM64_REG_TLBI_ALLE2IS = 2417189912
	UC_ARM64_REG_TLBI_ALLE3 = 2417194040
	UC_ARM64_REG_TLBI_ALLE3IS = 2417194008
	UC_ARM64_REG_TLBI_ASIDE1 = 2417181754
	UC_ARM64_REG_TLBI_ASIDE1IS = 2417181722
	UC_ARM64_REG_TLBI_IPAS2E1 = 2417189921
	UC_ARM64_REG_TLBI_IPAS2E1IS = 2417189889
	UC_ARM64_REG_TLBI_IPAS2LE1 = 2417189925
	UC_ARM64_REG_TLBI_IPAS2LE1IS = 2417189893
	UC_ARM64_REG_TLBI_VAAE1 = 2417181755
	UC_ARM64_REG_TLBI_VAAE1IS = 2417181723
	UC_ARM64_REG_TLBI_VAALE1 = 2417181759
	UC_ARM64_REG_TLBI_VAALE1IS = 2417181727
	UC_ARM64_REG_TLBI_VAE1 = 2417181753
	UC_ARM64_REG_TLBI_VAE1IS = 2417181721
	UC_ARM64_REG_TLBI_VAE2 = 2417189945
	UC_ARM64_REG_TLBI_VAE2IS = 2417189913
	UC_ARM64_REG_TLBI_VAE3 = 2417194041
	UC_ARM64_REG_TLBI_VAE3IS = 2417194009
	UC_ARM64_REG_TLBI_VALE1 = 2417181757
	UC_ARM64_REG_TLBI_VALE1IS = 2417181725
	UC_ARM64_REG_TLBI_VALE2 = 2417189949
	UC_ARM64_REG_TLBI_VALE2IS = 2417189917
	UC_ARM64_REG_TLBI_VALE3 = 2417194045
	UC_ARM64_REG_TLBI_VALE3IS = 2417194013
	UC_ARM64_REG_TLBI_VMALLE1 = 2417181752
	UC_ARM64_REG_TLBI_VMALLE1IS = 2417181720
	UC_ARM64_REG_TLBI_VMALLS12E1 = 2417189950
	UC_ARM64_REG_TLBI_VMALLS12E1IS = 2417189918
	UC_ARM64_REG_TLBTR = 2685337603
	UC_ARM64_REG_TPIDRPRW = 2685364228
	UC_ARM64_REG_TPIDRRO_EL0 = 2417221251
	UC_ARM64_REG_TPIDRURO = 2685364227
	UC_ARM64_REG_TPIDRURW = 2685364226
	UC_ARM64_REG_TPIDR_EL0 = 2417221250
	UC_ARM64_REG_TPIDR_EL1 = 2417215108
	UC_ARM64_REG_TPIDR_EL2 = 2685364258
	UC_ARM64_REG_TPIDR_EL3 = 2417227394
	UC_ARM64_REG_TTBCR = 2685341698
	UC_ARM64_REG_TTBR0 = 2685370624
	UC_ARM64_REG_TTBR0_EL1 = 2685341696
	UC_ARM64_REG_TTBR0_EL2 = 2417221888
	UC_ARM64_REG_TTBR0_EL3 = 2417225984
	UC_ARM64_REG_TTBR1 = 2685370632
	UC_ARM64_REG_TTBR1_EL1 = 2685341697
	UC_ARM64_REG_VBAR = 2685362176
	UC_ARM64_REG_VBAR_EL2 = 2685362208
	UC_ARM64_REG_VBAR_EL3 = 2417227264
	UC_ARM64_REG_VMPIDR = 2685337637
	UC_ARM64_REG_VMPIDR_EL2 = 2417221637
	UC_ARM64_REG_VPIDR = 2685337632
	UC_ARM64_REG_VPIDR_EL2 = 2417221632
	UC_ARM64_REG_VTCR = 2685341858
	UC_ARM64_REG_VTCR_EL2 = 2417221898
	UC_ARM64_REG_VTTBR = 2685370672
	UC_ARM64_REG_VTTBR_EL2 = 2417221896
	UC_ARM64_REG_WFAR = 2685349889
	UC_ARM64_REG_VBAR_EL1 = 2685362176
end