DEF_HELPER_4(uc_tracecode, void, i32, i32, ptr, i64)
DEF_HELPER_6(uc_traceopcode, void, ptr, i64, i64, i32, ptr, i64)
DEF_HELPER_1(uc_rh850_exit, void, env)

/* Exceptions */
DEF_HELPER_2(raise_exception, noreturn, env, i32)
DEF_HELPER_3(raise_exception_with_cause, noreturn, env, i32, i32)


/* Floating Point - rounding mode */
DEF_HELPER_FLAGS_2(set_rounding_mode, TCG_CALL_NO_WG, void, env, i32)

/* Floating Point - fused */
DEF_HELPER_FLAGS_4(fmadd_s, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fmadd_d, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fmsub_s, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fmsub_d, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fnmsub_s, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fnmsub_d, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fnmadd_s, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)
DEF_HELPER_FLAGS_4(fnmadd_d, TCG_CALL_NO_RWG, i64, env, i64, i64, i64)

/* Floating Point - Single Precision */
DEF_HELPER_FLAGS_2(f32_is_normal, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(f32_is_zero_or_normal, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(f32_is_infinity, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_1(f_sync_fflags, TCG_CALL_NO_RWG, void, env)

DEF_HELPER_FLAGS_3(fadd_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(fsub_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(fmul_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(fmax_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(fmin_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(fdiv_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_2(fabs_s, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fneg_s, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(ftrnc_sw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fceil_sw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(ffloor_sw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_sw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(ftrnc_suw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fceil_suw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(ffloor_suw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_suw, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_ws, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_ls, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(fcvt_hs, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_sh, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_uws, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(fcvt_uls, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(ftrnc_sl, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fceil_sl, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(ffloor_sl, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fcvt_sl, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(ftrnc_sul, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fceil_sul, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(ffloor_sul, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fcvt_sul, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fsqrt_s, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(frecip_s, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_2(frsqrt_s, TCG_CALL_NO_RWG, i32, env, i32)

DEF_HELPER_FLAGS_2(f_is_nan_s, TCG_CALL_NO_RWG, i32, env, i32)
DEF_HELPER_FLAGS_3(fle_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(flt_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_3(feq_s, TCG_CALL_NO_RWG, i32, env, i32, i32)
DEF_HELPER_FLAGS_2(fcvt_w_s, TCG_CALL_NO_RWG, tl, env, i64)
DEF_HELPER_FLAGS_2(fcvt_wu_s, TCG_CALL_NO_RWG, tl, env, i64)

DEF_HELPER_FLAGS_4(fmaf_s, TCG_CALL_NO_RWG, i32, env, i32, i32, i32)
DEF_HELPER_FLAGS_4(fmsf_s, TCG_CALL_NO_RWG, i32, env, i32, i32, i32)
DEF_HELPER_FLAGS_4(fnmaf_s, TCG_CALL_NO_RWG, i32, env, i32, i32, i32)
DEF_HELPER_FLAGS_4(fnmsf_s, TCG_CALL_NO_RWG, i32, env, i32, i32, i32)




#if defined(TARGET_RH85064)
DEF_HELPER_FLAGS_2(fcvt_l_s, TCG_CALL_NO_RWG, tl, env, i64)
DEF_HELPER_FLAGS_2(fcvt_lu_s, TCG_CALL_NO_RWG, tl, env, i64)
#endif
DEF_HELPER_FLAGS_2(fcvt_s_w, TCG_CALL_NO_RWG, i64, env, tl)
DEF_HELPER_FLAGS_2(fcvt_s_wu, TCG_CALL_NO_RWG, i64, env, tl)
#if defined(TARGET_RH85064)
DEF_HELPER_FLAGS_2(fcvt_s_l, TCG_CALL_NO_RWG, i64, env, tl)
DEF_HELPER_FLAGS_2(fcvt_s_lu, TCG_CALL_NO_RWG, i64, env, tl)
#endif
DEF_HELPER_FLAGS_1(fclass_s, TCG_CALL_NO_RWG_SE, tl, i64)

/* Floating Point - Double Precision */
DEF_HELPER_FLAGS_3(fadd_d, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_FLAGS_3(fsub_d, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_FLAGS_3(fmul_d, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_FLAGS_3(fmax_d, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_FLAGS_3(fmin_d, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_FLAGS_3(fdiv_d, TCG_CALL_NO_RWG, i64, env, i64, i64)
DEF_HELPER_FLAGS_2(fabs_d, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fneg_d, TCG_CALL_NO_RWG, i64, env, i64)

DEF_HELPER_FLAGS_2(ftrnc_dw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(fceil_dw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(ffloor_dw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(fcvt_dw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(ftrnc_duw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(fceil_duw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(ffloor_duw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(fcvt_duw, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_2(fcvt_wd, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fcvt_ld, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fcvt_sd, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fcvt_uwd, TCG_CALL_NO_RWG, i64, env, i32)
DEF_HELPER_FLAGS_2(fcvt_uld, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(ftrnc_dl, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fceil_dl, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(ffloor_dl, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fcvt_dl, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(ftrnc_dul, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fceil_dul, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(ffloor_dul, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fcvt_dul, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fsqrt_d, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(frecip_d, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(frsqrt_d, TCG_CALL_NO_RWG, i64, env, i64)

DEF_HELPER_FLAGS_2(f_is_nan_d, TCG_CALL_NO_RWG, i32, env, i64)
DEF_HELPER_FLAGS_3(fle_d, TCG_CALL_NO_RWG, i32, env, i64, i64)
DEF_HELPER_FLAGS_3(flt_d, TCG_CALL_NO_RWG, i32, env, i64, i64)
DEF_HELPER_FLAGS_3(feq_d, TCG_CALL_NO_RWG, i32, env, i64, i64)



DEF_HELPER_FLAGS_2(fcvt_s_d, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fcvt_d_s, TCG_CALL_NO_RWG, i64, env, i64)
DEF_HELPER_FLAGS_2(fcvt_w_d, TCG_CALL_NO_RWG, tl, env, i64)
DEF_HELPER_FLAGS_2(fcvt_wu_d, TCG_CALL_NO_RWG, tl, env, i64)
#if defined(TARGET_RH85064)
DEF_HELPER_FLAGS_2(fcvt_l_d, TCG_CALL_NO_RWG, tl, env, i64)
DEF_HELPER_FLAGS_2(fcvt_lu_d, TCG_CALL_NO_RWG, tl, env, i64)
#endif
DEF_HELPER_FLAGS_2(fcvt_d_w, TCG_CALL_NO_RWG, i64, env, tl)
DEF_HELPER_FLAGS_2(fcvt_d_wu, TCG_CALL_NO_RWG, i64, env, tl)
#if defined(TARGET_RH85064)
DEF_HELPER_FLAGS_2(fcvt_d_l, TCG_CALL_NO_RWG, i64, env, tl)
DEF_HELPER_FLAGS_2(fcvt_d_lu, TCG_CALL_NO_RWG, i64, env, tl)
#endif
DEF_HELPER_FLAGS_1(fclass_d, TCG_CALL_NO_RWG_SE, tl, i64)

/* Special functions */
//DEF_HELPER_3(csrrw, tl, env, tl, tl)
//DEF_HELPER_4(csrrs, tl, env, tl, tl, tl)
//DEF_HELPER_4(csrrc, tl, env, tl, tl, tl)
#ifndef CONFIG_USER_ONLY
//DEF_HELPER_2(sret, tl, env, tl)
//DEF_HELPER_2(mret, tl, env, tl)
//DEF_HELPER_1(wfi, void, env)
DEF_HELPER_1(tlb_flush, void, env)
#endif
