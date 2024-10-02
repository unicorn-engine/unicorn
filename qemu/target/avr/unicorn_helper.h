#ifndef QEMU_UNICORN_HELPER_H
#define QEMU_UNICORN_HELPER_H

#include <uc_priv.h>

#define UC_GET_TCG_CONTEXT(uc)          ((uc)->tcg_ctx)
#define DISAS_GET_UC_CONTEXT(ctx)       ((ctx)->env->uc)
#define DISAS_GET_TCG_CONTEXT(ctx)      UC_GET_TCG_CONTEXT(DISAS_GET_UC_CONTEXT(ctx))

#define INIT_UC_CONTEXT_FROM_DISAS(ctx) \
    struct uc_struct *const uc = DISAS_GET_UC_CONTEXT(ctx)
#define INIT_TCG_CONTEXT_FROM_UC(uc) \
    TCGContext *const tcg_ctx = UC_GET_TCG_CONTEXT(uc)
#define INIT_CPU_ENV_FROM_TCG_CONTEXT(ctx) \
    TCGv_ptr const cpu_env = (ctx)->cpu_env
#define INIT_TCG_CONTEXT_FROM_DISAS(ctx) \
    INIT_TCG_CONTEXT_FROM_UC((ctx)->env->uc)
#define INIT_TCG_CONTEXT_AND_CPU_ENV_FROM_DISAS(ctx) \
    INIT_TCG_CONTEXT_FROM_DISAS(ctx); \
    INIT_CPU_ENV_FROM_TCG_CONTEXT(tcg_ctx)

/* "qapi/error.h */
#if 0
#include <error.h>
#define error_report(...) \
    (error)(EXIT_FAILURE, 0, __VA_ARGS__)
#endif

/* "exec/address-spaces.h" */
#define address_space_memory \
    (cpu->uc->address_space_memory)
#define address_space_ldub(...) \
    glue(address_space_ldub, UNICORN_ARCH_POSTFIX)(uc, __VA_ARGS__)
#define address_space_stb(...) \
    glue(address_space_stb, UNICORN_ARCH_POSTFIX)(uc, __VA_ARGS__)

/* "tcg/tch.h" */
#define tcg_wrapper_I(func, ...) \
    (glue(tcg_,func))(tcg_ctx, ## __VA_ARGS__)
#define tcg_wrapper_X(func, ...) \
    tcg_wrapper_I(glue(func,_avr), ## __VA_ARGS__)
#define tcg_wrapper_tl(func, ...) \
    tcg_wrapper_I(glue(func,_i32), ## __VA_ARGS__)

#undef tcg_const_i32
#define tcg_const_i32(...)		tcg_wrapper_X(const_i32, __VA_ARGS__)
#undef tcg_gen_addi_i32
#define tcg_gen_addi_i32(...)		tcg_wrapper_X(gen_addi_i32, __VA_ARGS__)
//#undef tcg_gen_addi_tl
//#define tcg_gen_addi_tl(...)		tcg_wrapper_tl(gen_addi, __VA_ARGS__)
#undef tcg_gen_add_i32
#define tcg_gen_add_i32(...)		tcg_wrapper_I(gen_add_i32, __VA_ARGS__)
#undef tcg_gen_add_tl
#define tcg_gen_add_tl(...)		tcg_wrapper_tl(gen_add, __VA_ARGS__)
#undef tcg_gen_andc_i32
#define tcg_gen_andc_i32(...)		tcg_wrapper_X(gen_andc_i32, __VA_ARGS__)
//#undef tcg_gen_andc_tl
//#define tcg_gen_andc_tl(...)		tcg_wrapper_tl(gen_andc, __VA_ARGS__)
#undef tcg_gen_andi_i32
#define tcg_gen_andi_i32(...)		tcg_wrapper_X(gen_andi_i32, __VA_ARGS__)
//#undef tcg_gen_andi_tl
//#define tcg_gen_andi_tl(...)		tcg_wrapper_tl(gen_andi, __VA_ARGS__)
#undef tcg_gen_and_i32
#define tcg_gen_and_i32(...)		tcg_wrapper_I(gen_and_i32, __VA_ARGS__)
#undef tcg_gen_and_tl
#define tcg_gen_and_tl(...)		tcg_wrapper_tl(gen_and, __VA_ARGS__)
#undef tcg_gen_brcondi_i32
#define tcg_gen_brcondi_i32(...)	tcg_wrapper_X(gen_brcondi_i32, __VA_ARGS__)
//#undef tcg_gen_brcondi_tl
//#define tcg_gen_brcondi_tl(...)		tcg_wrapper_tl(gen_brcondi, __VA_ARGS__)
#undef tcg_gen_brcond_i32
#define tcg_gen_brcond_i32(...)		tcg_wrapper_X(gen_brcond_i32, __VA_ARGS__)
//#undef tcg_gen_brcond_tl
//#define tcg_gen_brcond_tl(...)		tcg_wrapper_tl(gen_brcond, __VA_ARGS__)
#undef tcg_gen_deposit_i32
#define tcg_gen_deposit_i32(...)	tcg_wrapper_X(gen_deposit_i32, __VA_ARGS__)
//#undef tcg_gen_deposit_tl
//#define tcg_gen_deposit_tl(...)		tcg_wrapper_tl(gen_deposit, __VA_ARGS__)
#undef tcg_gen_exit_tb
#define tcg_gen_exit_tb(...)		tcg_wrapper_X(gen_exit_tb, __VA_ARGS__)
#undef tcg_gen_ext8s_tl
#define tcg_gen_ext8s_tl(...)		tcg_wrapper_tl(gen_ext8s, __VA_ARGS__)
#undef tcg_gen_goto_tb
#define tcg_gen_goto_tb(...)		tcg_wrapper_X(gen_goto_tb, __VA_ARGS__)
#undef tcg_gen_insn_start
#define tcg_gen_insn_start(...)		tcg_wrapper_I(gen_insn_start, __VA_ARGS__)
#undef tcg_gen_movcond_tl
#define tcg_gen_movcond_tl(...)		tcg_wrapper_tl(gen_movcond, __VA_ARGS__)
#undef tcg_gen_movi_i32
#define tcg_gen_movi_i32(...)		tcg_wrapper_I(gen_movi_i32, __VA_ARGS__)
//#undef tcg_gen_movi_i32
//#define tcg_gen_movi_i32(...)		tcg_wrapper(gen_movi_i32, __VA_ARGS__)
#undef tcg_gen_movi_tl
#define tcg_gen_movi_tl(...)		tcg_wrapper_tl(gen_movi, __VA_ARGS__)
#undef tcg_gen_mov_i32
#define tcg_gen_mov_i32(...)		tcg_wrapper(gen_mov_i32, __VA_ARGS__)
#undef tcg_gen_mov_tl
#define tcg_gen_mov_tl(...)		tcg_wrapper_tl(gen_mov, __VA_ARGS__)
#undef tcg_gen_mul_i32
#define tcg_gen_mul_i32(...)		tcg_wrapper(gen_mul_i32, __VA_ARGS__)
#undef tcg_gen_mul_tl
#define tcg_gen_mul_tl(...)		tcg_wrapper_tl(gen_mul, __VA_ARGS__)
#undef tcg_gen_not_i32
#define tcg_gen_not_i32(...)		tcg_wrapper(gen_not_i32, __VA_ARGS__)
#undef tcg_gen_not_tl
#define tcg_gen_not_tl(...)		tcg_wrapper_tl(gen_not, __VA_ARGS__)
#undef tcg_gen_ori_i32
#define tcg_gen_ori_i32(...)		tcg_wrapper_X(gen_ori_i32, __VA_ARGS__)
//#undef tcg_gen_ori_tl
//#define tcg_gen_ori_tl(...)		tcg_wrapper_tl(gen_ori, __VA_ARGS__)
#undef tcg_gen_or_i32
#define tcg_gen_or_i32(...)		tcg_wrapper_I(gen_or_i32, __VA_ARGS__)
#undef tcg_gen_or_tl
#define tcg_gen_or_tl(...)		tcg_wrapper_tl(gen_or, __VA_ARGS__)
#undef tcg_gen_qemu_ld8u
#define tcg_gen_qemu_ld8u(...)		tcg_wrapper_I(gen_qemu_ld8u, __VA_ARGS__)
#undef tcg_gen_qemu_ld_tl
#define tcg_gen_qemu_ld_tl(...)		tcg_wrapper_tl(gen_qemu_ld, __VA_ARGS__)
#undef tcg_gen_qemu_st8
#define tcg_gen_qemu_st8(...)		tcg_wrapper_I(gen_qemu_st8, __VA_ARGS__)
#undef tcg_gen_qemu_st_tl
#define tcg_gen_qemu_st_tl(...)		tcg_wrapper_tl(gen_qemu_st, __VA_ARGS__)
#undef tcg_gen_setcondi_tl
#define tcg_gen_setcondi_tl(...)	tcg_wrapper_tl(gen_setcondi, __VA_ARGS__)
#undef tcg_gen_setcond_tl
#define tcg_gen_setcond_tl(...)		tcg_wrapper_tl(gen_setcond, __VA_ARGS__)
#undef tcg_gen_shli_i32
#define tcg_gen_shli_i32(...)		tcg_wrapper_X(gen_shli_i32, __VA_ARGS__)
//#undef tcg_gen_shli_tl
//#define tcg_gen_shli_tl(...)		tcg_wrapper_tl(gen_shli, __VA_ARGS__)
#undef tcg_gen_shri_i32
#define tcg_gen_shri_i32(...)		tcg_wrapper_X(gen_shri_i32, __VA_ARGS__)
//#undef tcg_gen_shri_tl
//#define tcg_gen_shri_tl(...)		tcg_wrapper_tl(gen_shri, __VA_ARGS__)
#undef tcg_gen_subi_i32
#define tcg_gen_subi_i32(...)		tcg_wrapper_X(gen_subi_i32, __VA_ARGS__)
//#undef tcg_gen_subi_tl
//#define tcg_gen_subi_tl(...)		tcg_wrapper_tl(gen_subi, __VA_ARGS__)
#undef tcg_gen_sub_i32
#define tcg_gen_sub_i32(...)		tcg_wrapper(gen_sub_i32, __VA_ARGS__)
#undef tcg_gen_sub_tl
#define tcg_gen_sub_tl(...)		tcg_wrapper_tl(gen_sub, __VA_ARGS__)
#undef tcg_gen_xori_i32
#define tcg_gen_xori_i32(...)		tcg_wrapper_X(gen_xori_i32, __VA_ARGS__)
//#undef tcg_gen_xori_tl
//#define tcg_gen_xori_tl(...)		tcg_wrapper_tl(gen_xori, __VA_ARGS__)
#undef tcg_gen_xor_i32
#define tcg_gen_xor_i32(...)		tcg_wrapper(gen_xor_i32, __VA_ARGS__)
#undef tcg_gen_xor_tl
#define tcg_gen_xor_tl(...)		tcg_wrapper_tl(gen_xor, __VA_ARGS__)
#undef tcg_global_mem_new_i32
#define tcg_global_mem_new_i32(...)	tcg_wrapper_I(global_mem_new_i32, __VA_ARGS__)
#undef tcg_temp_new_i32
#define tcg_temp_new_i32()		tcg_wrapper_I(temp_new_i32)
#undef tcg_temp_free
#define tcg_temp_free(...)		tcg_wrapper_tl(temp_free, __VA_ARGS__)
#undef tcg_temp_free_i32
#define tcg_temp_free_i32(...)		tcg_wrapper_I(temp_free_i32, __VA_ARGS__)
#undef tcg_op_buf_full
#define tcg_op_buf_full()		tcg_wrapper_I(op_buf_full)
#undef tcg_gen_lookup_and_goto_ptr
#define tcg_gen_lookup_and_goto_ptr() \
    tcg_wrapper_X(gen_lookup_and_goto_ptr)

#endif /* QEMU_UNICORN_HELPER_H */
