#ifndef _RH850_TRANSLATE_H
#define _RH850_TRANSLATE_H

#include "cpu.h"
#include "exec/translator.h"
#include "tcg/tcg-op.h"

/**
 * This structure contains data, which is needed to translate a
 * sequence of instructions, usually  inside one translation
 * block. The most important member is therefore 'pc', which
 * points to the instruction to be translated. This variable stores
 * PC during compile time (guest instructions to TCG instructions).
 * We must increment this variable manually during translation
 * according to instruction size.
 * Note: Consider renaming to TranslationContext, instead of DisasContext,
 * because it contains information for translation, not disassembler.
 */
typedef struct DisasContext {
    DisasContextBase base;
    CPURH850State *env;
    target_ulong pc;  // pointer to instruction being translated
    uint32_t opcode;
    uint32_t opcode1;  // used for 48 bit instructions

    // Unicorn
    struct uc_struct *uc;
} DisasContext;

void gen_get_gpr(TCGContext *tcg_ctx, TCGv t, int reg_num);
void gen_set_gpr(TCGContext *tcg_ctx, int reg_num_dst, TCGv t);
void gen_set_spr(TCGContext *tcg_ctx, int bank_id, int reg_id, TCGv t);
void gen_get_spr(TCGContext *tcg_ctx, int bank_id, int reg_id, TCGv t);

#endif /* _RH850_TRANSLATE_H */