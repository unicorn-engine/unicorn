#ifndef PPC_TRANSLATE_H
#define PPC_TRANSLATE_H

#include "cpu.h"
#include "tcg-op.h"
#include "qemu/host-utils.h"
#include "exec/cpu_ldst.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

/* internal defines */
typedef struct DisasContext {
    struct TranslationBlock *tb;
    target_ulong nip;
    uint32_t opcode;
    uint32_t exception;
    /* Routine used to access memory */
    bool pr, hv;
    int mem_idx;
    int access_type;
    /* Translation flags */
    int le_mode;
    TCGMemOp default_tcg_memop_mask;
#if defined(TARGET_PPC64)
    int sf_mode;
    int has_cfar;
#endif
    int fpu_enabled;
    int altivec_enabled;
    int vsx_enabled;
    int spe_enabled;
    ppc_spr_t *spr_cb; /* Needed to check rights for mfspr/mtspr */
    int singlestep_enabled;
    uint64_t insns_flags;
    uint64_t insns_flags2;

    // Unicorn engine
    struct uc_struct *uc;
} DisasContext;

struct opc_handler_t {
    /* invalid bits for instruction 1 (Rc(opcode) == 0) */
    uint32_t inval1;
    /* invalid bits for instruction 2 (Rc(opcode) == 1) */
    uint32_t inval2;
    /* instruction type */
    uint64_t type;
    /* extended instruction type */
    uint64_t type2;
    /* handler */
    void (*handler)(DisasContext *ctx);
#if defined(DO_PPC_STATISTICS) || defined(PPC_DUMP_CPU)
    const char *oname;
#endif
#if defined(DO_PPC_STATISTICS)
    uint64_t count;
#endif
};

typedef struct opcode_t {
    unsigned char opc1, opc2, opc3;
#if HOST_LONG_BITS == 64 /* Explicitly align to 64 bits */
    unsigned char pad[5];
#else
    unsigned char pad[1];
#endif
    opc_handler_t handler;
    const char *oname;
} opcode_t;

#if defined(TARGET_PPC64)
extern opcode_t opcodes[1625];
#else
extern opcode_t opcodes[1552];
#endif

void ppc_translate_init(struct uc_struct *uc);
void gen_invalid(DisasContext *ctx);
int is_indirect_opcode (void *handler);
opc_handler_t **ind_table(void *handler);
int register_insn (opc_handler_t **ppc_opcodes, opcode_t *insn);
void fix_opcode_tables (opc_handler_t **ppc_opcodes);
void fill_new_table (opc_handler_t **table, int len);
void init_proc_e500v2(CPUPPCState *env);
void init_proc_405 (CPUPPCState *env);
void init_proc_401 (CPUPPCState *env);
void init_proc_604(CPUPPCState *env);
void init_proc_970(CPUPPCState *env);
void ppc_cpu_reset(CPUState *s);

void gen_spr_generic(CPUPPCState *env);
void mmubooke_create_initial_mapping(CPUPPCState *env);

#endif

