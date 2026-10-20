/*
 * Unicorn: guest state seen by hooks called from TCG helpers.
 *
 * Hooks run in the middle of a TB, so cpu_restore_state() is used to make
 * the guest state precise for them.  It is meant to unwind to the start of
 * an insn before leaving the TB, though, while after the hooks the TB keeps
 * running.  State that the translator keeps on its own must therefore be put
 * back afterwards: on Arm, the IT bits are only written back at the end of a
 * TB that ends inside an IT block, so a restored value would leak into the
 * next TB.
 */

#ifndef UC_HOOK_STATE_H
#define UC_HOOK_STATE_H

#include "exec/exec-all.h"
#include "uc_priv.h"

typedef struct UcHookState {
    bool synced;
#ifdef TARGET_ARM
    uint32_t condexec_bits;
    uint32_t restored_condexec_bits;
#endif
} UcHookState;

static inline void uc_hook_state_init(CPUArchState *env, UcHookState *state)
{
    state->synced = false;
#ifdef TARGET_ARM
    state->condexec_bits = env->condexec_bits;
    state->restored_condexec_bits = env->condexec_bits;
#endif
}

/* Call before each hook callback. */
static inline void uc_hook_state_sync(CPUArchState *env, uintptr_t retaddr,
                                      UcHookState *state)
{
    struct uc_struct *uc = env->uc;

    if (!state->synced && !uc->skip_sync_pc_on_exit && retaddr) {
        cpu_restore_state(uc->cpu, retaddr, false);
        state->synced = true;
#ifdef TARGET_ARM
        state->restored_condexec_bits = env->condexec_bits;
#endif
    }
#ifdef TARGET_ARM
    else if (state->synced) {
        env->condexec_bits = state->restored_condexec_bits;
    }
#endif
}

/* Call once the hooks are done and the TB may continue. */
static inline void uc_hook_state_restore(CPUArchState *env,
                                         UcHookState *state)
{
#ifdef TARGET_ARM
    if (state->synced && !env->uc->stop_request) {
        env->condexec_bits = state->condexec_bits;
    }
#endif
}

#endif
