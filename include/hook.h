/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_HOOK_H
#define UC_HOOK_H

// return -1 on failure, index to traces[] on success.
size_t hook_add(struct uc_struct *uc, int type, uint64_t begin, uint64_t end, void *callback, void *user_data);

// return 0 on success, -1 on failure
uc_err hook_del(struct uc_struct *uc, uc_hook hh);

// return NULL on failure
struct hook_struct *hook_find(struct uc_struct *uc, int type, uint64_t address);

// return index of an free hook entry in hook_callbacks[] array.
// this realloc memory if needed.
size_t hook_find_new(struct uc_struct *uc);

#endif
