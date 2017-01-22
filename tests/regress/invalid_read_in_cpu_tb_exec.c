#include <unicorn/unicorn.h>

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  printf("hook_block(%p, %"PRIx64", %d, %p)\n", uc, address, size, user_data);
}

/*
 * Disassembly according to capstone:
 *   add byte ptr [rip - 1], 0x30
 *   jmp 0x1000000
 */
#define BINARY "\x80\x05\xff\xff\xff\xff\x30\xeb\xf7\x30"
#define MEMORY_SIZE 2 * 1024 * 1024
#define STARTING_ADDRESS 0x1000000

int main(int argc, char **argv, char **envp) {
  uc_engine *uc;
  if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc)) {
    printf("uc_open(…) failed\n");
    return 1;
  }
  uc_mem_map(uc, STARTING_ADDRESS, MEMORY_SIZE, UC_PROT_ALL);
  if (uc_mem_write(uc, STARTING_ADDRESS, BINARY, sizeof(BINARY) - 1)) {
    printf("uc_mem_write(…) failed\n");
    return 1;
  }
  uc_hook hook;
  uc_hook_add(uc, &hook, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
  printf("uc_emu_start(…)\n");
  uc_emu_start(uc, STARTING_ADDRESS, STARTING_ADDRESS + sizeof(BINARY) - 1, 0, 20);
  printf("done\n");
  return 0;
}
