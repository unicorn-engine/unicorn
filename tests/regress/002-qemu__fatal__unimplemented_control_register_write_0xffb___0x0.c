#include <unicorn/unicorn.h>

#define HARDWARE_ARCHITECTURE UC_ARCH_M68K
#define HARDWARE_MODE 1073741824
#define MEMORY_STARTING_ADDRESS 8388608
#define MEMORY_SIZE 2097152
#define MEMORY_PERMISSIONS 7
#define BINARY_CODE "\xaf\x80\x4e\x7b\xff\xfb\x80\x4e\x3e\x80"

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  printf("hook_code(…) called\n");
}

int main(int argc, char **argv, char **envp) {
  uc_engine *uc;
  if (uc_open(HARDWARE_ARCHITECTURE, HARDWARE_MODE, &uc)) {
    printf("uc_open(…) failed\n");
    return 1;
  }
  uc_mem_map(uc, MEMORY_STARTING_ADDRESS, MEMORY_SIZE, MEMORY_PERMISSIONS);
  if (uc_mem_write(uc, MEMORY_STARTING_ADDRESS, BINARY_CODE, sizeof(BINARY_CODE) - 1)) {
    printf("uc_mem_write(…) failed\n");
    return 1;
  }
  uc_hook trace;
  uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, (uint64_t)MEMORY_STARTING_ADDRESS, (uint64_t)(MEMORY_STARTING_ADDRESS + 1));
  printf("uc_emu_start(…)\n");
  uc_emu_start(uc, MEMORY_STARTING_ADDRESS, MEMORY_STARTING_ADDRESS + sizeof(BINARY_CODE) - 1, 0, 0);
  printf("done\n");
  return 0;
}
