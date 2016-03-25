#include <unicorn/unicorn.h>

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  printf("tracing\n");
}

#define HARDWARE_ARCHITECTURE UC_ARCH_MIPS
#define HARDWARE_MODE UC_MODE_MIPS32

#define MEMORY_STARTING_ADDRESS 0x1000000
#define MEMORY_SIZE 2 * 1024 * 1024
#define MEMORY_PERMISSIONS UC_PROT_ALL

#define BINARY_CODE "00000000000000000000000000AA"

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
  uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, MEMORY_STARTING_ADDRESS, MEMORY_STARTING_ADDRESS + 1);
  printf("uc_emu_start(…)\n");
  uc_emu_start(uc, MEMORY_STARTING_ADDRESS, MEMORY_STARTING_ADDRESS + sizeof(BINARY_CODE) - 1, 0, 0);
  printf("done\n");
  return 0;
}
