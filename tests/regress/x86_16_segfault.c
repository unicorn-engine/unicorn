#include <unicorn/unicorn.h>

#define BINARY "\x90"
#define MEMORY_SIZE 4 * 1024
#define STARTING_ADDRESS 100 * 1024

int main(int argc, char **argv, char **envp) {
  uc_engine *uc;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc)) {
    printf("uc_open(…) failed\n");
    return 1;
  }
  uc_mem_map(uc, STARTING_ADDRESS, MEMORY_SIZE, UC_PROT_ALL);
  if (uc_mem_write(uc, STARTING_ADDRESS, BINARY, sizeof(BINARY) - 1)) {
    printf("uc_mem_write(…) failed\n");
    return 1;
  }
  printf("uc_emu_start(…)\n");
  uc_emu_start(uc, STARTING_ADDRESS, STARTING_ADDRESS + sizeof(BINARY) - 1, 0, 20);
  printf("done\n");
  return 0;
}
