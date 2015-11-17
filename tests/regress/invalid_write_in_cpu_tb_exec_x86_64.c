#include <unicorn/unicorn.h>

/*
 * Disassembly according to capstone:
 *   mulx rsp, rsp, rdx
 */
#define BINARY "\xc4\xe2\xdb\xf6\xe2"
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
  printf("uc_emu_start(…)\n");
  uc_emu_start(uc, STARTING_ADDRESS, STARTING_ADDRESS + sizeof(BINARY) - 1, 0, 20);
  printf("done\n");
  return 0;
}
